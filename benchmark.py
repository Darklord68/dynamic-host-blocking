#!/usr/bin/env python3
"""D2 benchmark: baseline (MODE none) vs dynamic blocking.

Mock (any OS, no Mininet, writes FAKE data):  py benchmark.py --mock
Real (Ubuntu VM, Ryu already running, repo root):
    sudo python3 benchmark.py --quick --out results/results_quick.csv
    sudo python3 benchmark.py --attackers 1 --rates 10 50 100
"""
import argparse
import csv
import itertools
import os
import random
import re
import socket
import subprocess
import sys
import time
from subprocess import PIPE, STDOUT

COLUMNS = ["run_id", "mode", "attackers", "attack_rate", "rep",
           "time_to_block_s", "legit_attempts", "legit_success_pct",
           "legit_avg_ms", "legit_p95_ms", "attack_conns_at_server",
           "drop_packets"]

SERVER_IP, SERVER_PORT = "10.0.0.1", 9000
CTRL_IP = "10.0.0.254"
HELPER = ("127.0.0.1", 9100)
ATTACKERS = {1: ["h2"], 2: ["h2", "h5"]}
IPS = {"h2": "10.0.0.2", "h3": "10.0.0.3", "h5": "10.0.0.5"}
LEGIT_COUNT, LEGIT_DELAY_MS = 100, 250      # about 25 s of legit traffic
ATTACK_START_S, ATTACK_SECS = 3, 20
CLIENT = "./sockets/client"


def run_id(mode, attackers, rate, rep):
    tag = "dyn" if mode == "dynamic" else "none"
    return f"{tag}_a{attackers}_r{rate}_rep{rep}"


def combos(modes, attackers, rates, reps):
    for mode, a, r, rep in itertools.product(modes, attackers, rates,
                                             range(1, reps + 1)):
        yield mode, a, r, rep


def append_row(path, row):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    new = not os.path.exists(path) or os.path.getsize(path) == 0
    with open(path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        if new:
            w.writeheader()
        w.writerow({c: row.get(c, "") for c in COLUMNS})


# ---------------------------------------------------------------- mock mode
def mock_run(mode, attackers, rate, rep):
    """FAKE numbers with a plausible shape. Never put these in results.csv."""
    rid = run_id(mode, attackers, rate, rep)
    rnd = random.Random(rid)
    row = dict(run_id=rid, mode=mode, attackers=attackers, attack_rate=rate,
               rep=rep, legit_attempts=LEGIT_COUNT)
    if mode == "dynamic":
        ttb = round(rnd.uniform(1.5, 4.0) + 0.01 * rate, 3)
        ok = LEGIT_COUNT - rnd.randint(0, 3)
        avg = round(rnd.uniform(3, 8), 1)
        row.update(time_to_block_s=ttb, legit_success_pct=round(100 * ok / LEGIT_COUNT, 1),
                   legit_avg_ms=avg, legit_p95_ms=round(avg * 1.8, 1),
                   attack_conns_at_server=int(rate * ttb * attackers),
                   drop_packets=int(rate * (ATTACK_SECS - ttb) * attackers * 3))
    else:   # baseline: no block, so time_to_block and drop_packets stay EMPTY
        load = rate * attackers
        ok = max(10, int(LEGIT_COUNT * (1 - 0.0045 * load)) - rnd.randint(0, 3))
        avg = round(5 + 0.25 * load + rnd.uniform(-1, 1), 1)
        row.update(legit_success_pct=round(100 * ok / LEGIT_COUNT, 1),
                   legit_avg_ms=avg, legit_p95_ms=round(avg * 2.5, 1),
                   attack_conns_at_server=rate * ATTACK_SECS * attackers)
    return row


# ---------------------------------------------------------------- real mode
def helper(cmd, timeout=3):
    """One command on the controller helper port (new connection each time)."""
    with socket.create_connection(HELPER, timeout=timeout) as s:
        s.sendall((cmd + "\n").encode())
        return s.recv(1024).decode().strip()


def reset_controller(settle):
    if helper("RESET").startswith("ERR"):     # RESET not implemented yet
        for ip in ("10.0.0.2", "10.0.0.5"):
            helper(f"UNBLOCK {ip}")
    time.sleep(settle)


def parse_summary(text):
    """Summary line of the latency client, for example:
    summary attempts=5 ok=5 failed=0 timeout=0 success_pct=100.0 avg_ms=3.55 p95_ms=7.58 max_ms=7.58
    Returns a dict of the name=value numbers, or {} if there is no summary."""
    for line in reversed(text.strip().splitlines()):
        if not line.startswith("summary"):
            continue
        return {k.lower(): float(v) for k, v in
                re.findall(r"(\w+)\s*[=:]\s*([\d.]+)", line)}
    return {}


TIME_RE = re.compile(r"^\[(?:(\d{4}-\d{2}-\d{2}) )?(\d{2}:\d{2}:\d{2})(?:\.(\d{1,3}))?\]")


def line_epoch(line):
    """Seconds since epoch from an events.log line (old or millisecond format)."""
    m = TIME_RE.match(line)
    if not m:
        return None
    day = m.group(1) or time.strftime("%Y-%m-%d")
    t = time.mktime(time.strptime(f"{day} {m.group(2)}", "%Y-%m-%d %H:%M:%S"))
    return t + (int(m.group(3).ljust(3, "0")) / 1000 if m.group(3) else 0)


def log_offset(path="events.log"):
    return os.path.getsize(path) if os.path.exists(path) else 0


def first_block_time(offset, ips, path="events.log"):
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            for raw in f:
                line = raw.decode(errors="ignore")
                if "EVENT=BLOCK" in line and any(f"host={ip}" in line for ip in ips):
                    return line_epoch(line)
    except OSError:
        pass
    return None


def count_attacker_conns(path, ips):
    pat = re.compile("connect from (%s):" % "|".join(re.escape(i) for i in ips))
    try:
        with open(path, errors="ignore") as f:
            return sum(1 for line in f if pat.search(line))
    except OSError:
        return 0


def drop_packets():
    out = subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"],
                         capture_output=True, text=True).stdout
    total = 0
    for line in out.splitlines():
        if "priority=100" in line:
            m = re.search(r"n_packets=(\d+)", line)
            total += int(m.group(1)) if m else 0
    return total


def root_link():
    """Controller link 10.0.0.254 (the same commands that worked in D1)."""
    for c in ["ip link del rootns0 2>/dev/null",
              "ip link add rootns0 type veth peer name s1-root",
              "ovs-vsctl add-port s1 s1-root",
              f"ip addr add {CTRL_IP}/24 dev rootns0",
              "ip link set rootns0 up", "ip link set s1-root up"]:
        subprocess.run(c, shell=True)


def build_network():
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSSwitch
    net = Mininet(controller=None, switch=OVSSwitch)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    for i in range(1, 6):
        net.addLink(net.addHost(f"h{i}", ip=f"10.0.0.{i}/24"), s1)
    net.start()
    root_link()
    return net


def real_run(net, mode, attackers, rate, rep, settle):
    rid = run_id(mode, attackers, rate, rep)
    reset_controller(settle)
    reply = helper(f"MODE {mode}")
    if reply.startswith("ERR"):
        print(f"  warning: controller did not accept MODE ({reply})")
    h1, h3 = net.get("h1"), net.get("h3")
    h1.cmd("pkill -f sockets/server")
    slog = f"/tmp/server_{rid}.log"
    h1.cmd(f"./sockets/server {SERVER_PORT} {CTRL_IP} 9100 > {slog} 2>&1 &")
    time.sleep(1)
    offset = log_offset()

    legit = h3.popen([CLIENT, SERVER_IP, str(SERVER_PORT), "latency",
                      str(LEGIT_COUNT), str(LEGIT_DELAY_MS)], stdout=PIPE, stderr=STDOUT)
    time.sleep(ATTACK_START_S)
    attack_start = time.time()
    procs = [net.get(h).popen([CLIENT, SERVER_IP, str(SERVER_PORT), "flood",
                               str(rate), str(ATTACK_SECS)], stdout=PIPE, stderr=STDOUT)
             for h in ATTACKERS[attackers]]
    outs = [p.communicate()[0].decode(errors="ignore") for p in procs]
    starts = [int(m.group(1)) / 1000 for o in outs
              for m in [re.search(r"start_epoch_ms=(\d+)", o)] if m]
    if starts:
        attack_start = min(starts)               # the client's own start time
    drops = drop_packets()                       # the drop rule is still active here
    legit_out = legit.communicate()[0].decode(errors="ignore")

    vals = parse_summary(legit_out)
    if not vals:
        print("  warning: no summary line from the latency client. Output was:")
        print("  " + (legit_out[-300:] or "(empty)").replace("\n", "\n  "))
    ok = vals.get("ok", 0)
    attempts = int(vals.get("attempts", ok + vals.get("failed", 0) + vals.get("timeout", 0)))
    ips = [IPS[h] for h in ATTACKERS[attackers]]
    row = dict(run_id=rid, mode=mode, attackers=attackers, attack_rate=rate, rep=rep,
               legit_attempts=attempts,
               legit_success_pct=round(100 * ok / attempts, 1) if attempts else "",
               legit_avg_ms=vals.get("avg_ms", ""), legit_p95_ms=vals.get("p95_ms", ""),
               attack_conns_at_server=count_attacker_conns(slog, ips))
    if mode == "dynamic":
        t = first_block_time(offset, ips)
        if t is None:
            print("  warning: no BLOCK found in events.log for this run")
        else:
            row["time_to_block_s"] = round(t - attack_start, 3)
            row["drop_packets"] = drops
            if row["time_to_block_s"] < 0:
                print("  warning: negative time to block (clock or log mismatch)")
    print(f"  attempts={row['legit_attempts']} success={row['legit_success_pct']}% "
          f"avg={row['legit_avg_ms']}ms ttb={row.get('time_to_block_s', '-')}s "
          f"attack_conns={row['attack_conns_at_server']} drops={row.get('drop_packets', '-')}",
          flush=True)
    return row


# --------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mock", action="store_true", help="write FAKE rows, no Mininet")
    ap.add_argument("--quick", action="store_true", help="1 combination, 1 repetition")
    ap.add_argument("--out", default=None)
    ap.add_argument("--modes", nargs="+", default=["none", "dynamic"])
    ap.add_argument("--attackers", nargs="+", type=int, default=[1, 2])
    ap.add_argument("--rates", nargs="+", type=int, default=[10, 25, 50, 100])
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--settle", type=float, default=5, help="seconds between runs")
    a = ap.parse_args()
    if a.quick:
        a.modes, a.attackers, a.rates, a.reps = ["dynamic"], [1], [25], 1
    out = a.out or ("results/results_mock.csv" if a.mock else "results/results.csv")
    if a.mock and os.path.basename(out) == "results.csv":
        sys.exit("refusing to write mock data into results.csv")

    net = None
    if not a.mock:
        if os.geteuid() != 0:
            sys.exit("run with sudo")
        try:
            helper("LIST")
        except OSError:
            sys.exit("controller helper port 9100 not reachable: is Ryu running?")
        net = build_network()

    os.makedirs("results", exist_ok=True)
    runs = list(combos(a.modes, a.attackers, a.rates, a.reps))
    try:
        for i, (mode, att, rate, rep) in enumerate(runs, 1):
            rid = run_id(mode, att, rate, rep)
            print(f"[{i}/{len(runs)}] {rid}", flush=True)
            try:
                row = mock_run(mode, att, rate, rep) if a.mock else \
                      real_run(net, mode, att, rate, rep, a.settle)
                append_row(out, row)
            except Exception as e:                     # log it, repeat it later
                print(f"  FAILED: {e}")
                with open("results/failed_runs.txt", "a") as f:
                    f.write(f"{rid}: {e}\n")
    finally:
        if net:
            net.stop()
    print(f"done, rows in {out}")


if __name__ == "__main__":
    main()