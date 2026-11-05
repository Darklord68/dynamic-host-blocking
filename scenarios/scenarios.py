#!/usr/bin/env python3
"""Run Mininet scenarios S1-S3.
Run from repo root, with Ryu already running:
  sudo python3 scenarios/scenarios.py s1
Evidence: results/scenarios/*.txt
"""
import os
import subprocess
import sys
import time
from subprocess import PIPE, STDOUT

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
sys.path.insert(0, ROOT)
import benchmark as b  # noqa: E402

OUT = "results/scenarios"
SP = [b.CLIENT, b.SERVER_IP, str(b.SERVER_PORT)]
LEGIT_DELAY_MS = 500  # 2 connections/s; below the 15-in-5s detection threshold


def save(name, text):
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, name + ".txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text.rstrip() + "\n")
    print(text)
    print("Evidence saved:", path)


def prep(net, mode, tag):
    # Clear old OVS drop rules/controller counters between modes and scenarios.
    reply = b.reset_controller(5)
    if isinstance(reply, str) and reply.startswith("ERR"):
        raise RuntimeError("controller RESET failed: " + reply)
    reply = b.helper(f"MODE {mode}")
    if isinstance(reply, str) and reply.startswith("ERR"):
        raise RuntimeError("controller MODE failed: " + reply)
    h1 = net.get("h1")
    h1.cmd("pkill -f sockets/server")
    h1.cmd(f"./sockets/server {b.SERVER_PORT} {b.CTRL_IP} 9100 > /tmp/server_{tag}.log 2>&1 &")
    time.sleep(1)


def drop_rules():
    out = subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"],
        capture_output=True, text=True, check=False
    ).stdout
    rules = [line.strip() for line in out.splitlines() if "priority=100" in line]
    return "\n".join(rules) or "(no drop rules)"


def events_since(offset):
    try:
        with open("events.log", "rb") as f:
            f.seek(offset)
            lines = f.read().decode(errors="ignore").splitlines()
    except OSError:
        return "(no events.log)"
    return "\n".join(line for line in lines if "STATS" not in line) or "(no relevant events)"


def log_offset():
    try:
        return os.path.getsize("events.log")
    except OSError:
        return 0


def proc_output(proc, timeout=40):
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
        return "(client process timed out)\n" + out.decode(errors="ignore")
    return out.decode(errors="ignore").strip()


def last_line(text):
    lines = text.splitlines()
    return lines[-1] if lines else "(no output)"


def start_latency(host, count, delay=LEGIT_DELAY_MS):
    return host.popen(SP + ["latency", str(count), str(delay)], stdout=PIPE, stderr=STDOUT)


def start_flood(host, rate, seconds, name):
    path = f"/tmp/{name}_flood.txt"
    proc = host.popen(SP + ["flood", str(rate), str(seconds)], stdout=PIPE, stderr=STDOUT)
    return proc, path


def s1(net):
    """S1: h2 floods at 100/s while h3 performs ordinary, below-threshold logins."""
    report = []
    for mode in ("none", "dynamic"):
        prep(net, mode, f"s1_{mode}")
        off = log_offset()
        h3 = start_latency(net.get("h3"), 50, LEGIT_DELAY_MS)
        time.sleep(3)
        flood, _ = start_flood(net.get("h2"), 100, 20, f"s1_{mode}")
        flood_text = proc_output(flood, timeout=30)
        # Let the 25-second legitimate client complete and collect installed rules.
        legit_text = proc_output(h3, timeout=35)
        rules = drop_rules()
        events = events_since(off)
        if mode == "dynamic" and "host=10.0.0.3" in events and "EVENT=BLOCK host=10.0.0.3" in events:
            print("WARNING: h3 was blocked; inspect detector threshold and connection count.")
        report.append(
            f"== S1, MODE {mode} ==\nh3 summary: {last_line(legit_text)}\n"
            f"flood output: {last_line(flood_text)}\ndrop rules:\n{rules}\n"
            f"controller log:\n{events}\n"
        )
    save("s1_overload", "\n".join(report))


def s2(net):
    """S2: h2 connection flood, h5 failed logins, h3 and whitelisted h4 stay usable."""
    prep(net, "dynamic", "s2")
    off = log_offset()
    h3p = start_latency(net.get("h3"), 50, LEGIT_DELAY_MS)
    h4p = start_latency(net.get("h4"), 50, LEGIT_DELAY_MS)
    time.sleep(2)
    h2p = net.get("h2").popen(SP + ["flood", "25", "10"], stdout=PIPE, stderr=STDOUT)
    # Adapt the request below if the server's actual login protocol differs.
    # Each request uses one TCP connection; controller must detect failed logins.
    bad = (
        "for i in 1 2 3 4 5 6 7 8; do "
        f"printf 'LOGIN bad bad\\n' | timeout 2 nc -w1 {b.SERVER_IP} {b.SERVER_PORT}; "
        "sleep 0.5; done"
    )
    h5p = net.get("h5").popen(["bash", "-c", bad], stdout=PIPE, stderr=STDOUT)
    h2text = proc_output(h2p, timeout=20)
    h5text = proc_output(h5p, timeout=25)
    h3text = proc_output(h3p, timeout=35)
    h4text = proc_output(h4p, timeout=35)
    rules = drop_rules()
    events = events_since(off)
    # Match both common OVS field spellings.
    h2blocked = "nw_src=10.0.0.2" in rules or "ipv4_src=10.0.0.2" in rules
    h5blocked = "nw_src=10.0.0.5" in rules or "ipv4_src=10.0.0.5" in rules
    h4blocked = "nw_src=10.0.0.4" in rules or "ipv4_src=10.0.0.4" in rules
    verdict = f"h2 drop rule: {h2blocked}; h5 drop rule: {h5blocked}; h4 drop rule: {h4blocked} (must be False)"
    save("s2_two_attackers",
         f"== S2 ==\n{verdict}\nh2 output: {last_line(h2text)}\nh5 output: {last_line(h5text)}\n"
         f"h3 summary: {last_line(h3text)}\nh4 summary: {last_line(h4text)}\n"
         f"drop rules:\n{rules}\ncontroller log:\n{events}\n")


def s3(net):
    """S3: let first 30-second block expire, then check second block is 60 seconds."""
    prep(net, "dynamic", "s3")
    off = log_offset()
    parts = []
    for attempt in (1, 2):
        p = net.get("h2").popen(SP + ["flood", "25", "8"], stdout=PIPE, stderr=STDOUT)
        flood_text = proc_output(p, timeout=15)
        time.sleep(1)
        rules = drop_rules()
        parts.append(f"attack {attempt}: {last_line(flood_text)}\ndrop rule:\n{rules}")
        if attempt == 1:
            deadline = time.monotonic() + 75
            while ("nw_src=10.0.0.2" in drop_rules() or "ipv4_src=10.0.0.2" in drop_rules()):
                if time.monotonic() >= deadline:
                    raise RuntimeError("S3: first h2 block did not expire within 75 seconds")
                time.sleep(1)
            time.sleep(2)
    events = events_since(off)
    second_is_60 = "hard_timeout=60" in parts[1]
    note = ("PASS: second block is 60 s" if second_is_60 else
            "CHECK: second block is not 60 s; inspect detector escalation state and flow output")
    save("s3_repeat_offender", "== S3 ==\n" + "\n".join(parts) + f"\n{note}\ncontroller log:\n{events}\n")


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which not in ("all", "s1", "s2", "s3"):
        sys.exit("Usage: sudo python3 scenarios/scenarios.py [s1|s2|s3|all]")
    if os.geteuid() != 0:
        sys.exit("Run with sudo")
    try:
        b.helper("LIST")
    except Exception as e:
        sys.exit(f"Controller helper port 9100 not reachable; start Ryu first: {e}")
    net = None
    try:
        net = b.build_network()
        for name, fn in (("s1", s1), ("s2", s2), ("s3", s3)):
            if which in ("all", name):
                fn(net)
    finally:
        if net is not None:
            net.stop()
