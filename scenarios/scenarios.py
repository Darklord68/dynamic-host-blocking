#!/usr/bin/env python3
"""Scenarios S1 to S3. On the VM, with Ryu already running, from the repo root:
    sudo python3 scenarios/scenarios.py s1|s2|s3|all
Evidence is written to results/scenarios/.
"""
import os
import subprocess
import sys
import time
from subprocess import PIPE, STDOUT

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
sys.path.insert(0, ROOT)
import benchmark as b                                    # noqa: E402

OUT = "results/scenarios"
SP = [b.CLIENT, b.SERVER_IP, str(b.SERVER_PORT)]


def save(name, text):
    os.makedirs(OUT, exist_ok=True)
    with open(f"{OUT}/{name}.txt", "w") as f:
        f.write(text)
    print(text)


def prep(net, mode, tag):
    b.reset_controller(3)
    b.helper(f"MODE {mode}")
    h1 = net.get("h1")
    h1.cmd("pkill -f sockets/server")
    h1.cmd(f"./sockets/server {b.SERVER_PORT} {b.CTRL_IP} 9100 > /tmp/server_{tag}.log 2>&1 &")
    time.sleep(1)


def drop_rules():
    out = subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"],
                         capture_output=True, text=True).stdout
    rules = [l.strip() for l in out.splitlines() if "priority=100" in l]
    return "\n".join(rules) or "(no drop rules)"


def events_since(offset):
    try:
        with open("events.log", "rb") as f:
            f.seek(offset)
            lines = f.read().decode(errors="ignore").splitlines()
    except OSError:
        return "(no events.log)"
    return "\n".join(l for l in lines if "STATS" not in l)


def last_line(proc):
    out = proc.communicate()[0].decode(errors="ignore").strip()
    return out.splitlines()[-1] if out else "(no output)"


def s1(net):
    """Server overload: flood at 100/s while h3 does normal logins."""
    report = []
    for mode in ("none", "dynamic"):
        prep(net, mode, f"s1_{mode}")
        off = b.log_offset()
        legit = net.get("h3").popen(SP + ["latency", "100", "250"], stdout=PIPE, stderr=STDOUT)
        time.sleep(3)
        attack = net.get("h2").popen(SP + ["flood", "100", "20"], stdout=PIPE, stderr=STDOUT)
        attack.communicate()
        rules = drop_rules()
        report.append(f"== S1, MODE {mode} ==\nh3 summary: {last_line(legit)}\n"
                      f"drop rules at end of attack:\n{rules}\n"
                      f"controller log:\n{events_since(off)}\n")
    save("s1_overload", "\n".join(report))


def s2(net):
    """Two attackers: h2 floods, h5 guesses passwords; h3 and h4 stay unaffected."""
    prep(net, "dynamic", "s2")
    off = b.log_offset()
    legit = {h: net.get(h).popen(SP + ["latency", "60", "250"], stdout=PIPE, stderr=STDOUT)
             for h in ("h3", "h4")}
    time.sleep(2)
    bad = "for i in 1 2 3 4 5 6 7 8; do echo 'LOGIN bad bad' | nc -w1 10.0.0.1 9000; done"
    procs = [net.get("h2").popen(SP + ["flood", "25", "10"], stdout=PIPE, stderr=STDOUT),
             net.get("h5").popen(["bash", "-c", bad], stdout=PIPE, stderr=STDOUT),
             net.get("h4").popen(SP + ["flood", "25", "5"], stdout=PIPE, stderr=STDOUT)]
    for p in procs:
        p.communicate()
    rules = drop_rules()
    verdict = (f"h2 blocked: {'nw_src=10.0.0.2' in rules}   "
               f"h5 blocked: {'nw_src=10.0.0.5' in rules}   "
               f"h4 blocked: {'nw_src=10.0.0.4' in rules} (must be False)")
    save("s2_two_attackers",
         f"== S2 ==\n{verdict}\nh3 summary: {last_line(legit['h3'])}\n"
         f"h4 summary: {last_line(legit['h4'])}\ndrop rules:\n{rules}\n"
         f"controller log:\n{events_since(off)}\n")


def s3(net):
    """Repeat offender: block h2, wait for expiry, attack again."""
    prep(net, "dynamic", "s3")
    off = b.log_offset()
    parts = []
    for attempt in (1, 2):
        net.get("h2").popen(SP + ["flood", "25", "8"], stdout=PIPE, stderr=STDOUT).communicate()
        time.sleep(1)
        parts.append(f"attack {attempt}, drop rule:\n{drop_rules()}")
        if attempt == 1:
            for _ in range(90):                       # wait for the first block to expire
                if "nw_src=10.0.0.2" not in drop_rules():
                    break
                time.sleep(1)
            time.sleep(2)
    second = parts[1]
    note = ("second block is 60 s: escalation works" if "hard_timeout=60" in second
            else "second block is NOT 60 s: escalation (F2) is not active yet")
    save("s3_repeat_offender",
         "== S3 ==\n" + "\n".join(parts) + f"\n{note}\ncontroller log:\n{events_since(off)}\n")


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if os.geteuid() != 0:
        sys.exit("run with sudo")
    try:
        b.helper("LIST")
    except OSError:
        sys.exit("controller helper port 9100 not reachable: is Ryu running?")
    net = b.build_network()
    try:
        for name, fn in (("s1", s1), ("s2", s2), ("s3", s3)):
            if which in ("all", name):
                fn(net)
    finally:
        net.stop()