# controller/logger.py
import time

LOG_FILE = "events.log"
KINDS = {"DETECT", "BLOCK", "UNBLOCK", "EXPIRE", "STATS"}


def log_event(kind, **fields):
    """[time] EVENT=DETECT|BLOCK|UNBLOCK|EXPIRE|STATS host=ip reason=..."""
    if kind not in KINDS:
        raise ValueError(f"unknown event kind: {kind}")
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    parts = " ".join(f"{k}={v}" for k, v in fields.items())
    line = f"[{stamp}] EVENT={kind} {parts}".rstrip()
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")
    return line