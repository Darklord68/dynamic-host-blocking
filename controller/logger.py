# controller/logger.py
import time

LOG_FILE = "events.log"
KINDS = {"DETECT", "BLOCK", "UNBLOCK", "EXPIRE", "STATS",
         "ESCALATE", "RESET", "MODE"}


def _stamp():
    """2026-11-01 14:03:11.482 (millisecond precision)"""
    now = time.time()
    return (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
            + f".{int(now * 1000) % 1000:03d}")


def log_event(kind, **fields):
    """[time] EVENT=DETECT|BLOCK|UNBLOCK|EXPIRE|STATS|ESCALATE|RESET|MODE host=ip reason=..."""
    if kind not in KINDS:
        raise ValueError(f"unknown event kind: {kind}")
    parts = " ".join(f"{k}={v}" for k, v in fields.items())
    line = f"[{_stamp()}] EVENT={kind} {parts}".rstrip()
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")
    return line