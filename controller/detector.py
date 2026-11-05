import configparser
import os
from collections import deque, defaultdict

_cfg = configparser.ConfigParser()
_cfg.read(os.path.join(os.path.dirname(__file__), "..", "config.ini"))

WHITELIST = {
    ip.strip() for ip in _cfg.get(
        "network", "whitelist", fallback="10.0.0.1,10.0.0.4,10.0.0.254"
    ).split(",") if ip.strip()
}
CONN_LIMIT = _cfg.getint("detector", "conn_limit", fallback=15)
CONN_WINDOW = _cfg.getint("detector", "conn_window", fallback=5)
FAIL_LIMIT = _cfg.getint("detector", "fail_limit", fallback=5)
FAIL_WINDOW = _cfg.getint("detector", "fail_window", fallback=10)
BLOCK_SECS = _cfg.getint("detector", "block_secs", fallback=30)
OFFENCE_RESET_SECS = 300

if min(CONN_LIMIT, CONN_WINDOW, FAIL_LIMIT, FAIL_WINDOW, BLOCK_SECS) <= 0:
    raise ValueError("Detector limits, windows and block_secs must be positive")


class Detector:
    """Per-host detection and escalating blocks. History survives expiry, not RESET.

    Durations are block_secs, 2*block_secs, 4*block_secs (capped).
    With block_secs=30 these are 30, 60, 120 seconds.
    Public callback interface matches the original detector.
    """

    def __init__(self, block_fn=None, log_fn=None):
        self.block_fn = block_fn or (lambda ip, secs: None)
        self.log = log_fn or (lambda kind, **fields: print(kind, fields))
        self.conns = defaultdict(deque)
        self.fails = defaultdict(deque)
        self.blocked = {}
        self.offence_levels = {}
        self.last_offence = {}

    def _slide(self, q, now, window):
        while q and now - q[0] > window:
            q.popleft()

    def is_blocked(self, ip, now):
        until = self.blocked.get(ip)
        if until is None:
            return False
        if now >= until:
            self.blocked.pop(ip, None)
            return False
        return True

    def _trigger(self, ip, now, reason):
        if ip in WHITELIST or self.is_blocked(ip, now):
            return
        last = self.last_offence.get(ip)
        if last is None or now - last >= OFFENCE_RESET_SECS:
            level = 1
        else:
            level = min(self.offence_levels.get(ip, 0) + 1, 3)
        secs = BLOCK_SECS * (2 ** (level - 1))
        self.offence_levels[ip] = level
        self.last_offence[ip] = now
        self.blocked[ip] = now + secs
        self.conns[ip].clear()
        self.fails[ip].clear()
        self.log("DETECT", host=ip, reason=reason)
        if level > 1:
            self.log("ESCALATE", host=ip, level=level, secs=secs)
        self.block_fn(ip, secs)

    def on_connection(self, ip, now):
        if ip in WHITELIST or self.is_blocked(ip, now):
            return
        q = self.conns[ip]
        q.append(now)
        self._slide(q, now, CONN_WINDOW)
        if len(q) >= CONN_LIMIT:
            self._trigger(ip, now, f"conn_rate>={CONN_LIMIT}/{CONN_WINDOW}s")

    def on_failed_login(self, ip, now):
        if ip in WHITELIST or self.is_blocked(ip, now):
            return
        q = self.fails[ip]
        q.append(now)
        self._slide(q, now, FAIL_WINDOW)
        if len(q) >= FAIL_LIMIT:
            self._trigger(ip, now, f"failed_logins>={FAIL_LIMIT}/{FAIL_WINDOW}s")

    def on_expire(self, ip):
        # Keep offence history so the next attack escalates.
        self.blocked.pop(ip, None)

    def reset(self):
        self.conns.clear()
        self.fails.clear()
        self.blocked.clear()
        self.offence_levels.clear()
        self.last_offence.clear()
