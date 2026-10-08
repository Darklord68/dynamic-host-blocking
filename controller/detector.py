# controller/detector.py
import configparser
import os
from collections import deque, defaultdict

_cfg = configparser.ConfigParser()
_cfg.read(os.path.join(os.path.dirname(__file__), "..", "config.ini"))

WHITELIST = set(_cfg.get("network", "whitelist",
                         fallback="10.0.0.1,10.0.0.4,10.0.0.254").split(","))

CONN_LIMIT = _cfg.getint("detector", "conn_limit", fallback=15)
CONN_WINDOW = _cfg.getint("detector", "conn_window", fallback=5)
FAIL_LIMIT = _cfg.getint("detector", "fail_limit", fallback=5)
FAIL_WINDOW = _cfg.getint("detector", "fail_window", fallback=10)
BLOCK_SECS = _cfg.getint("detector", "block_secs", fallback=30)

class Detector:
    def __init__(self, block_fn=None, log_fn=None):
        # block_fn(ip, secs) is wired to block_host(dp, ip, secs) by the Ryu app
        self.block_fn = block_fn or (lambda ip, secs: None)
        self.log = log_fn or (lambda kind, **f: print(kind, f))
        self.conns = defaultdict(deque)
        self.fails = defaultdict(deque)
        self.blocked = {}            # ip -> unblock time

    def _slide(self, q, now, window):
        while q and now - q[0] > window:
            q.popleft()

    def is_blocked(self, ip, now):
        until = self.blocked.get(ip)
        if until is None:
            return False
        if now >= until:
            del self.blocked[ip]
            return False
        return True

    def _trigger(self, ip, now, reason):
        self.log("DETECT", host=ip, reason=reason)
        self.blocked[ip] = now + BLOCK_SECS
        self.conns[ip].clear()
        self.fails[ip].clear()
        self.block_fn(ip, BLOCK_SECS)

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
        # call from Member 2's flow-removed handler so state stays in sync
        self.blocked.pop(ip, None)