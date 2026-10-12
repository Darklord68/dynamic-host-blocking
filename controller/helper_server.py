# controller/helper_server.py
import ipaddress
import socketserver
import time

from controller.detector import WHITELIST


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_server(detector, block_fn, unblock_fn, log_fn,
                host="0.0.0.0", port=9100):
    """block_fn(ip, secs) and unblock_fn(ip) are supplied by the Ryu app."""

    def process(line):
        parts = line.split()
        if not parts:
            return "ERR empty"
        cmd = parts[0].upper()

        if cmd == "LIST":
            now = time.time()
            items = [f"{ip}:{int(t - now)}s"
                     for ip, t in detector.blocked.items() if t > now]
            return "OK " + (",".join(items) if items else "none")

        if len(parts) < 2:
            return "ERR missing ip"
        try:
            ip = str(ipaddress.ip_address(parts[1]))
        except ValueError:
            return "ERR bad ip"

        if cmd == "FAIL":
            detector.on_failed_login(ip, time.time())
            return "OK"

        if cmd == "BLOCK":
            if ip in WHITELIST:
                return "ERR whitelisted"
            try:
                secs = int(parts[2])
            except (IndexError, ValueError):
                return "ERR bad seconds"
            detector.blocked[ip] = time.time() + secs
            block_fn(ip, secs)
            return "OK"

        if cmd == "UNBLOCK":
            detector.on_expire(ip)
            log_fn("UNBLOCK", host=ip, reason="manual")
            unblock_fn(ip)
            return "OK"

        return "ERR unknown command"

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            for raw in self.rfile:
                reply = process(raw.decode(errors="ignore").strip())
                self.wfile.write((reply + "\n").encode())

    return _Server((host, port), Handler)