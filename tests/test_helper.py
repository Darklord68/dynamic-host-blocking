# tests/test_helper.py
import socket
import threading

from controller.detector import Detector
from controller.helper_server import make_server


def test_helper_commands():
    calls = []
    quiet = lambda *a, **k: None
    d = Detector(block_fn=lambda ip, s: calls.append((ip, s)), log_fn=quiet)
    srv = make_server(d, lambda ip, s: calls.append((ip, s)),
                      lambda ip: None, quiet, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def ask(msg):
        with socket.create_connection(("127.0.0.1", port)) as s:
            s.sendall((msg + "\n").encode())
            return s.recv(1024).decode().strip()

    assert ask("BLOCK 10.0.0.2 30") == "OK"
    assert calls == [("10.0.0.2", 30)]
    assert ask("BLOCK 10.0.0.4 30").startswith("ERR")   # whitelisted
    assert ask("BOGUS").startswith("ERR")
    assert "10.0.0.2" in ask("LIST")
    for _ in range(5):
        ask("FAIL 10.0.0.3")                            # 5 fails -> detector blocks
    assert ("10.0.0.3", 30) in calls
    srv.shutdown()