import socket
import threading

from controller.detector import Detector
from controller.helper_server import make_server


def test_mode_and_reset():
    calls, state = [], {"mode": "dynamic", "resets": 0}
    quiet = lambda *a, **k: None
    d = Detector(block_fn=lambda ip, s: calls.append((ip, s)), log_fn=quiet)

    def reset():
        state["resets"] += 1
        d.reset()

    srv = make_server(d, lambda ip, s: calls.append((ip, s)), lambda ip: None,
                      quiet, "127.0.0.1", 0,
                      get_mode=lambda: state["mode"],
                      set_mode=lambda m: state.update(mode=m), reset_fn=reset)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def ask(msg):
        with socket.create_connection(("127.0.0.1", port)) as s:
            s.sendall((msg + "\n").encode())
            return s.recv(1024).decode().strip()

    assert ask("MODE none") == "OK"
    assert ask("BLOCK 10.0.0.2 30").startswith("OK")     # ignored in baseline
    assert calls == []
    assert ask("MODE bogus").startswith("ERR")
    assert ask("MODE dynamic") == "OK"
    assert ask("BLOCK 10.0.0.2 30") == "OK"
    assert ask("RESET") == "OK"
    assert state["resets"] == 1
    assert ask("LIST") == "OK none"
    assert ask("WHITELIST").startswith("OK 10.0.0.1")
    srv.shutdown()