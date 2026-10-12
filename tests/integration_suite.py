# tests/integration_suite.py  (run on the VM while Ryu + Mininet are up)
import socket
import subprocess
import time
import unittest

HOST, PORT = "127.0.0.1", 9100


def send_cmd(cmd):
    with socket.create_connection((HOST, PORT), timeout=2) as s:
        s.sendall((cmd + "\n").encode())
        return s.recv(1024).decode().strip()


def flows():
    """Switch flow table, or None if ovs-ofctl isn't usable (run with sudo)."""
    try:
        r = subprocess.run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"],
                           capture_output=True, text=True, timeout=5)
        return r.stdout if r.returncode == 0 else None
    except Exception:
        return None


def listener_up():
    try:
        send_cmd("LIST")
        return True
    except OSError:
        return False


@unittest.skipUnless(listener_up(), "controller helper port 9100 not reachable")
class ControllerSuite(unittest.TestCase):

    def setUp(self):
        for ip in ("10.0.0.2", "10.0.0.3"):
            send_cmd(f"UNBLOCK {ip}")
        time.sleep(0.5)

    def tearDown(self):
        send_cmd("UNBLOCK 10.0.0.2")

    def test_01_normal_host_not_blocked(self):
        # Real traffic evidence for this one comes from the Mininet run.
        self.assertNotIn("10.0.0.3", send_cmd("LIST"))

    def test_02_below_threshold(self):
        for _ in range(3):                      # 3 < 5, uses h3 so test 4 starts clean
            self.assertEqual(send_cmd("FAIL 10.0.0.3"), "OK")
        self.assertNotIn("10.0.0.3", send_cmd("LIST"))

    def test_03_block_installs_drop_rule(self):
        # Manual BLOCK: tests the listener -> block_host path, not the detector.
        self.assertEqual(send_cmd("BLOCK 10.0.0.2 30"), "OK")
        self.assertIn("10.0.0.2", send_cmd("LIST"))
        table = flows()
        if table is not None:
            self.assertIn("nw_src=10.0.0.2", table)

    def test_04_failed_login_threshold(self):
        for _ in range(5):
            self.assertEqual(send_cmd("FAIL 10.0.0.2"), "OK")
        self.assertIn("10.0.0.2", send_cmd("LIST"))

    def test_05_whitelist(self):
        for _ in range(10):
            send_cmd("FAIL 10.0.0.4")
        self.assertTrue(send_cmd("BLOCK 10.0.0.4 30").startswith("ERR"))
        self.assertNotIn("10.0.0.4", send_cmd("LIST"))

    def test_06_expiry(self):
        send_cmd("BLOCK 10.0.0.2 2")
        time.sleep(3.5)
        self.assertNotIn("10.0.0.2", send_cmd("LIST"))
        table = flows()
        if table is not None:                   # proves the switch rule is really gone
            self.assertNotIn("nw_src=10.0.0.2", table)

    def test_07_isolation(self):
        send_cmd("BLOCK 10.0.0.2 30")
        resp = send_cmd("LIST")
        self.assertIn("10.0.0.2", resp)
        self.assertNotIn("10.0.0.3", resp)
        self.assertNotIn("10.0.0.4", resp)


if __name__ == "__main__":
    unittest.main(verbosity=2)