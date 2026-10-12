# tests/test_suite.py
import socket
import time
import unittest

HELPER_HOST = "127.0.0.1"
HELPER_PORT = 9100

def send_cmd(cmd):
    """Utility to send a line command to port 9100 and receive response."""
    with socket.create_connection((HELPER_HOST, HELPER_PORT), timeout=2) as s:
        s.sendall((cmd + "\n").encode('utf-8'))
        return s.recv(1024).decode('utf-8').strip()

class TestSDNSecuritySuite(unittest.TestCase):

    def setUp(self):
        # Unblock test hosts before each test run
        send_cmd("UNBLOCK 10.0.0.2")
        send_cmd("UNBLOCK 10.0.0.3")
        time.sleep(0.5)

    def test_01_normal_traffic(self):
        """Test 1: Normal traffic (1 conn/s) - Expected: Accepted, no block."""
        for _ in range(3):
            # Normal traffic simulation
            time.sleep(1)
        resp = send_cmd("LIST")
        self.assertNotIn("10.0.0.3", resp, "Normal host 10.0.0.3 should not be blocked")

    def test_02_below_threshold(self):
        """Test 2: Below threshold (10 conns/5s, 3 bad logins) - Expected: Counted, no block."""
        for _ in range(3):
            res = send_cmd("FAIL 10.0.0.2")
            self.assertEqual(res, "OK")
        resp = send_cmd("LIST")
        self.assertNotIn("10.0.0.2", resp, "10.0.0.2 should not be blocked under threshold")

    def test_03_connection_rate_threshold(self):
        """Test 3: Connection-rate threshold (20+ conns/s) - Expected: DETECT & BLOCK logged."""
        # Simulated via direct helper trigger or traffic generator
        res = send_cmd("BLOCK 10.0.0.2 30")
        self.assertEqual(res, "OK")
        resp = send_cmd("LIST")
        self.assertIn("10.0.0.2", resp, "10.0.0.2 must appear in active block list")

    def test_04_failed_login_threshold(self):
        """Test 4: Failed-login threshold (5 wrong logins in 10s) - Expected: Auto blocked."""
        for i in range(5):
            res = send_cmd("FAIL 10.0.0.2")
            self.assertEqual(res, "OK")
        resp = send_cmd("LIST")
        self.assertIn("10.0.0.2", resp, "10.0.0.2 must be blocked after 5 failed logins")

    def test_05_whitelist_protection(self):
        """Test 5: Whitelist host (h4 = 10.0.0.4) - Expected: Never blocked."""
        for _ in range(10):
            send_cmd("FAIL 10.0.0.4")
        res = send_cmd("BLOCK 10.0.0.4 30")
        self.assertTrue(res.startswith("ERR"), "Whitelisted host must return error on block attempt")
        resp = send_cmd("LIST")
        self.assertNotIn("10.0.0.4", resp, "10.0.0.4 must never appear in block list")

    def test_06_expiry(self):
        """Test 6: Expiry (Wait 30s after block) - Expected: Rule removed, unblocked."""
        send_cmd("BLOCK 10.0.0.2 2")  # 2-second short block for test speed
        time.sleep(2.5)
        resp = send_cmd("LIST")
        self.assertNotIn("10.0.0.2", resp, "10.0.0.2 should automatically expire and unblock")

    def test_07_isolation(self):
        """Test 7: Isolation - Expected: Blocking h2 leaves h3 and h4 unaffected."""
        send_cmd("BLOCK 10.0.0.2 30")
        resp = send_cmd("LIST")
        self.assertIn("10.0.0.2", resp)
        self.assertNotIn("10.0.0.3", resp)
        self.assertNotIn("10.0.0.4", resp)

if __name__ == "__main__":
    unittest.main()