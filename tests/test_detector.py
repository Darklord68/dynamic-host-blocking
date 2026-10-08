# tests/test_detector.py
from controller.detector import Detector

def make():
    calls = []
    return Detector(block_fn=lambda ip, s: calls.append((ip, s)),
                    log_fn=lambda *a, **k: None), calls

def test_normal_no_block():
    d, calls = make()
    for t in range(10): d.on_connection("10.0.0.3", t)
    assert not calls

def test_below_threshold():
    d, calls = make()
    for i in range(10): d.on_connection("10.0.0.2", i * 0.4)
    for i in range(3): d.on_failed_login("10.0.0.2", i)
    assert not calls

def test_conn_burst_blocks():
    d, calls = make()
    for i in range(20): d.on_connection("10.0.0.2", i * 0.1)
    assert calls == [("10.0.0.2", 30)]

def test_failed_logins_block():
    d, calls = make()
    for i in range(5): d.on_failed_login("10.0.0.2", i)
    assert calls == [("10.0.0.2", 30)]

def test_whitelist_never_blocked():
    d, calls = make()
    for i in range(50): d.on_connection("10.0.0.4", i * 0.01)
    for i in range(20): d.on_failed_login("10.0.0.4", i * 0.1)
    assert not calls

def test_isolation():
    d, calls = make()
    for i in range(20): d.on_connection("10.0.0.2", i * 0.1)
    d.on_connection("10.0.0.3", 2.0)
    assert [c[0] for c in calls] == ["10.0.0.2"]