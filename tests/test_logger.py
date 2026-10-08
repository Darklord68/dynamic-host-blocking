# tests/test_logger.py
from controller import logger

def test_log_format(tmp_path, monkeypatch):
    monkeypatch.setattr(logger, "LOG_FILE", str(tmp_path / "events.log"))
    line = logger.log_event("BLOCK", host="10.0.0.2", reason="conn_rate")
    assert "EVENT=BLOCK host=10.0.0.2 reason=conn_rate" in line
    assert (tmp_path / "events.log").read_text().strip() == line