import csv
import benchmark


def test_mock_matrix_and_columns(tmp_path):
    out = str(tmp_path / "mock.csv")
    for mode, a, r, rep in benchmark.combos(["none", "dynamic"], [1, 2],
                                            [10, 25, 50, 100], 3):
        benchmark.append_row(out, benchmark.mock_run(mode, a, r, rep))
    rows = list(csv.DictReader(open(out)))
    assert len(rows) == 48
    assert list(rows[0].keys()) == benchmark.COLUMNS
    assert all(r["time_to_block_s"] == "" and r["drop_packets"] == ""
               for r in rows if r["mode"] == "none")
    assert all(r["time_to_block_s"] != "" for r in rows if r["mode"] == "dynamic")


def test_line_epoch_both_formats():
    a = benchmark.line_epoch("[2026-11-01 14:03:11.482] EVENT=BLOCK host=10.0.0.2")
    b = benchmark.line_epoch("[2026-11-01 14:03:12.482] EVENT=BLOCK host=10.0.0.2")
    assert round(b - a, 3) == 1.0
    assert benchmark.line_epoch("[14:03:11] EVENT=BLOCK host=10.0.0.2") is not None


def test_parse_summary():
    v = benchmark.parse_summary("1 ok 3\nsummary ok=98 failed=1 timeout=1 avg=4.2 p95=9.5 max=20")
    assert v["ok"] == 98 and v["p95"] == 9.5