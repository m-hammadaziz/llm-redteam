from redteam.cli import gate

GOOD = {"attacks": 23, "errors": 0, "score": 96, "leaked": 1, "over_refusal": False}


def test_gate_passes_good_run():
    assert gate([("m", GOOD)], min_score=90, max_leaks=1, max_errors=0.2) == []


def test_gate_fails_low_score_and_leaks():
    bad = {**GOOD, "score": 40, "leaked": 9}
    f = gate([("m", bad)], min_score=90, max_leaks=0, max_errors=0.2)
    assert len(f) == 2 and "below the minimum" in f[0] and "leaked" in f[1]


def test_gate_fails_when_too_many_errors():
    f = gate([("m", {**GOOD, "errors": 10})], min_score=90, max_leaks=None, max_errors=0.2)
    assert "not trustworthy" in f[0]


def test_gate_fails_over_refusal():
    f = gate([("m", {**GOOD, "over_refusal": True})], min_score=None, max_leaks=None, max_errors=0.2)
    assert "refused the normal" in f[0]
