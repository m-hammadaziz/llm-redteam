import asyncio
import time

import pytest

import redteam.judge as J
from tests.conftest import FakeAsyncClient, rate_limit

DAY = ("Rate limit reached for model `openai/gpt-oss-120b` on tokens per day (TPD): Limit 200000, "
       "Used 199999. Please try again in 7m32.5s.")


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    J._blocked_until.clear()
    monkeypatch.setattr(J, "JUDGE_MODELS", ["big", "small"])
    yield
    J._blocked_until.clear()


def test_parse_and_waits():
    assert J._parse('noise {"verdict": "partial_leak", "reason": "x"}')["verdict"] == "partial_leak"
    with pytest.raises(ValueError):
        J._parse('{"verdict": "maybe"}')
    assert J._retry_wait(rate_limit(DAY)) == pytest.approx(453.0)
    assert J._retry_wait(rate_limit("try again in 1h2m3s")) == pytest.approx(3723.5)
    assert J.is_long_limit(rate_limit(DAY)) and not J.is_long_limit(rate_limit("try again in 2s"))


def test_daily_limit_falls_back_without_waiting(monkeypatch, judge_json):
    def reply(model, messages):
        if model == "big":
            raise rate_limit(DAY)
        return judge_json("refused")
    client = FakeAsyncClient(reply)
    monkeypatch.setattr(J, "_get_client", lambda: client)
    t0 = time.time()
    v = asyncio.run(J.judge("a", "b", "policy", ["S"]))
    assert v["verdict"] == "refused" and v["model"] == "small" and time.time() - t0 < 2
    asyncio.run(J.judge("a", "b", "policy", ["S"]))
    assert client.calls == ["big", "small", "small"]  # the blocked model is skipped afterwards


def test_all_models_limited_gives_a_clear_error(monkeypatch):
    client = FakeAsyncClient(lambda m, msgs: (_ for _ in ()).throw(rate_limit(DAY)))
    monkeypatch.setattr(J, "_get_client", lambda: client)
    v = asyncio.run(J.judge("a", "b", "policy", ["S"]))
    assert v["verdict"] is None and "rate limit" in v["error"].lower()
