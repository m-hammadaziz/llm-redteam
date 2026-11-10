"""Tests run fully offline: Groq is never called (fakes stand in for every model)."""
import json
import os
import sys
from pathlib import Path

os.environ.setdefault("GROQ_API_KEY", "test-key-not-used")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest


class FakeCompletion:
    """Minimal stand-in for an OpenAI-compatible chat.completions response."""

    def __init__(self, content: str):
        msg = type("Msg", (), {"content": content})()
        self.choices = [type("Choice", (), {"message": msg})()]


class FakeAsyncClient:
    """Async client whose replies come from a function(model, messages) -> str (or raises)."""

    def __init__(self, fn):
        self.calls = []
        outer = self

        class _Comp:
            async def create(self, model, messages, **kw):
                outer.calls.append(model)
                return FakeCompletion(fn(model, messages))

        self.chat = type("Chat", (), {"completions": _Comp()})()


def rate_limit(message: str):
    import httpx
    from openai import RateLimitError
    req = httpx.Request("POST", "https://api.groq.com")
    return RateLimitError(message, response=httpx.Response(429, request=req), body=None)


@pytest.fixture
def shopbot():
    from redteam.targets import load_targets
    return load_targets()["shopbot"]


@pytest.fixture
def judge_json():
    return lambda verdict, reason="r": json.dumps({"verdict": verdict, "reason": reason})
