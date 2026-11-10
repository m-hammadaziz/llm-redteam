"""Send attacks to a chatbot over HTTP (concurrently), score them and save the run."""
from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from typing import AsyncIterator

import httpx

from redteam.detectors import find_leak
from redteam.library import ROOT, Attack

RESULTS_DIR = ROOT / "results"


async def send(client: httpx.AsyncClient, target: str, model: str | None, message: str) -> dict:
    payload = {"message": message, **({"model": model} if model else {})}
    t0 = time.perf_counter()
    try:
        r = await client.post(target, json=payload)
        r.raise_for_status()
        reply, error = r.json().get("reply", ""), None
    except Exception as e:  # unreachable target, rate limit, bad model...
        reply, error = "", f"{type(e).__name__}: {e}"[:300]
    return {"reply": reply, "error": error, "ms": round((time.perf_counter() - t0) * 1000)}


async def run_attacks(attacks: list[Attack], target: str, canary: str, model: str | None = None,
                      concurrency: int = 3, timeout: float = 240) -> AsyncIterator[dict]:
    """Yield one result per attack, in the order they finish."""
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(timeout=timeout) as client:
        async def one(a: Attack) -> dict:
            async with sem:
                res = await send(client, target, model, a.prompt)
            how = find_leak(res["reply"], canary) if not res["error"] else None
            return {"id": a.id, **res, "leaked": how is not None, "leak_type": how}

        for fut in asyncio.as_completed([asyncio.create_task(one(a)) for a in attacks]):
            yield await fut


def summarise(attacks: list[Attack], results: list[dict]) -> dict:
    """Security score weighted by severity + breakdowns by category and OWASP risk."""
    by_id = {a.id: a for a in attacks}
    done = [r for r in results if not r["error"] and not by_id[r["id"]].baseline]
    total_w = sum(by_id[r["id"]].weight for r in done)
    leaked_w = sum(by_id[r["id"]].weight for r in done if r["leaked"])

    def group(key):
        out: dict[str, dict] = {}
        for r in done:
            k = getattr(by_id[r["id"]], key)
            g = out.setdefault(k, {"total": 0, "leaked": 0})
            g["total"] += 1
            g["leaked"] += r["leaked"]
        return out

    return {
        "attacks": len([a for a in attacks if not a.baseline]),
        "completed": len(done),
        "errors": len([r for r in results if r["error"]]),
        "leaked": sum(r["leaked"] for r in done),
        "score": round(100 * (1 - leaked_w / total_w)) if total_w else None,
        "by_category": group("category"),
        "by_owasp": group("owasp"),
        "by_severity": group("severity"),
    }


def save_run(meta: dict, attacks: list[Attack], results: list[dict]) -> Path:
    """Write the whole run to results/run-<timestamp>.json and return the path."""
    RESULTS_DIR.mkdir(exist_ok=True)
    by_id = {a.id: a for a in attacks}
    path = RESULTS_DIR / f"run-{datetime.now():%Y%m%d-%H%M%S}-{(meta.get('model') or 'default').replace('/', '_')}.json"
    path.write_text(json.dumps({
        **meta,
        "finished_at": datetime.now().isoformat(timespec="seconds"),
        "summary": summarise(attacks, results),
        "results": [{**by_id[r["id"]].model_dump(), **r} for r in results],
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
