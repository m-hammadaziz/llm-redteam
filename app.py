"""LLM Red Team dashboard - ONE command runs everything:

    uvicorn app:app --port 8100 --reload

then open http://localhost:8100

It serves:
  /             the dashboard (dashboard/index.html)
  /target/...   ShopBot, the demo chatbot we attack (target_bot/app.py)
  /api/...      endpoints the dashboard uses to run attacks
"""
import json
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from redteam.detectors import find_leak
from redteam.library import CATEGORIES, OWASP, load_attacks
from redteam.judge import JUDGE_MODEL, judge
from redteam.runner import LABELS, PENALTY, RESULTS_DIR, run_attacks, save_run, send, summarise
from target_bot.app import BOT_MODEL, CANARY
from target_bot.app import app as shopbot

load_dotenv()
MODELS = [m.strip() for m in os.getenv("TARGET_MODELS", BOT_MODEL).split(",") if m.strip()]
DASHBOARD = Path(__file__).parent / "dashboard" / "index.html"

app = FastAPI(title="LLM Red Team")
app.mount("/target", shopbot)  # ShopBot lives at /target/chat on the same server


def default_target(request: Request) -> str:
    return f"{str(request.base_url).rstrip('/')}/target/chat"


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(DASHBOARD)


@app.get("/api/config")
def config(request: Request):
    try:
        attacks = load_attacks()  # re-read every time: edit attacks.yaml, refresh the page
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {
        "target": default_target(request),
        "models": MODELS,
        "default_model": BOT_MODEL,
        "categories": CATEGORIES,
        "owasp": OWASP,
        "judge_model": JUDGE_MODEL,
        "labels": LABELS,
        "penalty": PENALTY,
        "tests": [a.public() for a in attacks],
    }


@app.get("/api/run")
async def run(target: str, model: str | None = None, category: str | None = None, judge: bool = False):
    """Run the attack library and stream each result to the browser as soon as it arrives (SSE)."""
    attacks = load_attacks()
    if category:
        attacks = [a for a in attacks if a.category in (category, "baseline")]

    async def events():
        results = []
        async for r in run_attacks(attacks, target, CANARY, model, use_judge=judge):
            results.append(r)
            yield f"data: {json.dumps(r)}\n\n"
        path = save_run({"target": target, "model": model, "category": category, "judge": judge}, attacks, results)
        done = {"summary": summarise(attacks, results), "saved": path.name}
        yield f"event: done\ndata: {json.dumps(done)}\n\n"

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/runs")
def runs():
    """Previous runs saved in results/ (newest first)."""
    out = []
    for p in sorted(RESULTS_DIR.glob("run-*.json"), reverse=True)[:30]:
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            out.append({"file": p.name, "model": d.get("model"), "finished_at": d.get("finished_at"),
                        "judge": d.get("judge", False),
                        **{k: d["summary"].get(k) for k in ("score", "leaked", "partial", "completed", "errors")}})
        except Exception:
            continue
    return out


class TryRequest(BaseModel):
    target: str
    message: str
    model: str | None = None
    judge: bool = False


@app.post("/api/try")
async def try_attack(req: TryRequest):
    """Send one custom message (the 'Try your own attack' box)."""
    async with httpx.AsyncClient(timeout=240) as client:
        res = await send(client, req.target, req.model, req.message)
    how = find_leak(res["reply"], CANARY) if not res["error"] else None
    verdict = await judge(req.message, res["reply"], CANARY) if req.judge and not res["error"] else None
    outcome = "error" if res["error"] else "full_leak" if how else (
        "refused" if not verdict or verdict["verdict"] in (None, "answered") else verdict["verdict"])
    return {**res, "leaked": outcome == "full_leak", "leak_type": how, "outcome": outcome,
            "judge_verdict": verdict and verdict["verdict"], "judge_reason": verdict and verdict["reason"],
            "judge_error": verdict and verdict["error"]}
