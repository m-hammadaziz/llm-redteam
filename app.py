"""LLM Red Team dashboard - ONE command runs everything:

    uvicorn app:app --port 8100 --reload

then open http://localhost:8100

It serves:
  /             the dashboard (dashboard/index.html)
  /target/...   ShopBot, the demo chatbot (target_bot/app.py)
  /api/...      endpoints the dashboard uses to run attacks
Targets (ShopBot, your Enterprise RAG, ...) are configured in targets.yaml.
"""
import json
import os
import re
from pathlib import Path

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from pydantic import BaseModel

from redteam.detectors import find_any_leak
from redteam.judge import JUDGE_MODEL, judge
from redteam.library import CATEGORIES, OWASP
from redteam.report import build_report
from redteam.runner import LABELS, PENALTY, RESULTS_DIR, run_attacks, save_run, send, summarise
from redteam.targets import load_targets, plant_fixtures, remove_fixtures
from target_bot.app import BOT_MODEL
from target_bot.app import app as shopbot

load_dotenv()
MODELS = [m.strip() for m in os.getenv("TARGET_MODELS", BOT_MODEL).split(",") if m.strip()]
DASHBOARD = Path(__file__).parent / "dashboard" / "index.html"

app = FastAPI(title="LLM Red Team")
app.mount("/target", shopbot)  # ShopBot lives at /target/chat on the same server


def get_target(target_id: str):
    try:
        targets = load_targets()  # re-read: edit targets.yaml, refresh the page
    except ValueError as e:
        raise HTTPException(400, str(e))
    if target_id not in targets:
        raise HTTPException(404, f"unknown target {target_id!r}")
    return targets[target_id]


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(DASHBOARD)


@app.get("/api/targets")
def targets():
    try:
        return [t.public() for t in load_targets().values()]
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/config")
def config(target: str = "shopbot"):
    t = get_target(target)
    try:
        attacks = t.load_attacks()
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {
        "target": t.public(),
        "models": MODELS if t.model_select else [],
        "default_model": BOT_MODEL,
        "categories": CATEGORIES,
        "owasp": OWASP,
        "judge_model": JUDGE_MODEL,
        "labels": LABELS,
        "penalty": PENALTY,
        "secrets": t.secrets,
        "tests": [a.public() for a in attacks],
    }


def sse(event: str | None, data) -> str:
    return (f"event: {event}\n" if event else "") + f"data: {json.dumps(data)}\n\n"


@app.get("/api/run")
async def run(target: str = "shopbot", model: str | None = None, category: str | None = None, judge: bool = False):
    """Plant test documents (if any), run the attacks, stream every result (SSE), clean up."""
    t = get_target(target)
    attacks = t.load_attacks()
    if category:
        attacks = [a for a in attacks if a.category in (category, "baseline")]
    model = model if t.model_select else None

    async def events():
        planted: list[int] = []
        async with httpx.AsyncClient(timeout=120) as admin:
            try:
                if t.fixtures:
                    yield sse("status", f"Planting {len(t.fixtures)} test document(s) in {t.name}…")
                    try:
                        planted = await plant_fixtures(admin, t)
                    except Exception as e:
                        # Without its test documents the run would be meaningless - stop instead of scoring nothing.
                        yield sse("fatal", f"Could not plant the test documents, so the run was stopped: {e}")
                        return
                    yield sse("status", f"Planted {len(planted)} test document(s). Attacking…")
                results = []
                async for r in run_attacks(attacks, t, model, use_judge=judge):
                    results.append(r)
                    yield sse(None, r)
                path = save_run({"target": t.url, "target_id": t.id, "target_name": t.name, "model": model,
                                 "category": category, "judge": judge, "secrets": t.secrets,
                                 "policy": t.policy, "fixtures": [f.title for f in t.fixtures], "fixtures_planted": len(planted),
                                 "control": t.control, "expected_leak_categories": t.expected_leak_categories},
                                attacks, results)
                yield sse("done", {"summary": summarise(attacks, results), "saved": path.name})
            finally:
                if planted:
                    await remove_fixtures(admin, t, planted)  # always clean up, even if the run fails

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/runs")
def runs():
    """Previous runs saved in results/ (newest first)."""
    out = []
    for p in sorted(RESULTS_DIR.glob("run-*.json"), reverse=True)[:30]:
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            out.append({"file": p.name, "model": d.get("model"), "target_name": d.get("target_name") or "ShopBot (demo)",
                        "finished_at": d.get("finished_at"), "judge": d.get("judge", False),
                        **{k: d["summary"].get(k) for k in ("score", "leaked", "partial", "completed", "errors")}})
        except Exception:
            continue
    return out


@app.get("/api/report/{file}", response_class=HTMLResponse)
def report(file: str):
    """Security report for one saved run (open it, then use Print -> Save as PDF)."""
    if not re.fullmatch(r"run-[\w.-]+\.json", file):  # only plain file names from results/
        raise HTTPException(400, "invalid run file name")
    path = RESULTS_DIR / file
    if not path.is_file():
        raise HTTPException(404, "run not found")
    return HTMLResponse(build_report(json.loads(path.read_text(encoding="utf-8")), source_name=file))


class TryRequest(BaseModel):
    target: str = "shopbot"
    message: str
    model: str | None = None
    judge: bool = False


@app.post("/api/try")
async def try_attack(req: TryRequest):
    """Send one custom message (the 'Try your own attack' box). Test documents are not planted here."""
    t = get_target(req.target)
    async with httpx.AsyncClient(timeout=240) as client:
        res = await send(client, t, req.model if t.model_select else None, req.message)
    how, secret = find_any_leak(res["reply"], t.secrets) if not res["error"] else (None, None)
    verdict = await judge(req.message, res["reply"], t.policy, t.secrets) if req.judge and not res["error"] else None
    outcome = "error" if res["error"] else "full_leak" if how else (
        "refused" if not verdict or verdict["verdict"] in (None, "answered") else verdict["verdict"])
    return {**res, "leaked": outcome == "full_leak", "leak_type": how, "leaked_secret": secret, "outcome": outcome,
            "judge_verdict": verdict and verdict["verdict"], "judge_reason": verdict and verdict["reason"],
            "judge_error": verdict and verdict["error"]}
