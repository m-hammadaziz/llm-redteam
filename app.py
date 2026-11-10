"""LLM Red Team dashboard - ONE command runs everything:

    uvicorn app:app --port 8100 --reload

then open http://localhost:8100

It serves:
  /             the dashboard (dashboard/index.html)
  /target/...   ShopBot, the demo chatbot (target_bot/app.py)
  /api/...      endpoints the dashboard uses to run attacks (and the AI attacker)
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

from redteam.attacker import ATTACKER_MODELS, evolve, pick_seeds, save_evolution, save_generated, summarise_evolution
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
def config(target: str = "shopbot", generated: bool = False):
    t = get_target(target)
    try:
        attacks = t.load_attacks(include_generated=generated)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {
        "target": t.public(),
        "models": MODELS if t.model_select else [],
        "default_model": BOT_MODEL,
        "categories": CATEGORIES,
        "owasp": OWASP,
        "judge_model": JUDGE_MODEL,
        "attacker_model": ATTACKER_MODELS[0],
        "labels": LABELS,
        "penalty": PENALTY,
        "secrets": t.secrets,
        "tests": [a.public() for a in attacks],
    }


def parse_defences(t, defences: str) -> list[str]:
    """'guard,output' -> ['guard', 'output'], only ids this target supports."""
    return [d for d in dict.fromkeys(x.strip() for x in defences.split(",")) if d in t.defences]


def sse(event: str | None, data) -> str:
    return (f"event: {event}\n" if event else "") + f"data: {json.dumps(data)}\n\n"


@app.get("/api/run")
async def run(target: str = "shopbot", model: str | None = None, category: str | None = None, judge: bool = False,
              generated: bool = False, defences: str = ""):
    """Plant test documents (if any), run the attacks, stream every result (SSE), clean up."""
    t = get_target(target)
    defs = parse_defences(t, defences)
    attacks = t.load_attacks(include_generated=generated)
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
                async for r in run_attacks(attacks, t, model, use_judge=judge, defences=defs):
                    results.append(r)
                    yield sse(None, r)
                path = save_run({"target": t.url, "target_id": t.id, "target_name": t.name, "model": model,
                                 "category": category, "judge": judge, "generated": generated, "defences": defs, "secrets": t.secrets,
                                 "policy": t.policy, "fixtures": [f.title for f in t.fixtures], "fixtures_planted": len(planted),
                                 "control": t.control, "expected_leak_categories": t.expected_leak_categories},
                                attacks, results)
                yield sse("done", {"summary": summarise(attacks, results), "saved": path.name})
            finally:
                if planted:
                    await remove_fixtures(admin, t, planted)  # always clean up, even if the run fails

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/evolve")
async def evolve_run(target: str = "shopbot", model: str | None = None, seeds: int = 4, rounds: int = 3,
                     judge: bool = False, seed_ids: str = "", defences: str = ""):
    """AI attacker: start from library attacks and let an LLM invent better ones, round by round (SSE)."""
    t = get_target(target)
    defs = parse_defences(t, defences)
    if not t.attacker_goal or t.control:
        raise HTTPException(400, "the AI attacker is not enabled for this target (set attacker_goal in targets.yaml)")
    seeds, rounds = max(1, min(seeds, 10)), max(1, min(rounds, 6))
    chosen = pick_seeds(t.load_attacks(), seeds, [s for s in seed_ids.split(",") if s] or None)
    model = model if t.model_select else None

    async def events():
        planted: list[int] = []
        log, seed_results = [], []
        async with httpx.AsyncClient(timeout=120) as admin:
            try:
                if t.fixtures:
                    yield sse("status", f"Planting {len(t.fixtures)} test document(s) in {t.name}…")
                    try:
                        planted = await plant_fixtures(admin, t)
                    except Exception as e:
                        yield sse("fatal", f"Could not plant the test documents, so the run was stopped: {e}")
                        return
                yield sse("start", {"seeds": [a.public() for a in chosen], "rounds": rounds,
                                    "attacker_model": ATTACKER_MODELS[0]})
                yield sse("status", f"AI attacker ({ATTACKER_MODELS[0]}) is working on {len(chosen)} attacks, "
                                    f"up to {rounds} new attempts each…")
                async for ev in evolve(t, chosen, model, rounds, judge, defs):
                    log.append(ev)
                    if ev["type"] == "seed_done":
                        seed_results.append(ev)
                    yield sse(ev["type"], ev)
                path = save_evolution({"target": t.url, "target_id": t.id, "target_name": t.name, "model": model,
                                       "attacker_model": ATTACKER_MODELS[0], "judge": judge, "rounds": rounds, "defences": defs,
                                       "goal": t.attacker_goal}, log, seed_results)
                gen_path, added = save_generated(t, chosen, seed_results)
                yield sse("done", {"summary": summarise_evolution(seed_results), "saved": path.name,
                                   "generated_added": added, "generated_total": len(t.load_generated()),
                                   "generated_file": gen_path and f"generated/{gen_path.name}"})
            finally:
                if planted:
                    await remove_fixtures(admin, t, planted)

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
                        "finished_at": d.get("finished_at"), "judge": d.get("judge", False), "defences": d.get("defences") or [],
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
    defences: list[str] = []


@app.post("/api/try")
async def try_attack(req: TryRequest):
    """Send one custom message (the 'Try your own attack' box). Test documents are not planted here."""
    t = get_target(req.target)
    async with httpx.AsyncClient(timeout=240) as client:
        res = await send(client, t, req.model if t.model_select else None, req.message,
                         parse_defences(t, ",".join(req.defences)))
    how, secret = find_any_leak(res["reply"], t.secrets) if not res["error"] else (None, None)
    verdict = await judge(req.message, res["reply"], t.policy, t.secrets) if req.judge and not res["error"] else None
    outcome = "error" if res["error"] else "full_leak" if how else (
        "refused" if not verdict or verdict["verdict"] in (None, "answered") else verdict["verdict"])
    return {**res, "leaked": outcome == "full_leak", "leak_type": how, "leaked_secret": secret, "outcome": outcome,
            "judge_verdict": verdict and verdict["verdict"], "judge_reason": verdict and verdict["reason"],
            "judge_error": verdict and verdict["error"]}
