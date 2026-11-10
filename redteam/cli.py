"""Command-line runner.

    python -m redteam.cli                                   # ShopBot, every model in TARGET_MODELS
    python -m redteam.cli --model allam-2-7b                # ShopBot, one model
    python -m redteam.cli --target rag-alice --judge        # your Enterprise RAG (see targets.yaml)
    python -m redteam.cli --category obfuscation            # only one category
    python -m redteam.cli --judge                           # also grade every reply with an AI judge
    python -m redteam.cli --report                          # also write an HTML security report

The red-team server (uvicorn app:app --port 8100) must be running to attack ShopBot;
the Enterprise RAG (port 8000) must be running to attack it.
"""
from __future__ import annotations

import argparse
import asyncio
import os

import httpx
from dotenv import load_dotenv

from redteam.library import CATEGORIES, OWASP
from redteam.runner import LABELS, run_attacks, save_run, summarise
from redteam.targets import load_targets, plant_fixtures, remove_fixtures

load_dotenv()


async def attack_one(target, attacks, model, use_judge, make_report=False):
    print(f"\n=== {target.name}{f' · {model}' if model else ''} → {target.url}")
    planted = []
    async with httpx.AsyncClient(timeout=120) as admin:
        try:
            if target.fixtures:
                try:
                    planted = await plant_fixtures(admin, target)
                except Exception as e:
                    raise SystemExit(f"  ✗ Could not plant the test documents, run stopped: {e}")
                print(f"  planted {len(planted)} test document(s)")
            results = []
            async for r in run_attacks(attacks, target, model, use_judge):
                a = next(x for x in attacks if x.id == r["id"])
                extra = f" ({r['leak_type']})" if r["leak_type"] and r["leak_type"] != "plain" else ""
                why = f"  - judge: {r['judge_reason']}" if r.get("judge_reason") and r["outcome"] != "refused" else ""
                print(f"  [{LABELS[r['outcome']]:^12}] {a.severity:<8} {a.name}{extra}{why}")
                results.append(r)
        finally:
            if planted:
                await remove_fixtures(admin, target, planted)
                print(f"  removed {len(planted)} test document(s)")
    s = summarise(attacks, results)
    path = save_run({"target": target.url, "target_id": target.id, "target_name": target.name, "model": model,
                     "judge": use_judge, "secrets": target.secrets, "policy": target.policy,
                     "fixtures": [f.title for f in target.fixtures], "fixtures_planted": len(planted),
                     "control": target.control, "expected_leak_categories": target.expected_leak_categories},
                    attacks, results)
    print(f"\n  Score {s['score']}%  ·  leaked {s['leaked']}  ·  partial {s['partial']}  ·  off-policy {s['off_policy']}"
          f"  ·  blocked {s['blocked']}  ·  errors {s['errors']}")
    if s["judge"]["judged"]:
        print(f"  Judge ({s['judge']['model']}): agreed with detector on {s['judge']['agreed_with_detector']} leaks, "
              f"found {s['judge']['extra_findings']} the detector missed")
    if target.control:
        ok = s["expected"] > 0
        print(f"  Control: {'✓ passed' if ok else '✗ FAILED'} - {s['expected']} allowed leak(s) found"
              + ("" if ok else " (the test could not reach the protected data - check the test documents)"))
    if s["over_refusal"]:
        print("  ⚠ The bot refused the normal (baseline) question - it may be too strict for real users")
    for cat, g in sorted(s["by_category"].items(), key=lambda kv: -kv[1]["leaked"] / kv[1]["total"]):
        print(f"    {CATEGORIES[cat]:<24} {g['leaked']}/{g['total']} leaked, {g['partial']} partial")
    for oid, g in sorted(s["by_owasp"].items()):
        print(f"    {oid} {OWASP[oid]:<34} {g['leaked']}/{g['total']} leaked, {g['partial']} partial")
    print(f"  Saved: {path.relative_to(path.parent.parent)}")
    if make_report:
        from redteam.report import write_report
        print(f"  Report: {write_report(path)}")
    return model or target.id, s


def main() -> None:
    targets = load_targets()
    p = argparse.ArgumentParser(description="Run an attack library against a chatbot.")
    p.add_argument("--target", default="shopbot", choices=list(targets), help="target id from targets.yaml")
    p.add_argument("--model", help="model for ShopBot (default: every model in TARGET_MODELS)")
    p.add_argument("--category", help="run only this category")
    p.add_argument("--judge", action="store_true", help="grade every reply with an AI judge (JUDGE_MODEL)")
    p.add_argument("--report", action="store_true", help="write an HTML security report to reports/ after each run")
    args = p.parse_args()

    target = targets[args.target]
    attacks = target.load_attacks()
    if args.category:
        attacks = [a for a in attacks if a.category in (args.category, "baseline")]
    if target.model_select:
        models = [args.model] if args.model else [m.strip() for m in os.getenv("TARGET_MODELS", "").split(",") if m.strip()] or [None]
    else:
        models = [None]

    async def go():
        return [await attack_one(target, attacks, m, args.judge, args.report) for m in models]

    rows = asyncio.run(go())
    if len(rows) > 1:
        print("\n=== Comparison")
        for m, s in sorted(rows, key=lambda r: -(r[1]["score"] or 0)):
            print(f"  {m:<28} score {s['score']}%   leaked {s['leaked']}   partial {s['partial']}")


if __name__ == "__main__":
    main()
