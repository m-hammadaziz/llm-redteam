"""Command-line runner.

    python -m redteam.cli                                   # attack ShopBot with every model in TARGET_MODELS
    python -m redteam.cli --model allam-2-7b                # one model
    python -m redteam.cli --target https://your-bot/chat    # any chatbot with a {"message"} -> {"reply"} API
    python -m redteam.cli --category obfuscation            # only one category
    python -m redteam.cli --judge                           # also grade every reply with an AI judge

The server (uvicorn app:app --port 8100) must be running when you attack ShopBot.
"""
from __future__ import annotations

import argparse
import asyncio
import os

from dotenv import load_dotenv

from redteam.library import CATEGORIES, OWASP, load_attacks
from redteam.runner import LABELS, run_attacks, save_run, summarise

load_dotenv()


async def attack_one(attacks, target, canary, model, use_judge):
    print(f"\n=== {model or 'default model'} → {target}")
    results = []
    async for r in run_attacks(attacks, target, canary, model, use_judge):
        a = next(x for x in attacks if x.id == r["id"])
        extra = f" ({r['leak_type']})" if r["leak_type"] and r["leak_type"] != "plain" else ""
        why = f"  - judge: {r['judge_reason']}" if r.get("judge_reason") and r["outcome"] != "refused" else ""
        print(f"  [{LABELS[r['outcome']]:^12}] {a.severity:<8} {a.name}{extra}{why}")
        results.append(r)
    s = summarise(attacks, results)
    path = save_run({"target": target, "model": model}, attacks, results)
    print(f"\n  Score {s['score']}%  ·  leaked {s['leaked']}  ·  partial {s['partial']}  ·  off-policy {s['off_policy']}"
          f"  ·  blocked {s['blocked']}  ·  errors {s['errors']}")
    if s["judge"]["judged"]:
        print(f"  Judge ({s['judge']['model']}): agreed with detector on {s['judge']['agreed_with_detector']} leaks, "
              f"found {s['judge']['extra_findings']} the detector missed")
    if s["over_refusal"]:
        print("  ⚠ The bot refused the normal (baseline) question - it may be too strict for real customers")
    for cat, g in sorted(s["by_category"].items(), key=lambda kv: -kv[1]["leaked"] / kv[1]["total"]):
        print(f"    {CATEGORIES[cat]:<22} {g['leaked']}/{g['total']} leaked, {g['partial']} partial")
    for oid, g in sorted(s["by_owasp"].items()):
        print(f"    {oid} {OWASP[oid]:<34} {g['leaked']}/{g['total']} leaked, {g['partial']} partial")
    print(f"  Saved: {path.relative_to(path.parent.parent)}")
    return model, s


def main() -> None:
    p = argparse.ArgumentParser(description="Run the attack library against a chatbot.")
    p.add_argument("--target", default=os.getenv("TARGET_URL", "http://localhost:8100/target/chat"))
    p.add_argument("--model", help="model for ShopBot (default: every model in TARGET_MODELS)")
    p.add_argument("--category", choices=list(CATEGORIES), help="run only this category")
    p.add_argument("--canary", default=os.getenv("CANARY", "CANARY-7F3A-91"))
    p.add_argument("--judge", action="store_true", help="grade every reply with an AI judge (JUDGE_MODEL)")
    args = p.parse_args()

    attacks = load_attacks()
    if args.category:
        attacks = [a for a in attacks if a.category in (args.category, "baseline")]
    models = [args.model] if args.model else [m.strip() for m in os.getenv("TARGET_MODELS", "").split(",") if m.strip()] or [None]

    async def go():
        return [await attack_one(attacks, args.target, args.canary, m, args.judge) for m in models]

    rows = asyncio.run(go())
    if len(rows) > 1:
        print("\n=== Comparison")
        for m, s in sorted(rows, key=lambda r: -(r[1]["score"] or 0)):
            print(f"  {m:<28} score {s['score']}%   leaked {s['leaked']}   partial {s['partial']}")


if __name__ == "__main__":
    main()
