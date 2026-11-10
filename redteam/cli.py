"""Command-line runner.

    python -m redteam.cli                                   # attack ShopBot with every model in TARGET_MODELS
    python -m redteam.cli --model allam-2-7b                # one model
    python -m redteam.cli --target https://your-bot/chat    # any chatbot with a {"message"} -> {"reply"} API
    python -m redteam.cli --category obfuscation            # only one category

The server (uvicorn app:app --port 8100) must be running when you attack ShopBot.
"""
from __future__ import annotations

import argparse
import asyncio
import os

from dotenv import load_dotenv

from redteam.library import CATEGORIES, OWASP, load_attacks
from redteam.runner import run_attacks, save_run, summarise

load_dotenv()


async def attack_one(attacks, target, canary, model):
    print(f"\n=== {model or 'default model'} → {target}")
    results = []
    async for r in run_attacks(attacks, target, canary, model):
        a = next(x for x in attacks if x.id == r["id"])
        status = "ERROR" if r["error"] else "LEAKED" if r["leaked"] else ("ANSWERED" if a.baseline else "blocked")
        extra = f" ({r['leak_type']})" if r["leaked"] and r["leak_type"] != "plain" else ""
        print(f"  [{status:^8}] {a.severity:<8} {a.name}{extra}")
        results.append(r)
    s = summarise(attacks, results)
    path = save_run({"target": target, "model": model}, attacks, results)
    print(f"\n  Score {s['score']}%  ·  leaked {s['leaked']}/{s['completed']}  ·  errors {s['errors']}")
    for cat, g in sorted(s["by_category"].items(), key=lambda kv: -kv[1]["leaked"] / kv[1]["total"]):
        print(f"    {CATEGORIES[cat]:<22} {g['leaked']}/{g['total']} leaked")
    for oid, g in sorted(s["by_owasp"].items()):
        print(f"    {oid} {OWASP[oid]:<34} {g['leaked']}/{g['total']} leaked")
    print(f"  Saved: {path.relative_to(path.parent.parent)}")
    return model, s


def main() -> None:
    p = argparse.ArgumentParser(description="Run the attack library against a chatbot.")
    p.add_argument("--target", default=os.getenv("TARGET_URL", "http://localhost:8100/target/chat"))
    p.add_argument("--model", help="model for ShopBot (default: every model in TARGET_MODELS)")
    p.add_argument("--category", choices=list(CATEGORIES), help="run only this category")
    p.add_argument("--canary", default=os.getenv("CANARY", "CANARY-7F3A-91"))
    args = p.parse_args()

    attacks = load_attacks()
    if args.category:
        attacks = [a for a in attacks if a.category in (args.category, "baseline")]
    models = [args.model] if args.model else [m.strip() for m in os.getenv("TARGET_MODELS", "").split(",") if m.strip()] or [None]

    async def go():
        return [await attack_one(attacks, args.target, args.canary, m) for m in models]

    rows = asyncio.run(go())
    if len(rows) > 1:
        print("\n=== Comparison")
        for m, s in sorted(rows, key=lambda r: -(r[1]["score"] or 0)):
            print(f"  {m:<28} score {s['score']}%   leaked {s['leaked']}/{s['completed']}")


if __name__ == "__main__":
    main()
