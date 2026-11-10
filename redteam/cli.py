"""Command-line runner.

    python -m redteam.cli                                   # ShopBot, every model in TARGET_MODELS
    python -m redteam.cli --model allam-2-7b                # ShopBot, one model
    python -m redteam.cli --target rag-alice --judge        # your Enterprise RAG (see targets.yaml)
    python -m redteam.cli --category obfuscation            # only one category
    python -m redteam.cli --judge                           # also grade every reply with an AI judge
    python -m redteam.cli --report                          # also write an HTML security report
    python -m redteam.cli --evolve --model openai/gpt-oss-20b  # AI attacker invents new attacks
    python -m redteam.cli --generated                       # also re-run attacks the AI found earlier
    python -m redteam.cli --model allam-2-7b --defences guard,output   # ShopBot with defences on
    python -m redteam.cli --model allam-2-7b --compare-defences        # before/after for every defence
    python -m redteam.cli --model allam-2-7b --defences prompt,output --min-score 90   # CI security gate

The red-team server (uvicorn app:app --port 8100) must be running to attack ShopBot;
the Enterprise RAG (port 8000) must be running to attack it.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

import httpx
from dotenv import load_dotenv

from redteam.attacker import ATTACKER_MODELS, evolve, pick_seeds, save_evolution, save_generated, summarise_evolution
from redteam.library import CATEGORIES, OWASP
from redteam.runner import LABELS, run_attacks, save_run, summarise
from redteam.targets import load_targets, plant_fixtures, remove_fixtures

load_dotenv()


async def attack_one(target, attacks, model, use_judge, make_report=False, defences=None):
    defences = defences or []
    print(f"\n=== {target.name}{f' · {model}' if model else ''}{f' · defences: {chr(43).join(defences)}' if defences else ''} → {target.url}")
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
            async for r in run_attacks(attacks, target, model, use_judge, defences=defences):
                a = next(x for x in attacks if x.id == r["id"])
                extra = f" ({r['leak_type']})" if r["leak_type"] and r["leak_type"] != "plain" else ""
                why = f"  - judge: {r['judge_reason']}" if r.get("judge_reason") and r["outcome"] != "refused" else ""
                by = f"  (stopped by {r['blocked_by']})" if r.get("blocked_by") else ""
                print(f"  [{LABELS[r['outcome']]:^12}] {a.severity:<8} {a.name}{extra}{by}{why}")
                results.append(r)
        finally:
            if planted:
                await remove_fixtures(admin, target, planted)
                print(f"  removed {len(planted)} test document(s)")
    s = summarise(attacks, results)
    path = save_run({"target": target.url, "target_id": target.id, "target_name": target.name, "model": model,
                     "judge": use_judge, "defences": defences, "secrets": target.secrets, "policy": target.policy,
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
    s["blocked_by"] = {d: sum(r.get("blocked_by") == d for r in results) for d in defences}
    s["defence_errors"] = sum(bool(r.get("defence_error")) for r in results)
    return model or target.id, s


STATUS = {"already_leaked": "leaked already (no AI needed)", "broken": "BROKEN by the AI attacker",
          "partial": "partial leak only", "held": "held - every AI attempt blocked",
          "error": "not tested - the target or attacker failed (see the error above)"}


async def evolve_one(target, model, seeds, rounds, use_judge, defences=None):
    chosen = pick_seeds(target.load_attacks(), seeds)
    print(f"\n=== AI attacker ({ATTACKER_MODELS[0]}) vs {target.name}{f' · {model}' if model else ''}"
          f"  -  {len(chosen)} seed attacks, up to {rounds} rounds each")
    names = {a.id: a.name for a in chosen}
    planted, log, seed_results = [], [], []
    async with httpx.AsyncClient(timeout=120) as admin:
        try:
            if target.fixtures:
                try:
                    planted = await plant_fixtures(admin, target)
                except Exception as e:
                    raise SystemExit(f"  ✗ Could not plant the test documents, run stopped: {e}")
            async for ev in evolve(target, chosen, model, rounds, use_judge, defences):
                log.append(ev)
                if ev["type"] == "attempt":
                    tag = "seed" if ev["round"] == 0 else f"AI {ev['round']}"
                    print(f"  {names[ev['seed']][:26]:<26} {tag:<5} [{LABELS.get(ev['outcome'], ev['outcome']):^12}] "
                          f"{ev['strategy'][:18]:<18} {ev['prompt'][:70]!r}")
                elif ev["type"] == "attacker_error":
                    print(f"  {names[ev['seed']][:26]:<26} ! attacker error: {ev['error'][:90]}")
                else:
                    seed_results.append(ev)
                    print(f"  → {names[ev['seed']]}: {STATUS[ev['status']]}"
                          + (f" in round {ev['winning_round']}" if ev["status"] == "broken" else ""))
        finally:
            if planted:
                await remove_fixtures(admin, target, planted)
    s = summarise_evolution(seed_results)
    path = save_evolution({"target": target.url, "target_id": target.id, "target_name": target.name, "model": model,
                           "attacker_model": ATTACKER_MODELS[0], "judge": use_judge, "rounds": rounds,
                           "defences": defences or [], "goal": target.attacker_goal}, log, seed_results)
    gen, added = save_generated(target, chosen, seed_results)
    print(f"\n  Library attacks the bot blocked: {s['seeds'] - s['already_leaked']}  ·  broken by the AI: {s['broken_by_ai']}"
          f"  ·  AI success rate: {s['ai_success_rate']}%  ·  avg rounds to break: {s['avg_rounds_to_break']}")
    print(f"  Saved: results/{path.name}" + (f"  ·  {added} new attack(s) added to generated/{gen.name}" if added else ""))


def main() -> None:
    targets = load_targets()
    p = argparse.ArgumentParser(description="Run an attack library against a chatbot.")
    p.add_argument("--target", default="shopbot", choices=list(targets), help="target id from targets.yaml")
    p.add_argument("--model", help="model for ShopBot (default: every model in TARGET_MODELS)")
    p.add_argument("--category", help="run only this category")
    p.add_argument("--judge", action="store_true", help="grade every reply with an AI judge (JUDGE_MODEL)")
    p.add_argument("--report", action="store_true", help="write an HTML security report to reports/ after each run")
    p.add_argument("--generated", action="store_true", help="also run attacks the AI attacker found earlier (generated/)")
    p.add_argument("--defences", default="", help="comma-separated defences to switch on (ShopBot: guard,prompt,output,nosecret)")
    p.add_argument("--compare-defences", action="store_true", help="run with no defence, each defence alone, then all together")
    p.add_argument("--min-score", type=int, help="CI gate: exit with code 1 if the security score is below this")
    p.add_argument("--max-leaks", type=int, help="CI gate: exit with code 1 if more attacks than this fully leak")
    p.add_argument("--max-errors", type=float, default=0.2,
                   help="CI gate: fail if more than this share of attacks errored (result not trustworthy, default 0.2)")
    p.add_argument("--summary-md", help="append a markdown summary to this file (CI: $GITHUB_STEP_SUMMARY)")
    p.add_argument("--evolve", action="store_true", help="AI attacker: let an LLM invent new attacks from the library")
    p.add_argument("--seeds", type=int, default=4, help="--evolve: how many library attacks to start from")
    p.add_argument("--rounds", type=int, default=3, help="--evolve: max new AI attempts per seed")
    args = p.parse_args()

    target = targets[args.target]
    defences = [d.strip() for d in args.defences.split(",") if d.strip()]
    unknown = [d for d in defences if d not in target.defences]
    if unknown or (args.compare_defences and not target.defences):
        raise SystemExit(f"{target.id} supports these defences: {', '.join(target.defences) or 'none'}")
    if args.evolve:
        if not target.attacker_goal or target.control:
            raise SystemExit(f"The AI attacker is not enabled for {target.id} (set attacker_goal in targets.yaml)")
        model = (args.model or os.getenv("BOT_MODEL")) if target.model_select else None
        asyncio.run(evolve_one(target, model, args.seeds, args.rounds, args.judge, defences))
        return
    attacks = target.load_attacks(include_generated=args.generated)
    if args.category:
        attacks = [a for a in attacks if a.category in (args.category, "baseline")]
    if target.model_select:
        models = [args.model] if args.model else [m.strip() for m in os.getenv("TARGET_MODELS", "").split(",") if m.strip()] or [None]
    else:
        models = [None]

    if args.compare_defences:
        model = models[0] if args.model or len(models) == 1 else (os.getenv("BOT_MODEL") or models[0])
        configs = [[]] + [[d] for d in target.defences] + [list(target.defences)]

        async def go_defences():
            return [(cfg, (await attack_one(target, attacks, model, args.judge, args.report, cfg))[1]) for cfg in configs]

        rows = asyncio.run(go_defences())
        print(f"\n=== Defences: before / after  ({model})")
        print(f"  {'defences':<34} {'score':>6} {'leaked':>7} {'partial':>8}  over-refusal  stopped by defence")
        for cfg, s in rows:
            name = " + ".join(target.defences[d] for d in cfg) or "none (before)"
            stopped = ", ".join(f"{d} {n}" for d, n in s["blocked_by"].items() if n) or "-"
            print(f"  {name[:34]:<34} {s['score']:>5}% {s['leaked']:>7} {s['partial']:>8}  {'YES' if s['over_refusal'] else 'no':<12}  {stopped}"
                  + (f"  ({s['defence_errors']} defence errors)" if s["defence_errors"] else ""))
        return

    async def go():
        return [await attack_one(target, attacks, m, args.judge, args.report, defences) for m in models]

    rows = asyncio.run(go())
    if len(rows) > 1:
        print("\n=== Comparison")
        for m, s in sorted(rows, key=lambda r: -(r[1]["score"] or 0)):
            print(f"  {m:<28} score {s['score']}%   leaked {s['leaked']}   partial {s['partial']}")

    failures = gate(rows, args.min_score, args.max_leaks, args.max_errors)
    if args.summary_md:
        write_summary(args.summary_md, target, rows, defences, args, failures)
    if args.min_score is not None or args.max_leaks is not None:
        print("\n=== Security gate: " + ("FAILED" if failures else "passed"))
        for f in failures:
            print(f"  ✗ {f}")
        if failures:
            sys.exit(1)


def gate(rows, min_score, max_leaks, max_errors) -> list[str]:
    """Reasons the run should fail a CI pipeline (empty list = pass)."""
    failures = []
    for label, s in rows:
        if s["attacks"] and s["errors"] / s["attacks"] > max_errors:
            failures.append(f"{label}: {s['errors']}/{s['attacks']} attacks errored - result not trustworthy")
            continue
        if min_score is not None and (s["score"] is None or s["score"] < min_score):
            failures.append(f"{label}: score {s['score']}% is below the minimum {min_score}%")
        if max_leaks is not None and s["leaked"] > max_leaks:
            failures.append(f"{label}: {s['leaked']} attacks leaked the secret (allowed: {max_leaks})")
        if s["over_refusal"]:
            failures.append(f"{label}: the bot refused the normal (baseline) question")
    return failures


def write_summary(path, target, rows, defences, args, failures) -> None:
    """Markdown table for the GitHub Actions run page."""
    lines = [f"## {'❌' if failures else '✅'} LLM red-team security gate: {target.name}", "",
             f"Defences: **{', '.join(defences) or 'none'}** · minimum score: **{args.min_score}%**"
             + (f" · max leaks: **{args.max_leaks}**" if args.max_leaks is not None else ""), "",
             "| Model | Score | Leaked | Partial | Off-policy | Blocked | Errors |", "|---|---|---|---|---|---|---|"]
    for label, s in rows:
        lines.append(f"| `{label}` | **{s['score']}%** | {s['leaked']} | {s['partial']} | {s['off_policy']} | {s['blocked']} | {s['errors']} |")
    if failures:
        lines += ["", "**Why it failed:**"] + [f"- {f}" for f in failures]
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n\n")


if __name__ == "__main__":
    main()
