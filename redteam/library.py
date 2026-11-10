"""Load and validate the attack library (attacks.yaml)."""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LIBRARY = ROOT / "attacks.yaml"

Severity = Literal["none", "low", "medium", "high", "critical"]
CATEGORIES = {
    "baseline": "Baseline (not an attack)",
    "prompt-injection": "Prompt injection",
    "jailbreak": "Jailbreak",
    "prompt-leaking": "Prompt leaking",
    "obfuscation": "Obfuscation",
    "indirect-injection": "Indirect injection",
    "social-engineering": "Social engineering",
    "access-control": "Access control bypass",
    "data-poisoning": "Data poisoning",
}
OWASP = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM04": "Data and Model Poisoning",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "-": "",
}
# How much a successful attack of each severity hurts the score
SEVERITY_WEIGHT = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Attack(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9-]+$")
    name: str
    category: str
    severity: Severity
    owasp: str = "-"
    prompt: str

    @field_validator("category")
    @classmethod
    def known_category(cls, v: str) -> str:
        if v not in CATEGORIES:
            raise ValueError(f"unknown category {v!r}; use one of {', '.join(CATEGORIES)}")
        return v

    @field_validator("owasp")
    @classmethod
    def known_owasp(cls, v: str) -> str:
        if v not in OWASP:
            raise ValueError(f"unknown OWASP id {v!r}; use one of {', '.join(OWASP)}")
        return v

    @property
    def baseline(self) -> bool:
        return self.category == "baseline"

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHT[self.severity]

    def public(self) -> dict:
        """Shape sent to the dashboard."""
        return {**self.model_dump(), "baseline": self.baseline,
                "category_label": CATEGORIES[self.category], "owasp_label": OWASP[self.owasp]}


def load_attacks(path: str | Path = DEFAULT_LIBRARY) -> list[Attack]:
    """Read attacks.yaml. Raises a clear error if an entry is wrong or an id is repeated."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    raw = data.get("attacks") or []
    attacks, seen = [], set()
    for i, item in enumerate(raw, start=1):
        try:
            a = Attack(**item)
        except Exception as e:
            raise ValueError(f"attacks.yaml entry #{i} ({item.get('id', '?')}): {e}") from None
        if a.id in seen:
            raise ValueError(f"attacks.yaml: duplicate id {a.id!r}")
        seen.add(a.id)
        attacks.append(a)
    if not attacks:
        raise ValueError("attacks.yaml contains no attacks")
    return attacks
