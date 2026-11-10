"""Targets: how to talk to each chatbot (targets.yaml), plus test-document fixtures."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx
import yaml
from pydantic import BaseModel

from redteam.library import ROOT, load_attacks

TARGETS_FILE = ROOT / "targets.yaml"


class Fixture(BaseModel):
    title: str
    filename: str
    allowed_groups: list[str]
    content: str


class Admin(BaseModel):
    base_url: str
    headers: dict[str, str] = {}


class Target(BaseModel):
    id: str
    name: str
    description: str = ""
    url: str
    headers: dict[str, str] = {}
    body: dict[str, Any]
    reply_field: str = "reply"
    model_select: bool = False
    concurrency: int = 3
    control: bool = False  # control run: proves the test can detect leaks
    # leaks in these categories are ALLOWED for this user (control run) -> 'expected', not a finding
    expected_leak_categories: list[str] = []
    attacks: str = "attacks.yaml"
    secrets: list[str]
    policy: str
    admin: Admin | None = None
    fixtures: list[Fixture] = []

    def load_attacks(self):
        return load_attacks(ROOT / self.attacks)

    def render_body(self, prompt: str, model: str | None) -> dict:
        """Fill "{prompt}" / "{model}" into the body template. Fields that end up empty are dropped."""
        def fill(v):
            if isinstance(v, str):
                return v.replace("{prompt}", prompt).replace("{model}", model or "")
            if isinstance(v, dict):
                return {k: fill(x) for k, x in v.items()}
            return v
        return {k: x for k, x in fill(self.body).items() if x != ""}

    def extract_reply(self, data: Any) -> str:
        """Follow a dotted path like 'answer' or 'choices.0.message.content'."""
        for part in self.reply_field.split("."):
            data = data[int(part)] if isinstance(data, list) else data.get(part, "")
        return data if isinstance(data, str) else str(data)

    def public(self) -> dict:
        return {"id": self.id, "name": self.name, "description": self.description, "url": self.url,
                "model_select": self.model_select, "fixtures": [f.title for f in self.fixtures], "control": self.control,
                "expected_leak_categories": self.expected_leak_categories,
                "secrets": len(self.secrets)}


def load_targets() -> dict[str, Target]:
    data = yaml.safe_load(TARGETS_FILE.read_text(encoding="utf-8")) or {}
    targets = {}
    for i, item in enumerate(data.get("targets") or [], start=1):
        try:
            t = Target(**item)
        except Exception as e:
            raise ValueError(f"targets.yaml entry #{i}: {e}") from None
        targets[t.id] = t
    if not targets:
        raise ValueError("targets.yaml contains no targets")
    return targets


async def plant_fixtures(client: httpx.AsyncClient, t: Target) -> list[int]:
    """Upload the target's test documents through its admin API. Returns their document ids.

    All-or-nothing: if one upload fails, the ones already uploaded are removed and the error
    is raised - a run without its test documents would give meaningless results."""
    if not t.fixtures:
        return []
    if not t.admin:
        raise ValueError(f"target {t.id} has fixtures but no admin settings")
    ids: list[int] = []
    try:
        for f in t.fixtures:
            r = await client.post(f"{t.admin.base_url}/ingest/file", headers=t.admin.headers,
                                  files={"file": (f.filename, f.content.encode("utf-8"), "text/markdown")},
                                  data={"allowed_groups": ",".join(f.allowed_groups), "title": f.title})
            if r.status_code >= 400:
                raise RuntimeError(f"could not plant '{f.title}': HTTP {r.status_code} {r.text[:200]}")
            ids.append(r.json()["document_id"])
    except Exception as e:
        await remove_fixtures(client, t, ids)
        if isinstance(e, httpx.TransportError):
            raise RuntimeError(f"cannot reach {t.admin.base_url} - is the target running? ({type(e).__name__})") from None
        raise
    return ids


async def remove_fixtures(client: httpx.AsyncClient, t: Target, ids: list[int]) -> None:
    for doc_id in ids:
        try:
            await client.delete(f"{t.admin.base_url}/documents/{doc_id}", headers=t.admin.headers)
        except Exception:
            pass  # best effort - never hide the real result because cleanup failed
