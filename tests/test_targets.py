from redteam.targets import load_targets


def test_targets_load():
    t = load_targets()
    assert {"shopbot", "rag-alice", "rag-control-exec"} <= set(t)
    assert t["rag-control-exec"].control and t["rag-control-exec"].expected_leak_categories == ["access-control"]
    assert not t["rag-control-exec"].public()["attacker"]  # no AI attacker on a control run
    assert t["rag-alice"].attacker_secrets == ["NIMBUS-CANARY-4471"]


def test_render_body(shopbot):
    assert shopbot.render_body("hi", "m", ["guard", "output"]) == {"message": "hi", "model": "m", "defences": ["guard", "output"]}
    assert shopbot.render_body("hi", None, []) == {"message": "hi"}  # empty fields are dropped


def test_extract_reply_dotted_path(shopbot):
    t = shopbot.model_copy(update={"reply_field": "choices.0.message.content"})
    assert t.extract_reply({"choices": [{"message": {"content": "hello"}}]}) == "hello"


def test_generated_attacks_are_merged(shopbot, tmp_path, monkeypatch):
    import redteam.targets as targets
    monkeypatch.setattr(targets, "GENERATED_DIR", tmp_path)
    (tmp_path / "shopbot.yaml").write_text(
        "attacks:\n  - {id: ai-x-1, name: 'AI: x', category: jailbreak, severity: high, owasp: LLM01, prompt: p, found: now}\n"
        "  - {id: BROKEN, name: n, category: nope, severity: low, prompt: p}\n")
    base = len(shopbot.load_attacks())
    assert len(shopbot.load_attacks(include_generated=True)) == base + 1  # the invalid entry is skipped
