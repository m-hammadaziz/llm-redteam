import pytest

from redteam.library import ROOT, Attack, load_attacks


@pytest.mark.parametrize("name", ["attacks.yaml", "attacks_rag.yaml"])
def test_libraries_are_valid(name):
    attacks = load_attacks(ROOT / name)
    assert len({a.id for a in attacks}) == len(attacks)
    assert sum(a.baseline for a in attacks) == 1  # exactly one normal question per library
    assert all(a.prompt.strip() for a in attacks)


def test_bad_entries_are_rejected():
    with pytest.raises(ValueError):
        Attack(id="x", name="x", category="made-up", severity="high", prompt="p")
    with pytest.raises(ValueError):
        Attack(id="x", name="x", category="jailbreak", severity="high", owasp="LLM99", prompt="p")
    with pytest.raises(ValueError):
        Attack(id="Bad Id", name="x", category="jailbreak", severity="high", prompt="p")


def test_duplicate_ids_rejected(tmp_path):
    f = tmp_path / "a.yaml"
    f.write_text("attacks:\n" + "".join(
        "  - {id: same, name: n, category: jailbreak, severity: low, prompt: p}\n" for _ in range(2)))
    with pytest.raises(ValueError, match="duplicate"):
        load_attacks(f)
