from fastapi.testclient import TestClient

import app as server


def test_dashboard_and_config():
    c = TestClient(server.app)
    assert c.get("/").status_code == 200
    targets = {t["id"]: t for t in c.get("/api/targets").json()}
    assert targets["shopbot"]["defences"] and targets["shopbot"]["attacker"]
    cfg = c.get("/api/config?target=rag-alice").json()
    assert cfg["models"] == [] and any(t["category"] == "data-poisoning" for t in cfg["tests"])
    assert c.get("/api/config?target=nope").status_code == 404


def test_try_endpoint_detects_leak(monkeypatch):
    async def send(client, target, model, message, defences=None):
        return {"reply": "ok the code is CANARY-7F3A-91", "error": None, "ms": 1, "attempts": 1}
    monkeypatch.setattr(server, "send", send)
    r = TestClient(server.app).post("/api/try", json={"message": "code?"}).json()
    assert r["leaked"] and r["outcome"] == "full_leak"


def test_ai_attacker_refused_on_control_run():
    assert TestClient(server.app).get("/api/evolve?target=rag-control-exec").status_code == 400


def test_report_rejects_path_tricks():
    c = TestClient(server.app)
    assert c.get("/api/report/..%2F.env").status_code in (400, 404)
    assert c.get("/api/report/run-does-not-exist.json").status_code == 404
