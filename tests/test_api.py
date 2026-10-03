import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from goldmansachs.app import main


def test_hook_routes_to_sandbox_and_audits(monkeypatch, tmp_path):
    monkeypatch.delenv("BACKBOARD_API_KEY", raising=False)
    monkeypatch.setenv("DEMO_READONLY_SECRET", "test-secret")
    monkeypatch.setattr(main, "AUDIT_PATH", tmp_path / "audit.jsonl")
    monkeypatch.setattr(
        main,
        "run_in_sandbox",
        lambda tier, payload: {"ok": True, "result": {"status": 200}},
    )
    body = json.dumps(
        {"url": "https://api.github.com/zen", "method": "GET"}
    ).encode()
    signature = "sha256=" + hmac.new(
        b"test-secret", body, hashlib.sha256
    ).hexdigest()

    response = TestClient(main.app).post(
        "/hook/demo-readonly",
        content=body,
        headers={
            "content-type": "application/json",
            "x-hook-signature": signature,
        },
    )

    assert response.status_code == 200
    assert response.json()["tier"] == "readonly"
    event = json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[0])
    assert event["authenticated"] is True
    assert event["decision"] == "allow"


def test_invalid_signature_falls_back_to_untrusted(monkeypatch, tmp_path):
    monkeypatch.delenv("BACKBOARD_API_KEY", raising=False)
    monkeypatch.setenv("DEMO_READONLY_SECRET", "test-secret")
    monkeypatch.setattr(main, "AUDIT_PATH", tmp_path / "audit.jsonl")
    seen = {}
    monkeypatch.setattr(
        main, "run_in_sandbox", lambda tier, payload: seen.update(tier=tier) or {"ok": True}
    )
    response = TestClient(main.app).post(
        "/hook/demo-readonly",
        json={"url": "https://api.github.com/zen", "method": "GET"},
        headers={"x-hook-signature": "sha256=bad"},
    )
    assert response.status_code == 200
    assert seen["tier"] == "untrusted"


def test_jev_classifier_routes_and_audits_confidence(monkeypatch, tmp_path):
    monkeypatch.setenv("BACKBOARD_API_KEY", "test-key")
    monkeypatch.setenv("DEMO_READONLY_SECRET", "test-secret")
    monkeypatch.setattr(main, "AUDIT_PATH", tmp_path / "audit.jsonl")
    monkeypatch.setattr(
        main,
        "classify_jev",
        fake_classifier_result("readonly", 0.93),
    )
    monkeypatch.setattr(
        main, "run_in_sandbox", lambda tier, payload: {"ok": True}
    )
    body = json.dumps(
        {"url": "https://api.github.com/zen", "method": "GET"}
    ).encode()
    signature = "sha256=" + hmac.new(
        b"test-secret", body, hashlib.sha256
    ).hexdigest()

    response = TestClient(main.app).post(
        "/hook/demo-readonly",
        content=body,
        headers={
            "content-type": "application/json",
            "x-hook-signature": signature,
        },
    )

    assert response.status_code == 200
    assert response.json()["tier"] == "readonly"
    event = json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[0])
    assert event["classifier"] == "jev"
    assert event["classifier_confidence"] == 0.93


def fake_classifier_result(tier, confidence):
    async def classify(*args):
        return tier, "jev", confidence

    return classify
