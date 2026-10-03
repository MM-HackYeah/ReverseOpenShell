import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from defence.app import main


def signed_event(secret: str, event: dict) -> tuple[bytes, str]:
    body = json.dumps(event, separators=(",", ":")).encode()
    signature = "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()
    return body, signature


def test_ingress_policy_denies_before_sandbox_and_quarantines_source(
    monkeypatch, tmp_path
):
    secret_a = "sensor-a-test-secret"
    secret_b = "sensor-b-test-secret"
    monkeypatch.setenv("DEFENCE_SENSOR_A_SECRET", secret_a)
    monkeypatch.setenv("DEFENCE_SENSOR_B_SECRET", secret_b)
    monkeypatch.setattr(main, "AUDIT_PATH", tmp_path / "audit.jsonl")
    main.QUARANTINE.clear()
    calls = []

    def execute(sandbox, payload):
        calls.append(sandbox)
        return {
            "status": "accepted",
            "action": payload["action"],
            "sensor_id": payload["sensor_id"],
            "event_id": payload["event_id"],
            "flow_lpm": payload["flow_lpm"],
        }

    monkeypatch.setattr(main, "_execute_in_openshell", execute)
    client = TestClient(main.app)

    attack, sig_a = signed_event(
        secret_a,
        {
            "action": "telemetry.write",
            "sensor_id": "A-01",
            "event_id": "evt-attack",
            "flow_lpm": 12.5,
        },
    )
    response = client.post(
        "/sensor/sensor-a",
        content=attack,
        headers={"x-hook-signature": sig_a},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "action not allowed; source quarantined"
    assert calls == []

    next_a, sig_a = signed_event(
        secret_a,
        {
            "action": "telemetry.read",
            "sensor_id": "A-01",
            "event_id": "evt-next",
            "flow_lpm": 10,
        },
    )
    assert (
        client.post(
            "/sensor/sensor-a",
            content=next_a,
            headers={"x-hook-signature": sig_a},
        ).status_code
        == 423
    )

    normal_b, sig_b = signed_event(
        secret_b,
        {
            "action": "telemetry.read",
            "sensor_id": "B-01",
            "event_id": "evt-normal",
            "flow_lpm": 8,
        },
    )
    response_b = client.post(
        "/sensor/sensor-b",
        content=normal_b,
        headers={"x-hook-signature": sig_b},
    )
    assert response_b.status_code == 200
    assert response_b.json()["status"] == "accepted"
    assert calls == ["defence-sensor-b"]

    state = client.get("/events").json()
    assert state["quarantined_sources"] == ["sensor-a"]
    assert state["active_sources"] == ["sensor-b"]
    assert state["metrics"] == {
        "accepted_events": 1,
        "blocked_ingress_requests": 1,
    }


def test_invalid_signature_never_executes_sandbox(monkeypatch, tmp_path):
    monkeypatch.setenv("DEFENCE_SENSOR_A_SECRET", "expected")
    monkeypatch.setattr(main, "AUDIT_PATH", tmp_path / "audit.jsonl")
    called = False

    def execute(*_args):
        nonlocal called
        called = True
        return {"status": "accepted"}

    monkeypatch.setattr(main, "_execute_in_openshell", execute)
    response = TestClient(main.app).post(
        "/sensor/sensor-a",
        json={
            "action": "telemetry.read",
            "sensor_id": "A-01",
            "event_id": "evt",
            "flow_lpm": 5,
        },
        headers={"x-hook-signature": "sha256=invalid"},
    )
    assert response.status_code == 401
    assert called is False


def test_unknown_source_is_rejected(monkeypatch):
    called = False

    def execute(*_args):
        nonlocal called
        called = True
        return {"status": "accepted"}

    monkeypatch.setattr(main, "_execute_in_openshell", execute)
    response = TestClient(main.app).post("/sensor/unknown", json={})
    assert response.status_code == 404
    assert called is False


def test_gateway_endpoint_override_is_used(monkeypatch):
    created = {}

    class FakeClient:
        def __init__(self, endpoint, *, timeout):
            created.update(endpoint=endpoint, timeout=timeout)

    monkeypatch.setenv("OPENSHELL_GRPC_ENDPOINT", "127.0.0.1:8080")
    monkeypatch.setattr(main, "SandboxClient", FakeClient)
    main._openshell_client()
    assert created == {"endpoint": "127.0.0.1:8080", "timeout": 10}
