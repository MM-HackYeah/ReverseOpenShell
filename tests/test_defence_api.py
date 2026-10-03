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
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "state.sqlite3")
    calls = []

    def execute(sandbox, payload, runtime_env=None):
        calls.append(sandbox)
        return {
            "status": "accepted",
            "action": payload["action"],
            "sensor_id": payload["sensor_id"],
            "event_id": payload["event_id"],
            "flow_lpm": 8,
        }

    monkeypatch.setattr(main, "_execute_in_openshell", execute)
    client = TestClient(main.app)

    attack, sig_a = signed_event(
        secret_a,
        {
            "action": "telemetry.write",
            "sensor_id": "A-01",
            "event_id": "evt-attack",
            "vendor_document": "flow_lpm: 12.5\n",
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
            "vendor_document": "flow_lpm: 10\n",
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
            "vendor_document": "flow_lpm: 8\n",
        },
    )
    response_b = client.post(
        "/sensor/sensor-b",
        content=normal_b,
        headers={"x-hook-signature": sig_b},
    )
    assert response_b.status_code == 200
    assert response_b.json()["status"] == "accepted"
    assert calls == ["def-sensor-b"]

    state = client.get("/events").json()
    assert state["quarantined_sources"] == ["sensor-a"]
    assert state["active_sources"] == ["sensor-b"]
    assert state["metrics"] == {
        "accepted_events": 1,
        "blocked_ingress_requests": 1,
        "parser_compromises": 0,
        "invalid_signatures": 0,
    }


def test_invalid_signature_never_executes_sandbox(monkeypatch, tmp_path):
    monkeypatch.setenv("DEFENCE_SENSOR_A_SECRET", "expected")
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "state.sqlite3")
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
            "vendor_document": "flow_lpm: 5\n",
        },
        headers={"x-hook-signature": "sha256=invalid"},
    )
    assert response.status_code == 401
    assert called is False
    assert main.events()["metrics"]["invalid_signatures"] == 1


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


def test_parser_compromise_is_quarantined_and_reported(monkeypatch, tmp_path):
    monkeypatch.setenv("DEFENCE_SENSOR_A_SECRET", "test-secret")
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "state.sqlite3")
    called = []
    report = {
        "secret_read": "blocked",
        "exfiltration": "blocked_by_openshell",
        "setpoint_write": "blocked",
    }

    def execute(sandbox, payload, runtime_env=None):
        called.append((sandbox, payload, runtime_env))
        return {
            "status": "parser_compromised",
            "action": payload["action"],
            "sensor_id": payload["sensor_id"],
            "event_id": payload["event_id"],
            "attack_report": report,
        }

    monkeypatch.setattr(main, "_execute_in_openshell", execute)
    body, signature = signed_event(
        "test-secret",
        {
            "action": "telemetry.read",
            "sensor_id": "A-01",
            "event_id": "evt-exploit",
            "vendor_document": "synthetic exploit payload",
        },
    )
    response = TestClient(main.app).post(
        "/sensor/sensor-a",
        content=body,
        headers={"x-hook-signature": signature},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "quarantined"
    assert response.json()["containment"] == report
    assert len(called) == 1
    assert called[0][0] == "def-sensor-a"
    assert called[0][2]["DEMO_CANARY_PATH"] == "/opt/demo-protected/canary.secret"
    persisted = main.events()["events"][0]
    assert "vendor_document" not in persisted
    assert main.events()["metrics"]["parser_compromises"] == 1


def test_unquarantine_requires_operator_and_persists_reason(monkeypatch, tmp_path):
    monkeypatch.setenv("DEFENCE_SENSOR_A_SECRET", "sensor-a-secret")
    monkeypatch.setenv("DEFENCE_ADMIN_TOKEN", "operator-test-token")
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "state.sqlite3")
    calls = []

    def execute(sandbox, payload, runtime_env=None):
        calls.append(sandbox)
        return {
            "status": "accepted",
            "action": payload["action"],
            "sensor_id": payload["sensor_id"],
            "event_id": payload["event_id"],
            "flow_lpm": 4,
        }

    monkeypatch.setattr(main, "_execute_in_openshell", execute)
    client = TestClient(main.app)
    body, signature = signed_event(
        "sensor-a-secret",
        {
            "action": "telemetry.write",
            "sensor_id": "A-01",
            "event_id": "evt-denied",
            "vendor_document": "flow_lpm: 4\n",
        },
    )
    denied = client.post(
        "/sensor/sensor-a",
        content=body,
        headers={"x-hook-signature": signature},
    )
    assert denied.status_code == 403
    assert (
        client.post(
            "/sensor/sensor-a",
            content=body,
            headers={"x-hook-signature": signature},
        ).status_code
        == 423
    )

    unapproved = client.post(
        "/admin/sources/sensor-a/unquarantine",
        json={"reason": "reviewed"},
    )
    assert unapproved.status_code == 401

    released = client.post(
        "/admin/sources/sensor-a/unquarantine",
        json={"reason": "Operator reviewed the source and rotated its key."},
        headers={"authorization": "Bearer operator-test-token"},
    )
    assert released.status_code == 200
    assert released.json()["was_quarantined"] is True
    assert main.events()["quarantined_sources"] == []
    assert main.events()["events"][-1]["decision"] == "unquarantine"
    accepted_body, accepted_signature = signed_event(
        "sensor-a-secret",
        {
            "action": "telemetry.read",
            "sensor_id": "A-01",
            "event_id": "evt-after-review",
            "vendor_document": "flow_lpm: 4\n",
        },
    )
    accepted = client.post(
        "/sensor/sensor-a",
        content=accepted_body,
        headers={"x-hook-signature": accepted_signature},
    )
    assert accepted.status_code == 200
    assert calls == ["def-sensor-a"]
