from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from fastapi import FastAPI, HTTPException, Request
from openshell import SandboxClient
from openshell.errors import GatewayError
import yaml

app = FastAPI(title="Defence Sensor Inbound Shield", version="0.1.0")
DB_PATH = Path(os.getenv("DEFENCE_DB_PATH", "var/defence.db"))
MAX_REQUEST_BYTES = 8_192
EXEC_TIMEOUT_SECONDS = 8
WORKSPACE = os.getenv("OPENSHELL_WORKSPACE", "default")
POLICY_PATH = Path(
    os.getenv(
        "DEFENCE_INGRESS_POLICY",
        str(Path(__file__).resolve().parents[2] / "policies" / "defence-ingress.yaml"),
    )
)


def _load_ingress_policy() -> dict[str, Any]:
    try:
        policy = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RuntimeError(f"cannot load ingress policy: {POLICY_PATH}") from exc
    if not isinstance(policy, dict) or policy.get("version") != 1:
        raise RuntimeError("ingress policy must be a version 1 mapping")
    if policy.get("default_decision") != "deny":
        raise RuntimeError("ingress policy must default to deny")
    sources = policy.get("sources")
    if not isinstance(sources, dict) or not sources:
        raise RuntimeError("ingress policy must define sources")
    for name, source in sources.items():
        if (
            not isinstance(name, str)
            or not isinstance(source, dict)
            or not isinstance(source.get("secret_env"), str)
            or not isinstance(source.get("sandbox"), str)
            or not isinstance(source.get("allowed_actions"), list)
            or not source["allowed_actions"]
            or not all(isinstance(action, str) for action in source["allowed_actions"])
        ):
            raise RuntimeError(f"invalid ingress source policy: {name}")
    return policy


INGRESS_POLICY = _load_ingress_policy()
SOURCE_SANDBOXES = {
    name: config["sandbox"] for name, config in INGRESS_POLICY["sources"].items()
}
_state_lock = threading.RLock()


def _openshell_client() -> SandboxClient:
    endpoint = os.getenv("OPENSHELL_GRPC_ENDPOINT")
    if endpoint:
        return SandboxClient(endpoint, timeout=10)
    return SandboxClient.from_active_cluster()


def _signature_valid(source: str, body: bytes, signature: str | None) -> bool:
    if not signature:
        return False
    source_policy = INGRESS_POLICY["sources"].get(source)
    if source_policy is None:
        return False
    secret_name = source_policy["secret_env"]
    secret = os.getenv(secret_name)
    if not secret:
        return False
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def _connect_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """CREATE TABLE IF NOT EXISTS audit_events (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            decision TEXT NOT NULL,
            reason TEXT,
            event_json TEXT NOT NULL
        )"""
    )
    connection.execute(
        """CREATE TABLE IF NOT EXISTS quarantined_sources (
            source TEXT PRIMARY KEY,
            quarantined_at TEXT NOT NULL,
            reason TEXT NOT NULL
        )"""
    )
    return connection


def _audit(event: dict[str, Any]) -> None:
    with closing(_connect_db()) as connection, connection:
        connection.execute(
            """INSERT INTO audit_events
               (id, timestamp, source, decision, reason, event_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                event["id"],
                event["timestamp"],
                event.get("source", "system"),
                event.get("decision", "unknown"),
                event.get("reason"),
                json.dumps(event, ensure_ascii=False),
            ),
        )
        if event.get("decision") == "quarantine":
            connection.execute(
                """INSERT OR REPLACE INTO quarantined_sources
                   (source, quarantined_at, reason) VALUES (?, ?, ?)""",
                (event["source"], event["timestamp"], event["reason"]),
            )


def _is_quarantined(source: str) -> bool:
    with closing(_connect_db()) as connection:
        return connection.execute(
            "SELECT 1 FROM quarantined_sources WHERE source = ?", (source,)
        ).fetchone() is not None


def _execute_in_openshell(
    sandbox_name: str,
    payload: dict[str, Any],
    runtime_env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    # The sandbox name comes only from SOURCE_SANDBOXES, never from the request.
    with _openshell_client() as client:
        session = client.get_session(sandbox_name, workspace=WORKSPACE)
        result = session.exec(
            ["python3.12", "/app/defence_runner.py"],
            stdin=json.dumps(payload, separators=(",", ":")).encode(),
            env=runtime_env,
            timeout_seconds=EXEC_TIMEOUT_SECONDS,
        )
    if result.exit_code != 0:
        raise RuntimeError(f"OpenShell handler exited with code {result.exit_code}")
    try:
        output = json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise RuntimeError("OpenShell handler returned invalid JSON") from exc
    if not isinstance(output, dict):
        raise RuntimeError("OpenShell handler returned an invalid event")
    return output


def _recent_events(limit: int = 100) -> list[dict[str, Any]]:
    with closing(_connect_db()) as connection:
        rows = connection.execute(
            "SELECT event_json FROM audit_events ORDER BY rowid DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [json.loads(row["event_json"]) for row in reversed(rows)]


def _quarantined_sources() -> list[str]:
    with closing(_connect_db()) as connection:
        rows = connection.execute(
            "SELECT source FROM quarantined_sources ORDER BY source"
        ).fetchall()
    return [row["source"] for row in rows]


@app.get("/health")
def health() -> dict[str, str]:
    try:
        with _openshell_client() as client:
            client.health()
        openshell = "available"
    except Exception:
        openshell = "unavailable"
    return {"status": "ok", "openshell": openshell}


@app.get("/events")
def events() -> dict[str, Any]:
    quarantined = _quarantined_sources()
    recent = _recent_events()
    return {
        "quarantined_sources": quarantined,
        "active_sources": sorted(set(SOURCE_SANDBOXES) - set(quarantined)),
        "metrics": {
            "accepted_events": sum(event.get("decision") == "allow" for event in recent),
            "blocked_ingress_requests": sum(
                event.get("reason") == "ingress_action_not_allowed"
                for event in recent
            ),
            "parser_compromises": sum(
                event.get("reason") == "vendor_parser_compromise"
                for event in recent
            ),
            "invalid_signatures": sum(
                event.get("reason") == "invalid_source_signature"
                for event in recent
            ),
        },
        "events": recent,
    }


@app.post("/sensor/{source}")
async def ingest_sensor(source: str, request: Request) -> dict[str, Any]:
    request_id = str(uuid.uuid4())
    source_policy = INGRESS_POLICY["sources"].get(source)
    if source_policy is None:
        raise HTTPException(status_code=404, detail="unknown sensor source")

    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="event too large")
        chunks.append(chunk)
    body = b"".join(chunks)
    authenticated = _signature_valid(
        source, body, request.headers.get("x-hook-signature")
    )
    if not authenticated:
        _audit(
            {
                "id": request_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": source,
                "authenticated": False,
                "decision": "deny",
                "reason": "invalid_source_signature",
            }
        )
        raise HTTPException(status_code=401, detail="invalid source signature")

    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="event must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="event must be a JSON object")

    action = payload.get("action")
    if not isinstance(action, str) or len(action) > 64:
        raise HTTPException(status_code=400, detail="action is required")

    with _state_lock:
        if _is_quarantined(source):
            raise HTTPException(status_code=423, detail="source is quarantined")
        sandbox = source_policy["sandbox"]

    event: dict[str, Any] = {
        "id": request_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "authenticated": True,
        "action": action,
        "sandbox": sandbox,
    }
    runtime_env = {
        "DEMO_CANARY_PATH": "/opt/demo-protected/canary.secret",
        "DEMO_SETPOINT_PATH": "/opt/demo-protected/setpoint.json",
        "DEMO_EXFIL_URL": os.getenv(
            "DEMO_EXFIL_URL", "http://host.openshell.internal:9999/collect"
        ),
        "DEMO_EXFIL_TOKEN": os.getenv("DEMO_EXFIL_TOKEN", ""),
        "DEMO_ATTACK_REPORT_PATH": f"/tmp/reverseopenshell-attack-{request_id}.json",
    }

    # Ingress authorization happens before sandbox execution. A validly signed
    # source cannot request actions outside its allowlist.
    if action not in source_policy["allowed_actions"]:
        event.update(
            decision="quarantine",
            reason="ingress_action_not_allowed",
            blocked_actions=1,
        )
        _audit(event)
        raise HTTPException(status_code=403, detail="action not allowed; source quarantined")

    try:
        result = _execute_in_openshell(sandbox, payload, runtime_env=runtime_env)
    except (RuntimeError, OSError, GatewayError) as exc:
        event.update(decision="error", reason=type(exc).__name__)
        _audit(event)
        raise HTTPException(status_code=502, detail="sandbox execution failed") from exc

    if result.get("status") == "parser_compromised":
        report = result.get("attack_report")
        if not isinstance(report, dict):
            report = {}
        event.update(
            decision="quarantine",
            reason="vendor_parser_compromise",
            containment=report,
        )
        _audit(event)
        return {
            "request_id": request_id,
            "status": "quarantined",
            "blocked_by": "ReverseOpenShell",
            "source": source,
            "containment": report,
        }

    if (
        result.get("status") != "accepted"
        or result.get("action") != action
        or result.get("sensor_id") != payload.get("sensor_id")
    ):
        event.update(decision="deny", reason="invalid_or_unexpected_handler_result")
        _audit(event)
        raise HTTPException(status_code=400, detail="invalid sensor event")

    event.update(decision="allow", sensor_event_id=result.get("event_id"))
    _audit(event)
    return {"request_id": request_id, **result}


@app.post("/admin/sources/{source}/unquarantine")
async def unquarantine_source(source: str, request: Request) -> dict[str, Any]:
    if source not in SOURCE_SANDBOXES:
        raise HTTPException(status_code=404, detail="unknown sensor source")
    admin_token = os.getenv("DEFENCE_ADMIN_TOKEN")
    supplied = request.headers.get("authorization", "")
    if not admin_token or not hmac.compare_digest(supplied, f"Bearer {admin_token}"):
        raise HTTPException(status_code=401, detail="operator authorization required")

    body = await request.body()
    if len(body) > 4_096:
        raise HTTPException(status_code=413, detail="request too large")
    try:
        payload = json.loads(body or b"{}")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="body must be valid JSON") from exc
    reason = payload.get("reason") if isinstance(payload, dict) else None
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
        raise HTTPException(status_code=400, detail="a review reason is required")

    timestamp = datetime.now(timezone.utc).isoformat()
    with closing(_connect_db()) as connection, connection:
        deleted = connection.execute(
            "DELETE FROM quarantined_sources WHERE source = ?", (source,)
        ).rowcount
        event = {
            "id": str(uuid.uuid4()),
            "timestamp": timestamp,
            "source": source,
            "decision": "unquarantine",
            "reason": reason.strip(),
            "operator": "authenticated_admin",
        }
        connection.execute(
            """INSERT INTO audit_events
               (id, timestamp, source, decision, reason, event_json)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                event["id"],
                event["timestamp"],
                source,
                event["decision"],
                event["reason"],
                json.dumps(event, ensure_ascii=False),
            ),
        )
    return {
        "source": source,
        "status": "active",
        "was_quarantined": bool(deleted),
    }
