from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from openshell import SandboxClient
from openshell.errors import GatewayError
import yaml

app = FastAPI(title="Defence Sensor Inbound Shield", version="0.1.0")
AUDIT_PATH = Path(os.getenv("DEFENCE_AUDIT_PATH", "var/defence-audit.jsonl"))
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
QUARANTINE: set[str] = set()
_state_lock = threading.RLock()
_audit_lock = threading.Lock()


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


def _audit(event: dict[str, Any]) -> None:
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _audit_lock:
        with AUDIT_PATH.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, ensure_ascii=False) + "\n")


def _execute_in_openshell(sandbox_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    # The sandbox name comes only from SOURCE_SANDBOXES, never from the request.
    with _openshell_client() as client:
        session = client.get_session(sandbox_name, workspace=WORKSPACE)
        result = session.exec(
            ["python3.12", "/app/defence_runner.py"],
            stdin=json.dumps(payload, separators=(",", ":")).encode(),
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
    if not AUDIT_PATH.exists():
        return []
    parsed = []
    for line in AUDIT_PATH.read_text(encoding="utf-8").splitlines()[-limit:]:
        try:
            parsed.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return parsed


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
    with _state_lock:
        quarantined = sorted(QUARANTINE)
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
        if source in QUARANTINE:
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

    # Ingress authorization happens before sandbox execution. A validly signed
    # source cannot request actions outside its allowlist.
    if action not in source_policy["allowed_actions"]:
        with _state_lock:
            QUARANTINE.add(source)
        event.update(
            decision="quarantine",
            reason="ingress_action_not_allowed",
            blocked_actions=1,
        )
        _audit(event)
        raise HTTPException(status_code=403, detail="action not allowed; source quarantined")

    try:
        result = _execute_in_openshell(sandbox, payload)
    except (RuntimeError, OSError, GatewayError) as exc:
        event.update(decision="error", reason=type(exc).__name__)
        _audit(event)
        raise HTTPException(status_code=502, detail="sandbox execution failed") from exc

    if result.get("status") != "accepted" or result.get("action") != action:
        event.update(decision="deny", reason="invalid_or_unexpected_handler_result")
        _audit(event)
        raise HTTPException(status_code=400, detail="invalid sensor event")

    event.update(decision="allow", sensor_event_id=result.get("event_id"))
    _audit(event)
    return {"request_id": request_id, **result}
