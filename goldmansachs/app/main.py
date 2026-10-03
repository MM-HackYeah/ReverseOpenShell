from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request

from .classifier import classify, classify_jev
from .policy import verify_signature

app = FastAPI(title="Inbound Sandbox for AI Agents", version="0.1.0")
AUDIT_PATH = Path(os.getenv("AUDIT_PATH", "var/audit.jsonl"))
MAX_REQUEST_BYTES = 16_384
RUNNER_TIMEOUT_SECONDS = 8
WORKSPACE = os.getenv("OPENSHELL_WORKSPACE", "default")
_audit_lock = threading.Lock()


def append_audit(event: dict[str, Any]) -> None:
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _audit_lock:
        with AUDIT_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")


def run_in_sandbox(tier: str, payload: dict[str, Any]) -> dict[str, Any]:
    from openshell import SandboxClient

    sandbox = os.getenv(f"OPENSHELL_SANDBOX_{tier.upper()}", f"tier-{tier}")
    with SandboxClient.from_active_cluster() as client:
        session = client.get_session(sandbox, workspace=WORKSPACE)
        result = session.exec(
            ["python3.12", "/app/runner.py"],
            stdin=json.dumps(payload).encode(),
            timeout_seconds=RUNNER_TIMEOUT_SECONDS,
        )
    if result.exit_code != 0:
        # Do not forward sandbox stderr; it may contain request-specific data.
        raise RuntimeError("sandbox execution denied or failed")
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise RuntimeError("sandbox returned an invalid response") from exc


@app.get("/health")
def health() -> dict[str, str]:
    try:
        from openshell import SandboxClient

        with SandboxClient.from_active_cluster() as client:
            client.health()
        status = "available"
    except Exception:
        status = "unavailable"
    return {"status": "ok", "openshell": status}


@app.get("/events")
def events(limit: int = 50) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 200))
    if not AUDIT_PATH.exists():
        return []
    lines = AUDIT_PATH.read_text(encoding="utf-8").splitlines()[-limit:]
    return [json.loads(line) for line in lines]


@app.post("/hook/{source}")
async def hook(source: str, request: Request) -> dict[str, Any]:
    request_id = str(uuid.uuid4())
    body_chunks = []
    body_size = 0
    async for chunk in request.stream():
        body_size += len(chunk)
        if body_size > MAX_REQUEST_BYTES:
            raise HTTPException(status_code=413, detail="request body too large")
        body_chunks.append(chunk)
    raw = b"".join(body_chunks)
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="body must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON body must be an object")
    if not isinstance(payload.get("url"), str) or not isinstance(
        payload.get("method"), str
    ):
        raise HTTPException(status_code=400, detail="url and method are required")
    if payload["method"].upper() not in {"GET", "POST"}:
        raise HTTPException(status_code=400, detail="only GET and POST are supported")
    parsed_url = urlsplit(payload["url"])
    if (
        parsed_url.scheme != "https"
        or not parsed_url.hostname
        or parsed_url.username
        or parsed_url.password
        or parsed_url.fragment
    ):
        raise HTTPException(status_code=400, detail="url must be a valid HTTPS URL")

    authenticated = verify_signature(
        source, raw, request.headers.get("x-hook-signature")
    )
    if os.getenv("BACKBOARD_API_KEY"):
        tier, classifier, confidence = await classify_jev(
            source, payload, authenticated
        )
    else:
        tier, classifier = classify(source, payload, authenticated)
        confidence = None
    event: dict[str, Any] = {
        "id": request_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "authenticated": authenticated,
        "tier": tier,
        "classifier": classifier,
        "classifier_confidence": confidence,
        "method": payload["method"].upper(),
        # Log only the destination host, never query parameters or request data.
        "destination": parsed_url.hostname,
        "decision": "allow",
    }

    try:
        result = run_in_sandbox(tier, payload)
        event["result_ok"] = bool(result.get("ok"))
        if not event["result_ok"]:
            event["decision"] = (
                "deny" if result.get("status") == 403 else "handler_error"
            )
        append_audit(event)
        return {"request_id": request_id, "tier": tier, **result}
    except (OSError, RuntimeError) as exc:
        event["decision"] = "deny" if "denied" in str(exc).lower() else "error"
        event["reason"] = type(exc).__name__
        append_audit(event)
        raise HTTPException(status_code=502, detail=event["decision"]) from exc
