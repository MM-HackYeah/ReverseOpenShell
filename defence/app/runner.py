"""Deliberately vulnerable vendor YAML parser for the Defence demo.

This intentionally uses yaml.unsafe_load so the demo can exercise an RCE
payload inside OpenShell. Never copy this parser into a real service.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

import yaml


def handle(payload: dict[str, Any]) -> dict[str, Any]:
    action = payload.get("action")
    if action != "telemetry.read":
        raise ValueError("unsupported action")

    sensor_id = payload.get("sensor_id")
    event_id = payload.get("event_id")
    vendor_document = payload.get("vendor_document")
    if not isinstance(sensor_id, str) or not sensor_id or len(sensor_id) > 80:
        raise ValueError("invalid sensor_id")
    if not isinstance(event_id, str) or not event_id or len(event_id) > 100:
        raise ValueError("invalid event_id")
    if not isinstance(vendor_document, str) or len(vendor_document) > 4_096:
        raise ValueError("invalid vendor document")

    report_path = Path(
        os.getenv(
            "DEMO_ATTACK_REPORT_PATH",
            f"/tmp/reverseopenshell-attack-{uuid.uuid4().hex}.json",
        )
    )
    report_path.unlink(missing_ok=True)
    try:
        # Intentionally vulnerable: untrusted vendor documents can execute code.
        parsed = yaml.unsafe_load(vendor_document)
    except Exception:
        parsed = None

    if report_path.is_file():
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report_path.unlink(missing_ok=True)
        return {
            "status": "parser_compromised",
            "action": action,
            "sensor_id": sensor_id,
            "event_id": event_id,
            "attack_report": report,
        }

    if not isinstance(parsed, dict):
        return {"status": "invalid_vendor_document"}
    flow_lpm = parsed.get("flow_lpm")
    if isinstance(flow_lpm, bool) or not isinstance(flow_lpm, (int, float)):
        return {"status": "invalid_vendor_document"}
    if not 0 <= flow_lpm <= 100_000:
        return {"status": "invalid_vendor_document"}

    return {
        "status": "accepted",
        "action": action,
        "sensor_id": sensor_id,
        "event_id": event_id,
        "flow_lpm": flow_lpm,
    }


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise ValueError("event must be an object")
        print(json.dumps(handle(payload), separators=(",", ":")))
        return 0
    except (ValueError, TypeError, json.JSONDecodeError):
        print(json.dumps({"status": "invalid_event"}))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
