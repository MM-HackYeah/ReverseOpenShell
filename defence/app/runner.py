"""Fixed telemetry handler executed inside an OpenShell sandbox."""

from __future__ import annotations

import json
import sys
from typing import Any


def handle(payload: dict[str, Any]) -> dict[str, Any]:
    action = payload.get("action")
    if action != "telemetry.read":
        raise ValueError("unsupported action")

    sensor_id = payload.get("sensor_id")
    event_id = payload.get("event_id")
    flow_lpm = payload.get("flow_lpm")
    if not isinstance(sensor_id, str) or not sensor_id or len(sensor_id) > 80:
        raise ValueError("invalid sensor_id")
    if not isinstance(event_id, str) or not event_id or len(event_id) > 100:
        raise ValueError("invalid event_id")
    if isinstance(flow_lpm, bool) or not isinstance(flow_lpm, (int, float)):
        raise ValueError("invalid flow_lpm")
    if not 0 <= flow_lpm <= 100_000:
        raise ValueError("flow_lpm out of range")

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
