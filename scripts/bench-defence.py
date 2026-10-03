#!/usr/bin/env python3
"""Run the repeatable Defence exploit benchmark and save a JSON report."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import platform
import subprocess
import sys
import uuid
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
COMPARISON = ROOT / "scripts" / "compare-defence-exploit.py"


def _request_json(
    url: str, *, method: str = "GET", body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={"content-type": "application/json", **(headers or {})},
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read())
        except json.JSONDecodeError:
            payload = {"detail": "non-JSON HTTP error"}
        return exc.code, payload


def _unquarantine(api: str, source: str, token: str) -> dict[str, Any]:
    status, result = _request_json(
        f"{api}/admin/sources/{source}/unquarantine",
        method="POST",
        body={"reason": "Preparing a repeatable synthetic Defence benchmark."},
        headers={"authorization": f"Bearer {token}"},
    )
    if status != 200:
        raise RuntimeError(f"Could not prepare {source}: HTTP {status}: {result}")
    return result


def _probe_sensor_b(api: str, secret: str) -> dict[str, Any]:
    event = {
        "action": "telemetry.read",
        "sensor_id": "B-01",
        "event_id": "benchmark-sensor-b-isolation",
        "vendor_document": "flow_lpm: 7.25",
    }
    body = json.dumps(event, separators=(",", ":")).encode()
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    status, result = _request_json(
        f"{api}/sensor/sensor-b",
        method="POST",
        body=event,
        headers={"x-hook-signature": f"sha256={signature}"},
    )
    return {"http_status": status, "result": result}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=20, help="repetitions per exploit case (1-100)")
    parser.add_argument("--api", default="http://127.0.0.1:8001", help="local Defence API URL")
    parser.add_argument("--output", type=Path, help="JSON result path (default: var/defence-benchmark-<UTC>.json)")
    args = parser.parse_args()

    if not 1 <= args.trials <= 100:
        parser.error("--trials must be between 1 and 100")
    required_env = (
        "DEFENCE_SENSOR_A_SECRET",
        "DEFENCE_SENSOR_B_SECRET",
        "DEFENCE_ADMIN_TOKEN",
        "DEMO_EXFIL_TOKEN",
        "OPENSHELL_GRPC_ENDPOINT",
    )
    missing = [key for key in required_env if not os.getenv(key)]
    if missing:
        parser.error("export the required environment variables: " + ", ".join(missing))

    started = datetime.now(timezone.utc)
    try:
        reset = _unquarantine(
            args.api, "sensor-a", os.environ["DEFENCE_ADMIN_TOKEN"]
        )
    except (OSError, RuntimeError) as exc:
        print(f"Benchmark preflight failed: {exc}", file=sys.stderr)
        return 2

    child_env = os.environ.copy()
    child_env["DEMO_BENCHMARK_TRIALS"] = str(args.trials)
    child_env["DEFENCE_API_URL"] = args.api.rstrip("/")
    completed = subprocess.run(
        [sys.executable, str(COMPARISON)],
        cwd=ROOT,
        env=child_env,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.stderr:
        print(completed.stderr, file=sys.stderr, end="")
    try:
        comparison = json.loads(completed.stdout)
    except json.JSONDecodeError:
        print(
            f"Comparison failed (exit {completed.returncode}):\n{completed.stdout}",
            file=sys.stderr,
        )
        return completed.returncode or 1

    sensor_b = _probe_sensor_b(
        args.api, os.environ["DEFENCE_SENSOR_B_SECRET"]
    )
    git_revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    git_status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    report = {
        "schema_version": 1,
        "started_at": started.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "configuration": {
            "trials_per_case": args.trials,
            "api": args.api,
            "sandbox_a": os.getenv("DEFENCE_SENSOR_A_SANDBOX", "def-sensor-a"),
            "sandbox_b": os.getenv("DEFENCE_SENSOR_B_SANDBOX", "def-sensor-b"),
            "collector": "local-only",
            "payload": "fixed synthetic YAML RCE; repeated trials are not distinct attack classes",
        },
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "git_revision": git_revision or None,
            "git_worktree_dirty": bool(git_status),
            "percentile_method": "linear interpolation over sorted samples",
        },
        "preparation": {"source_a_unquarantine": reset},
        "exploit_comparison": comparison,
        "isolation_check": {
            "description": "one benign sensor-b telemetry.read after sensor-a exploit quarantine",
            **sensor_b,
        },
        "limitations": [
            "Confirm egress denial from OpenShell NET:REFUSE/DENIED logs; zero collector bytes alone does not establish the denial cause.",
            "Baseline timing is local handler time; sandbox timing includes SDK/gateway session.exec round-trip and is not a pure sandbox overhead measurement.",
            "This run repeats one synthetic exploit payload; it is not a multi-technique attack benchmark.",
        ],
        "passed": (
            completed.returncode == 0
            and sensor_b["http_status"] == 200
            and sensor_b["result"].get("status") == "accepted"
        ),
    }

    output = args.output
    if output is None:
        stamp = started.strftime("%Y%m%dT%H%M%S%fZ")
        output = ROOT / "var" / f"defence-benchmark-{stamp}-{uuid.uuid4().hex[:8]}.json"
    elif not output.is_absolute():
        output = ROOT / output
    if output.exists():
        print(f"Refusing to overwrite existing report: {output}", file=sys.stderr)
        return 2
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")

    summary = {
        "passed": report["passed"],
        "trials": args.trials,
        "report": str(output),
        "baseline": {
            key: value
            for key, value in comparison.get("baseline_unconfined", {}).items()
            if key != "trial_results"
        },
        "openshell": {
            key: value
            for key, value in comparison.get("openshell_contained", {}).items()
            if key != "trial_results"
        },
        "sensor_b_isolation": sensor_b,
    }
    print(json.dumps(summary, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
