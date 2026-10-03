# Defence experiment log

This log records experiments actually run against the local prototype. It is not a production performance report or a security certification. Synthetic canary, setpoint, and collector only.

## Recorded runs

| ID | Date | Experiment | Result |
|---|---|---|---|
| D-01 | 2026-10-03 | Sandbox naming/setup | OpenShell rejected `defence-sensor-a-shield` at 23 characters (gateway limit: 19). Renamed sandboxes to `def-sensor-a` and `def-sensor-b`; user confirmed both were created. |
| D-02 | 2026-10-03 | Sensor B signature negative control | First request returned `401 invalid source signature` because the caller shell had no `DEFENCE_SENSOR_B_SECRET`. After exporting the same demo secret used by the API, a valid sensor B `telemetry.read` returned HTTP 200 and `accepted`. |
| D-03 | 2026-10-03 | Same synthetic exploit, local baseline vs OpenShell | 20 repetitions of one payload. Baseline: 20/20 canary reads, 20/20 collector deliveries, 680 bytes total, and setpoint changed from 40 to 9999. OpenShell: 20/20 canary reads blocked, 20/20 setpoint writes blocked, 0 collector bytes. |
| D-04 | 2026-10-03 | OpenShell egress evidence | Sandbox logs contained repeated `NET:REFUSE [MED] DENIED host.openshell.internal [reason:policy_dns_ineligible]` entries during the exploit comparison. This is the evidence that OpenShell denied egress; the HTTP-oriented `exfiltration_requests_blocked_by_openshell` counter was 0 because the denial did not return HTTP 403. |
| D-05 | 2026-10-03 | Source quarantine and isolation | The exploit request returned HTTP 200 with application result `status: quarantined`; `/events` showed sensor A quarantined and sensor B active. The separate signed benign sensor B request was accepted. |
| D-06 | 2026-10-03 | Local automated tests | 9 Defence API/runner tests passed after the short sandbox names were introduced. One existing Starlette warning notes that `httpx` is deprecated in `TestClient`; it did not fail tests. |
| D-07 | 2026-10-03 | One-command benchmark | `scripts/bench-defence.py --trials 20` returned `passed: true`, including a post-quarantine sensor B check (HTTP 200). Full report is ignored under `var/`: `defence-benchmark-20261003T190317983031Z-c6789e82.json`. Source was run from HEAD `ec00ca2` with uncommitted benchmark/documentation changes. |
| D-08 | 2026-10-03 | Polished one-command benchmark | Reran after making stdout concise and storing all trial detail in JSON. `passed: true`; 20/20 baseline reads, deliveries, and writes succeeded; 20/20 sandbox reads and writes were blocked; 0 collector bytes; sensor B returned HTTP 200 after A was quarantined. Report: `var/defence-benchmark-20261003T190418725368Z-06f1ff57.json`. |

## D-03 measurements

One local 20-trial run produced:

| Measurement | Baseline | OpenShell |
|---|---:|---:|
| Secret read outcome | 20 succeeded | 20 blocked |
| Collector delivery outcome | 20 succeeded | 0 succeeded |
| Bytes received by local collector | 680 | 0 |
| Setpoint write outcome | 20 succeeded | 20 blocked |
| Final synthetic setpoint | 9999 | unchanged (each write attempt reported blocked) |
| p50 | 4.20 ms | 188.33 ms |
| p95 | 5.56 ms | 210.48 ms |

The baseline timing covers the local `handle()` call. The sandbox timing covers the Python SDK `session.exec()` round trip, including SDK/gateway communication. These are not equivalent timing boundaries, so their difference is not a clean estimate of sandbox-only overhead. This recorded run used the script's then-current lower-rank percentile selection; the repeatable benchmark now records its percentile method in JSON. This is one machine, one run, and one payload repeated 20 times, not 20 distinct attack classes.

### D-07 one-command benchmark measurements

This run uses linear interpolation for percentiles:

| Measurement | Baseline | OpenShell |
|---|---:|---:|
| Secret read | 20/20 succeeded | 20/20 blocked |
| Collector delivery | 20/20 succeeded | 0/20 succeeded |
| Bytes received | 680 | 0 |
| Setpoint write | 20/20 succeeded | 20/20 blocked |
| p50 / p95 | 4.19 / 7.03 ms | 245.88 / 477.19 ms |

OpenShell logs again showed `NET:REFUSE [MED] DENIED host.openshell.internal [reason:policy_dns_ineligible]`. The HTTP-specific sandbox denial counter was 0; all 20 attempts failed and the collector received no bytes. Sensor A was quarantined by the API, then a benign sensor B read was accepted (HTTP 200).

### D-08 polished benchmark measurements

The final one-command benchmark rerun reported:

| Measurement | Baseline | OpenShell |
|---|---:|---:|
| Secret read | 20/20 succeeded | 20/20 blocked |
| Collector delivery | 20/20 succeeded | 0/20 succeeded |
| Bytes received | 680 | 0 |
| Setpoint write | 20/20 succeeded | 20/20 blocked |
| p50 / p95 | 4.17 / 6.09 ms | 206.24 / 226.56 ms |

Sensor A was quarantined and the benign sensor B isolation request was accepted (HTTP 200). The egress-denial log signature was verified in the same live setup in D-04; the benchmark itself records unsuccessful egress and byte counts, not raw logs.

## Repeatable benchmark

The one-command benchmark runs the comparison, saves full per-trial JSON, tests sensor B after the exploit quarantines sensor A, and saves configuration/environment metadata:

```shell
uv run python scripts/bench-defence.py --trials 20
```

Required in the invoking shell: `DEFENCE_SENSOR_A_SECRET`, `DEFENCE_SENSOR_B_SECRET`, `DEFENCE_ADMIN_TOKEN`, `DEMO_EXFIL_TOKEN`, and `OPENSHELL_GRPC_ENDPOINT`. The API process must have the same sensor secrets, operator token, `DEMO_EXFIL_TOKEN`, and `DEMO_EXFIL_URL=http://host.openshell.internal:9999/collect`. The script will unquarantine sensor A first, run the comparison, and leave A quarantined after the exploit case. It writes a new report under `var/defence-benchmark-<UTC>-<id>.json`; it refuses to overwrite an existing report.

The report includes baseline and sandbox trials, byte counts, per-effect outcomes, linearly interpolated p50/p95, the API quarantine result, and a benign sensor B isolation check. It marks egress attempts unsuccessful separately from confirmed `NET:REFUSE` evidence. Check the latter in the OpenShell sandbox logs:

```shell
openshell logs def-sensor-a --since 10m --source sandbox
```

The saved JSON does not include the raw exploit document, HMAC values, or collector token. Do not add real credentials or targets to this benchmark.

## Reproduction limits

- Results depend on the local OpenShell version, compute driver, host load, and SDK.
- The collector listens on host port 9999 and accepts only the configured demo token. Keep it local and stop the benchmark process if it remains active after an interrupted run.
- This suite exercises one fixed payload that reads/writes only synthetic files and attempts egress only to the local collector alias. It does not test arbitrary files, real infrastructure, or all sandbox escape techniques.
- The handler's compromise marker is part of this fixed demo payload. It is not general-purpose exploit detection.
