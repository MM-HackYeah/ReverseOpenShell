# Defence — MVP: ingress policy and exploit containment

> **Jev showcase:** Deterministic ingress allows the signed `telemetry.read` action first. Jev then gets one last, downgrade-only `Choice`: `untrusted` or `read`. Try a benign document and a suspicious one with [`scripts/demo-defence-jev.sh`](../scripts/demo-defence-jev.sh). This demonstrates a semantic signal before sandbox execution; it does not replace OpenShell containment.

## Problem and user

An operator of critical infrastructure receives data from external vendors, such as sensor events. An error or compromise of one source's handler should not provide access to secrets or stop processing for other sources.

## Real threat and demonstration boundaries

Imagine an integration accepting a signed `telemetry.read` together with a device profile in YAML. The HMAC signature confirms who sent the body, but does not prove that the profile is safe: the source could be compromised, its key could leak, or a trusted vendor could provide dangerous data. If the handler passes such YAML to `yaml.unsafe_load`, special tags can execute Python in the handler process. This falls within the risk class **CWE-502: Deserialization of Untrusted Data**. In a practical integration, the first remediation step is `yaml.safe_load` (or a format without executable types), schema validation, and least-privilege process permissions.

The ingress allowlist answers “can this source system perform `telemetry.read`?”, not “is every byte of the profile safe?”. OpenShell answers a different question after the handler starts: “which files and network hosts can this process access?” The demo deliberately allows the parser to execute code to show this second defensive boundary.

Without a sandbox, the process has the current user's permissions and access to resources and networks that user can use. Code can therefore potentially read accessible files, modify writable data, and attempt to communicate over allowed connections. This does not mean automatic root compromise or control of an OT device; actual impact depends on process identity, host, and network segmentation.

The no-OpenShell scenario runs **the same fixed, deliberately malicious payload locally outside the sandbox**, but only against temporary synthetic files and a `127.0.0.1` listener. It does not touch real secrets, user configuration, SCADA/PLC, or external addresses. This demonstrates the impact of a vulnerable handler; it is not a MOVEit exploit or evidence of a vulnerability in any specific operator.

## Flow

```text
Sensor → signature verification → ingress policy → OpenShell sandbox → handler
                                  └ deny → quarantine + audit
Other sources ───────────────────────────────────────────────→ continue operating
```

## MVP scope

- `POST /sensor/{source}` accepts a standardized JSON event.
- Two demonstration sources: `sensor-a` and `sensor-b`; each maps to its own pre-created sandbox.
- The central ingress policy in `policies/defence-ingress.yaml` has `default_decision: deny` and defines HMAC secrets, sandbox, and allowed actions for each source.
- The HMAC signature is verified before authorization. An invalid signature is rejected, does not run the handler, and does not quarantine the authenticated source.
- For the MVP, both sources may request only `telemetry.read`. A disallowed action is rejected at ingress before invoking OpenShell, recorded in the audit, and quarantines the source.
- Optional Jev semantic gating runs only after signature verification and deterministic action authorization. For the allowed `telemetry.read` action, its System One `Choice` options are only `untrusted` and `read`; it cannot authorize an action or tier forbidden by the base policy. Low confidence or a classifier error fails closed as `untrusted`, which is denied before OpenShell and recorded without quarantining the source.
- The handler runs through the OpenShell Python SDK in the sandbox assigned to the source.
- The event contains `action`, `sensor_id`, `event_id`, and `vendor_document`. The parser demo deliberately uses vulnerable `yaml.unsafe_load`; never use it in a real system.
- A fixed YAML payload attempts to read a synthetic canary, send it to a local collector, and overwrite a synthetic setpoint file.
- OpenShell is the post-ingress containment layer: policy restricts files and egress, and the sandbox has a limit of 1 CPU and 256 MiB RAM.
- Quarantine and audit are stored in local SQLite (`var/defence.db`) and therefore survive process restarts. This is still a single local file, not a shared or highly available store.
- `POST /admin/sources/{source}/unquarantine` requires `DEFENCE_ADMIN_TOKEN` as a Bearer token and a recorded review reason; the operation is added to the audit.
- `/events` shows the audit, quarantine state, and counters for allowed, blocked, and compromised events.
- Jev is opt-in with `DEFENCE_JEV_ENABLED=1` and `BACKBOARD_API_KEY`. It is disabled by default so the existing exploit-containment experiment still reaches the intentionally vulnerable parser. Enable it to demonstrate semantic pre-sandbox blocking; disable it to demonstrate OpenShell post-ingress containment.

## Demo

### Highlight: Jev as the last resort

Start the API with Jev enabled and run the two-case showcase:

```shell
export DEFENCE_SENSOR_A_SECRET='demo-sensor-a'
export DEFENCE_JEV_ENABLED=1
uv run --env-file .env uvicorn defence.app.main:app --port 8001
```

In another terminal, with the same sensor secret:

```shell
export DEFENCE_SENSOR_A_SECRET='demo-sensor-a'
sh scripts/demo-defence-jev.sh
```

Both events have a valid HMAC and request the already-allowed `telemetry.read`. The benign YAML should be classified `read` and reach `def-sensor-a`. The second event asks, in ordinary language, for a credential to be included in a report. This text does not match the current deterministic ingress action rule; Jev can lower it to `untrusted`, in which case the API denies it before calling OpenShell. `/events` shows Jev's raw `classifier_choice`, its `classifier_confidence`, the effective `semantic_tier` after any low-confidence downgrade, and the `semantic_policy_denials` count without storing the vendor document.

Record both `classifier_choice` and `semantic_tier` when presenting the result: the former is Jev's selection; the latter may also reflect the low-confidence downgrade. This is a demonstration, not a guaranteed classification or a calibrated accuracy claim. Jev confidence is not a guarantee. If the result differs on the day, show the actual result.

**Live Jev observation (2026-10-04):** the benign fixture returned `read` at confidence `0.80`; the semantic-risk fixture returned `untrusted` at confidence `0.23`. Both were live classifier calls with synthetic data. Jev is probabilistic, so rerun the showcase and report the values actually returned that day.

**Then show the other boundary separately:** stop the API, unset `DEFENCE_JEV_ENABLED` (or set it to `0`), restart it, and run the fixed exploit comparison below. With Jev out of the path, the signed exploit reaches the allowed parser inside OpenShell, where filesystem and egress restrictions demonstrate containment. The two demonstrations distinguish semantic early rejection from runtime sandbox containment.

1. The local variant runs the same parser and payload outside OpenShell. It should read the synthetic canary, send its bytes to the local collector, and change the setpoint from `40` to `9999`.
2. The OpenShell variant sends the exploit as an allowed, correctly signed `telemetry.read`. The parser is compromised, but the sandbox policy is expected to block reads of protected files, egress, and the setpoint write.
3. The gateway reports containment and quarantines the source after detecting compromise. A disallowed action is still blocked earlier by ingress.
4. `sensor-b` has an independent sandbox and remains active.

## Completion criteria

- A disallowed action is blocked by ingress policy without invoking OpenShell.
- An allowed action is forwarded only to the sandbox assigned to that source.
- The sandbox demonstrates filesystem and egress restrictions after ingress allows the request.
- After an ingress denial, one source is quarantined while the other continues operating.
- Logs do not contain raw payloads or secrets.
- Tests cover a valid read, denial, quarantine, source isolation, and an invalid signature.

## Out of scope

Actual connection to SCADA, device control, operation in production infrastructure, a durable state database, multi-tenant configuration, and automatic creation of a sandbox for every source.

The project uses synthetic demonstration data only. Do not connect it to operational systems or submit real secrets.
The cautious mapping of the example to a water utility, IEC 62443, MITRE ATT&CK for ICS, and NIS2 is in [SCENARIO.md](SCENARIO.md); it is not a compliance claim.

## Running the local demo

Requirements: a working Docker-backed OpenShell gateway, Docker, and an environment with `uv`. Run `openshell` commands in a terminal compatible with your POC configuration.

From the repository root:

```shell
docker build -t reverseopenshell-runner:dev .
uv sync
sh scripts/create-defence-sandboxes.sh
export DEFENCE_SENSOR_A_SECRET='demo-sensor-a'
export DEFENCE_SENSOR_B_SECRET='demo-sensor-b'
export DEFENCE_ADMIN_TOKEN='local-demo-operator-token'
export OPENSHELL_GRPC_ENDPOINT='127.0.0.1:8080'
uv run uvicorn defence.app.main:app --port 8001
```

To enable the optional Jev gate, put `BACKBOARD_API_KEY` in `.env` and start with:

```shell
export DEFENCE_JEV_ENABLED=1
uv run --env-file .env uvicorn defence.app.main:app --port 8001
```

`DEFENCE_JEV_MIN_CONFIDENCE` defaults to `0.70`. A low-confidence result or classifier failure becomes `untrusted` and is denied before sandbox execution. The audit distinguishes Jev's raw `classifier_choice` from the effective `semantic_tier` after the confidence threshold. `/events` also records `classifier_confidence`; `semantic_policy_denials` counts semantic denials. No raw `vendor_document` or API key is written to the audit. Leave Jev disabled for the exploit-containment benchmark, because Jev may deny the malicious fixture before it reaches OpenShell.

The script creates two sandboxes before serving traffic; it does not create a new sandbox for every event. A sandbox created before an image/policy change does not update automatically. Use new names, or recreate old ones only after confirming that they contain no state you need.
The endpoint override is needed when the active gateway has address `host.docker.internal`, which works from containers but does not resolve on the macOS host.
The image sets `/workspace` as a working directory writable by UID 1000. Handler files in `/app` are explicitly readable by this UID, and policy treats that directory as read-only.

Sign the raw body using HMAC-SHA256 in the format `sha256=<hex>` and pass it in the `x-hook-signature` header. Example allowed read:

```shell
BODY='{"action":"telemetry.read","sensor_id":"A-01","event_id":"evt-001","vendor_document":"flow_lpm: 7.25\n"}'
SIG=$(printf %s "$BODY" | openssl dgst -sha256 -hmac "$DEFENCE_SENSOR_A_SECRET" -hex | awk '{print $2}')
curl -sS -X POST http://127.0.0.1:8001/sensor/sensor-a \
  -H 'content-type: application/json' -H "x-hook-signature: sha256=$SIG" \
  --data "$BODY"
```

## Exploit comparison

The baseline alone, without OpenShell and without a running API, can be run separately:

```shell
export DEMO_EXFIL_TOKEN='local-demo-collector-token'
uv run python scripts/compare-defence-exploit.py --baseline-only --trials 1
```

This command runs the deliberately vulnerable handler in a local Python process. The report should show `passed: true`, a successful synthetic canary read, 34 bytes at the loopback listener, and setpoint `9999`. Files are in a temporary directory removed after the test. The payload is fixed in code; do not provide it with other paths or addresses.

The full baseline–OpenShell comparison requires a local gateway and API. Start the API with the test collector token (after stopping any previous API process):

```shell
export DEMO_EXFIL_TOKEN='local-demo-collector-token'
export DEMO_EXFIL_URL='http://host.openshell.internal:9999/collect'
uv run uvicorn defence.app.main:app --port 8001
```

In a second terminal:

```shell
export DEFENCE_SENSOR_A_SECRET='demo-sensor-a'
export DEFENCE_SENSOR_B_SECRET='demo-sensor-b'
export DEFENCE_ADMIN_TOKEN='local-demo-operator-token'
export DEMO_EXFIL_TOKEN='local-demo-collector-token'
export OPENSHELL_GRPC_ENDPOINT='127.0.0.1:8080'
uv run python scripts/bench-defence.py --trials 20
```

The benchmark first unquarantines sensor A, runs 20 local baselines and 20 sandbox runs, then checks A's quarantine and a valid read from B. It prints a summary and saves per-trial JSON with metadata to a new file under `var/`. Sensor A remains quarantined after the test.

The baseline should demonstrate a canary read, bytes received by the local collector, and setpoint `9999`. For the sandbox, require blocked reads and writes and `collector_received_bytes: 0`. Check OpenShell logs to confirm the reason for egress denial; the absence of data at the collector alone does not prove it. Do not use real secrets or a remote collector.

### Saved local test result

The detailed trial log, previous results, and limitations are in [EXPERIMENTS.md](EXPERIMENTS.md). The latest saved run is D-08:

One run of 20 repetitions (2026-10-03):

| Measurement | Result |
|---|---:|
| Baseline: canary read / collector receive | 20/20 |
| Baseline: bytes delivered to collector | 680 |
| Baseline: setpoint after attack | `9999` |
| OpenShell: canary read blocked | 20/20 |
| OpenShell: setpoint write blocked | 20/20 |
| OpenShell: bytes delivered to collector | 0 |
| Baseline `handle()` p50 / p95 | 4.17 / 6.09 ms |
| Sandbox `session.exec()` p50 / p95 | 206.24 / 226.56 ms |

The sandbox log showed `NET:REFUSE [MED] DENIED host.openshell.internal [reason:policy_dns_ineligible]`, confirming policy-based egress denial. The `exfiltration_requests_blocked_by_openshell` counter was 0 because connections were rejected at the network level and did not return HTTP 403; the appropriate evidence is the OpenShell entries and 0 bytes at the local collector.

This is the result from one local environment and one synthetic payload. The timings are not a measurement of “pure sandbox overhead”: the baseline measures only the handler call, while `session.exec()` also includes SDK/gateway communication. Do not generalize these numbers to production.

Example disallowed ingress action:

```shell
BODY='{"action":"telemetry.write","sensor_id":"A-01","event_id":"evt-denied","vendor_document":"flow_lpm: 7.25\n"}'
SIG=$(printf %s "$BODY" | openssl dgst -sha256 -hmac "$DEFENCE_SENSOR_A_SECRET" -hex | awk '{print $2}')
curl -sS -X POST http://127.0.0.1:8001/sensor/sensor-a \
  -H 'content-type: application/json' -H "x-hook-signature: sha256=$SIG" \
  --data "$BODY"
```

Expected result for a disallowed action: HTTP 403, `source quarantined`, and no handler execution. After `sensor-a` is quarantined, verify that `sensor-b` still accepts signed `telemetry.read`. `/events` shows active and quarantined sources and the number of blocked ingress requests.

### Sensor independence test

After sensor A has been quarantined, send a correctly signed, benign read to sensor B. In the same terminal, set the secret used when starting the API:

```shell
export DEFENCE_SENSOR_B_SECRET='demo-sensor-b'
BODY='{"action":"telemetry.read","sensor_id":"B-01","event_id":"evt-b-normal","vendor_document":"flow_lpm: 7.25"}'
SIG=$(printf %s "$BODY" | openssl dgst -sha256 -hmac "$DEFENCE_SENSOR_B_SECRET" -hex | awk '{print $2}')
curl -sS -X POST http://127.0.0.1:8001/sensor/sensor-b \
  -H 'content-type: application/json' \
  -H "x-hook-signature: sha256=$SIG" \
  --data "$BODY"
```

Expect an HTTP 200 response with `status: accepted`. This tests routing and sandbox independence; it is not an exploit containment test.

After manually reviewing a source, it can be released. Use a strong local token instead of the example value:

```shell
curl -sS -X POST http://127.0.0.1:8001/admin/sources/sensor-a/unquarantine \
  -H "authorization: Bearer $DEFENCE_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  --data '{"reason":"Reviewed synthetic incident and rotated source key."}'
```

The demo has no identity provider or operator roles. Do not expose this endpoint outside a local test environment.
