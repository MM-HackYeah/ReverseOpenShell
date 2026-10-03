# Implementation Plan — Defence

## MVP goal

Demonstrate ingress authorization before handler execution: policy explicitly allows actions for signed sources, blocks a disallowed request before it reaches the sandbox, quarantines the source, and allows other sources to continue delivering synthetic readings.

## Stages

### 1. Finalize scope and scenario

- `POST /sensor/{source}` endpoint for two demonstration sources.
- One type of JSON telemetry event and one controlled handler.
- Valid case, signature failure, and correctly signed request for an action outside the ingress allowlist.
- Explicitly state that the prototype reduces risk but is not a certified sandbox or complete exploit protection.

**Exit criterion:** the `sensor-a` → ingress deny → quarantine scenario, while `sensor-b` continues operating, is documented as a test.

### 2. Define the shared core interface

- Adopt the shared request, decision (`allow`, `deny`, `redact`), and audit-entry model described in `common/README.md`.
- Ingress policy is a versioned YAML file with a default `deny` decision, source list, env secret, sandbox, and allowed actions.
- The handler receives only validated data required to handle the event.

**Exit criterion:** the sample Defence policy passes validation, and invalid configuration stops application startup.

### 3. Implement the Defence gateway

- Accept an event and generate a correlation ID.
- Limit request size and validate fields and numeric values.
- Verify the source-specific HMAC signature.
- Authorize `action` against the central ingress policy **before** invoking OpenShell.
- Do not execute or quarantine a source for an invalid signature; for a valid signature and forbidden action, return 403 and record the denial.
- Map each source to a fixed sandbox, with no client ability to choose a sandbox.
- Reject unknown, unsigned, and quarantined sources before handler execution.

**Exit criterion:** a request cannot change the sandbox through its payload or reach the runner without an allowed action.

### 4. Add sandboxes and a controlled abuse attempt

- Prepare a separate OpenShell sandbox for each source (created before the demo, not per request).
- Each policy has a read-only filesystem, minimal `/tmp` access, `landlock.compatibility: hard_requirement`, and no egress by default.
- Do not expose a client switch that simulates an attack or unauthorized egress as an example of ingress denial.
- After ingress denial, mark the source quarantined in SQLite; other sources retain their own state and sandbox.

**Exit criterion:** a test confirms that a forbidden action does not invoke the sandbox, that the source rejects subsequent requests, and that the other source continues working.

### 5. Audit, presentation, and tests

- Record correlation ID, source, decision, trust level, reason, time, and quarantine state; do not record the body or keys.
- Provide an `/events` endpoint with audit data and source state.
- Add tests for valid reads, invalid signatures, ingress denial before the runner, quarantine, and source independence.
- Prepare a comparison script: the same synthetic exploit outside the sandbox and inside it; additionally, a signed attack through ingress causes quarantine.

**Completion criterion:** the demo runs repeatably from a clean start, tests pass, and every decision is explainable in the log.

## Work sequence

First complete the gateway → HMAC verification → ingress policy → handler in its assigned sandbox → audit flow. Then demonstrate that ingress denial ends the request before sandbox invocation and that the other source continues working. A JSON `/events` endpoint is sufficient; no graphical dashboard is needed.

## Risks and limitations

- Every sandbox uses the same compute driver/gateway as the existing POC; names and workspace are configurable.
- Quarantine and audit are stored in local SQLite; this is a single local store without HA.
- Exploit comparison uses one fixed synthetic YAML payload, a temporary canary, a local collector, and a mock setpoint. It does not connect to real systems.
- Ingress denial should be visible in the application audit; do not present it as an OpenShell `DENIED` event.
- OpenShell is a second containment layer for the allowed handler, not the source of ingress decisions.
- The container shares the kernel; do not claim protection against every kernel exploit.

## Next step

Remaining work after the MVP: run the benchmark against a working OpenShell, expand tests to multiple distinct safe cases, and replace the local operator token with proper identity/approval in the target integration. Water utility/IEC 62443/MITRE/NIS2 are mapped conceptually in `SCENARIO.md`, not as a compliance claim. The POC at `/Users/marcinbodych/Workspace/HackYeah2026/OpenShell` is the source of truth for commands and runtime behavior.
