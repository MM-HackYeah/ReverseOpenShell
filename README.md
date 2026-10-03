# ReverseOpenShell

Minimal MVP for the **Goldman Sachs AI Control Layer** challenge. The project accepts webhooks from external integrations, assigns them a maximum trust level, optionally lowers it based on local LLM classification, and then runs the request in an existing OpenShell sandbox.

## Scope

- Three pre-created sandboxes: `untrusted`, `readonly`, `write`.
- FastAPI gateway: `POST /hook/{source}`.
- Classification cannot raise trust above the configured source limit.
- Source HMAC signature; a missing or invalid secret means `untrusted`.
- Isolated execution through `openshell sandbox exec`, a JSONL audit log, and an endpoint for reading it.
- Optional classification through local Ollama. Deterministic rules work without a model; classifier errors lower the level to `untrusted`.

## Running

Requirements: Python 3.11+, `uv`, Docker, and a configured local OpenShell gateway. From the repository directory:

```shell
docker build -t reverseopenshell-runner:dev .
uv sync
sh scripts/create-sandboxes.sh
export DEMO_READONLY_SECRET='local-demo-readonly'
export PARTNER_WRITE_SECRET='local-demo-write'
uv run uvicorn goldmansachs.app.main:app --reload
```

The secrets above are example values for a local demo only. Do not use them elsewhere.

Send a signed, allowed request:

```shell
BODY='{"url":"https://api.github.com/zen","method":"GET"}'
SIGNATURE=$(printf %s "$BODY" | openssl dgst -sha256 -hmac "$DEMO_READONLY_SECRET" -hex | awk '{print $2}')
curl -sS -X POST http://127.0.0.1:8000/hook/demo-readonly \
  -H "content-type: application/json" \
  -H "x-hook-signature: sha256=$SIGNATURE" \
  --data "$BODY"
```

Check `/docs`, `/health`, and `/events`. Set `OLLAMA_MODEL` (and optionally `OLLAMA_URL`) to enable semantic classification through local Ollama. The Python SDK connects to the active gateway selected by the OpenShell CLI.

## Security and limitations

OpenShell enforces filesystem and network restrictions inside the sandbox; the gateway does not treat LLM classification alone as access control. The demo does not accept arbitrary code from a request and does not expose external keys. The `write` sandbox permits only `POST` to the example endpoint `postman-echo.com/post`, without secrets. Integration with the OpenShell credential provider is not part of this minimal MVP.

Production use would require, among other things, source authentication with proper secret management, durable auditing, rate limiting, replay protection, secure sandbox management, and operational threat validation.

## Defence — ingress policy and post-ingress containment

Separate Defence flow demonstrates two distinct controls: `policies/defence-ingress.yaml` authorizes signed inbound actions before the request reaches OpenShell, then OpenShell confines the deliberately vulnerable YAML parser after an allowed request enters its sandbox. The synthetic exploit compares an unconfined baseline with the sandbox for access to a canary file, egress to a local-only collector, and a write to a synthetic setpoint. A parser compromise triggers source quarantine.

The parser intentionally uses `yaml.unsafe_load` and is exploit-vulnerable by design. Never deploy it or connect the demo to real infrastructure. Run the repeatable local benchmark with `uv run python scripts/bench-defence.py --trials 20`; it saves per-trial JSON under ignored `var/`. [`defence/EXPERIMENTS.md`](defence/EXPERIMENTS.md) records experiments and limits, and [`defence/README.md`](defence/README.md) has setup instructions and one measured run. SQLite persists audit/quarantine state; the local operator-token endpoint records unquarantine reasons. [`defence/SCENARIO.md`](defence/SCENARIO.md) gives conceptual standards mappings, not a compliance assessment.

See [`defence/README.md`](defence/README.md) for setup, comparison, and limitations.
