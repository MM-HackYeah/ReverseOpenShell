# Shared MVP Core

## Goal

A shared layer for policy enforcement and containment of dangerous input. This core supports two scenarios: protecting a webhook handler (Defence) and controlling tool calls by an AI agent (Goldman Sachs).

## Demonstration scope

```text
Client → Gateway → Policy Engine → Isolated Runner → Result
                            └────→ Audit Log / Metrics
```

The MVP should include:

1. An HTTP gateway that accepts requests and assigns them a correlation ID.
2. A Policy Engine that reads YAML configuration and returns an `allow`, `deny`, or `redact` decision.
3. An Isolated Runner that runs a selected handler with restricted permissions.
4. An Audit Log recording the decision, reason, rule name, time, and execution result.
5. A simple interface or endpoints for viewing events and metrics.
6. Automated tests for allowed and blocked cases.

## Minimal policy model

```yaml
version: 1
default_action: deny
limits:
  request_bytes: 65536
  execution_seconds: 3
  memory_mb: 128
network:
  default: deny
  allow:
    - api.example.test
rules:
  - id: allow-demo-handler
    action: allow
    target: demo-handler
  - id: redact-demo-secret
    action: redact
    match: "DEMO_SECRET"
```

This is a sample configuration for demonstration, not a production-ready format. The behavior of `default_action` and rule precedence must be unambiguous and tested.

## MVP boundaries

- One gateway and one demonstration handler/agent.
- An explicitly defined set of functions; no promise of complete exploit protection.
- No assumption that AI semantic controls are reliable. Security decisions in the demo should be reproducible through tests.
- No elaborate multi-tenant system, production key management, or high availability.

## Completion criteria

- The whole system can be started with one documented command or set of commands.
- A policy change affects subsequent requests without rebuilding components.
- A disallowed request does not reach the handler.
- The runner cannot access host secrets or unapproved networks.
- Every decision has an audit entry with a reason.
- Tests cover at least one `allow`, `deny`, and `redact` case each.

## Demonstration

First show an allowed request, then a request that violates policy, and finally the audit entries and metrics. Do not present mocked events as the result of actual enforcement.
