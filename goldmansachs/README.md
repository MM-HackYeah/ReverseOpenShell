# Goldman Sachs AI Control Layer — MVP

## Problem and user

An AI agent can be tricked into using a dangerous tool, exposing data, or exceeding its budget. Users include development teams integrating agents and security teams monitoring their behavior.

## MVP scope

- One demonstration agent using a local model or deterministic mock.
- A proxy that intercepts every tool call and response.
- Central YAML configuration with an allowlist of tools, block/redact rules, and call and budget limits.
- Deterministic controls: schema validation, tool and endpoint allowlists, and detection of a sample secret.
- One isolated runner for a risky action, such as processing a file in a prepared directory.
- Audit and a simple dashboard: allowed, blocked, and redacted interactions, reasons for decisions, and limit usage.
- An automated positive and negative test suite.
- Policy reload at runtime.

Semantic control can be added as an optional feature, but it should not be the only security barrier. A free local model or mock avoids dependence on a paid API.

## Demonstration scenario

1. The agent uses an allowed tool, such as searching for information in a demo directory.
2. A malicious instruction in the input attempts to persuade the agent to read a secret or send data to a disallowed host.
3. The Policy Engine rejects the disallowed tool or redacts the secret; the runner restricts the process's file and network access.
4. The dashboard shows the decision, rule, audit event, and budget-limit status.
5. Change the configuration, for example by blocking a previously allowed tool, and show the effect on the next request.

## Minimal test suite

- Allowed tool and valid input → execution.
- Unknown tool → blocked.
- Secret in data → redacted or blocked according to policy.
- Call/budget limit exceeded → blocked.
- Runner attempts to access a disallowed file or host → access denied and audit entry recorded.
- Configuration change → new decision without restart, if that mode is implemented.

## Completion criteria

- The full flow from prompt to controlled tool call works.
- Policies are centralized, visible, and changeable.
- Tests include positive and negative cases.
- Dashboard/logs show the decision and its rationale.
- Budget or resource limits are actually enforced, not merely displayed.
- The whole system can run without paid services.

## Out of scope

Full compatibility with every agent framework, protection against all prompt injection, a production multi-tenant service, automatic signature acquisition from multiple sources, and an elaborate key-management system.

## Presentation

Show a working allowed flow, an attempted unsafe call, a block or redaction, an audit entry, budget usage, and changed behavior after editing the policy. Prepare tests for evaluators to run and describe the prototype's limitations.
