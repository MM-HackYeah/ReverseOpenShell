# Implementation Plan — Goldman Sachs AI Control Layer

## MVP goal

Demonstrate an intermediary layer that controls agent tool calls, enforces central policies, limits resources, and provides testable reporting. The isolated runner and audit should use the shared core; the agent and budget scope is specific to this challenge.

## Shared core dependency

This plan assumes a working contract for policies, decisions (`allow`, `deny`, `redact`), isolated execution, and audit from `common/README.md`, as well as the Defence vertical slice described in `defence/PLAN.md`. Do not wait for an elaborate Defence product: a stable interface and contract tests are sufficient.

## Stages

### 1. Define the minimal agent flow

- One demonstration agent and two tools: one safe (e.g. search a demo directory) and one privileged, requiring an explicit rule.
- The agent and tools run locally or are deterministically mocked; no paid API is required.
- Every tool call passes through the Control Layer, with no direct agent access to the tool.

**Exit criterion:** the architecture shows that there is no path around the policy engine.

### 2. Extend the policy model

- Define rules for tool names, parameters, allowed models, and network endpoints.
- Add call limits and a simple cost/token limit or demonstration units.
- Introduce `allow`, `deny`, and `redact` behavior and a safe default decision.
- Handle invalid configuration and policy changes at runtime.

**Exit criterion:** tests demonstrate that a policy change alters decisions for subsequent calls.

### 3. Integrate the agent and tool controls

- Intercept a tool request before execution.
- Validate schema and parameters, apply allowlists, and detect the demonstration secret.
- Run approved actions through the shared runner, with restricted file and network access.
- Return a controlled result or safe denial message to the agent.

**Exit criterion:** the agent can use an allowed tool but cannot bypass a block by changing prompt content.

### 4. Add budget, audit, and dashboard

- Enforce a call counter and resource/cost limit, rather than merely displaying their values.
- Record the demonstration user/actor, tool, decision, reason, time, result, and limit usage.
- Show recent interactions, blocked attempts, limit usage, and policy status in a simple dashboard.
- Do not log secrets in plaintext; redact sensitive values.

**Exit criterion:** exceeding a limit blocks the next action and is visible in the audit.

### 5. Prepare self-contained runnable tests

- Allowed tool with valid parameters.
- Unknown or blocked tool.
- Secret in input or output: redact or block according to configuration.
- Exceeded budget/counter.
- Runner attempt to access a disallowed file or host.
- Policy change while running.

**Completion criterion:** the test suite runs with one documented command, includes positive and negative cases, and requires no paid API.

### 6. Evaluation and demo rehearsal

- Run tests before the presentation and prepare a resettable demo state.
- Show a legitimate call, prompt injection or abuse attempt, block/redaction, audit event, and limit enforcement.
- Change configuration while running and repeat the call.
- Prepare a short statement on limitations, performance, and behavior when the model or tool fails.

## Completion criteria

- Central configuration manages policies and limits.
- Every tool call passes through the control layer.
- Deterministic controls are available, as well as at least one demonstrated semantic mechanism if it can run locally and reliably.
- Budgets and execution constraints are enforced.
- Dashboard/logs present events for security teams.
- Automated positive and negative tests pass.

## Risks and limitations

- AI semantic control is probabilistic; it cannot be the only block.
- The agent framework should not be the project; the control layer is what is evaluated.
- Demo cost/tokens may be simulated units, but must be clearly labeled as such.
- The detailed challenge description and rules give different weights for the final two criteria. Confirm the applicable distribution with the organizer.

## Sequence relative to Defence

Start after shared interfaces and the isolated-execution demonstration in Defence are stable. Reuse the runner, policy decisions, and audit, but do not try to turn the entire Defence solution into an agent platform before a working prototype exists.
