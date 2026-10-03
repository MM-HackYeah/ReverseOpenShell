# HackYeah 2026 — Goldman Sachs: AI Control Layer

## Challenge description

Build a lightweight and flexible control layer for agentic AI systems: agents, MCP services, language models, and APIs. The solution should help organizations protect data, enforce safeguards, manage API budgets, and block attacks without excessively slowing developer workflows.

AI agents may gain unauthorized access to resources, impersonate other actors, perform irreversible actions, fall victim to prompt injection, expose sensitive data, or consume excessive resources in autonomous loops. The challenge calls for real-time interaction control through a flexible intermediary that combines deterministic rules with AI-based semantic controls.

## Expected outcome

1. **AI Control Layer** — a working gateway, proxy, middleware, SDK wrapper, or equivalent component that can be inserted into application–agent, agent–agent, agent–MCP, or agent–model communication.
2. **Sample configuration** — a documented policy file showing configurable strictness levels, budget rules, and control settings.
3. **Interactive dashboard** — a view of controls, overall security posture, blocked threats, and metrics such as resource consumption or cost.
4. **Runnable test suite** — automated positive (allowed) and negative (blocked or redacted) cases, including budget limits and exploit mitigation.
5. **Architecture diagram** and demonstration of the layer in operation.

You may build your own agent or use an existing one. The control layer is the primary focus of evaluation.

## Functional requirements

### Central policy engine

A single source of configuration should manage controls, sensitivity thresholds, block/redact behavior, allowed LLM models, and resource and cost limits.

### Deterministic and semantic controls

- **Deterministic:** for example, pattern matching for personal data and secrets, authentication checks, and access permissions.
- **Semantic:** where appropriate, use a model or another AI control to assess the meaning of an interaction.

### Budgets and resources

The layer should support enforcing limits such as commercial API spend, tokens, compute time, and resource access.

### Mitigation of known attacks

Consider detecting or mitigating known exploit patterns in AI infrastructure, such as malicious code execution, unsafe deserialization, and model supply-chain attacks. Signatures may come from an externally managed source.

### Reporting and audit

The solution should expose live metrics, such as blocked interactions and budget usage, as well as exportable audit logs useful to security teams.

### Self-testing

An automated test suite should check both valid, allowed behavior and cases that should be blocked or redacted.

## Evaluation validation

Judges will run the provided test suite and may submit previously unseen prompts to the system in real time. They may also change the configuration or signature sources to see how the layer responds to rule changes, removal of a control, or changed thresholds. Be prepared to show performance telemetry, architecture, dashboard, and logs.

## Technology and available resources

The stack is unrestricted, including Go, Rust, or Python; existing open-source tools may also be used, subject to their licenses. Existing components may be used for agents, models, and applications.

The challenge does not provide ready-made datasets, paid APIs, or specialized hardware. Design a solution that can run in your own environment, for example with a local model, and prepare your own test prompts. The organizers do not provide subscriptions to paid services such as OpenAI, Anthropic, or Copilot.

## Evaluation criteria

- Solution resilience and security quality — 30%
- Architecture and performance — 20%
- Security reporting — 20%
- Completeness of the self-testing suite — 20% according to the rules
- Practical deployability and scalability — 10% according to the rules

**Note:** the challenge description assigns 15% and 15% to the final two criteria, respectively, while the competition rules assign 20% and 10%. Both versions total 100%; check which version applies before submitting.

## Submission

The rules call for a project title, team name and members, description, and a PDF presentation of up to 10 slides. You may include screenshots, a code repository, a demo, and other materials. Individual or team participation is allowed, with up to 6 people.
