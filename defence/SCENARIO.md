# Demonstration Scenario: Water Utility

## Assumed flow

The operator of a water utility receives telemetry reports from an external vendor. The vendor adapter parses a YAML document, and the result may be consumed by an internal telemetry process. An attacker sends a correctly signed `telemetry.read` request with a document that exploits the deliberately vulnerable parser.

The demo uses only a fictitious `sensor-a` source, the text `SYNTHETIC-CANARY-NOT-A-REAL-SECRET`, a local collector, and a JSON file that represents a flow setpoint. It does not connect to a PLC, SCADA, OT network, or real water utility system.

## IEC 62443 reference

This is an architectural sketch using the concepts of zones and conduits, not a compliance assessment or a target design.

| Demonstration element | Example role in zone model | Meaning of the control |
|---|---|---|
| Webhook and HMAC verification | DMZ/edge zone receiving external data | Source authentication does not mean the document contents are trusted |
| Vendor YAML parser in OpenShell | Isolated intermediate workload, not a control zone | Limits the effects of compromise to the process and its explicitly available resources |
| Synthetic setpoint file | Mock resource in a protected process zone | Policy should block access; the demo contains no actual OT resource |
| Local collector | Mock unauthorized outbound channel | Egress should be denied; check the OpenShell policy event |
| Separate sandbox per source | Isolation boundary between workloads | An incident affecting source A should not interrupt source B |

IEC 62443-3-2 describes defining the system under consideration, dividing it into zones and conduits, and assessing risk. A sandbox or this table alone does not establish OT zones, a Security Level, or compliance with the IEC 62443 series. In a real deployment, the operator would need to identify assets, dependencies, channels, and security requirements for the specific system.

## MITRE ATT&CK for ICS reference

- **T0836, Modify Parameter:** the demonstration payload attempts to change a value in a JSON file representing a setpoint. This conceptually corresponds to an attempted parameter modification, but does not modify an industrial device parameter.
- **T0831, Manipulation of Control:** this would be relevant only if access to control could affect the physical process. The demo takes no such action and does not demonstrate protection against process manipulation.
- The scenario also demonstrates the risk of code execution by a parser processing untrusted input; it does not map this to a specific ICS technique without evidence that the technique fits a real attack path.

## NIS2, Article 21 reference

The demo illustrates a limited set of topics from Article 21 risk-management measures: incident handling, supply-chain security, access control, and business continuity. HMAC identifies the source, the ingress allowlist limits the permitted action, the sandbox limits the impact of a parser flaw, and quarantine of one source is intended to leave the other active.

This is not an organizational risk assessment, implementation of all required measures, certification, or legal opinion. The scope of obligations depends on the entity, sector, national implementation of the directive, and operational context. The local operator token and SQLite file are demonstration mechanisms only, not equivalents of identity management, high availability, or an organizational response process.

## Sources

- [IEC 62443-3-2:2020, official IEC catalogue](https://webstore.iec.ch/en/publication/30727)
- [MITRE ATT&CK for ICS: T0836 Modify Parameter](https://attack.mitre.org/techniques/T0836/)
- [MITRE ATT&CK for ICS: T0831 Manipulation of Control](https://attack.mitre.org/techniques/T0831/)
- [Directive (EU) 2022/2555 (NIS2), EUR-Lex](https://eur-lex.europa.eu/eli/dir/2022/2555/oj/eng)
