# CDR and Retention Model

Status: Product design hypothesis, not legal advice.

## Product objective

Provide each tenant with accurate, exportable call records and sufficient evidence for billing, troubleshooting, fraud investigation, customer policy, and applicable compliance duties.

## Data classes

- CDR: caller/callee, timestamps, duration, direction, tenant, route, disposition, correlation ID, and quality summary.
- Operational telemetry: node, trunk, options health, counters, alarms, configuration version, and failover events.
- SIP trace: headers and signaling ladder captured only for controlled troubleshooting.
- Media: RTP/audio should not be recorded or retained by default.

## Retention principle

“Years and years” should be an available governed policy, not an indefinite default. Caller/callee numbers, identities, IP addresses, routes, and timestamps are personal or sensitive business data. Longer retention increases security, privacy, discovery, and breach exposure.

Offer explicit customer-selected retention tiers after legal validation, for example:

- Operational CDR: 12 months.
- Extended compliance CDR: 3, 5, or 7 years.
- SIP traces: short-lived, incident-scoped retention such as 7–30 days.
- Legal hold: separate, authorized, immutable hold that suspends normal deletion.

Exact periods must be mapped to customer sector, carrier contract, legal basis, and UAE requirements; no universal period is assumed.

## Controls

- Customer is normally controller for its tenant CDRs; Vivolution acts as processor under a DPA. Vivolution may separately control limited billing/security telemetry.
- UAE-region primary storage where practical, encryption in transit and at rest, tenant RBAC, MFA, audit, and scoped support access.
- Tenant partitioning and export must be tested against cross-tenant leakage.
- Immutable storage for approved compliance archives, with separate keys and retention locks.
- Automated expiry, deletion/anonymization, end-of-service export, legal-hold workflow, and evidence of deletion.
- No raw SIP credentials in traces; redact authentication, identity, and sensitive headers where possible.
- Document subprocessors, backup locations, cross-border support access, breach handling, and lawful-request procedures.

CDR retention does not by itself satisfy lawful-interception, emergency-service, or carrier compliance obligations.
