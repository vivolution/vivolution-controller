# Discovery Plan

No POC starts automatically. Jay must approve progression after Stage 0.

## Stage 0 — Feasibility and business case

1. Confirm Microsoft's current hosting topology and exact customer onboarding requirements.
2. Define the Open Edge acceptance criteria. Use OpenSIPS 3.6 LTS as the working POC choice, retain Kamailio as fallback, and run only bounded existing-platform checks after approval.
3. Obtain comparable commercial and technical information for at least three certified SBC platforms.
4. Obtain written UAE legal/regulatory advice for PBX relay, direct BYOC, operator-partner, and resale models.
5. Validate the architecture, provider-of-record boundary, emergency/CLI duties, and SIP-trunk terms with candidate UAE licensed carriers.
6. Build five-year unit economics across customer count and concurrent-session scenarios.
7. Define the minimum product, support boundary, SLA, security baseline, and customer responsibility matrix.

### Stage 0 exit criteria

- A credible Open Edge data plane and a certified fallback path are identified.
- The Open Edge protocol/test matrix and explicit unsupported-service boundary are documented.
- Two-node UAE HA is commercially plausible.
- Multi-tenancy and delegation are contractually permitted.
- The BYOC model has a defensible regulatory and carrier path.
- Gross margin remains viable under conservative utilization.
- Tenant isolation and failure-containment controls are testable.

## Stage 1 — Internal single-tenant lab

Only after approval: validate basic Teams Direct Routing, PBX interoperability, security, monitoring, and rollback without external customers. Use Jay's Azure credit and synthetic/non-PSTN calls unless written operator and regulatory approval permits live PSTN traffic.

## Stage 2 — Two-tenant isolation lab

Use one Vivolution/provider Microsoft 365 tenant plus two separate customer tenants and their derived FQDNs. Validate no cross-tenant routing, data, administration, CDR, or failure leakage. A provider-plus-one-customer lab is only a partial proof.

## Stage 3 — Controlled friendly-customer pilot

Only after written regulatory/carrier clearance and successful internal testing. Start with one or two BYOC customers and a deliberately narrow supported configuration.

## Future test matrix

- Inbound/outbound calling and CLI.
- DTMF, hold, transfer, voicemail, auto attendants, and call queues.
- Teams endpoint, SBC node, carrier, and network failure.
- Codec negotiation, NAT, media bypass on/off, packet loss, jitter, and MOS.
- Tenant classification, overlapping number ranges, and cross-tenant negative tests.
- Quotas, rate limits, fraud controls, CDR isolation, and audit trails.
- Certificate rotation, upgrades, backup/restore, drain, and rollback.
- Emergency-calling behavior and failure modes where legally applicable.
