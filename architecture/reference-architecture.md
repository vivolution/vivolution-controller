# Reference Architecture

Status: Certified Edge reference option; not the current Open Edge POC baseline and not approved for implementation.

## Recommended topology

```text
Customer Microsoft 365 tenants
  -> customer-specific derived trunk FQDNs
  -> two Microsoft-certified multi-tenant SBC nodes in separate UAE failure domains
  -> isolated per-customer routing contexts
  -> customer SIP carrier, on-premises PBX/contact centre, or both
```

This document remains the certified-product alternative. The working low-cost POC is documented in [Open-source reference path](open-source-reference.md), with the same Enhanced/Dedicated isolation and provider-neutral control-plane model.

Example Teams identities for Customer A:

- `customer-a.sbc1.voice.vivolution.ae`
- `customer-a.sbc2.voice.vivolution.ae`

The two FQDNs represent two distinct SBCs and public IP addresses. Both belong in the customer's Teams voice routes. DNS round-robin behind one SBC FQDN is not the recommended Direct Routing HA mechanism.

## Microsoft-facing edge

- Use only a Microsoft-certified SBC product and certified firmware supported by its vendor for the hosting model.
- Register provider-owned base domains in the Vivolution service tenant.
- Register and activate a unique derived subdomain in each customer tenant.
- Present the customer-derived FQDN in the SIP Contact header so Teams maps the call to the correct tenant.
- Use public trusted certificates, TLS 1.2, SRTP, and the required Microsoft SIP/media endpoints.
- Treat the carrier trunk as shared infrastructure with strict change and drain controls because its state can affect every derived customer trunk.

## Per-tenant isolation boundary

Each customer requires an independently testable boundary for:

- Teams trunk identity and Contact-header classification.
- Southbound carrier, PBX, and contact-centre trunks.
- Dial plan, normalization, routing, CLI, codec, DTMF, and media rules.
- Concurrent-session and calls-per-second limits.
- Fraud limits, destinations, time policies, and alert thresholds.
- CDRs, quality metrics, SIP traces, dashboards, and exports.
- RBAC, audit history, configuration backups, and secrets.

Customer portal access should expose safe intent-level controls, not the unrestricted shared SBC administration plane.

## Control plane

The product value sits largely above the SBC. A Vivolution control plane could provide:

- Customer and tenant lifecycle.
- Guided Microsoft 365 domain/FQDN onboarding.
- DNS and certificate workflow.
- SIP-trunk and PBX-leg templates.
- Number inventory and routing-policy management.
- Capacity, CDR, quality, alert, and SLA dashboards.
- Change approval, audit, rollback, and billing data.

Prefer customer-run onboarding scripts or time-bound least-privilege delegated access. Do not retain customer Global Administrator credentials.

## High availability and operations

- Place SBC nodes in separate UAE failure domains with independent public IPs and power/network paths.
- Use both customer-derived FQDNs in each tenant's voice routes.
- Monitor SIP OPTIONS, TLS/certificate health, carrier trunks, concurrent sessions, call failures, post-dial delay, packet loss, jitter, and MOS.
- Use synthetic inbound/outbound test calls and documented failover exercises.
- Protect signaling and media with ACLs, topology hiding, SIP-flood controls, rate limits, and fraud detection.
- Define maintenance, drain, backup, restore, certificate-rotation, and rollback procedures before production.

## Optional open-source service layer

Kamailio, OpenSIPS, RTPengine, FreeSWITCH, Asterisk, or similar components may be useful behind the certified edge for routing, orchestration, media services, or analytics. They should not be the production Teams-facing SBC unless the exact product and firmware is on Microsoft's certified list. Add this layer only when it provides measurable value; otherwise it increases support and failure complexity.
