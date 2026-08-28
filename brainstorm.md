# Vivolution SBC — Brainstorm

## Problem statement

UAE customers that want Teams telephony may have limited practical access to Microsoft Calling Plans or Operator Connect and may therefore depend on Teams Direct Routing. Customer-by-customer certified SBC deployments can be costly and operationally heavy.

## Product idea

Provide a managed, UAE-hosted SBC-as-a-Service platform in which multiple customer Microsoft 365 tenants share a resilient Open Edge or Certified Edge service. Each customer receives isolated Teams and southbound SIP connectivity, routing policy, capacity limits, records, monitoring, and delegated access.

The Hosted Exchange analogy is directionally useful: shared infrastructure, isolated tenants, quotas, delegated administration, reporting, and recurring billing. Voice adds harder constraints, however: real-time availability, fraud exposure, carrier interconnection, emergency calling, CLI integrity, call-quality accountability, and a larger shared failure radius.

## Jay's reference customer scenario

Customer A already owns an on-premises PBX and a du/e& SIP trunk. The customer wants Teams Enterprise Voice but cannot justify a dedicated certified SBC or specialist operational skills. Vivolution supplies a managed cloud edge and portal while the customer retains its existing carrier, numbers, PBX, and Teams tenant.

This should be the first design target because it solves a real cost/skills problem without requiring Vivolution to sell PSTN service.

## Southbound connection modes

1. **PBX relay mode — preferred first boundary**  
   Teams connects to Vivolution SBC; Vivolution connects over TLS/VPN to the customer's on-premises PBX; the PBX retains the existing du/e& trunk. This causes the least change to the carrier relationship.
2. **Direct BYOC mode**  
   The customer-owned carrier trunk terminates directly on Vivolution SBC in Azure. This is operationally cleaner but requires the carrier to approve Azure IPs, hosted termination, and the third-party service model.
3. **Hybrid mode**  
   Use the on-premises PBX for local survivability, analogue devices, or carrier anchoring while routing selected workloads through Teams and the hosted platform.

## Customer onboarding experience

1. Create the tenant and choose Open Edge or Certified Edge.
2. Allocate immutable tenant ID, two customer-derived SBC FQDNs, capacity, retention, and policy.
3. Generate Microsoft 365 domain-verification instructions and a customer-run Teams PowerShell configuration package.
4. Configure the customer's PBX or approved carrier leg, number ranges, normalization, CLI, codecs, CPS, and session limits.
5. Run automated validation and test calls before activation.
6. Expose health, capacity, CDRs, quality, changes, and audit events through the customer portal.

## Central question

Can Vivolution reduce per-customer cost through pooled real-time infrastructure and automation while offering an honest Open/Certified support choice and respecting telecom regulation, security, and tenant-isolation boundaries?

## Discovery principles

- Treat open-source Direct Routing as technically feasible and worth testing.
- Never market the open-source edge as Microsoft-certified or promise Microsoft/vendor escalation for it.
- Keep a certified-edge path available for customers whose procurement or support requirements demand it.
- Keep the managed-SBC layer distinct from regulated PSTN/carrier resale until UAE requirements are confirmed.
- Prefer a bring-your-own-carrier model for the first commercial version.
- Prove tenant isolation, operational supportability, and failure containment before optimizing cost.

## Recommended product layers

1. **Pluggable voice data plane** — two Open Edge or Certified Edge nodes, hosted in separate UAE failure domains.
2. **Tenant isolation** — a distinct routing realm/context, FQDN identity, trunks, policies, quotas, CDR view, and audit boundary for every customer.
3. **Control plane** — onboarding, DNS/certificate workflow, trunk configuration, number inventory, routing policies, capacity, monitoring, billing, and audit.
4. **Operations service** — 24/7 health monitoring, certificate lifecycle, change control, incident ownership, call-quality troubleshooting, backup, and recovery testing.
5. **Carrier boundary** — customer-owned SIP/PSTN service for the first version; a licensed-carrier bundle only after legal and commercial validation.

## Candidate customer profiles

- UAE organizations that want Teams Phone while retaining an existing e&/du or other supported enterprise voice arrangement.
- Customers replacing or integrating an on-premises PBX, contact centre, analogue devices, or branch telephony.
- Microsoft 365 customers too small to justify their own redundant certified SBC deployment.
- Multi-site organizations needing central routing, policy, monitoring, and local UAE support.

## Potential differentiation

- UAE-hosted, locally supported Direct Routing infrastructure.
- Predictable subscription rather than customer-owned SBC capital and specialist operations.
- Fast, repeatable tenant onboarding with documented rollback.
- Carrier-neutral and PBX-neutral integration where commercial agreements permit it.
- Per-tenant dashboards for capacity, CDRs, quality, alerts, and audit evidence.
- Strong security and fraud controls as part of the managed service rather than optional consulting.

## Important non-goals for version 1

- Calling an open-source Direct Routing edge Microsoft-certified or Microsoft-supported.
- Acting as an unlicensed public voice provider or selling PSTN minutes independently.
- Giving customers unrestricted low-level SBC access that could affect other tenants.
- Storing reusable customer Global Administrator credentials.
- Promising emergency-calling, number portability, or carrier features before written validation.

## Open questions

- Which certified SBC products permit supported multi-tenant hosting and delegated administration?
- Does each customer require a unique FQDN, certificate identity, public IP, or SBC instance?
- What are the vendor licensing units: sessions, tenants, nodes, features, or throughput?
- Can Vivolution legally provide only the managed SBC layer without becoming a voice-service reseller?
- Which UAE carriers will provide supported enterprise SIP trunks for this model?
- What emergency calling, CLI, lawful-intercept, data-retention, and local-hosting obligations apply?
- What is the smallest provider-plus-two-customer lab that proves derived-trunk behavior and hard isolation?
- Does a certified vendor support safe customer delegation through RBAC or an API without exposing the shared platform?
- Which workloads truly need a separate SIP routing/media layer behind the certified SBC?
- What minimum recurring revenue and session utilization make a redundant platform profitable?
