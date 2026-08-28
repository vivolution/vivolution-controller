# Vivolution SBC Proof-of-Concept Blueprint

Status: Local Debian 13.6 ARM64 CP1 foundation qualification complete. Azure resources, DNS, Microsoft 365 configuration, public certificates, and live calls remain unstarted and require Jay's separate approval.

## POC question

Can Vivolution operate a low-cost, two-tenant Teams Direct Routing edge that safely connects each tenant to its own PBX, is driven by versioned portal configuration, produces trustworthy tenant-isolated CDRs, and survives expected control-plane and single-node failures?

The POC is successful only if it proves **isolation and operability**, not just one completed phone call.

## Current local foundation evidence

The controller host/database/HTTPS/Django foundation has completed two local qualification runs in a disposable Debian 13.6 ARM64 UTM environment:

- `deploy/evidence/20260827T180455Z-19848` passed after the first clean deployment exposed and the automation repaired a PgBouncer first-boot ordering defect.
- `deploy/evidence/20260827T183743Z-74252` passed as an untouched clean first-pass regression and proved that the second installation completed with `changed=0`.

This evidence qualifies the local CP1 foundation and rebuild procedure only. Azure was untouched, and no vulnerability scan was performed. A clean Azure AMD64 deployment with PostgreSQL Flexible Server and public TLS remains an acceptance gate. Enrollment/PKI and the SIP/media data plane also remain unimplemented or unqualified and must pass their own POC stages before CP1 can be described as a working SBC product.

## In scope

- One Vivolution/provider Microsoft 365 tenant plus two separate customer test tenants.
- Two base SBC FQDNs in the provider tenant and two customer-derived SBC FQDNs per customer tenant.
- PBX Relay mode only.
- Two logically separate test PBXs/connectors, including overlapping extensions.
- Teams inbound/outbound call flows, common supplementary features, and media quality observation.
- Minimal Vivolution operator console/API and configuration compiler.
- Tenant-scoped CDRs, quality samples, audit history, alerts, publish, and rollback.
- Two edge nodes for failover in the final stage.
- Enhanced Isolation from day one: unique southbound signaling allocations, separate per-tenant RTPengine units/media blocks, and tenant-scoped configuration on the shared pair.
- Provider-neutral Edge Agent enrollment, signed desired state, fleet health, drift detection, and node replacement.
- Signed-package plus interactive hidden-token enrollment UX, with a privilege-separated agent/root helper and no arbitrary remote command path.
- One local/non-Azure disposable enrollment to prove portability of the management contract; it need not carry Teams traffic.
- Let’s Encrypt as a lab certificate strategy, with rotation rehearsed.
- A bounded existing-platform check before committing substantial custom control-plane work.

## Explicit non-goals

- Production SLA or capacity sizing.
- A customer-facing production portal.
- Microsoft certification or a claim of Microsoft support.
- Live du/e& PSTN trunks, number porting, minutes resale, or customer traffic.
- Emergency calling, lawful intercept, audio recording, contact centre, or billing.
- Media bypass.
- Indefinite SIP traces or CDR retention.
- Kubernetes, Azure Firewall, or other production platform complexity.
- A production-grade two-controller/database/PKI HA claim in the first voice-evidence stage.

## Prerequisites

- Three Microsoft 365/Entra tenants in the same Microsoft cloud: one Vivolution/provider tenant and two independent customer tenants. The customer tenants need Teams and Teams Phone entitlements plus at least two test users each. The provider/base and derived domains need the eligible activation identities required by Microsoft's then-current procedure.
- A lab domain/subdomain that can be delegated to Azure DNS.
- Access to run the reviewed Teams PowerShell onboarding and rollback packages in both tenants.
- Two PBX identities. These can initially be two isolated Asterisk containers/VMs or one carefully separated lab host; they must not share routing context.
- A decision on whether the PBX simulator runs in Jay's lab or on a temporarily powered Azure B1ms VM.
- Azure budget alert and an explicit maximum spend before provisioning.
- No live UAE trunk until carrier/regulatory gates are cleared.

Microsoft 365 test licensing may be the largest prerequisite not covered by the Azure credit. Confirm it before starting infrastructure. If only two tenants are available, the lab can prove one hosted customer but must be reported as a partial multi-tenancy test.

## Microsoft hosted-SBC topology

```text
Vivolution/provider tenant
  sbc1.lab...  -> provider/base gateway 1
  sbc2.lab...  -> provider/base gateway 2

Customer Tenant A
  customer-a.sbc1.lab... -> derived trunk in voice route
  customer-a.sbc2.lab... -> derived trunk in voice route

Customer Tenant B
  customer-b.sbc1.lab... -> derived trunk in voice route
  customer-b.sbc2.lab... -> derived trunk in voice route
```

Create gateways only for the base FQDNs in the provider tenant. Customer voice routes reference derived FQDNs; Microsoft derives their properties from the provider trunks. For calls toward Teams, the edge presents the exact customer-derived FQDN in Contact. The POC must capture actual Teams-to-edge traffic and prove the trusted inbound tenant selector before Customer B is enabled.

See [FQDN and tenant matrix](fqdn-and-tenant-matrix.md).

## Azure lab shape

Region: UAE North, subject to actual subscription availability and quotas.

### Stage 1 — functional edge

- One Linux B2s VM.
- 64 GiB Standard SSD.
- One Standard static public IPv4 address.
- Azure DNS zone.
- NSG with explicit management and SIP/media rules.
- Approximate always-on base: USD 46/month before logs, backup, and egress.

Network baseline:

- Expose only TLS signaling and the required media range to Microsoft's then-current published endpoints.
- Keep public UDP/TCP 5060, SIP registration, portal, database, and management interfaces closed.
- Put portal/database and synthetic PBX services on a private application subnet, reached through a tightly restricted management path or WireGuard.
- Restrict southbound SIP/media to the lab PBX identity/network.
- Use DNS-01 so ACME renewal does not require a public HTTP service.
- Do not send malformed, load, or fuzz traffic toward Microsoft; hostile tests target Vivolution-owned interfaces only.

### Stage 2 — two-node topology

- Two Linux B2s VMs.
- Two 32 or 64 GiB Standard SSDs.
- Two Standard static public IPv4 addresses.
- Approximate always-on base: USD 86–92/month before logs, backup, and egress.

The USD 100 credit is sufficient for a lean lab if nodes are sequenced and verbose telemetry is controlled. B-series CPU credits make this unsuitable for production performance conclusions.

Avoid Azure Firewall, NAT Gateway, managed database, load balancer, and full-time Log Analytics in the POC. The VMs may initially be created manually or through Azure automation, but they must join through the provider-neutral enrollment flow. Use Ansible Core locally for the host baseline and systemd for services; do not make Bicep, Terraform, or any cloud API part of the ongoing fleet-management contract.

## Candidate software

### Data plane

- Working choice: OpenSIPS 3.6 LTS + RTPengine. The current planning baseline is OpenSIPS 3.6.8 LTS; re-verify and pin the maintained patch release at execution.
- Internal engineering aid only: the matching OpenSIPS Control Panel release, never exposed to customers.
- Accelerator/reference check: Sipwise C5 Community Edition.
- Optional short call-path check: LibreSBC.
- Optional Asterisk worker only when B2BUA/normalization behavior is required.

For the lab, Asterisk provides echo, announcement, record/playback, DTMF capture, busy/reject/no-answer, and controlled inbound origination. It remains southbound of the edge and cannot route to PSTN.

Kamailio remains the fallback if measured interoperability or team operating experience shows a specific advantage. FreePBX is not the product portal.

### Control and evidence plane

- Minimal server-rendered FastAPI or Django operator application.
- PostgreSQL with tenant row-level security.
- Versioned structured route documents and a deterministic configuration compiler.
- Local signed last-known-good artifacts on each edge node.
- Prometheus/Grafana or similarly light metrics.
- HOMER enabled only for bounded troubleshooting windows.
- Local operational CDRs; immutable Azure Blob is simulated or used only for a small retention test.

The POC portal can be ugly. It must prove safe workflows, isolation, audit, and rollback—not visual polish.

## Work plan

### Phase 0 — design and test fixtures (2–3 days)

- Freeze the v0.1 objects, tenant-classification method, number format, and route schema.
- Confirm the provider plus two customer test tenants, licenses, domain, Azure quota, and lab PBX location.
- Prepare threat cases, expected CDRs, and cost alerts.
- Create repeatable infrastructure/runbook and teardown instructions plus the provider-neutral cluster enrollment contract.

Exit gate: all prerequisites exist, the lab cannot reach PSTN, and no live carrier/customer dependency is required.

### Phase 1 — one-tenant call path (3–5 days)

- Deploy one edge node and lab certificate.
- Configure the provider base trunks, then connect Customer Tenant A through its derived trunks to PBX A.
- Prove TLS, SIP OPTIONS, inbound/outbound calls, E.164 normalization, media, DTMF, hold, and transfer.
- Record exact CDRs and quality evidence.

Exit gate: stable repeated calls and a documented, reproducible build.

### Phase 2 — platform check and data-plane decision (2–3 days)

- Give Sipwise C5 CE one bounded day as an API/UX/reference benchmark; optionally run the same minimal call path through LibreSBC.
- Score resource use, Teams behavior, configuration safety, CDR completeness, API/branding fit, upgrades, and troubleshooting against OpenSIPS.
- Retain OpenSIPS unless a candidate removes substantial backend work without forcing unsafe or irrelevant PBX/carrier semantics.

Exit gate: evidence-backed platform choice; no portal sunk-cost decision.

### Phase 3 — two tenants and control plane (4–6 days)

- Add Tenant B and PBX B with overlapping extension/number fixtures.
- Provision both using the minimal operator console/compiler.
- Prove tenant-specific routes, CDR searches, RBAC, audit, publish, rollback, and negative isolation tests.
- Generate Teams onboarding and rollback packages.
- Allocate different PBX-facing TLS ports, source policies, media blocks, and RTPengine units for Tenant A and Tenant B.
- While Tenant B generates calls, change/roll back Tenant A and restart only Tenant A's media unit; prove no failed B calls and quality/setup within the agreed baseline tolerance.
- Implement cluster registry, node enrollment, Enhanced placement, capacity rejection, and logical Dedicated exclusivity.

Exit gate: zero cross-tenant leakage and complete expected CDRs.

### Phase 4 — resilience and operations (3–5 days)

- Add the second edge node and derived FQDNs.
- Test node, RTPengine, portal, database, PBX, DNS, and certificate failure scenarios.
- Rehearse certificate replacement and a bad-configuration rollback while calls are generated.
- Measure cost, setup time, call setup, media metrics, and operator effort.
- Keep the second edge powered for the final resilience window rather than the full month when possible.
- Revoke and replace an enrolled node, reject replay/downgrade/wrong-slot artifacts, and verify local last-known-good behavior during control-plane loss.
- Enroll a local/non-Azure disposable VM, test unsupported-host/drift detection, then revoke and remove it without exposing global/other-tenant secrets.

Exit gate: acceptance thresholds in the test matrix and no critical/high security finding.

### Phase 5 — decision pack (1–2 days)

- Produce architecture, configuration, test evidence, cost, risk, and operational runbooks.
- Decide Go, Pivot to Certified Edge, Repeat with changes, or Stop.
- Only then consider carrier/TDRA validation and a controlled customer pilot.

## Cost-control strategy

- Run the two bake-off platforms sequentially, not concurrently.
- Deallocate the second edge and any PBX VM outside resilience test windows.
- Cap and rotate SIP traces locally; avoid high-volume Log Analytics ingestion.
- Apply Azure budget alerts before the first VM.
- Use test traffic, not production volume, for the POC.
- Record actual daily cost and project the full-month equivalent separately.

A practical month can keep Edge 1 B2s and a private portal/PBX B1ms running throughout, then power Edge 2 B2s only for the final seven-day HA window. With three small disks, two public IPs, and DNS, the base estimate is roughly USD 80; reserve USD 10–15 for Key Vault operations, Blob, egress, and bounded telemetry. Domain and Microsoft 365 licensing are outside the Azure credit.

If Jay selects a controller-first sequence, run CP1 + CP2 with a tiny independent witness and enroll a local/customer-style Edge first. Move the two-public-Edge voice HA stage to a later credit cycle or tightly staged window. Two controllers without a witness may be tested, but database promotion must remain manual and cannot be reported as automatic HA.

## Deliverables

- Rebuildable IaC and automation.
- Provider-neutral enrollment kit, node/cluster lifecycle evidence, and optional cloud-adapter interface.
- Selected data-plane decision record.
- Teams onboarding/rollback package for each lab tenant.
- Versioned route schema and compiler.
- Test report mapped to every acceptance criterion.
- CDR reconciliation and tenant-isolation evidence.
- Failure/rollback evidence and first operating runbooks.
- Actual Azure cost and a defensible production-cost model.
- Go/Pivot/Stop recommendation.

## Approval boundary

Creating these documents does not authorize Azure spend or external changes. POC execution begins only after Jay approves the resource plan and confirms the Microsoft 365 test tenants, domain, and maximum spend.

See [Provider-neutral cluster enrollment](cluster-enrollment.md) for its separate security and acceptance tests.
