# Vivolution SBC

Status: Azure generation-2 synthetic POC qualified; generation-3 Direct
Routing/Twilio path under remediation and not yet live-accepted

## Working hypothesis

Vivolution may be able to offer a UAE-hosted, multi-tenant managed SBC platform for Microsoft Teams Direct Routing. The commercial idea is to pool signaling/media infrastructure and operations across customers while preserving strict tenant isolation, customer-specific routing, carrier choice, reporting, and access control.

## Initial verdict

The concept is technically credible through both certified and open-source data planes. Jay has previously proved real Direct Routing interoperability by patching/recompiling Asterisk behind FreePBX and using Twilio for PSTN calls from Teams. Microsoft certification is therefore a support, procurement, and change-assurance boundary—not a claim that SIP cannot work without it.

The product should separate the Vivolution control plane from the voice data plane. The same portal could eventually provision either:

- **Vivolution Open Edge** — Kamailio/OpenSIPS, RTPengine, and optional Asterisk/FreeSWITCH; technically interoperable but explicitly not Microsoft-certified.
- **Vivolution Certified Edge** — a pooled certified product for customers that require Microsoft/vendor support.

This preserves the low-cost engineering opportunity without presenting the open-source edition as equivalent to Microsoft certification.

The recommended first product shape is **Managed Direct Routing Edge in PBX Relay mode**. Teams connects through Vivolution to the customer's existing PBX; that PBX retains the customer-owned du/e& or other approved carrier trunk. This solves the SBC cost/skills problem while changing the carrier boundary as little as possible. Direct carrier termination, operator partnership, PSTN resale, and bundled minutes remain later gates requiring written commercial and regulatory validation.

The v0.1 Open Edge isolation baseline is **Enhanced Isolation** on a shared two-node cluster, with tenant-specific PBX signaling allocation, RTPengine unit/media block, policy, quotas, CDRs, and audit. **Dedicated Isolation** uses the same control plane but locks a complete two-node cluster to one customer. Certified products must prove equivalent native capabilities before using those labels. Clusters enroll through a provider-neutral outbound Edge Agent; Azure/AWS/other provisioning is an optional adapter, not the management contract.

Customer-owned cloud or on-premises VMs are supported as a separate **Customer-Hosted Dedicated Edge** direction. Customer hosting is not another isolation tier: the customer owns the substrate while Vivolution manages the signed Edge appliance lifecycle. Two controller application nodes are the production direction, but safe automatic state failover additionally needs managed database HA or a third quorum witness.

## Current boundary

- Jay authorized a disposable local CP1 lab on this Mac. Debian 13.6 ARM64 runs
  in UTM, and the first Django/PostgreSQL controller vertical slice is deployed
  through the repeatable Ansible kit.
- Clean UTM rebuilds and the local functional suite passed on August 27 and 28,
  including HTTPS/admin access, backup/restore, controlled database outage,
  failed-release recovery, reboot recovery, and two-minute readiness soaks.
  The latest untouched-OS run recorded 904 successful requests, zero failures,
  101.46 MiB peak controller memory, and 3.01% peak CPU.
- An independent August 28 audit withdrew the broader “qualified” conclusion.
  It proved the prior `changed=0` result hid changing PostgreSQL SCRAM state and
  found material RLS, Caddy-admin, mutable-image, credential, evidence, and
  coverage gaps. Those historical runs remain credible bounded functional
  evidence, not current security/release acceptance.
- Remediation was promoted through a one-release signed-RLS compatibility
  bridge to the signed-only/least-privilege Lab release. The UTM kit can now
  create the protected primary from a truly empty registry without a template
  VM, then run the signed current-release and distinct N-1 gates. The latest
  verified evidence, rather than this narrative, is authoritative for pass/fail
  status; the bridge itself is not the final isolation boundary.
- The authorized Azure POC group is live in UAE North with replacement CP1 and
  two generation-2 Edge nodes. Signed synthetic TLS/SIP/RTP calls, SBC failover,
  reboot recovery, and replacement-CP1 restore have passed. The preserved
  legacy controller remains the DNS target and rollback source until cutover.
- The implementation includes a fail-closed
  OpenSIPS/RTPengine Edge bootstrap, signed desired-state verifier/compiler,
  transactional activation and rollback, public-certificate automation, a
  private no-PSTN SIP/TLS/RTP fixture, first-tenant CP1 catalog reconciliation,
  replacement-controller restore automation, and a guarded Microsoft 365
  onboarding package. A parallel generation-3 Direct Routing profile adds the
  CP1 carrier gateway and Twilio termination path. It remains a guarded draft
  until its public-NAT/media, certificate, authorization/CDR, rollback, and
  teardown gates pass independent review and live host qualification.
- Trivy is pinned for the replacement qualification. The signed gate blocks
  every fixable HIGH/CRITICAL finding in the committed source, exact running
  OCI image, and guest package database. It also retains the complete unfixed
  HIGH/CRITICAL inventory as signed evidence; findings for which Trivy reports
  no fixed version remain explicit residual risk rather than being hidden or
  mislabeled as remediated.
- The Azure acceptance kit includes a deliberately self-contained
  `azure-single` profile: one Debian 13 AMD64 VM runs PostgreSQL, PgBouncer,
  Caddy, Podman, and the immutable CP1 application. It does not depend on Azure
  Database for PostgreSQL or another managed runtime service. The separately
  retained `azure` profile continues to require an external PostgreSQL service.
  Signed evidence, rather than this narrative, is authoritative for the latest
  Azure qualification result.
- No vendor purchase, customer pilot, production traffic, or production
  deployment is authorized. Jay accepted OpenSIPS/RTPengine as an explicitly
  non-certified POC boundary. Microsoft supportability, carrier agreements,
  and UAE regulatory feasibility remain mandatory production gates.
- The private synthetic gate cannot be described as a live Teams/PSTN pass.
  The first live profile uses the root FQDNs `sbc1.vivolution.ae`,
  `sbc2.vivolution.ae`, and `carrier.vivolution.ae` for the single Vivolution
  tenant. Jay reports that `jay@vivolution.ae` has Microsoft 365 E5/Teams Phone;
  live tenant verification must be repeated after normal browser sign-in.
  Twilio is outbound-only for this POC because no DID exists, and its account,
  verified caller ID, permitted destination, TLS/SRTP, and live call evidence
  remain pending.
- Four VMs are presently powered, including the preserved legacy controller.
  Their retail baseline is approximately USD 8.48/day, so the live acceptance
  window must be short and idle compute deallocated promptly.

## Working documents

- [Brainstorm](brainstorm.md)
- [Architecture options](architecture/options.md)
- [Reference architecture](architecture/reference-architecture.md)
- [Architecture diagram](architecture/reference-architecture.html)
- [Modular turnkey architecture](architecture/modular-turnkey-architecture.html)
- [Open-source reference path](architecture/open-source-reference.md)
- [Provider-neutral fleet management](architecture/fleet-management.md)
- [Control plane high availability](architecture/control-plane-ha.md)
- [Customer-hosted Edge](architecture/customer-hosted-edge.md)
- [Open Edge POC diagram](architecture/open-source-poc.html)
- [Product specification v0.1](product-spec-v0.1.md)
- [Security and isolation model](security-model.md)
- [Microsoft supportability](research/microsoft-supportability.md)
- [Platform shortlist](research/platform-shortlist.md)
- [Existing-platform preflight](research/existing-platform-preflight.md)
- [Azure lab economics](research/azure-lab.md)
- [UAE regulatory boundary](research/uae-regulatory.md)
- [CDR and retention model](data-retention.md)
- [Commercial model](commercial-model.md)
- [Discovery plan](discovery-plan.md)
- [POC blueprint](poc/blueprint.md)
- [Authorized turnkey first-tenant execution profile](poc/turnkey-first-tenant-execution.md)
- [POC cluster enrollment](poc/cluster-enrollment.md)
- [POC FQDN and tenant matrix](poc/fqdn-and-tenant-matrix.md)
- [POC test matrix](poc/test-matrix.md)
- [POC decision gates](poc/go-no-go.md)
- [Risk register](risk-register.md)
- [Research sources](research/sources.md)
- [Decision log](decisions/decision-log.md)
- [Controller vertical slice](controller/README.md)
- [Repeatable CP1 deployment kit](deploy/README.md)
- [Disposable UTM lab](lab/utm/README.md)
