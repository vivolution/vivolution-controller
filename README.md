# Vivolution SBC

Status: Local Debian 13.6 ARM64 CP1 functional POC working; security/release requalification in progress; Azure is no-go

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
- Remediation is being promoted through a one-release signed-RLS compatibility
  bridge, then a signed-only/least-privilege release and a new guarded clean
  rebuild. Do not treat the bridge itself as the final isolation boundary.
- This is a management-plane foundation POC, not a working SBC product. Edge
  enrollment/PKI, signed configuration, telemetry, SIP signaling, RTP/media,
  Teams onboarding, and carrier interworking are not implemented yet.
- Trivy is now pinned for the replacement qualification, but no release passes
  the new security gate until its committed source, exact running OCI image,
  and guest package database all pass the signed HIGH/CRITICAL scan.
- The existing Azure CP1 VM remains outside this automation and has not been
  changed by the local qualification work. Azure Database for PostgreSQL has
  not been provisioned by this kit.
- No vendor purchase, customer pilot, live traffic, or production deployment is
  authorized. Microsoft supportability, certified-SBC licensing, carrier
  agreements, and UAE regulatory feasibility remain mandatory gates.

## Working documents

- [Brainstorm](brainstorm.md)
- [Architecture options](architecture/options.md)
- [Reference architecture](architecture/reference-architecture.md)
- [Architecture diagram](architecture/reference-architecture.html)
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
