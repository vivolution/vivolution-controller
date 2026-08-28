# Vivolution SBC

Status: Local Debian 13.6 ARM64 CP1 foundation qualified; Azure acceptance and data-plane discovery pending

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
- The first clean rebuild exposed a PgBouncer startup-ordering defect. The
  ordering was fixed and the complete foundation suite then passed after
  repairing that interrupted deployment. Evidence:
  `deploy/evidence/20260827T180455Z-19848`.
- A final untouched clean rebuild passed the complete suite from its first
  application install; the required second install reported `changed=0`.
  Evidence: `deploy/evidence/20260827T183743Z-74252`.
- The final 120-second endurance gate used eight concurrent HTTPS workers and
  recorded 896 successful requests, zero failures, 0.175329 seconds maximum
  latency, 101.95 MiB peak controller memory, 3.17% peak CPU, 0.2 MiB root-disk
  growth, and zero journal growth.
- This is a management-plane foundation POC, not a working SBC product. Edge
  enrollment/PKI, signed configuration, telemetry, SIP signaling, RTP/media,
  Teams onboarding, and carrier interworking are not implemented yet.
- No qualified vulnerability scanner is installed, so a vulnerability scan was
  not performed. Component inventory and secret-non-exposure checks are not a
  substitute for that pending gate.
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
