# Vivolution Control Plane and SBC

Status: provider-neutral Ubuntu CP1 turnkey installer release candidate; local
tests pass and clean Ubuntu 24.04 qualification is the next release gate.

## Turnkey Controller installer

The product installer configures an administrator-supplied Ubuntu Server VM or
physical host. It does **not** create Azure, AWS, GCP, VMware, DNS, NAT, public
IP, or load-balancer resources.

The first released mode is standalone CP1. CP2 and CP3 are deliberately hidden
until replication, fencing, quorum, failover, and rejoin acceptance tests pass;
the installer will never disguise independent databases as an HA cluster.

On a fresh Ubuntu Server 24.04 LTS host, clone or unpack the reviewed source and
run:

```sh
sudo ./installer/install.sh
```

The wizard validates the host and public DNS, preserves the active SSH source,
asks for the node/shared FQDNs and initial operator, generates protected
credentials, installs PostgreSQL/PgBouncer/Podman/Caddy, deploys the controller,
runs health checks, and prints the console URL. Interrupted runs use
`sudo ./installer/install.sh resume`.

- [Installer guide](installer/README.md)
- [Turnkey architecture and HA contract](architecture/turnkey-installer.md)
- [Controller application and operator guide](controller/README.md)

The older Azure and SBC material retained below is research and disposable POC
history. It is not a dependency of the provider-neutral installer.

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
- The authorized three-node POC implementation now includes a fail-closed
  OpenSIPS/RTPengine Edge bootstrap, signed desired-state verifier/compiler,
  transactional activation and rollback, public-certificate automation, a
  private no-PSTN SIP/TLS/RTP fixture, first-tenant CP1 catalog reconciliation,
  replacement-controller restore automation, and a guarded Microsoft 365
  onboarding package. This is source readiness, not a deployment claim: Azure
  host qualification, end-to-end calls, failover, and signed final evidence
  remain pending until the new CP1/SBC1/SBC2 environment is built and tested.
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
- No vendor purchase, customer pilot, live traffic, or production deployment is
  authorized. Microsoft supportability, certified-SBC licensing, carrier
  agreements, and UAE regulatory feasibility remain mandatory gates.
- The private synthetic gate cannot be described as a live Teams/PSTN pass.
  Live Direct Routing remains blocked by the unverified
  `voice.vivolution.ae` Microsoft 365 domain, absent Teams/Phone System test
  licenses and users, and acceptance of the non-certified support boundary.

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
