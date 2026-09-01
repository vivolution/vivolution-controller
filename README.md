# Vivolution Control Plane and SBC

Status: standalone Ubuntu CP1 public beta available; the v0.3.0-rc3 Controller
and enrollment-only Edge source candidate is locally qualified. Real
PostgreSQL, fresh Ubuntu, and live Teams/SIP acceptance remain pending.

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
asks for the node/shared FQDNs, initial operator, and Let's Encrypt ACME contact,
generates protected credentials, installs PostgreSQL/PgBouncer/Podman/Caddy,
deploys the controller, runs health checks, and prints the console URL.
Interrupted runs use `sudo ./installer/install.sh resume`.

- [Installer guide](installer/README.md)
- [Turnkey architecture and HA contract](architecture/turnkey-installer.md)
- [Controller application and operator guide](controller/README.md)

The separate public `vivolution-install` repository uses immutable tags and
minimal checksum-pinned assets. The `v0.3.0-rc3` design keeps two commands and
archives separate: standalone CP1, and an enrollment-only Edge
client/placeholder. The latter does not install an SBC, SIP/RTP, Teams, or a
carrier profile, and neither command claims CP2/CP3 high availability.

The standalone Controller pins Caddy to the Let's Encrypt production ACME
directory as its only certificate issuer. Caddy requests and automatically
renews public certificates for both the unique Controller VM FQDN and stable
shared FQDN; trusted HTTPS readiness fails closed if issuance is unavailable.
This Controller certificate flow is separate from future Teams/SBC signaling
certificates.

The rc3 source requires a fresh installation and does not claim to convert a
certificate already cached by an rc2 host.

The Hosted SBC material below is a separate guarded POC module. Its invariant
is **Microsoft Teams -> Common Teams Leg -> SBC routing/media -> Generic SIP
Trunk Leg -> customer-selected provider**. Twilio is the first example profile,
not a hard-coded product dependency.

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

- The `v0.3.0-rc4` source candidate has separate deterministic Controller and Edge
  enrollment archives, checksum-pinned bootstraps, exact allowlists, and tamper
  tests. It corrects the stock Ubuntu 24.04 `/etc/os-release` symlink preflight
  and adds a non-installing packaged host-OS check. A complete fresh-host run
  remains an acceptance gate.
- The bounded Edge enrollment client accepts the canonical Controller shared
  HTTPS URL plus a display-once grant, creates a local Ed25519 identity, enters
  pending approval, and reports signed heartbeat visibility after fingerprint
  approval. It provides no desired-state delivery, remote actions, mTLS, or
  voice data plane.
- The Hosted SBC implementation includes fail-closed OpenSIPS/RTPengine Edge
  bootstrap, signed desired state, transactional activation and rollback,
  certificate automation, a private no-PSTN fixture, a guarded one-call broker,
  provider-neutral CDR adapters, and a generic outbound SIP-provider profile.
- The common Teams process is restricted to RTP `30000-30063`; the isolated
  provider-egress process is restricted to `30064-30127`. Each receives only
  its own root-owned `0440` certificate copy and UID-scoped nftables authority.
- Offline verification passes 58 carrier tests, 249 deployment tests, 83
  Controller tests (12 PostgreSQL-only skips), 57 installer tests, 16 installer
  Ansible tests, and 42 Edge enrollment tests (one root-only tmpfs skip), plus
  syntax, digest-compatibility, whitespace, and independent security gates.
  This is source readiness, not a live-call or production claim.
- A 2026-09-01 Azure audit found no current Vivolution POC resource group, VM,
  or compute resource. The existing DNS zones remain, but the planned
  controller, SBC, and carrier records are absent. Historical UTM/Azure evidence
  remains bounded historical evidence only.
- Live acceptance still requires fresh hosts, reviewed DNS and certificates, a
  Microsoft Teams administrator session and test identity, a protected customer
  SIP profile, and an explicitly approved destination and spend ceiling for the
  controlled call. No live Teams-to-provider call has yet been claimed.
- OpenSIPS/RTPengine remains explicitly non-Microsoft-certified. No vendor
  purchase, customer pilot, production traffic, or production deployment is
  implied; supportability, carrier agreements, and UAE regulatory feasibility
  remain production gates.

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
