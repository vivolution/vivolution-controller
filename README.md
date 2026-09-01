# Vivolution Control Plane and SBC

Status: `v0.3.0-rc6` is the approved universal-launcher beta source for public
prerelease packaging. Static and security gates pass; real PostgreSQL, fresh
Ubuntu, and live Teams/SIP acceptance remain pending.

## Turnkey Controller installer

The product installer configures an administrator-supplied Ubuntu Server VM or
physical host. It does **not** create Azure, AWS, GCP, VMware, DNS, NAT, public
IP, or load-balancer resources.

The first released mode is one standalone Controller. Additional Controller
nodes are deliberately unavailable until replication, fencing, quorum,
failover, and rejoin acceptance tests pass; the installer will never disguise
independent databases as an HA cluster.

On a fresh Ubuntu Server 24.04 LTS host, run the permanent, checksum-verifying
public bootstrap:

```sh
curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' --tlsv1.2 https://raw.githubusercontent.com/vivolution/vivolution-install/main/install.sh | sudo sh
```

The rc6 wizard validates the host and public DNS, detects and confirms the
public IPv4, asks for the node/shared FQDNs, firewall ownership, initial
operator, Let's Encrypt ACME contact, IANA timezone, and Chrony policy,
generates protected credentials, installs PostgreSQL/PgBouncer/Podman/Caddy,
deploys the Controller, runs health checks, and prints the console URL.
Interrupted rc6 runs must use the exact version-pinned bootstrap:

```sh
curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' --tlsv1.2 https://raw.githubusercontent.com/vivolution/vivolution-install/v0.3.0-rc6/install.sh | sudo sh -s -- resume
```

- [Installer guide](installer/README.md)
- [Turnkey architecture and HA contract](architecture/turnkey-installer.md)
- [Controller application and operator guide](controller/README.md)

The separate public `vivolution-install` repository uses immutable tags and
minimal checksum-pinned assets. The `v0.3.0-rc6` prerelease promotes one
permanent universal-launcher command and retains a separate enrollment-only
Edge archive for compatibility. The latter does not install an SBC, SIP/RTP,
Teams, or a carrier profile, and neither artifact claims Controller high
availability.

The standalone Controller pins Caddy to the Let's Encrypt production ACME
directory as its only certificate issuer. Caddy requests and automatically
renews public certificates for both the unique Controller VM FQDN and stable
shared FQDN; trusted HTTPS readiness fails closed if issuance is unavailable.
This Controller certificate flow is separate from future Teams/SBC signaling
certificates.

The rc6 beta requires a fresh installation and does not claim to convert an
rc5 ledger or a certificate already cached by an older host.

### v0.3.0-rc6 beta boundary

The rc6 launcher provides one permanent installer command and this neutral
menu:

```text
Vivolution Turnkey Installer

> Create a new Controller Plane
  Join an existing Controller Plane          [Unavailable]
  Deploy an Edge Appliance (SBC)             [Unavailable]
  Manage an existing installation
  Diagnostics / network readiness test
```

It does not suggest CP1/CP2/CP3/SBC1/SBC2 hostnames. The enabled scope is one
new standalone Controller, non-mutating diagnostics, and Manage actions for
status, a redacted support bundle, resume, reconcile, and discard only when
schema-5 evidence proves that an incomplete run never crossed the mutation
boundary. Recognized rc3-rc5 state is detected and can be previewed, but rc6
refuses to delete it because the older removable lock cannot provide the same
race-free safety guarantee.

The candidate adds multi-source HTTPS public-IP prefill with operator
confirmation, interactive DNS wait/retry, explicit infrastructure-managed or
installer-managed firewall ownership, IANA timezone selection, Chrony
automatic/custom NTP configuration, and audit-grade redacted logging. It begins
the secured-namespace migration with installer state/logs and scoped host
ownership evidence beneath `/var/lib/vivolution` and `/var/log/vivolution`.
Moving releases to `/opt/vivolution/releases` and completing the broader FHS
migration and mutation manifest remain future lifecycle work.

Controller joining/HA, full Edge voice installation, upgrade, rollback,
repair, backup/restore, and post-mutation uninstall remain design-only. The
private complete voice-plane POC currently expects Debian 13 AMD64; the public
Controller and bounded enrollment-only Edge expect Ubuntu 24.04. Therefore rc6
must keep **Deploy an Edge Appliance (SBC)** unavailable until one declared
Edge OS contract is ported and independently qualified.

rc6 does not claim in-place migration or resume from the rc5 schema-4 ledger.
It can detect and preview an exact recognized legacy state set, but automated
legacy deletion is deliberately refused. Fresh Ubuntu 24.04 remains the
acceptance path. Any rc5 host requires either replacement or a separately
reviewed offline cleanup/migration procedure.

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

- The `v0.3.0-rc6` source has separate deterministic Controller and Edge
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
  Controller tests (12 PostgreSQL-only skips), 86 installer tests, 18 installer
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
- [Historical repeatable standalone-Controller deployment kit](deploy/README.md)
- [Disposable UTM lab](lab/utm/README.md)
