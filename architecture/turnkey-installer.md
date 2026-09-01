# Vivolution Turnkey Installer

Status: `v0.3.0-rc7` beta implementation contract. Static, regression, and
security gates pass. A clean Ubuntu 24.04.4 ARM64 run reaches Controller
activation and the trusted-HTTPS gate; public ACME validation on the Azure test
VM remains outstanding.

## Product boundary

The installer configures an administrator-supplied Ubuntu Server virtual or
physical machine. It does not create cloud resources, virtual machines, public
addresses, NAT rules, DNS zones, load balancers, or provider identities.

The product target is for the same versioned, verified launcher to select the
complete Vivolution lifecycle:

- create a new Controller Plane;
- join an additional Controller node to an existing Controller Plane;
- deploy an Edge Appliance (SBC);
- status, repair, backup, restore, upgrade, rollback, remove-node, and uninstall.

Only a mode that has passed its own clean-machine and failure tests may appear
as enabled in the released interactive menu. The rc7 beta enables creation
of a new one-node Controller Plane, non-mutating diagnostics, and a bounded
Manage surface for status, support bundle, resume, reconcile, and safe
pre-mutation discard. Join, HA, complete SBC deployment, backup/restore,
upgrade/rollback, repair, post-mutation removal, and uninstall remain
unavailable. An unfinished path must explain the boundary and return safely;
it must never silently install a second independent database or describe an
enrollment-only client as an SBC.

Node order is not identity. Product UX and hostname examples do not suggest
`CP1`, `CP2`, `CP3`, `SBC1`, or `SBC2`. Every Controller and Edge node has an
immutable generated UUID, an operator-selected FQDN/display name, and explicit
plane/cluster membership. Its current topology role is derived from
authoritative state.

## Administrator experience

The source bundle exposes one entry point. The public repository wraps the same
entry point with a checksum-pinned, reviewed release bootstrap:

```text
sudo ./installer/install.sh
```

The rc7 beta begins with this neutral menu:

```text
Vivolution Turnkey Installer

> Create a new Controller Plane
  Join an existing Controller Plane          [Unavailable]
  Deploy an Edge Appliance (SBC)             [Unavailable]
  Manage an existing installation
  Diagnostics / network readiness test
```

A capable TTY uses Up/Down arrows and Enter. A numbered/text fallback is
mandatory for serial/dumb terminals and automation. The menu itself cannot
depend on a package that has not yet been installed.

The default run performs these phases:

1. Acquire an exclusive installer lock and inspect the OS, architecture, time,
   DNS, network, CPU, memory, disk, SSH access, firewall ownership, existing
   listeners, and prior Vivolution ledger without changing the host.
2. Ask validated questions, persist only sanitized non-secret answers for
   resume, detect and confirm the public service IPv4, interactively wait for
   DNS where necessary, configure the selected timezone/NTP policy, and display
   a redacted confirmation summary.
3. Require explicit confirmation, then verify the local source manifest and
   immutable base-image reference before apt or service mutation.
4. Install the bounded prerequisites, generate secrets in a separate root-only
   file, and reconcile the host idempotently with
   local Ansible while streaming redacted progress to the console and log.
5. Run database, HTTPS, authentication, documentation, and service checks.
6. Record a completed phase ledger and print the console URL, initial operator,
   credential-file path, documentation URL, log path, and support command.

Interrupted runs resume from a durable phase boundary. A rerun reconciles
desired state; it does not replay arbitrary shell lines.

### Public address and DNS interaction

Public-address discovery uses short-timeout HTTPS requests to at least two
independent echo sources when available. `ifconfig.me/ip` may be one source,
but it is neither a trust root nor proof of the inbound service address. The
operator sees any disagreement, is warned that outbound NAT may differ from
the inbound/load-balancer address, and must confirm or enter the service IPv4.
Failure offers Retry, manual entry, requirements, or safe exit.

The rc7 implementation validates the system resolver's A/AAAA results. It
reports lookup failure, wrong A answers, and unsupported AAAA answers without
discarding the collected form. The operator can retry, run a bounded timed
retry, change the FQDN/address, follow a direct propagation-check link, or exit
and resume later. Retry paths make a bounded best-effort call to flush the local
systemd-resolved cache first. Direct authoritative-versus-recursive
classification, split-view analysis, and CAA diagnosis remain later diagnostics
work and must not be claimed by rc7.

## Supported platform

The first qualified target is a fresh Ubuntu Server 24.04 LTS installation on
AMD64 or ARM64. Unsupported distributions or releases fail before any package
or configuration change. The release must declare and enforce its minimum CPU,
memory, and disk envelope.

That Ubuntu contract currently covers the Controller and bounded
enrollment-only Edge client. The complete private OpenSIPS/RTPengine voice-plane
preflight currently declares Debian 13 AMD64. rc7 must keep **Deploy an Edge
Appliance (SBC)** unavailable on Ubuntu; neither the Debian POC nor the bounded
enrollment client may be presented as a qualified Ubuntu SBC. A future Edge
release must declare one role-specific OS contract and pass its own clean-host,
media, failure, and live-call qualification.

The first online bundle uses Ubuntu-signed packages plus the PostgreSQL Global
Development Group repository for PostgreSQL 17. The complete PGDG signing-key
fingerprint is verified before the repository is trusted. An offline signed
bundle is a later release artifact, not an implicit promise of the online
installer.

## Runtime baseline

The initial standalone controller uses:

- Caddy pinned to the Let's Encrypt production ACME directory as its single
  Controller-web certificate issuer, with automatic public-certificate renewal;
- a rootful, systemd-managed Podman Quadlet for the immutable Django/Gunicorn
  application image;
- PgBouncer on loopback;
- PostgreSQL 17 on loopback;
- an explicit firewall ownership mode. `Infrastructure-managed` is the rc7
  default: the installer does not enable/reset UFW and the operator's
  NSG/cloud/on-premises firewall owns exposure. `Installer-managed` previews
  and applies inbound default-deny, HTTPS/ACME access, and SSH restricted to
  validated administrator sources while preserving the active session. This
  release publishes IPv4 only and creates no IPv6 inbound allow rule;
- Chrony with a selected IANA timezone, UTC RTC, and automatic packaged/existing
  Chrony policy or validated custom NTP sources. The validated handoff stops
  systemd-timesyncd even when package removal left its process active without a
  loaded unit file. Readiness requires bounded correction, normal leap state,
  valid stratum, and systemd NTP synchronization without waiting for a fresh
  frequency-skew estimate to converge. Database, CDR, API, inter-node, and
  audit timestamps remain timezone-aware UTC regardless of host display timezone;
- systemd/journald and unattended Ubuntu security updates.

Automatic container-image updates remain disabled. The candidate binds the
installed controller to a deterministic local source manifest and an immutable
base-image digest. That detects source changes during a run; it does not prove
publisher identity. A detached publisher-signed release manifest and trusted
public-key distribution remain mandatory gates before production publication.

## Secured FHS namespace and persistent records

rc7 starts the namespace migration with transaction state under
`/var/lib/vivolution/installer`, evidence under
`/var/log/vivolution/installer`, and exact host ownership records beneath
`/var/lib/vivolution/ownership`. It does not yet migrate every existing
Controller runtime path. The complete approved FHS target is:

```text
/opt/vivolution/releases/  immutable releases
/etc/vivolution/           configuration and protected secrets
/var/lib/vivolution/       data, schema-5 ledger and ownership manifest
/var/log/vivolution/       human, structured and audit evidence
/var/cache/vivolution/     disposable digest-verified staging
/run/vivolution/           volatile sockets, locks and runtime files
```

rc7 records scoped host/time, SSH, and firewall ownership evidence plus package
intent. A complete per-object mutation manifest covering every systemd, apt,
Caddy, PostgreSQL, and runtime change is still required before post-mutation
removal can be offered. Cleanup must eventually operate on exact records, never
a broad prefix/glob.

The `/opt/vivolution/releases` move and remaining runtime/cache consolidation
are future, separately tested lifecycle work and are not an rc7 completion
claim.

### Installer and lifecycle logging

The evidence model is detailed but sanitized:

- `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`, and `FATAL` severity, plus a
  separate lifecycle/security `AUDIT` stream;
- RFC 3339 UTC timestamps plus installation/run/correlation, phase, attempt,
  step, and node/FQDN context whenever that context is known;
- the bootstrap and Ansible execution runner capturing a redacted semantic
  command description, working directory, effective numeric identity where
  known, start/end/duration, exit code, and ordered redacted stdout/stderr;
- ordinary console output with bounded sanitized command output when verbose
  mode is selected; and
- protected human/JSONL evidence with 10 MiB size rotation, five retained
  generations, and per-command output limits of 10,000 lines or 4 MiB.

There is no unredacted mode and no `set -x`. Enrollment grants, passwords,
database URLs, authorization headers, private keys, carrier credentials, and
customer-sensitive call data are redacted at source and excluded by the
support-bundle allowlist. Logs are never uploaded without explicit operator
action.

### Failed-run discard and uninstall

The rc7 beta's only destructive lifecycle action is a schema-5
pre-mutation discard. It is available only when the schema-5 ledger/ownership
manifest proves that no apt, firewall, service, database, certificate, or
application mutation began. A dry-run previews exact allow-listed objects;
deletion requires `DISCARD-INCOMPLETE` and refuses on any ownership, path,
directory-content, or ledger ambiguity. A schema-5 support bundle is a separate
Manage action.

This is not a general uninstall. Post-mutation uninstall, rollback, and removal
remain unavailable. Their future contract requires backup/export, service
drain, identity/credential revocation, external-dependency warnings, exact
manifest cleanup, and safe package-ownership checks. The installer must never
delete foreign data, shared packages, unrelated firewall rules, external DNS,
cloud resources, Microsoft objects, carrier objects, or off-host backups.

The schema-5 rc7 beta does not claim in-place resume/upgrade or automated
deletion of an rc5 schema-4 ledger. It can detect and preview recognized legacy
state, but execution is refused because the older lock cannot provide race-free
cleanup. A fresh Ubuntu VM remains the rc7 acceptance path; an old host requires
a separately reviewed offline cleanup/migration plan.

## Web console and documentation

The first console is the secured Django operator administration surface. It
must provide:

- a staff-authenticated `/docs/` manual built into the exact application
  release;
- a minimal database-independent `/recovery/` page;
- a visible installed release identifier;
- private/no-store documentation responses and a restrictive same-origin CSP.

The manual documents only implemented features. Planned portal, MFA, HA, Edge
enrollment, Microsoft 365, carrier, or backup capabilities must be labelled as
unavailable until their release gates pass.

## HA contract

Every controller is a full HTTPS application node with an individual public
FQDN. The target shared controller FQDN may use round-robin A records or an
external HTTPS load balancer. Round-robin DNS distributes addresses but does
not remove failed nodes. An external load balancer may add health removal and
cookie affinity.

The current standalone candidate supports direct DNS only: both its node FQDN
and shared FQDN must resolve exclusively to the node's declared public IPv4
and publish no AAAA record. The installer separately asks for a Let's Encrypt
ACME contact (defaulting to the validated operator email), and Caddy obtains and
renews certificates for both names through that one production issuer. No
alternate public CA or local/self-signed fallback is configured. The rc5 ledger
also refuses rc2 resume/reconcile because an earlier host may already cache a
different issuer's certificate. External-load-balancer mode is not offered
until its TLS termination/re-encryption, health-check, forwarding, and
trusted-proxy contract is explicitly selected and qualified.

The target database design is PostgreSQL under Patroni with an mTLS-protected
etcd distributed configuration store:

- one node: standalone application/database node and one-member DCS;
- two nodes: primary/replica, automatic promotion disabled, manual promotion
  requires fencing the old primary and guarded DCS recovery;
- three full Controller nodes: 2-of-3 DCS quorum, with automatic promotion
  enabled only after watchdog/fencing and partition tests.

All application nodes route writes to the elected PostgreSQL primary. Sessions
must work across nodes without relying on node-local `/tmp`; otherwise DNS
round-robin is invalid. Controller peer, DCS, database-replication, and join
traffic uses mutually authenticated certificates and exact peer addresses.

## Release gates

### Standalone Controller

- detached publisher signature verification before the first mutation (release
  packaging gate; not yet satisfied by the local candidate);
- clean Ubuntu 24.04 installation from the supported entry point;
- idempotent second run;
- safe interrupted-run resume;
- trusted HTTPS, operator login, `/docs/`, and `/recovery/` checks;
- database RLS and least-privilege checks;
- reboot recovery, backup/restore, upgrade failure, and rollback evidence;
- no secret in logs, arguments, world-readable files, or support bundle.

### Joining a second Controller node

- authenticated one-time join and certificate enrollment;
- verified PostgreSQL base backup and continuous replication;
- application access through both node and shared names;
- manual promotion refuses until the old primary is fenced;
- rejoin of the former primary without divergent history.

### Three-node automatic-HA topology

- safe etcd transition to three members;
- quorum loss and asymmetric partition tests;
- automatic failover only with a proven fencing mechanism;
- stale-leader writes and configuration publication rejected;
- loss and recovery of each controller independently.

Passing standalone Controller acceptance does not imply join or HA readiness.
Each mode receives an explicit release status in the installer and web
documentation.
