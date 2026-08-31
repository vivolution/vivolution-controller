# Vivolution Control Plane Turnkey Installer

Status: implementation contract. The current artifact is a standalone-CP1
release candidate awaiting its first clean Ubuntu 24.04 qualification run.

## Product boundary

The installer configures an administrator-supplied Ubuntu Server virtual or
physical machine. It does not create cloud resources, virtual machines, public
addresses, NAT rules, DNS zones, load balancers, or provider identities.

The product target is for the same installer to own the complete Control Plane
lifecycle:

- create a standalone CP1;
- join CP2 as a replicated standby with fenced manual promotion;
- join CP3 as a full controller and third quorum member;
- status, repair, backup, restore, upgrade, rollback, remove-node, and uninstall.

Only a mode that has passed its own clean-machine and failure tests may appear
in the released interactive menu. The current candidate exposes standalone CP1
installation, resume, reconciliation, status, and a redacted support bundle.
Join, HA, backup/restore, upgrade/rollback, removal, and uninstall are target
capabilities and remain unavailable. An unfinished path must fail explicitly;
it must never silently install a second independent database.

## Administrator experience

The source bundle exposes one entry point:

```text
sudo ./installer/install.sh
```

The default run performs these phases:

1. Acquire an exclusive installer lock and inspect the OS, architecture, time,
   DNS, network, CPU, memory, disk, SSH access, and existing listeners without
   changing the host.
2. Ask validated questions, persist only the sanitized non-secret answers for
   resume, verify direct IPv4 DNS, and display a redacted confirmation summary.
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

## Supported platform

The first qualified target is a fresh Ubuntu Server 24.04 LTS installation on
AMD64 or ARM64. Unsupported distributions or releases fail before any package
or configuration change. The release must declare and enforce its minimum CPU,
memory, and disk envelope.

The first online bundle uses Ubuntu-signed packages plus the PostgreSQL Global
Development Group repository for PostgreSQL 17. The complete PGDG signing-key
fingerprint is verified before the repository is trusted. An offline signed
bundle is a later release artifact, not an implicit promise of the online
installer.

## Runtime baseline

The initial standalone controller uses:

- Caddy for public HTTPS and automatic public-certificate renewal;
- a rootful, systemd-managed Podman Quadlet for the immutable Django/Gunicorn
  application image;
- PgBouncer on loopback;
- PostgreSQL 17 on loopback;
- UFW with inbound default-deny, HTTPS/ACME access, and SSH restricted to the
  administrator-approved IPv4 `/32` sources; this release publishes IPv4 only
  and creates no IPv6 inbound allow rule;
- systemd/journald and unattended Ubuntu security updates.

Automatic container-image updates remain disabled. The candidate binds the
installed controller to a deterministic local source manifest and an immutable
base-image digest. That detects source changes during a run; it does not prove
publisher identity. A detached publisher-signed release manifest and trusted
public-key distribution remain mandatory gates before production publication.

## Persistent records

The current installer keeps human and machine-readable evidence separately:

```text
/var/log/vivolution-installer/install.log
/var/log/vivolution-installer/events.jsonl
/var/lib/vivolution-installer/ledger.json
/var/lib/vivolution-installer/answers.json
/var/lib/vivolution-installer/secrets.json
/var/lib/vivolution-installer/credentials.txt
```

The human log and support bundle redact every generated or supplied secret.
Secrets never appear in process arguments. Logs are never uploaded without an
explicit administrator action.

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
and shared FQDN must resolve exclusively to CP1's declared public IPv4 address,
and Caddy obtains certificates for both names. External-load-balancer mode is
not offered until its TLS termination/re-encryption, health-check, forwarding,
and trusted-proxy contract is explicitly selected and qualified.

The target database design is PostgreSQL under Patroni with an mTLS-protected
etcd distributed configuration store:

- CP1: one application/database node and one-member DCS;
- CP1 + CP2: primary/replica, automatic promotion disabled, manual promotion
  requires fencing the old primary and guarded DCS recovery;
- CP1 + CP2 + CP3: three full application/database nodes, 2-of-3 DCS quorum,
  automatic promotion enabled only after watchdog/fencing and partition tests.

All application nodes route writes to the elected PostgreSQL primary. Sessions
must work across nodes without relying on node-local `/tmp`; otherwise DNS
round-robin is invalid. Controller peer, DCS, database-replication, and join
traffic uses mutually authenticated certificates and exact peer addresses.

## Release gates

### Standalone CP1

- detached publisher signature verification before the first mutation (release
  packaging gate; not yet satisfied by the local candidate);
- clean Ubuntu 24.04 installation from the supported entry point;
- idempotent second run;
- safe interrupted-run resume;
- trusted HTTPS, operator login, `/docs/`, and `/recovery/` checks;
- database RLS and least-privilege checks;
- reboot recovery, backup/restore, upgrade failure, and rollback evidence;
- no secret in logs, arguments, world-readable files, or support bundle.

### CP2

- authenticated one-time join and certificate enrollment;
- verified PostgreSQL base backup and continuous replication;
- application access through both node and shared names;
- manual promotion refuses until the old primary is fenced;
- rejoin of the former primary without divergent history.

### CP3

- safe etcd transition to three members;
- quorum loss and asymmetric partition tests;
- automatic failover only with a proven fencing mechanism;
- stale-leader writes and configuration publication rejected;
- loss and recovery of each controller independently.

Passing CP1 does not imply CP2/CP3 readiness. Each mode receives an explicit
release status in the installer and web documentation.
