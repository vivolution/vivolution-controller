# CP1 deployment kit

This kit keeps the controller host portable across a local lab, a self-contained
Azure acceptance VM, and a future managed-database Azure layout.

## Profiles

- `lab`: installs PostgreSQL 17 on Debian, loopback only.
- `azure-single`: installs PostgreSQL 17, PgBouncer, Caddy, Podman, and CP1 on
  one Debian 13 AMD64 VM. PostgreSQL, PgBouncer, and CP1 remain loopback-only;
  only SSH from approved `/32` sources and public HTTP/HTTPS ingress are
  accepted.
- `azure`: refuses a loopback database target and never installs PostgreSQL;
  it is reserved for the future managed-database topology.
- Every profile places PgBouncer on `127.0.0.1:6432`, so the application
  connection contract does not change between environments.

The tracked `azure-single` inventory is specific to the approved UAE North
acceptance VM. Its SSH host identity and credentials are protected local state
and are never committed. The managed-database Azure inventory remains an
inactive example.

## Local commands

From a completely empty UTM registry and Documents directory, first create and
base-verify the protected Debian VM:

```bash
lab/utm/bootstrap-lab.sh
```

The script records UTM's generated UUID and pins the fresh SSH host key. It
never deletes or replaces an existing VM. See `lab/utm/README.md` for the
empty-state and failure-recovery contract.

```bash
bin/cpctl init
bin/cpctl trust-init
bin/cpctl preflight
bin/cpctl syntax
bin/cpctl install
bin/cpctl upgrade
bin/cpctl rollback
bin/cpctl failure-test
bin/cpctl restore-test
bin/cpctl verify
bin/cpctl outage-test
bin/cpctl reboot-test
bin/cpctl resource-test
bin/cpctl secret-test
bin/cpctl admin-test
bin/cpctl bridge-test
bin/cpctl bridge-qualify
bin/cpctl rollback-qualify
bin/cpctl vulnerability-test
bin/cpctl qualify
bin/cpctl verify-evidence deploy/evidence/<run-id>
```

`outage-test` stops only the explicitly authorized profile's local PostgreSQL
cluster. It proves that HTTPS liveness remains available, readiness returns
`503`, and the controller reconnects after PostgreSQL is restored. Its `always`
recovery path starts PostgreSQL even when an assertion fails.

`failure-test` activates an intentionally unhealthy release and proves that the
exact prior image and runtime environment are restored. `restore-test` restores
a logical database dump into an isolated database and reruns the tenant-RLS
behavioral checks.

`bridge-test` is used only while promoting the signed-RLS compatibility release.
It proves that the signed-capable N-1 image and the preceding legacy image can
both operate against migration `0003`; the final migration then removes legacy
database-selected authorization.

`reboot-test` performs a clean guest reboot, waits for systemd and SSH, checks
all controller services and trusted HTTPS, and then reruns the full acceptance
playbook.

`resource-test` is an explicitly authorized, roughly two-minute endurance gate.
After a ten-second idle sample, it drives eight concurrent trusted HTTPS
readiness workers, with each worker pausing one second between requests. The
inventory selects either the lab CA and host forward or the Azure system CA and
static public endpoint. It records idle and peak controller memory and CPU,
minimum free guest memory, root-disk and journal baseline/final/growth, request
failures, and maximum latency. It fails on OOM events, failed systemd units,
changed controller limits, readiness failure, or growth outside the declared
inventory bounds. It never stops services, reboots, changes the VM, or
intentionally exhausts memory. A sanitized log and result marker are kept under
the ignored, mode-protected `deploy/evidence/` directory.

## Historical functional record — 2026-08-27 (superseded)

- The first clean Debian 13.6 ARM64 rebuild exposed a PgBouncer startup-ordering
  defect. After the ordering fix, reconciliation repaired the interrupted
  deployment and the complete foundation suite passed. Evidence:
  `deploy/evidence/20260827T180455Z-19848`.
- A final untouched clean rebuild passed the then-current suite from its first
  application install, and Ansible reported `changed=0` on the second install. Evidence:
  `deploy/evidence/20260827T183743Z-74252`.
- Its 120-second HTTPS soak used eight concurrent workers: 896 successful
  requests, zero failures, 0.175329 seconds maximum latency, 101.95 MiB peak
  controller memory, 3.17% peak CPU, 0.2 MiB root-disk growth, and zero journal
  growth.
- The Azure CP1 VM was not changed. This is local ARM64 foundation evidence, not
  Azure AMD64, managed-PostgreSQL, public-TLS, production, or full-SBC
  acceptance.
- A later direct state comparison proved that the old `changed=0` gate hid
  changing PostgreSQL SCRAM verifiers. The historical run also lacked a
  vulnerability scan and committed/signed source provenance. It is functional
  engineering evidence only and must not be cited as current security or
  release qualification.

The default inventory is the protected working lab. To qualify the separately
guarded clean-rebuild VM after its base installation completes, select its
inventory explicitly:

```bash
VIVO_CP_INVENTORY=deploy/inventories/rebuild/hosts.yml bin/cpctl qualify
```

The rebuild inventory uses host ports 2223/8081 and a separate exported Caddy
root, so it cannot accidentally test or overwrite the working lab's endpoints.

The self-contained Azure profile requires both its explicit inventory and its
dedicated secrets file:

```bash
VIVO_CP_INVENTORY=deploy/inventories/azure-single/hosts.yml \
VIVO_CP_SECRETS=deploy/.state/azure-single-secrets.yml \
bin/cpctl qualify
```

Its signed qualification additionally audits the exact read-only Azure
control-plane contract before and after deployment: subscription, UAE North
resource group, six-resource VM footprint, pinned Debian image, Trusted Launch,
encrypted private OS disk, static public IP, NIC, NSG rules, and public DNS.
Public HTTPS uses the system trust store and the declared DNS name; guest probes
pin that name to loopback while runner probes pin it to the approved static IP.

The local logical backup/restore gate proves database recoverability inside the
host. Because the approved topology deliberately uses no second service or
storage target, those local backups do **not** protect against complete VM or OS
disk loss. Off-VM backup is a separate production prerequisite.

`secret-test` scans source and accumulated qualification evidence, the active
OCI image metadata/layers/history, process arguments, and relevant service
journals for the protected deployment values without printing those values. It
also records the active/base image digests and Debian/Python component
inventories. `vulnerability-test` separately pins Trivy, scans the committed
controller source, exact running OCI image, and guest Debian package database,
and retains signed JSON reports, CycloneDX SBOMs, input hashes, and scanner
database provenance. Any Trivy-reported fixable HIGH or CRITICAL dependency/OS
package finding fails the gate. Findings for which the current Trivy database
reports no fixed version remain in the signed inventory with explicit High and
Critical counts; they are residual risk, not a general vulnerability waiver or
a claim that application-level security analysis is complete.

Every signed gate requires a clean Git tree and a tracked in-repository
inventory, records a normalized inventory hash and complete source identity,
rechecks them before PASS, and seals its file-exact checksum manifest with the
enrolled Ed25519 identity. `verify-evidence` rejects changed, missing, extra,
linked, or unsigned evidence files.

The compatibility `bridge-qualify` command intentionally records
`security_release_gate=transitional-not-passed`. Only the later signed-only
release may run the complete `qualify` gate. `qualify` records that the distinct
N-1 rollback gate is still pending; `rollback-qualify` separately proves and
signs the exact final → N-1 → final cycle, verifies HTTPS/admin behavior at both
ends, and force-recovers the final immutable release and canonical marker pair
if any normal rollback step is interrupted.

`deploy/.state` is mode-protected and excluded from version control. Commands
use `no_log` for secret-bearing Ansible tasks. In the active `azure-single`
profile, administration is limited to the pinned Ed25519 identity over
source-restricted SSH; password and root login are disabled. The inactive
managed-database `azure` example must receive its own equivalent host identity
and source policy before it can be activated.

The current automation covers the host, nftables, PostgreSQL, PgBouncer,
Podman, and an immutable Django controller image with active/previous release
markers. The latest sealed evidence is authoritative for qualification status.
The enrollment gateway and step-ca are unimplemented future layers that require
separate implementation and qualification. SIP signaling, RTP/media, Edge
Agent behavior, signed artifacts, and production telemetry are also outside
this foundation qualification.
