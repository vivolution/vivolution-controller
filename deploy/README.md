# CP1 deployment kit

This kit keeps the controller host portable and separates the disposable local
database from the future Azure Database for PostgreSQL Flexible Server profile.

## Profiles

- `lab`: installs PostgreSQL 17 on Debian, loopback only.
- `azure`: refuses a loopback database target and never installs PostgreSQL.
- Both profiles place PgBouncer on `127.0.0.1:6432`, so the application
  connection contract does not change between environments.

The Azure inventory is deliberately an example only. It must not be activated
until the final Azure acceptance test is explicitly approved.

## Local commands

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

`outage-test` stops only the disposable lab's concrete PostgreSQL cluster. It
proves that HTTPS liveness remains available, readiness returns `503`, and the
controller reconnects after PostgreSQL is restored. Its `always` recovery path
starts PostgreSQL even when an assertion fails.

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

`resource-test` is a local-lab-only, roughly two-minute endurance gate. After a
ten-second idle sample, it drives eight concurrent trusted HTTPS readiness
workers through the macOS host forward, with each worker pausing one second
between requests, using
`lab/utm/generated/caddy-root.crt`. It records idle and peak controller memory
and CPU, minimum free guest memory, root-disk and journal baseline/final/growth,
request failures and maximum latency. It fails on OOM events, failed systemd
units, changed controller limits, readiness failure, or growth outside the
declared inventory bounds. It never stops services, reboots, changes the VM,
or intentionally exhausts memory. A sanitized log and result marker are kept
under the ignored, mode-protected `deploy/evidence/` directory.

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

`secret-test` scans source and accumulated qualification evidence, the active
OCI image metadata/layers/history, process arguments, and relevant service
journals for the protected deployment values without printing those values. It
also records the active/base image digests and Debian/Python component
inventories. `vulnerability-test` separately pins Trivy, scans the committed
controller source, exact running OCI image, and guest Debian package database,
and retains signed JSON reports, CycloneDX SBOMs, input hashes, and scanner
database provenance. Any HIGH or CRITICAL result—including an unfixed finding—
fails the gate unless a future review adds an explicit, documented waiver.

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
use `no_log` for secret-bearing Ansible tasks. The initial lab uses
passwordless sudo only on the disposable UTM VM; that is not the Azure policy.

The current layers qualify the host, nftables, PostgreSQL, PgBouncer, Podman,
and an immutable Django controller image with active/previous release markers.
The enrollment gateway and step-ca are unimplemented future layers that require
separate implementation and qualification. SIP signaling, RTP/media, Edge
Agent behavior, signed artifacts, and production telemetry are also outside
this foundation qualification.
