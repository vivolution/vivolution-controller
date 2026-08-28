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
bin/cpctl qualify
```

`outage-test` stops only the disposable lab's concrete PostgreSQL cluster. It
proves that HTTPS liveness remains available, readiness returns `503`, and the
controller reconnects after PostgreSQL is restored. Its `always` recovery path
starts PostgreSQL even when an assertion fails.

`failure-test` activates an intentionally unhealthy release and proves that the
exact prior image and runtime environment are restored. `restore-test` restores
a logical database dump into an isolated database and reruns the tenant-RLS
behavioral checks.

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

## Qualification record — 2026-08-27

- The first clean Debian 13.6 ARM64 rebuild exposed a PgBouncer startup-ordering
  defect. After the ordering fix, reconciliation repaired the interrupted
  deployment and the complete foundation suite passed. Evidence:
  `deploy/evidence/20260827T180455Z-19848`.
- A final untouched clean rebuild passed the complete suite from its first
  application install, and the second install reported `changed=0`. Evidence:
  `deploy/evidence/20260827T183743Z-74252`.
- Its 120-second HTTPS soak used eight concurrent workers: 896 successful
  requests, zero failures, 0.175329 seconds maximum latency, 101.95 MiB peak
  controller memory, 3.17% peak CPU, 0.2 MiB root-disk growth, and zero journal
  growth.
- The Azure CP1 VM was not changed. This is local ARM64 foundation evidence, not
  Azure AMD64, managed-PostgreSQL, public-TLS, production, or full-SBC
  acceptance.
- No qualified vulnerability scanner is installed; a vulnerability scan was
  not performed.

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
inventories. It does not claim a vulnerability scan: no supported scanner with
a qualified local vulnerability database is currently installed, so a
vulnerability scan was not performed.

`deploy/.state` is mode-protected and excluded from version control. Commands
use `no_log` for secret-bearing Ansible tasks. The initial lab uses
passwordless sudo only on the disposable UTM VM; that is not the Azure policy.

The current layers qualify the host, nftables, PostgreSQL, PgBouncer, Podman,
and an immutable Django controller image with active/previous release markers.
The enrollment gateway and step-ca are unimplemented future layers that require
separate implementation and qualification. SIP signaling, RTP/media, Edge
Agent behavior, signed artifacts, and production telemetry are also outside
this foundation qualification.
