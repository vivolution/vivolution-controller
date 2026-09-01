# Vivolution turnkey installer orchestration

This directory contains the provider-neutral entry point for configuring a
Vivolution role on an administrator-supplied host. It does not create Azure,
AWS, GCP, VMware, DNS, NAT, load-balancer, Microsoft 365, or carrier resources.

The `v0.3.0-rc6` beta exposes the neutral universal launcher, but enables only
creation of one standalone Controller plus bounded diagnostics and management.
It does not make Controller joining, Controller HA, or the complete SBC voice
role available. Those paths remain visibly unavailable until their own
implementation and qualification gates pass.

This is a release candidate for the first clean-VM qualification. It binds the
installed controller to a deterministic source manifest and immutable base
image, but the source bundle does not yet carry a detached Vivolution publisher
signature. Use it for the planned qualification, not an unreviewed production
deployment.

## v0.3.0-rc6 beta boundary

The following is the rc6 beta contract. Package/static/security verification is
complete, but this remains a prerelease rather than a fresh-Ubuntu or
production qualification claim.

```text
Vivolution Turnkey Installer

> Create a new Controller Plane
  Join an existing Controller Plane          [Unavailable]
  Deploy an Edge Appliance (SBC)             [Unavailable]
  Manage an existing installation
  Diagnostics / network readiness test
```

The menu uses Up/Down arrows on a capable TTY and a numbered fallback
elsewhere. It never suggests `CP1`, `CP2`, `CP3`, `SBC1`, or `SBC2` as a
hostname. A node receives an immutable internal ID and uses the FQDN/display
name chosen by the operator.

The rc6 beta enables only:

- creation of a new one-node Controller Plane on Ubuntu Server 24.04;
- non-mutating diagnostics/network-readiness checks; and
- a bounded Manage path for status, redacted support-bundle creation,
  resume of an incomplete schema-5 run, reconcile of a completed schema-5
  installation, and discard only when the ledger proves no host mutation
  occurred.

Controller join/replication/quorum/fencing, complete SBC deployment, upgrade,
rollback, repair, backup/restore, post-mutation uninstall, and node removal are
design-only. Selecting an unavailable path must explain this boundary and
return safely; it must not install a second independent Controller or an
enrollment-only client while calling it an SBC.

The full private voice-plane deployment currently has a Debian 13 AMD64 host
contract. The public Controller and enrollment-only Edge artifacts target
Ubuntu 24.04. The rc6 Ubuntu menu must therefore keep the complete SBC path
unavailable until the OpenSIPS/RTPengine runtime is ported and independently
qualified on the declared role-specific OS.

### rc6 interactive preflight

- Public IPv4 discovery uses short-timeout HTTPS queries to independent
  address-echo sources, validates and compares their answers, labels the result
  as an outbound/NAT observation, and requires operator confirmation or manual
  override. Discovery failure offers Retry, manual entry, network requirements,
  or safe exit.
- DNS validation through the host resolver reports lookup failure, wrong A
  answers, and forbidden AAAA answers. It offers Retry, a bounded timed retry,
  change values, a direct propagation-check link, or safe exit without losing
  the other validated answers. Retry paths make a bounded best-effort flush of
  the local systemd-resolved cache. Direct authoritative-recursive comparison
  and CAA diagnosis remain future diagnostics work.
- Firewall ownership is explicit. `Infrastructure-managed` is the default and
  leaves UFW ownership to the operator's NSG/cloud/on-premises firewall while
  publishing the exact port contract. `Installer-managed` previews and applies
  a deny-by-default UFW policy while preserving verified administrator access.
  Neither mode silently opens SSH to `0.0.0.0/0`.
- Timezone is selected from the host's IANA list rather than free text. Chrony
  is the rc6 Controller time service, using either automatic/provider sources
  or validated custom primary/secondary/additional NTP sources. The installer
  applies time configuration and proves synchronization before certificates,
  database, or Controller activation.

### rc6 source and installed commands

These are the same lifecycle commands packaged by the rc6 launcher. The public
permanent bootstrap remains checksum-pinned to the explicitly promoted
prerelease.

```sh
sudo ./installer/install.sh
sudo ./installer/install.sh diagnostics
sudo ./installer/install.sh diagnostics \
  --node-fqdn node-a.voice.example.com \
  --shared-fqdn controller.voice.example.com \
  --public-ip 1.1.1.1
sudo ./installer/install.sh status
sudo ./installer/install.sh resume --verbose
sudo ./installer/install.sh reconcile --verbose
sudo ./installer/install.sh support-bundle --output /root/vivolution-support.tar.gz
sudo ./installer/install.sh discard-incomplete --dry-run
sudo ./installer/install.sh discard-incomplete
```

No argument opens the universal menu. `diagnostics` is read-only and does not
create installer state. It reports current/legacy installer state, host OS,
three-source public-IP observations, the Controller port contract, and current
systemd time state; optional FQDN/address arguments add system-resolver A/AAAA
checks. `discard-incomplete --dry-run` prints the exact bounded plan. The
deletion form revalidates the evidence under lock and requires the exact token
`DISCARD-INCOMPLETE` at the terminal. `--verbose` shows redacted, bounded
apt/Ansible output that is always retained in the protected logs.

The menu's Manage section enables actions according to state: status always;
support bundle, resume, or reconcile for compatible schema-5 state; and discard
for a recognized incomplete schema-5 pre-mutation ledger. A recognized legacy
schema-4 ledger enables a cleanup preview only; deletion is refused.

## Fresh-host prerequisites (current Controller role)

- Ubuntu Server 24.04 LTS on AMD64 or ARM64, booted with systemd.
- At least 2 vCPU, 4 GiB RAM, and a 40 GB root disk.
- Working outbound Internet/DNS access, no pending reboot, and an approximately
  correct clock so the initial HTTPS bootstrap can be authenticated. The rc6
  candidate configures and verifies Chrony before service activation.
- A non-root sudo/SSH administrator with at least one ordinary, option-free
  public key. The home directory must not be group/world writable; `.ssh` must
  be `0700` and `authorized_keys` must be `0600`.
- Two distinct public names, such as `node-a.voice.example.com` and
  `controller.voice.example.com`, both resolving exclusively to the same
  declared globally routable IPv4 address, with no published AAAA records.
- TCP 80 and 443 forwarded to this VM when it is behind NAT. The standalone
  candidate uses direct DNS, does not support an external load balancer, and
  deliberately opens no IPv6 ingress.
- No existing Vivolution installation, PostgreSQL/PgBouncer/Caddy state, or
  foreign listeners on TCP 80, 443, 5432, 6432, or 8000.

## Published rc5 behavior (legacy reference)

The following commands and schema apply only to the immutable
`v0.3.0-rc5` source/release, not `v0.3.0-rc6`:

```sh
sudo ./installer/install.sh
sudo ./installer/install.sh check-host-os
sudo ./installer/install.sh status
sudo ./installer/install.sh resume
sudo ./installer/install.sh reconcile
sudo ./installer/install.sh support-bundle --output /root/vivo-support.tar.gz
```

For unattended installation, pass a JSON answer file:

```sh
sudo ./installer/install.sh install \
  --answers /root/controller-answers.json \
  --accept-configuration
```

```json
{
  "deployment_mode": "standalone",
  "node_fqdn": "node-a.voice.example.com",
  "shared_fqdn": "controller.voice.example.com",
  "public_ipv4": "1.1.1.1",
  "ssh_source_cidrs": ["8.8.8.8/32"],
  "ssh_allowed_user": "ubuntu",
  "admin_username": "cpadmin",
  "admin_email": "admin@example.com",
  "acme_email": "certificates@example.com"
}
```

`acme_email` is the Let's Encrypt ACME account contact. For compatibility with
an older protected answer file it defaults to the validated `admin_email`, but
every new interactive installation asks for it explicitly and offers the
administrator email as the default.

The rc5 ledger schema remains version 4, so it can safely resume an rc3/rc4 run
that failed during the initial read-only preflight. It deliberately refuses
resume/reconcile of an rc2-managed installation. An rc2 host may already have
an alternate-CA certificate cached;
silently reusing that leaf would not prove the new Let's Encrypt-only contract.
This candidate therefore requires a fresh rc3-or-later host until a separately
reviewed certificate migration exists.

Ubuntu 24.04 normally publishes `/etc/os-release` as the relative symlink
`../usr/lib/os-release`. The host check accepts only that canonical link or a
direct regular file, then opens the selected root-owned metadata file without
following a final symlink. `check-host-os` exercises this packaged compatibility
gate without creating installer state or changing the host.

Unknown keys and non-standalone modes fail closed. Passwords and application
secrets are generated locally and are never accepted through the answer file.
`--accept-configuration` is deliberately required with an answer file; merely
providing the file cannot authorize host mutation. Interactive installation
prints the complete validated, non-secret configuration and requires the exact
token `INSTALL`. Declining leaves apt and controller services untouched and the
durable ledger can be continued with `resume`.

Before that confirmation, the read-only preflight requires:

- Ubuntu 24.04 with systemd, no pending `/var/run/reboot-required`, and an
  NTP-enabled, synchronized clock;
- no existing listeners on TCP 80, 443, 5432, 6432, or 8000;
- any listener on TCP 22 to be owned exclusively by `sshd`; and
- both the distinct node and shared FQDNs to resolve over IPv4 exclusively to
  the public IPv4 entered by the administrator, with no AAAA records because
  this standalone profile deliberately exposes no IPv6 ingress.

DNS is checked once before confirmation and again immediately before apt. The
clock, reboot marker, and listener inventory are also rechecked at that final
read-only boundary, including after a delayed resume. Up to sixteen exact IPv4
SSH /32 sources are accepted, matching the Ansible enforcement limit.
RFC1918 or public management /32s are accepted. When `SSH_CONNECTION` contains
an IPv4 client, the wizard offers that address as its default and automatically
adds it so firewall reconciliation cannot omit the active session. If `sudo`
does not preserve the SSH connection metadata, the field is required and
invalid or blank input is re-prompted immediately. `0.0.0.0/0` is deliberately
refused: opening administrative SSH to the entire Internet is not a safe
turnkey default. `ssh_allowed_user` must name the existing non-root Linux
administrator; when omitted, a validated `SUDO_USER` is used.

## Current rc5 state and logs

- Real-install atomic phase ledger: `/var/lib/vivolution-installer/ledger.json`
- Protected generated secrets: `/var/lib/vivolution-installer/secrets.json`
- Final web credential handoff: `/var/lib/vivolution-installer/credentials.txt`
- Safe final summary: `/var/lib/vivolution-installer/summary.json`
- Real-install redacted human log: `/var/log/vivolution-installer/install.log`
- Real-install redacted JSONL events: `/var/log/vivolution-installer/events.jsonl`
- Dry-run state: `/var/lib/vivolution-installer-dry-run/`
- Dry-run logs: `/var/log/vivolution-installer-dry-run/`

All of these paths are root-only. The support bundle uses an explicit allowlist
and excludes both `secrets.json` and `credentials.txt`.

Default dry-run state and logs are physically separate from real installation
state. Consequently, a completed `install --dry-run` cannot block a later real
`install`. Inspect them with `status --dry-run` or create their support archive
with `support-bundle --dry-run`. Explicit `--state-dir` and `--log-dir`
overrides remain available when a different protected location is required.

An exclusive `flock` prevents simultaneous installer commands. `resume` skips
only atomically completed phases and reuses the original generated secrets.
After preflight, questions, DNS validation, explicit confirmation, and local
source/base-image validation, a separate logged and resumable apt phase installs `ansible-core`,
`ca-certificates`, `python3-apt`, and `ufw`. Apt and Ansible output are redacted,
shown live on the console, and appended with an `fsync` per line to the human
log. If power is lost, progress emitted before the loss is already durable.
Network-service units remain masked until the exact firewall and their managed
configuration are ready, so a failed package phase cannot expose a default
service after reboot.

## rc6 secured namespace and evidence contract

rc6 begins the secured-namespace migration by moving its transaction state to
`/var/lib/vivolution/installer`, logs to `/var/log/vivolution/installer`, and
exact host-ownership records beneath `/var/lib/vivolution/ownership`. It does
not yet claim that every existing Controller runtime path has migrated.

```text
/var/lib/vivolution/installer/ledger.json
/var/lib/vivolution/installer/answers.json
/var/lib/vivolution/installer/ownership.json
/var/lib/vivolution/installer/secrets.json
/var/lib/vivolution/installer/credentials.txt
/var/lib/vivolution/installer/summary.json
/var/log/vivolution/installer/install.log
/var/log/vivolution/installer/events.jsonl
```

These files and their parent directories are root-only. Dry-run state and logs
remain physically separate under `installer-dry-run` subdirectories.

The approved complete target is one clearly owned Vivolution **FHS namespace**,
not one writable directory containing code, configuration, secrets, databases,
logs, and sockets together:

```text
/opt/vivolution/releases/  immutable application releases
/etc/vivolution/           root-owned configuration and protected secrets
/var/lib/vivolution/       persistent state, ledger, ownership manifest and data
/var/log/vivolution/       installer/runtime logs and lifecycle audit evidence
/var/cache/vivolution/     disposable, digest-verified staging and cache
/run/vivolution/           volatile sockets, locks and PID/runtime files
```

Only bounded integration files may be written to standard systemd, apt, SSH,
Caddy, PostgreSQL, and firewall locations. The rc6 host manifest records the
installed role, release identity, selected firewall/time settings, and the
Vivolution namespace roots. It is ownership evidence and a foundation for a
future complete mutation manifest; rc6 does not claim post-mutation automatic
uninstall. Configuration, secrets, state, and logs use least-privilege
ownership/modes; private keys and credentials are never stored in release or
cache trees.

Moving immutable releases to `/opt/vivolution/releases` and completing the
remaining runtime/cache migration is a later, separately tested lifecycle
change. rc6 documentation must not imply that this full move has occurred.

The rc6 beta implements detailed redacted evidence in the protected human
log and JSONL event log:

- levels `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`, and `FATAL`, with a separate
  lifecycle/security `AUDIT` stream;
- RFC 3339 UTC timestamp and event name on every structured record, plus
  installation/run/correlation and phase/attempt/step context whenever that
  context is applicable and known;
- the bootstrap and Ansible execution runner recording a sanitized semantic
  command description, working directory, effective numeric identity where
  known, start/end/duration, exit code, and ordered redacted stdout/stderr;
- normal console output with bounded sanitized command output when verbose
  mode is selected; there is no unredacted mode and no shell `set -x`
  transcript;
- 10 MiB size rotation with five retained generations for both evidence files,
  plus per-command output ceilings of 10,000 lines and 4 MiB; and
- an explicit support-bundle allowlist that excludes credentials, private keys,
  enrollment grants, database URLs, authorization headers, carrier secrets,
  and customer-sensitive call data.

Commands shown in evidence are semantic/redacted descriptions. Recording raw
shell text and output without filtering is forbidden because it can leak
secrets even when the command itself looks harmless.

## Failed-run cleanup and uninstall boundary

The rc6 Manage path offers **Discard incomplete deployment** only when the
schema-5 ledger and ownership manifest prove that the run stopped before the
first mutation. The operator can create a schema-5 redacted support bundle
separately. `discard-incomplete --dry-run` previews every exact allow-listed object;
deletion requires `DISCARD-INCOMPLETE`, removes only allow-listed installer
state/log objects, and refuses if manifest, ownership, phase, path type, or
directory contents are inconsistent. This is a failed-attempt reset, not
uninstall.

The stable non-secret, PID-bearing coordination lock at
`/run/vivolution/installer.lock` is intentionally retained after discard until
the host reboots. Keeping the
volatile lock inode prevents another installer process from acquiring a new,
different inode while the discard command is still finishing; Ubuntu clears
`/run` at boot. Persistent installer state and log objects are removed by the
exact displayed plan.

If apt, firewall, service, database, certificate, or application mutation may
have begun, rc6 must preserve the evidence and offer resume/support guidance.
It must not claim or attempt a general uninstall. A future uninstall requires a
manifest-driven plan, backup/export option, service drain, credential and node
identity revocation, exact integration-file removal, and safe package ownership
accounting. It must never remove a shared package, foreign database, unrelated
firewall rule, customer DNS/cloud object, or external backup implicitly.

### Moving from rc5

rc6 does not resume, upgrade, or automatically delete an rc5 schema-4 ledger.
It can detect a recognized rc3-rc5 schema-4 ledger and produce a cleanup preview
only when the exact legacy allowlist is present and `bootstrap`, `secrets`,
`ansible`, and `summary` all remain pending. Execution is refused because the
older removable lock cannot provide race-free cleanup against the rc5 code.
The acceptance path is a fresh Ubuntu 24.04 VM. Any old host requires a
separately reviewed offline cleanup/migration procedure.

Caddy is configured with exactly one certificate issuer: the Let's Encrypt
production ACME directory. It registers with the validated `acme_email`,
requests public certificates for both configured FQDNs, redirects HTTP to
HTTPS, stores its managed keys under the protected Caddy service data directory,
and renews automatically. It has no ZeroSSL or local/self-signed fallback in
this profile. The existing trusted HTTPS probes cause installation to fail
closed when public issuance does not complete. TCP 80/443 reachability, fully
propagated A records, and any CAA permission for `letsencrypt.org` remain the
administrator's prerequisites.

On success, the handoff prints and persists these endpoints:

- Console: `https://<shared-fqdn>/admin/`
- Documentation: `https://<shared-fqdn>/docs/`
- Recovery: `https://<shared-fqdn>/recovery/`

## Testing and packaging hooks

`--dry-run` completes validation and state generation without invoking Ansible.
`--root /tmp/fake-root` remaps operating-system/state/log paths for safe tests;
it also permits non-root execution. `--source-root`, `--playbook`,
`--ansible-config`, and `--ansible-playbook` make the Ansible handoff
configurable without putting secret values on the process command line.

The orchestration engine is one standard-library module, so it can later be
placed directly into a Python 3.12 zipapp. The bootstrap intentionally requires
Python 3.12, which is the system Python supplied by Ubuntu 24.04.

## Reconcile versus resume

Use `resume` only for the current interrupted or failed install/reconcile run.
Use `reconcile` after a real installation has completed when current packaged
controller source or declarative configuration must be applied again.

Reconcile validates and reuses the protected stored answers and secrets. It
preserves the completed preflight, answers, confirmation, bootstrap, and
secrets phase records, then resets only `release`, `ansible`, and `summary`.
The release ID is recalculated before Ansible runs. A dry-run ledger, missing
ledger, or incomplete/failed ledger is refused.

The protected ledger retains `run_count`, `reconcile_count`, and a timestamped
record for every install/reconcile run, including failures and resume times.
