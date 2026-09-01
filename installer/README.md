# Vivolution CP installer orchestration core

This directory contains the provider-neutral entry point for installing the
Vivolution Controller on an administrator-supplied Ubuntu Server 24.04 LTS
machine. It does not create Azure, AWS, GCP, VMware, DNS, or load-balancer
resources.

The current release exposes **standalone CP1 only**. CP2/CP3 join, replication,
quorum, and witness modes are deliberately rejected until their design and
playbooks are implemented.

This is a release candidate for the first clean-VM qualification. It binds the
installed controller to a deterministic source manifest and immutable base
image, but the source bundle does not yet carry a detached Vivolution publisher
signature. Use it for the planned qualification, not an unreviewed production
deployment.

## Fresh-host prerequisites

- Ubuntu Server 24.04 LTS on AMD64 or ARM64, booted with systemd.
- At least 2 vCPU, 4 GiB RAM, and a 40 GB root disk.
- Working Internet access, NTP enabled and synchronized, and no pending reboot.
- A non-root sudo/SSH administrator with at least one ordinary, option-free
  public key. The home directory must not be group/world writable; `.ssh` must
  be `0700` and `authorized_keys` must be `0600`.
- Two distinct public names, such as `cp1.voice.example.com` and
  `controller.voice.example.com`, both resolving exclusively to the same
  declared globally routable IPv4 address, with no published AAAA records.
- TCP 80 and 443 forwarded to this VM when it is behind NAT. The standalone
  candidate uses direct DNS, does not support an external load balancer, and
  deliberately opens no IPv6 ingress.
- No existing Vivolution installation, PostgreSQL/PgBouncer/Caddy state, or
  foreign listeners on TCP 80, 443, 5432, 6432, or 8000.

## Commands

Run as root on a fresh Ubuntu Server 24.04 LTS host:

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
  --answers /root/cp1-answers.json \
  --accept-configuration
```

```json
{
  "deployment_mode": "standalone",
  "node_fqdn": "cp1.voice.example.com",
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

The rc4 ledger schema remains version 4, so it can safely resume an rc3 run that
failed during the initial read-only preflight. It deliberately refuses
resume/reconcile of an rc2-managed installation. An rc2 host may already have
an alternate-CA certificate cached;
silently reusing that leaf would not prove the new Let's Encrypt-only contract.
This candidate therefore requires a fresh rc3-or-later host until a separately reviewed
certificate migration exists.

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
an IPv4 client, that active session is automatically added so firewall
reconciliation cannot omit it. `ssh_allowed_user` must name the existing
non-root Linux administrator; when omitted, a validated `SUDO_USER` is used.

## State and logs

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
