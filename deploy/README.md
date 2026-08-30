# CP1 deployment kit

This kit keeps the controller host portable across a local lab, a self-contained
Azure acceptance VM, and a future managed-database Azure layout.

## Profiles

- `lab`: installs PostgreSQL 17 on Debian, loopback only.
- `azure-single`: installs PostgreSQL 17, PgBouncer, Caddy, Podman, and CP1 on
  one Debian 13 AMD64 VM. PostgreSQL, PgBouncer, and CP1 remain loopback-only;
  only SSH from approved `/32` sources and public HTTP/HTTPS ingress are
  accepted.
- The isolated three-node POC enables the same `azure-single` controller roles
  in its own inventory, opts into only the fixed CP1 voice-fixture firewall
  ports, and may enable `cp_controller_reconcile_vivolution_poc`. That owner-run
  command creates bounded first-tenant inventory in pending/planned state; it
  does not claim M365 verification or mark either SBC online.
- Each Edge host owns one nftables table with default-deny input, forward, and
  output chains. Common Azure/DNS/NTP/web/control-plane egress is fixed, while
  synthetic fixture and Direct Routing voice egress are mutually exclusive;
  RTPengine UDP is never permitted to arbitrary destinations.
- PBX media is directional: the Edge-local first-tenant range is UDP
  20000-20255, while the separately trusted PBX-side range is exact in node
  facts and signed connector input. Synthetic fixes that remote range to
  21000-21127; the reviewed Direct template uses 30000-30127.
- `azure`: refuses a loopback database target and never installs PostgreSQL;
  it is reserved for the future managed-database topology.
- Every profile places PgBouncer on `127.0.0.1:6432`, so the application
  connection contract does not change between environments.
- Every managed host receives an `LLMNR=no` systemd-resolved policy and
  verification rejects any TCP or UDP listener on port 5355. The deployment
  neither installs nor starts systemd-resolved solely for this policy, and
  unicast DNS remains under the host or cloud network configuration. The
  `azure-single` gate also proves the Azure DNS server, local stub, and a real
  network-backed DNS lookup before and after reboot.

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

For a replacement Azure controller, decrypt the already-qualified off-VM age
archive only as a stream over the pinned SSH connection into the fixed remote
path `/var/lib/vivolution/backups/cp1-qualified-import.pgdump` (root-owned mode
`0600`). `playbooks/restore-replacement-controller.yml` then verifies the
approved SHA-256 and archive inventory, restores into an isolated database,
reinstalls the current signed-RLS key, runs the existing integrity gate, and
only then swaps database names while the application is stopped. The fresh
pre-import database is retained under a deterministic rollback name until
final acceptance; the plaintext remote archive is removed in every outcome.
The playbook refuses to run without the exact acknowledgement
`RESTORE_QUALIFIED_BACKUP_TO_REPLACEMENT_CP1`.

The replacement restore is a durable transaction. A fixed root-owned `0600`
journal is atomically replaced and fsynced before and after import, selection,
readiness, and rollback phases. Every rerun reconciles that exact digest-bound
journal with the database names PostgreSQL actually exposes. It can therefore
distinguish a crash immediately before an atomic rename from a crash
immediately after it, resume only the proven next action, or fail closed on an
unrecognized topology. A completed transaction is idempotently rechecked; a
rolled-back failed import remains visibly failed and is never reported as a
successful restore.

One fixed root-only `flock` is held by a bounded transient systemd unit across
the entire observed-state/import/swap/recovery sequence. A concurrent restore
runner fails before observing or changing PostgreSQL; the lock is released by a
forced handler on every normal/error path and by `RuntimeMaxSec` if the control
connection disappears. The imported operator must also be active, staff,
superuser, and have a usable password hash before selection; the later signed
admin-login qualification still proves the actual configured credential.

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

The controller automation covers the host, nftables, PostgreSQL, PgBouncer,
Podman, and an immutable Django image with active/previous release markers. The
separate first-tenant POC automation now also provides pinned native OpenSIPS
and userspace RTPengine packages, DNS-01 public certificates, a signed
desired-state verifier/compiler, transactional Edge activation/recovery, and a
private no-PSTN SIP/TLS/RTP fixture. These additions do not expand any earlier
CP1 evidence: only a new, clean three-node Azure run and its sealed evidence can
qualify the combined solution. A production enrollment gateway, production
certificate/key lifecycle, multi-tenant media-unit isolation, complete
telemetry, certified-SBC support, and live carrier interworking remain outside
this POC boundary.

Each Edge certificate job must receive the exact host-derived delegated zone
`acme-<node-fqdn>` (for example,
`acme-sbc1.voice.vivolution.ae`). The Azure DNS deployment CNAMEs the public
challenge name into that isolated zone. This is a durable permission boundary:
Lego deletes the challenge TXT record set during cleanup, while the managed
identity's Reader/Contributor roles remain on the child zone. The preflight
rejects the parent zone, the peer's zone, or any non-derived zone name.

The Edge egress contract permits DNS only to Azure WireServer
`168.63.129.16`; direct UDP/TCP queries to Azure's public authoritative
servers are intentionally denied. Lego is therefore pinned to that recursive
resolver and disables only its direct-authoritative propagation probe. It
still requires the exact challenge TXT value through the approved recursive
resolver, follows the public CNAME into the node-isolated child zone, and the
public CA independently validates DNS authority before issuance. The fixed
post-issuance validator continues to require the exact SANs, RSA key, EKU,
chain, lifetime, and public trust. The systemd job allows ten minutes because
two identifiers can each consume the bounded three-minute propagation window;
it remains a hard timeout. Initial installation permits only one automatic
retry after a three-minute managed-identity/RBAC convergence delay. Thus a
persistent DNS or ACME failure is bounded to two service starts (at most 23
minutes including the delay), instead of silently creating dozens of orders.

## Edge profile deployment and replacement

`playbooks/install-edge.yml` and `playbooks/activate-edge.yml` accept exactly
`SYNTHETIC_PRIVATE` generation 1 or `DIRECT_ROUTING` generation 2 and later.
The synthetic branch requires the fixed CP1 fixture files and source. The
Direct Routing branch requires no fixture credential; it requires a
controller-side PBX CA bundle pinned by SHA-256, real globally routable PBX
source CIDRs no broader than `/24`, and separate exact install and activation
acknowledgements.

Activation crosses an exact six-file root-owned inbox boundary, including the
original `signed-envelope.json`. The privileged runtime reads the fixed
root-owned signing-key pin and independently verifies the Ed25519 signature,
local tenant/network identity, replay and rollback lineage, signed local-health
plan, and signed artifact declarations. The unprivileged Agent receipt and
compiler evidence are corroborating inputs, never privileged signing
authority.

Never change an active synthetic node's authority in place. Populate a private
inventory that points `edge_nodes` at distinct reimaged replacement hosts,
sets each predecessor host/generation, supplies signed Direct Routing envelopes,
and preserves the predecessor fleet. The pinned `known_hosts` file must contain
both replacement and predecessor SSH identities. Each predecessor entry also
supplies its explicit SSH user and absolute private-key path; the wrapper pins
its own strict `UserKnownHostsFile` policy and rejects linked or non-`0600` key
and host-key files. Raw-host delegation never inherits the controller user's
identity. The wrapper reads the
predecessor's root authority and runtime status before and after staging and
requires the exact synthetic candidate to remain byte-identical. Then run:

```bash
ANSIBLE_ROLES_PATH=deploy/roles ansible-playbook \
  -i /absolute/private/direct-replacement/hosts.yml \
  deploy/playbooks/transition-direct-routing-replacement.yml
```

The wrapper preflights the replacement contract, imports the normal install
and transactional activation workflows, proves the exact active candidate, and
writes non-secret `DIRECT_ROUTING_REPLACEMENT_STAGED_NO_CUTOVER` evidence. It
does not alter DNS or Microsoft 365. Before that separate cutover, rollback is
fail-safe: leave the preserved synthetic predecessor serving and abandon or
deallocate the replacement. Required acknowledgements are intentionally long,
literal values documented in the private inventory; do not store an
acknowledgement as a standing global default.
The transition inventory must also contain exactly one `controllers` host for
the CP1 fixture. The wrapper runs locked runtime health on the predecessor and
both synthetic call directions through CP1 before and after replacement
staging, then runs locked runtime health on the replacement. Its evidence keeps
`replacementLiveInteroperability=NOT_ASSERTED`; only the separate Microsoft
365/PBX call gate may change that conclusion.

## Private synthetic node-failover gate

`playbooks/qualify-synthetic-node-failover.yml` is the bounded disruptive POC
gate for new-call availability on the generation-1 private fleet. Supply its
exact acknowledgement only on the command line; do not store it as an
inventory default:

```bash
ANSIBLE_ROLES_PATH=deploy/roles ansible-playbook \
  -i /absolute/private/poc-edge/hosts.yml \
  -e edge_synthetic_failover_acknowledgement=RUN_SYNTHETIC_SBC1_TO_SBC2_FAILOVER_WITHIN_120_SECONDS \
  deploy/playbooks/qualify-synthetic-node-failover.yml
```

The playbook binds both healthy nodes to one immutable logical tenant route,
proves a complete two-direction fixture call through SBC1, then starts a
conservative 120-second clock before stopping SBC1 OpenSIPS and RTPengine. It
requires CP1 to observe SBC1 TLS 5061 closed and complete a fresh same-route
two-direction call through SBC2 inside the gate. The alternate command has a
110-second hard process timeout and acceptance time is measured with the
fixture host's monotonic clock, so wall-clock correction cannot shorten the
gate.

Before either service is stopped, SBC1 persists an exact root-owned recovery
marker. One protected node-local injector then arms a 150-second transient
systemd deadman and stops OpenSIPS followed by RTPengine, eliminating a runner
or SSH gap between arming recovery and injecting the failure. If the runner or
session disappears, that timer starts RTPengine and then OpenSIPS; the marker
remains. A rerun detects the marker, restores the same order, proves active
services, exact protected runtime status/health, and a fresh SBC1 call, then
disarms the timer and removes only the exact recovery directory. The normal
unconditional recovery uses the same checks. Neither path disarms or removes
the marker before the post-restore call passes.

The offline compiler `scripts/synthetic_failover_evidence.py` verifies the
complete bounded contents of all three fixture SHA-256 manifests, rejects
missing/extra/unverified/linked or wrongly protected result files, and binds
positive RTP/CDR deltas, exact node/runtime identity, complete injected stop,
monotonic timing, and restoration. Each phase also exports Edge CDRs and must
produce exact Edge-to-fixture reconciliation evidence as defined in
[`poc/synthetic-cdr-evidence.md`](../poc/synthetic-cdr-evidence.md). Canonical
evidence is written only below the ignored private inventory's
`generated/synthetic-failover/` directory. The result always records
`liveM365Interoperability=NOT_ASSERTED` and
`activeCallMigration=NOT_TESTED_NOT_CLAIMED`: the private runner selects SBC2
itself and does not simulate or claim Microsoft OPTIONS/gateway selection.

## Interrupted Edge activation recovery

If SSH or the operator process is lost after Agent staging, do not delete state
or rerun activation over the existing workspace. Populate the five dedicated
recovery identity values in the protected per-host inventory so they exactly
repeat the original node, profile, generation, sequence, and manifest digest.
Then supply the one-time acknowledgement and run:

```bash
ANSIBLE_ROLES_PATH=deploy/roles ansible-playbook \
  -i /absolute/private/poc-edge/hosts.yml \
  -e edge_activation_recovery_acknowledgement=RECOVER_EXACT_EDGE_ACTIVATION \
  deploy/playbooks/recover-edge-activation.yml
```

The recovery playbook is serialized across the Edge fleet. For each node it
first invokes the root runtime journal recovery, proves a journal-free protected
runtime identity and locked baseline health, and inspects the Agent's fully
validated protected state as the unprivileged service user. It permits only
five outcomes: clean only exact candidate-specific debris when Agent staging
never completed, commit the exact pending candidate when that candidate is the
healthy runtime, abort it when the exact prior Agent LKG is the healthy runtime,
or verify those same terminal states were already committed/aborted. The
never-staged path also covers the first activation, where protected Agent state
does not yet exist, but only when the runtime is untouched bootstrap state and
legacy/v3 state files are securely proven absent. A runtime
`COMMIT_PENDING` or `ABORT_PENDING` recovery result must agree with that
classification. Baseline health is never commit authority: a commit names the
original immutable `RUNTIME_APPLIED_HEALTHY` evidence digest, and the Agent
reopens the fixed root-owned evidence file, verifies its self-digest, exact
signed local-health plan and ordered results, candidate/release identity, and
profile-specific runtime checks. A no-live-change preflight rejection and a
healthy rollback both produce exact `ABORT_PENDING` evidence, so neither leaves
staged Agent state stranded. An Agent abort atomically records the candidate's
sequence and manifest digest in the protected last-aborted tombstone; recovery
will not classify `ALREADY_ABORTED` from the replay floor alone.

After the health-gated exact Agent transition, both protected states and
runtime health are reread and compared again. Only then are the exact
candidate-specific abandoned Agent workspace and root inbox removed. Runtime,
Agent, and terminal non-secret evidence remain both on the node and under the
ignored protected controller evidence directory. Rerunning the playbook proves
`ALREADY_COMMITTED` or `ALREADY_ABORTED` and is idempotent; an identity mismatch,
missing/mismatched abort tombstone, unexpected journal result, unhealthy
runtime, or replaced cleanup path fails closed without deleting it.
