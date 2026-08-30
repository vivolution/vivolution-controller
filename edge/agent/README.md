# Edge Agent security core

This directory contains the bounded v0.1 acceptance boundary between a signed
CP1 desired-state envelope and future Edge activation code. It verifies and
stages a pending candidate, then provides explicit local metadata-only commit
and abort transitions. It never downloads artifacts or secrets, applies
configuration, executes commands, opens a listener, or requires root.

## Security invariants

- Envelope JSON is size-bounded, decoded as strict UTF-8 and parsed through
  `edge/schema/manifest_tool.py`, including duplicate-member rejection and its
  canonical manifest bytes.
- The parsed envelope must pass non-optional Draft 2020-12 validation with
  Debian's `python3-jsonschema` against the checked-in v0.1 schema before any
  semantic validation. A missing dependency, missing schema, invalid schema or
  malformed envelope fails closed.
- At least one Ed25519 signature over
  `edge.vivolution.ae/SignedDesiredState/v0.1\0 || canonical_manifest` must
  verify using Debian's `python3-cryptography` against an explicit key-id
  allowlist. A key named only by the envelope is never trusted.
- The manifest must equal a frozen, locally supplied cluster, node, generation,
  slot, scope and (for tenant state) complete tenant identity. The protected
  state file is permanently bound to that same identity.
- Tenant signaling and media allocations are also local-authority inputs. The
  manifest must contain exactly one tenant listener and media resource matching
  those ports, tenant port 5061 is forbidden, and the media allocation must sit
  inside the locally provisioned cluster pool.
- The connector's PBX media destination start/end are separate immutable local
  authority. The exact signed range must match those node-local values, remain
  canonical and bounded, avoid signaling/control-port collisions, and provide
  at least two UDP ports per declared non-multiplexed session.
- ACTIVE tenant authority additionally binds the exact globally routable
  advertised IPv4 and a canonical, sorted, non-overlapping PBX CIDR allowlist
  no broader than `/24`. ACTIVE cluster authority binds the corresponding
  Microsoft CIDR allowlist, globally routable and no broader than `/14`.
  These inputs are persisted in protected identity state and cannot be rebound
  by changing CLI flags after first stage; the same flags remain mandatory for
  later ABSENT/DECOMMISSION transitions so identity continuity is explicit.
- Expiry, monotonic sequence, previous digest and rollback lineage are enforced
  by the existing v0.1 semantic validator while an exclusive file lock is held;
  rollback artifact digests must also match protected last-known-good metadata.
- Protected format v3 separates `highestSeenSequence`, `pendingCandidate`,
  `activeLastKnownGood`, and the minimal `lastAbortedCandidate` tombstone.
  Staging advances the replay floor and pending metadata only. Each candidate
  binds `localHealthGatePlanDigest`, calculated over the canonical full signed
  `healthGates` array plus its `manifestDigest`. It never promotes a candidate
  or replaces rollback lineage.
- The only commit-capable tenant plan is the ordered local set
  `ARTIFACT_DIGESTS`, `OPENSIPS_CONFIG`, `RTPENGINE_READY`, with the reviewed
  timeouts, attempts and `ROLLBACK_TO_TARGET`. External SIP OPTIONS, synthetic
  calls, PSTN calls and Teams interoperability are never accepted as local
  commit proofs and remain `NOT_ASSERTED`.
- `commit-pending` has no Boolean health override and accepts no evidence path.
  It takes the digest of a root-produced success record, derives the only valid
  filename beneath `/var/lib/vivolution-edge/runtime/evidence`, and validates
  the canonical record, self-digest, pending identity, signed plan, exact
  ordered results/proofs, attempts, release digest, rollback result, profile
  checks, and runtime checks before promotion. `abort-pending` atomically clears
  only the exact pending candidate and records its sequence/manifest digest as
  the protected last-aborted tombstone. It preserves active LKG and the replay
  floor, so a failed candidate cannot be replayed and interrupted recovery can
  bind an already-completed abort to the exact candidate.
- `status` takes the same complete immutable context, locks and fully validates
  protected state, then returns only the active, pending, and last-aborted
  sequence/manifest-digest summaries plus the replay floor. It exposes no
  artifacts, signatures, keys, or configuration and fails if state is absent
  or bound to another identity.
- If the first-ever candidate is aborted, no active LKG exists. The structural
  contract requires lineage for sequence 2+, while semantic validation forbids
  lineage when no LKG exists, so neither null nor aborted-candidate lineage is
  accepted. Recovery requires reviewed retirement of that target state and
  re-enrollment; this core never silently resets its replay floor.
- State uses fixed leaf names beneath an absolute, pre-created directory.
  Directory components and state/lock files are opened with `O_NOFOLLOW`; the
  directory must be owned by the process user and not group/world writable.
  State and lock files must be owner-only regular files with one hard link.
- A separate stable lock inode covers read, validation and replacement. New
  canonical state is written to an owner-only same-directory temporary file,
  `fsync`ed, atomically renamed, and followed by a directory `fsync`. A crash
  before rename leaves the old state authoritative; stale temp files are never
  read as state.
- Runtime success evidence is read through `openat`/`O_NOFOLLOW` from the fixed
  absolute directory only. The directory must be
  `root:vivolution-edge-agent 0750`; the digest-derived evidence file must be a
  canonical, single-link regular file owned `root:vivolution-edge-agent 0440`.
  The Agent account has read access but cannot replace or forge evidence.

Formats v1 and v2 are refused rather than automatically migrated. V1 conflated
a staged candidate with active LKG; v2 did not bind the signed local-health
plan. A reviewed migration must independently prove which configuration is
active and which signed plan authorized it.

Activation/rollback execution, artifact and secret retrieval, enrollment,
initial identity provisioning, signing-key rotation, and tamper resistance
against root remain out of scope. The separate privileged runtime produces the
immutable local-health evidence; this Agent only validates and consumes it.

## Runtime dependency

On Debian install the distribution package:

```sh
apt-get install python3-cryptography python3-jsonschema
```

No Python package installer or daemon is required by the agent core.

Create a private state directory as the non-root Edge service account, for
example:

```sh
install -d -m 0700 "$PWD/edge-state"
```

Use a distinct state directory for each immutable cluster or tenant target;
the first accepted envelope permanently binds that directory to its local
identity.

Then run from the repository root. Public keys are raw 32-byte Ed25519 public
keys encoded as canonical base64; repeat `--pinned-key` during an authorized
key overlap:

```sh
python3 -m edge.agent verify-and-stage signed-envelope.json \
  --state-dir "$PWD/edge-state" \
  --scope TENANT \
  --cluster-id cluster-uaen-poc-01 \
  --node-id sbc1 \
  --generation 1 \
  --slot A \
  --customer-account-id vivolution-technologies-llc \
  --m365-tenant-id 9b7a1c2d-3e4f-4a5b-8c6d-7e8f9012abcd \
  --tenant-context-id tenant-vivolution-poc \
  --service-instance-id service-vivolution-pbx-relay \
  --allocation-id allocation-vivolution-uaen-poc \
  --tenant-listener-port 15061 \
  --tenant-media-port-start 20000 \
  --tenant-media-port-end 20255 \
  --pbx-media-destination-port-start 30000 \
  --pbx-media-destination-port-end 30127 \
  --cluster-media-port-start 20000 \
  --cluster-media-port-end 29999 \
  --expected-advertised-public-ip 20.74.155.72 \
  --authorized-pbx-source-cidr 203.0.113.10/32 \
  --pinned-key 'cp1-signing-2026-01=BASE64_RAW_PUBLIC_KEY'
```

For a cluster target, omit every tenant identity/allocation/network flag and
provide the locally authorized Microsoft networks in canonical sorted order:

```sh
python3 -m edge.agent verify-and-stage signed-cluster-envelope.json \
  --state-dir "$PWD/edge-cluster-state" \
  --scope CLUSTER --cluster-id cluster-uaen-poc-01 --node-id sbc1 \
  --generation 1 --slot A \
  --authorized-microsoft-source-cidr 52.112.0.0/14 \
  --authorized-microsoft-source-cidr 52.120.0.0/14 \
  --pinned-key 'cp1-signing-2026-01=BASE64_RAW_PUBLIC_KEY'
```

Only canonical result evidence is written to standard output. Rejections go to
standard error and leave the prior protected state unchanged.

After the privileged runtime succeeds, repeat the exact immutable
context/allocation flags above, identify the pending candidate exactly, and
provide the digest printed in its immutable success evidence:

```sh
python3 -m edge.agent commit-pending \
  --state-dir "$PWD/edge-state" \
  --scope TENANT --cluster-id cluster-uaen-poc-01 --node-id sbc1 \
  --generation 1 --slot A \
  --customer-account-id vivolution-technologies-llc \
  --m365-tenant-id 9b7a1c2d-3e4f-4a5b-8c6d-7e8f9012abcd \
  --tenant-context-id tenant-vivolution-poc \
  --service-instance-id service-vivolution-pbx-relay \
  --allocation-id allocation-vivolution-uaen-poc \
  --tenant-listener-port 15061 \
  --tenant-media-port-start 20000 --tenant-media-port-end 20255 \
  --pbx-media-destination-port-start 30000 \
  --pbx-media-destination-port-end 30127 \
  --cluster-media-port-start 20000 --cluster-media-port-end 29999 \
  --expected-advertised-public-ip 20.74.155.72 \
  --authorized-pbx-source-cidr 203.0.113.10/32 \
  --sequence 1 --manifest-digest 'sha256:...' \
  --runtime-evidence-digest 'sha256:...'
```

On apply or health failure, use the same arguments with `abort-pending` and
omit `--runtime-evidence-digest`. The active LKG remains the rollback authority
and the aborted sequence remains below the protected replay floor.

Interrupted activation recovery uses `status` with the same immutable context
before and after reconciliation. It is intentionally not a path-free shortcut:
all identity, tenant allocation, advertised-address, and PBX-authority flags
remain mandatory so protected-state rebinding still fails closed.
Recovery commit must pass the original `lastEvidenceDigest`; a fresh baseline
health check cannot replace the original signed-plan result. An
`ALREADY_ABORTED` recovery is legal only when the protected last-aborted
tombstone matches both the requested sequence and manifest digest.

## Focused tests

```sh
python3 -m unittest discover -s edge/agent/tests -v
```
