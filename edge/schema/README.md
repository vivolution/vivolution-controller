# Edge desired state v0.1

This directory defines the canonical signed desired-state contract between CP1
and one enrolled Edge node. It is a contract and test artifact only; it does not
perform deployment or apply configuration.

## Files

- `edge-desired-state-v0.1.schema.json` is the JSON Schema 2020-12 structural
  contract.
- `manifest_tool.py` provides dependency-free canonical JSON, SHA-256 and the
  security-critical semantic preflight needed on a minimal node.
- `examples/v0.1-one-tenant-pbx-relay.json` is a complete Vivolution
  Technologies LLC PBX Relay example for SBC1.
- `examples/v0.1-one-tenant-pbx-relay.sha256` is independently testable digest
  evidence for the canonical `manifest` member.
- `vectors/ed25519-v0.1-example.json` is a deterministic cross-language
  canonicalization/domain-separation/Ed25519 vector. Its private seed is public
  test material and must never be used outside tests.

The example uses documentation-only IP ranges and placeholder artifact digests,
secret versions and signature bytes. It is not deployable material and is not a
claim that the Ed25519 signature is valid.

## Signed bytes and digest

1. Parse UTF-8 JSON while rejecting duplicate object members.
2. Canonicalize only the `manifest` member: sort ASCII member names, emit no
   insignificant whitespace, preserve array order, use UTF-8 strings, and emit
  integers in decimal. Floating-point/exponent tokens and integers outside the
  interoperable `[-(2^53-1), 2^53-1]` domain are rejected during parsing.
3. `manifestDigest` is `sha256:` plus the lowercase SHA-256 hex digest of those
   canonical manifest bytes.
4. Each Ed25519 signature is calculated over the domain-separated bytes
   `edge.vivolution.ae/SignedDesiredState/v0.1\0` followed by the canonical
   manifest bytes.

The constrained data domain is compatible with RFC 8785/JCS without needing a
floating-point canonicalizer. Implementations in other languages must reproduce
the same bytes and must not normalize Unicode strings.

`manifest_tool.py` checks signature encoding but deliberately does not perform
Ed25519 verification. The Edge Agent/root helper must verify an authorized,
pinned signing key before an apply path. A `PREFLIGHT_VALID` result by itself is
therefore never authorization to activate state.

## Enforcement model

Every envelope targets one immutable `(clusterId, nodeId, generation)` and one
scope. A tenant target additionally binds the legal customer, Microsoft tenant,
technical tenant context, service instance and allocation. The node supplies its
own expected target and protected high-water state to validation; signed fields
are not trusted as that local context.

Tenant and cluster state are deliberately different schema branches:

- A `TENANT` manifest may contain only typed tenant connector, PBX listener,
  route, media and capacity resources. Every artifact, secret reference, health
  gate, resource and rollback target repeats the tenant/allocation identity, and
  semantic validation requires exact equality with the target.
- A `CLUSTER` manifest owns software, the shared Teams listener and shared
  firewall policy. A tenant manifest is structurally unable to name those
  resource types or cluster artifacts.
- `resourceSet.mode=COMPLETE` means the list is the complete desired inventory
  for that exact target. It avoids ambiguous patch/delete behavior and makes
  drift comparison deterministic.
- `lifecycle=ACTIVE` requires the complete tenant five-type inventory or the
  complete cluster baseline (four named software components, shared Teams
  listener and default-deny firewall), plus every mandatory typed health gate.
- A tenant may use `lifecycle=ABSENT` only with empty artifact, secret and
  active-resource arrays, an exact tenant/allocation-bound
  `TENANT_RESOURCES_ABSENT` cleanup intent, and its typed absence gate. A
  cluster may use `DECOMMISSION` only with empty arrays and an exact node-bound
  intent/gate. Cluster `ABSENT` is deliberately unsupported and rejected.
- Artifacts are immutable, size-bounded and fetched only through a
  content-addressed controller path. The declared fetch path must match the
  SHA-256 digest, every resource must name exact artifacts, and unused artifacts
  are rejected.
- Secret entries carry reference identity, purpose, version and offline policy
  only. Values, ciphertext, passwords, tokens and private-key material are not
  valid manifest fields. Every consuming field is purpose-bound, every used
  secret must set `requiredOnNode=true`, and unused references are rejected.
- Tenant activation health gates are limited to the three checks the node can
  prove inside the transactional apply boundary: artifact digests, parsed and
  active OpenSIPS configuration, and RTPengine readiness. There are no commands,
  scripts, raw paths, service-unit names or arbitrary helper arguments in the
  contract. Each gate type must reference exactly the applicable resource
  type(s), with one gate per type. Peer OPTIONS, bidirectional calls, and N-1
  behavior require external participants; they are separately sealed
  environment-acceptance evidence and are never asserted by a local activation.

The node's locally protected validation context—not signed self-assertions—also
supplies its public media IP and authorized PBX/Microsoft source CIDR envelopes.
The media IP must match exactly, signed source networks must be subsets, and
all-addresses `/0` networks are forbidden. Activation TTL is at most one hour;
issued-at time is bounded to one hour in the past and five minutes in the
future, and an expired envelope is always rejected.

Sequence is strictly greater than the node's protected per-target high-water
mark. For non-initial state, `previousDigest` and `rollbackTarget` must name the
accepted last-known-good sequence and digest. A rollback is restored locally on
failed activation; publishing an older envelope is still a replay. Any later
controller-requested rollback must be a newly signed, higher-sequence manifest.

Expiry prevents a new activation after `expiresAt`; it does not stop a committed
last-known-good configuration during a controller outage.

## Tests and reproducible checks

Run all focused tests with:

```sh
python3 -m unittest discover -s edge/tests -v
```

The suite invokes AJV 8.20.0 as a real Draft 2020-12 validator and does not skip
schema validation. On a clean runner, install the pinned test dependency with
Run `cd edge/tests && npm ci --ignore-scripts` before the Python suite. The
validator fails rather than falling back to an unpinned global dependency.

Recompute the example evidence with:

```sh
python3 edge/schema/manifest_tool.py digest \
  edge/schema/examples/v0.1-one-tenant-pbx-relay.json
```

Run its deterministic preflight with:

```sh
python3 edge/schema/manifest_tool.py validate \
  edge/schema/examples/v0.1-one-tenant-pbx-relay.json \
  --expected-cluster-id cluster-uaen-poc-01 \
  --expected-node-id sbc1 \
  --expected-generation 1 \
  --expected-tenant-context-id tenant-vivolution-poc \
  --expected-allocation-id allocation-vivolution-uaen-poc \
  --expected-tenant-listener-port 15061 \
  --expected-media-port-start 20000 \
  --expected-media-port-end 20255 \
  --expected-advertised-public-ip 198.51.100.20 \
  --authorized-pbx-source-cidr 203.0.113.10/32 \
  --accepted-sequence 6 \
  --accepted-digest sha256:1111111111111111111111111111111111111111111111111111111111111111 \
  --now 2026-08-30T04:45:00Z
```

The negative fixture files under `../tests/fixtures` are compact scenarios over
the canonical example. Tests apply each declared mutation, recompute the digest
where needed, and then prove rejection for cross-scope state, replay and a wrong
node. This keeps them focused on the intended invariant rather than allowing an
unrelated stale-digest failure to mask the result.

## Deliberate v0.1 tradeoffs

- The one-tenant POC uses the same tenant/allocation binding required for later
  shared-cluster multi-tenancy; adding a tenant means a distinct signed target,
  not adding another tenant's resources to one envelope.
- PBX routing uses typed E.164 prefixes rather than free-form OpenSIPS snippets.
  More expressive dial plans require a new reviewed schema version.
- Artifact and resource application remains ordered compensation, not a claim
  of cross-component ACID behavior.
- JSON Schema cannot compare fields or know local node/high-water state. Those
  checks are explicit semantic requirements and are exercised by the stdlib
  tool and fixtures.
