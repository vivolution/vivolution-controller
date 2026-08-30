# CP1 first-tenant materializer

This package creates one node-targeted `ACTIVE` v0.1 tenant envelope for
`sbc1/A` or `sbc2/B` for either the bounded CP1 fixture or the reviewed
`DIRECT_ROUTING` profile. It does not copy the schema example's placeholder
artifacts. It builds the complete inventory, calls the same deterministic
renderers used by `edge.compiler`, fills each exact SHA-256 digest, byte size,
content-addressed fetch path and fixed apply order, validates the finished
envelope, and then signs domain-separated canonical manifest bytes.

The profile parser and `NodeFacts` parser reject unknown members, booleans in
integer fields, cross-tenant identity, altered fixed allocations, broad PBX
authority, and non-canonical network data. The same profile can be used with
the separately trusted node-facts file for both Azure SBCs.

## Fixture boundary

This is deliberately a synthetic no-PSTN qualification profile:

- PBX host and SNI: `pbx-fixture.invalid`, statically resolved by the reviewed
  runtime to CP1;
- PBX TLS destination: CP1 TCP 16061;
- tenant PBX source authority: CP1 `10.20.1.4/32` only;
- tenant media allocation: UDP 20000-20255;
- PBX fixture media destination: the exact fixed UDP 21000-21127 range; and
- synthetic Teams traffic is **not** put in the tenant manifest or node facts.
  The privileged runtime owns its separate fixed `SYNTHETIC_PRIVATE` CP1-only
  exception on TCP 5061.

Successful materialization means signed, schema-valid, compiler-matched input.
It does not mean runtime activation, PSTN connectivity, live Microsoft Teams
interoperability, Microsoft certification, codec enforcement, call-rate
enforcement or bandwidth enforcement. These limitations are explicit in
`materialization-evidence.json` and compiler evidence.

## Direct Routing boundary

`FirstTenantDirectRoutingProfile` with `deploymentMode: DIRECT_ROUTING` is a
separate fail-closed input contract. It accepts only:

- the exact ordered Microsoft SIP targets
  `sip.pstnhub.microsoft.com`, `sip2.pstnhub.microsoft.com`, and
  `sip3.pstnhub.microsoft.com`, all using TLS on TCP 5061;
- a canonical lowercase ASCII PBX FQDN whose `remoteHost` exactly equals its
  TLS server name, with no IP literal, wildcard, trailing dot, special-use
  suffix, example name, or replacement marker;
- the reviewed PBX TLS destination port 5061;
- one explicit canonical PBX media destination range. Its start must be even,
  its end odd, it must contain no more than 4096 UDP ports, must not collide
  with signaling or reserved control ports, and must provide at least two
  ports per declared non-multiplexed session. The reviewed first-tenant
  template uses UDP 30000-30127;
- one through eight unique public IPv4 PBX source networks, each `/24` or
  narrower, written canonically and in canonical network order;
- the UAE route prefix `+971` and reviewed priority 100; and
- the exact Microsoft tenant and Vivolution allocation identities already
  present in separately trusted node facts.

Direct materialization is restricted to replacement node generation 2 or
later. A fresh replacement Agent can use direct profile sequence 1 with null
accepted state; synthetic lineage is not fabricated for a new Agent state.
Later Direct releases must carry `acceptedState.profileKind` equal to
`FirstTenantDirectRoutingProfile` and the same replacement generation as the
trusted node facts. This prevents a synthetic digest from being presented as
Direct lineage while preserving normal Direct-to-Direct updates.

Direct materialization also requires both the PBX source networks and PBX
media destination range in the profile to equal node-facts authority exactly,
and forbids tenant-controlled synthetic Teams authority. The destination range
is signed connector input and remains distinct from the Edge-local
`20000-20255` RTPengine allocation. Its signed manifest uses
`manifest-direct-*` plus direct-only connector, listener and route resource
IDs, so the profile mode is distinguishable inside the signed data rather than
inferred from a filename.

`first-tenant-direct-routing-profile.template.json` is intentionally invalid
until an operator replaces the Microsoft tenant UUID, real PBX FQDN, public
source CIDRs, trust references, versions and accepted lineage as applicable.
The parser does not perform DNS, certificate-chain, M365 licensing, domain or
route activation checks; those remain activation and external-qualification
gates. A signed direct release therefore reports live interoperability as
`REQUIRES_EXTERNAL_QUALIFICATION` and never claims runtime application.

Direct `secretReferences` retain the existing signed schema roles as metadata:

- `pbxClientIdentity` identifies the node's public Edge certificate/key role
  used for outbound mutual TLS to the real PBX;
- `pbxServerIdentity` identifies that public Edge identity's inbound-listener
  role (the schema requires a distinct reference ID); and
- `pbxClientCa` identifies the exact real-PBX CA bundle used to validate the
  PBX peer.

The Direct runtime independently pins and digest-checks those deployed files;
these references do not fetch or install secret material. Direct profiles
reject reference IDs or versions containing `fixture`, and do not require the
fixture CA, client certificate or fixture client key.

## Signing key

Create the signing seed under a pre-existing, owner-owned private directory
(normally mode 0700). The path must be absolute:

```sh
python3 -m edge.controlplane generate-key \
  /absolute/private/path/edge-signing.seed \
  --key-id edge-signing-key-2026-01 \
  > edge-signing-public-key.json
```

The command atomically publishes a new 32-byte raw Ed25519 seed at mode 0600.
It refuses an existing file, symlink, hard-linkable replacement, public parent
directory, or relative path. Standard output contains public metadata only;
the private seed is never emitted or copied.

Pin the returned key ID and raw public key on each Edge before staging any
envelope. Key IDs are never inferred from a filename or public-key hash.

## Materialize

Copy `first-tenant-profile.example.json` for the fixture, or copy and fully
resolve every replacement in
`first-tenant-direct-routing-profile.template.json` for Direct Routing. Use
node facts produced from trusted Azure deployment outputs and fixed bootstrap
allocations. Then create a brand-new release directory:

```sh
python3 -m edge.controlplane materialize \
  first-tenant-profile.json \
  sbc1-node-facts.json \
  /absolute/private/path/edge-signing.seed \
  sbc1-release-000001 \
  --key-id edge-signing-key-2026-01 \
  --issued-at 2026-08-30T04:30:00Z
```

Omit `--issued-at` to use the current whole UTC second. A fixed value is useful
for reproducible qualification evidence. The new output contains:

- `signed-envelope.json`: exact canonical JSON, without a trailing byte;
- `signing-public-key.json`: non-secret raw-public-key metadata;
- `materialization-evidence.json`: non-secret digest and readiness evidence;
- `artifacts/`: the three exact compiler outputs plus compiler evidence.

Every output file is mode 0600 inside a new mode-0700 directory. Existing
output paths are never merged or overwritten.

For sequence 1, `acceptedState` must be null. Later profiles must increment by
exactly one and carry the protected active manifest digest and the sorted three
active artifact digests. The Edge Agent still compares that signed rollback
lineage against its own protected last-known-good state before accepting it.
This permits an exact synthetic-to-direct signed lineage, but it does not alter
the node's trusted network facts or runtime authority; the reviewed activation
transaction must reconcile those local authorities separately.

## Tests

The focused suite independently verifies Ed25519 with `cryptography`, stages
both fixture and Direct Routing wire envelopes through the real Edge Agent,
recompiles them through the public compiler API, exercises both node targets
and cross-profile lineage, and covers key-path, FQDN, CIDR, route and Microsoft
target rejection:

```sh
python3 -m unittest discover -s edge/controlplane/tests -p 'test_*.py' -v
```
