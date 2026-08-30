# First-tenant Edge compiler

This package deterministically compiles one `ACTIVE`, verifier-approved tenant
desired state into three bounded artifacts:

- an OpenSIPS 3.6 tenant route include;
- a userspace RTPengine tenant configuration; and
- a canonical JSON nftables merge policy for the table owned by Vivolution.

It is intentionally not an apply helper. It does not verify signatures, fetch
artifacts or secrets, write an active path, invoke OpenSIPS/RTPengine/nftables,
or accept commands, scripts, paths, service units, package names, secret values,
or raw configuration from the manifest. The exact receipt returned by the Edge
verifier is required and is rebound to the canonical manifest digest before
compilation. The output directory must be new.

The verifier receipt also carries `localHealthGatePlanDigest`. The compiler
reconstructs `TenantLocalHealthGatePlan` from the complete signed
`manifest.healthGates` array, preserving its order, and accepts only the fixed
`ARTIFACT_DIGESTS` → `OPENSIPS_CONFIG` → `RTPENGINE_READY` execution order and
reviewed `30/1`, `30/1`, and `30/3` timeout/attempt parameters. The digest is
SHA-256 over canonical plan JSON. A missing, reordered, substituted, or
parameter-mutated plan fails before artifact output.

## Fixed POC boundary

- Microsoft signaling is TLS TCP 5061.
- PBX ingress is mutual TLS TCP 15061.
- The signed PBX `optionsIntervalSeconds` is consumed and fixed to the reviewed
  value `60`. The exact interval is carried in the byte-canonical OpenSIPS
  fragment for independent runtime parsing; another accepted schema value is
  never silently ignored.
- The cluster media pool is UDP 20000-29999 and this first tenant owns
  20000-20255.
- The signed connector carries a separate PBX-side media destination range.
  Compiler output admits PBX media only when its remote source port is inside
  that exact range and its local destination is inside 20000-20255; the two
  ranges are never treated as interchangeable.
- The RTPengine NG control socket is UDP 127.0.0.1:2223; CLI control remains
  loopback on 2224.
- Node private/public IPv4 addresses, node-specific FQDN and current Microsoft
  source CIDRs are locally trusted facts, never tenant manifest values.
- The signed RTPengine artifact is always canonical `privateIpv4!publicIpv4`.
  It never accepts a profile-selected advertised address. After independently
  validating those exact bytes and their digest, the privileged runtime alone
  narrows `SYNTHETIC_PRIVATE` to `privateIpv4!privateIpv4`; Direct Routing
  preserves `privateIpv4!publicIpv4`.
- Optional synthetic-Teams sources must be RFC1918 CIDRs of /24 or narrower.
- `ABSENT` and `DECOMMISSION` are rejected. Removal needs a separate, reviewed
  compiler and apply transaction.

The three generated artifact bytes must exactly match the signed artifact
digest, size, media type and fixed apply order declared in the manifest. This
prevents a compiler result from silently diverging from the signed content-
addressed artifact inventory. Controller-side manifest construction must use
the same deterministic renderer before signing.

## Readiness boundary

Successful compilation means `BOOTSTRAP_ARTIFACTS_READY`, not that the files are
active. `compile-evidence.json` always records `runtimeApplied: false` and
`liveTeamsInteroperability: NOT_ASSERTED`. It also embeds the full canonical
`localHealthGatePlan` and its receipt-matched digest. This preserves the signed
execution contract for independent runtime validation; it does not claim that
any gate has run.

The generated OpenSIPS file is an include fragment. A separately reviewed
shared base must still provide the TLS listeners/domains and secret-to-fixed-
path mapping, load `tm`, `rr`, `sipmsgops`, `proto_tls`, `tls_mgm` and
`rtpengine`, authenticate and dispatch the Teams/PBX ingress legs, handle
in-dialog requests and CANCEL, and qualify Contact/FQDN rewriting and Microsoft
SRTP/SDP behavior. It currently uses the primary Microsoft SIP hub only.
The primary hub in this include is the deterministic routing seed. For a
root-authorized `DIRECT_ROUTING` release, the privileged runtime expands it to
all three fixed Microsoft hubs and originates periodic OPTIONS to those hubs
and the exact signed PBX peer. The compiler itself does not originate traffic,
and a `SYNTHETIC_PRIVATE` runtime does not inherit those live-peer probes.

The nftables artifact is typed merge input for the future fixed root helper,
not raw text for `nft -f`. Shared TCP 5061 rules are explicitly listed as
cluster prerequisites; the tenant owns only its PBX listener and allocated
media rules. Direct Routing egress starts from the tenant allocation and may
reach the locally authorized PBX CIDRs only on the exact signed PBX-side
destination range. An apply path must atomically merge these into
`inet vivolution_edge_filter`, preserve foreign tables and retain default deny.

Consequently this stage can feed later synthetic SIP/TLS/RTP integration tests,
but no actual Teams interoperability, failover, certificate activation, live
firewall state, transcoding, codec enforcement, CPS/bandwidth quota enforcement
or Microsoft supportability is claimed. Those unenforced controls are also
explicitly false in compile evidence.

## CLI

From the repository root:

```sh
python3 -m edge.compiler \
  signed-envelope.json node-facts.json verifier-receipt.json new-output-directory
```

Only non-secret canonical compile evidence is printed. Duplicate JSON members,
existing output paths and every contract mismatch fail closed.

Run focused tests with:

```sh
python3 -m unittest discover -s edge/compiler/tests -v
```
