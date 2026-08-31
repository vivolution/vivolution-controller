# Edge runtime apply and rollback

This package is the privileged, offline activation boundary for an Edge/SBC
node. It accepts only verifier-approved/compiler-produced artifacts at fixed
root-owned paths, independently re-verifies the signed envelope against the
root-installed Ed25519 pin, validates its local identity, rollback lineage,
typed grammar, and artifact digests,
renders complete OpenSIPS, RTPengine, and nftables configurations, then changes
the live node through a journaled A/B transaction.

It does **not** claim that Microsoft Teams interoperability, codec policy, call
rate limits, bandwidth quotas, end-to-end SIP, or end-to-end RTP have passed.
Successful runtime evidence intentionally reports `liveTeamsInteroperability`
as `NOT_ASSERTED`. Those are separate live qualification gates.

## Fixed production contract

The entry point is:

```text
python3 -m edge.runtime activate --sequence N --manifest-digest sha256:<64 lowercase hex>
python3 -m edge.runtime rollback --sequence N --manifest-digest sha256:<64 lowercase hex>
python3 -m edge.runtime recover
python3 -m edge.runtime health
python3 -m edge.runtime status
```

The production CLI must run as root and resolves the `opensips`, `rtpengine`,
and `vivolution-edge-agent` groups locally. It accepts no path, command,
service, unit, package, port, firewall syntax, or secret argument.

The command examples describe the Python entry point, not a safe sudo rule.
Never grant an unprivileged account sudo access to `python3`, `python3 -m`, a
caller-controlled working tree, or a caller-controlled `PYTHONPATH`. Install
the package in a root-owned location and expose a root-owned absolute launcher
which invokes the system interpreter in isolated mode (`-I`) with a cleared
environment. The privilege rule must name only that launcher and its fixed
subcommands.

The fixed files are:

```text
/etc/vivolution-edge/node-facts.json
/var/lib/vivolution-edge/runtime/runtime-authority.json
/usr/lib/vivolution-edge/config/signing-public-key.json
/etc/vivolution-edge/tls/teams-fullchain.pem
/etc/vivolution-edge/tls/teams-key.pem
/etc/vivolution-edge/tls/microsoft-ca-bundle.pem
/etc/vivolution-edge/tls/pbx-ca-bundle.pem
/etc/vivolution-edge/tls/public-ca-bundle.pem
/var/lib/vivolution-edge/runtime-inbox/<16-digit-sequence>-<manifest-digest-hex>/
/var/lib/vivolution-edge/runtime/
```

The three `fixture-*` files are additionally present only for
`SYNTHETIC_PRIVATE`; both live Microsoft profiles have exactly the five common
TLS digests and the runtime neither reads nor validates fixture paths. A live
replacement refuses retained fixture files instead of carrying
synthetic credentials into the live profile.

The node facts and runtime authority must be root-owned mode `0600`; the
canonical signing-key pin is root-owned mode `0444`. Every
profile-selected TLS file must be root:`opensips` mode `0440` and must match the
digest pinned in the runtime authority. The public server leaf is fail-closed to RSA-2048, exactly
the node FQDN plus its direct wildcard SAN, an explicit Server Authentication
EKU, a complete issuer chain, public-root verification, and at least 24 hours
of remaining validity. The Microsoft peer bundle must contain all seven
Microsoft-published current SIP roots by thumbprint (reviewed 2025-12-12); its
content digest is separately pinned in runtime authority. `python3-cryptography`
with the `cryptography.x509.verification` API is therefore a runtime dependency.

The inbox root and candidate directory must be root-owned mode `0700`. The
candidate directory name is canonical and its exact root-owned mode `0600`
file set is:

```text
compile-evidence.json
nftables-tenant-policy.json
opensips-tenant.cfg
rtpengine-tenant.conf
signed-envelope.json
verifier-receipt.json
```

Symlinks, hard links, unexpected files, non-regular files, permissive modes,
oversized files, duplicate JSON members, identity mismatches, replayed
sequences, and raw configuration extensions are rejected before any service is
stopped. The unsigned verifier receipt and compiler evidence are never root
authority: their candidate identity, verified key IDs, signed health plan, and
artifact digests must exactly match the envelope that the privileged runtime
itself verifies.

Runtime success evidence is stored below
`/var/lib/vivolution-edge/runtime/evidence`, an exact
root:`vivolution-edge-agent` mode `0750` directory. Each digest-named evidence
file is an immutable single-link regular file owned
root:`vivolution-edge-agent` mode `0440`. JSON is canonical with one trailing
LF; `evidenceDigest` hashes the canonical record before that member is added.

The root-provisioned runtime authority has this exact shape (replace the
administrator CIDR placeholder with the actual public `/32`):

```json
{
  "administratorSourceIpv4Cidrs": ["YOUR.PUBLIC.IP.ADDRESS/32"],
  "apiVersion": "edge.vivolution.ae/runtime-authority/v0.1",
  "azureDhcpServerIpv4": "168.63.129.16",
  "generation": 1,
  "nodeId": "sbc1",
  "profile": "SYNTHETIC_PRIVATE",
  "secretDigests": {
    "edgeCertificateChainPem": "sha256:<64 lowercase hex>",
    "edgePrivateKeyPem": "sha256:<64 lowercase hex>",
    "fixtureCaCrt": "sha256:<64 lowercase hex>",
    "fixtureClientCrt": "sha256:<64 lowercase hex>",
    "fixtureClientKey": "sha256:<64 lowercase hex>",
    "microsoftCaBundlePem": "sha256:<64 lowercase hex>",
    "pbxCaBundlePem": "sha256:<64 lowercase hex>",
    "publicCaBundlePem": "sha256:<64 lowercase hex>"
  },
  "slot": "A"
}
```

## TLS identities and profiles

Both public Edge server listeners (`5061` for Teams-side ingress and `15061`
for PBX-side ingress) always present `teams-fullchain.pem` with `teams-key.pem`.
The private fixture leaf is never assigned to either server listener.

`SYNTHETIC_PRIVATE` is the bounded POC profile. It uses the fixture client leaf
only for outbound mutual TLS from the Edge to the CP1 fixture at
`10.20.1.4:16061` and `10.20.1.4:25061`. The compiler represents the PBX TLS
identity as `pbx-fixture.invalid:16061`; the privileged runtime pins its network
address to `10.20.1.4` while preserving that DNS SNI. Because both fixture legs
come from the same CP1 address, compiler synthetic-source authority remains
empty and the root profile authorizes the exact `10.20.1.4/32` source on the
separate listener ports. Its live RTPengine interface is
`privateIpv4!privateIpv4`, so synthetic SDP remains inside the VNet and never
depends on Azure public-IP hairpinning.

`DIRECT_ROUTING` refuses synthetic Teams source authority. It uses the public
Edge identity outbound and renders fixed primary, secondary, and tertiary
Microsoft SIP hub failover. It additionally requires generation 2 or later, a
real canonical PBX FQDN on TLS 5061, globally routable canonical PBX source
CIDRs no broader than `/24`, an exact controller-pinned PBX CA bundle, and the
`+971` route. Placeholder, reserved, private, overbroad, or synthetic inputs
are rejected before live mutation. Moving to this profile still requires the separate
Microsoft tenant/domain, certificate, DNS, connectivity, and live call
qualification steps. Its live RTPengine interface remains
`privateIpv4!publicIpv4`, advertising the node's public media address.

`DIRECT_ROUTING_PRIVATE_PBX_POC` is a separately acknowledged generation-3+
profile for the current test architecture. Microsoft-side behavior is the
same live three-hub behavior as Direct Routing, but the other leg
is deliberately private: signed SNI `carrier.vivolution.ae`, statically pinned
to CP1 `10.20.1.4:5061`, with only `10.20.1.4/32` peer authority and UDP
`30000-30127` carrier media. The Edge still listens for that leg on TCP 15061
and uses its tenant-local UDP `20000-20255` allocation. Root validation requires
the exact POC manifest/resource identity, generation, address, ports, `+971`
route, PBX CA, and absence of fixture credentials before rendering anything.
It cannot be selected by a production `DIRECT_ROUTING` manifest, and a POC
manifest cannot run under either other root profile.

Its live RTPengine interface is exactly
`private/privateIpv4;public/privateIpv4!publicIpv4`. The Teams-to-PBX offer
selects `public` to `private`, the PBX-to-Teams offer selects `private` to
`public`, and their answer routes explicitly reverse those selections with the
pinned OpenSIPS `in-iface`/`out-iface` grammar. Consequently SDP sent to CP1
contains the private Edge address while SDP sent to Microsoft contains the
public address; neither leg relies on Azure public-IP hairpinning.

This profile is a POC bridge to a CP1-hosted carrier/PBX gateway. It does not
relax Microsoft certificate, hub, public RTP, firewall, replay, signature, or
transactional rollback rules. It also does not claim Microsoft certification,
Twilio authorization, licensed-user policy propagation, or PSTN success.

For both live Microsoft profiles, the runtime consumes the signed, compiler-carried
`optionsIntervalSeconds` and renders one OpenSIPS `timer_route` at the exact
reviewed 60-second interval. Each tick creates a stateful mutual-TLS OPTIONS
request to all three fixed Microsoft hubs and to the exact signed PBX TLS
endpoint. OpenSIPS `local_route` assigns the matching TLS/SNI domain, forces
Microsoft probes through `tls:privateIpv4:5061` and PBX probes through
`tls:privateIpv4:15061`, and adds a Contact URI containing the public node FQDN
and corresponding listener port. `SYNTHETIC_PRIVATE` renders no periodic
Microsoft or real-PBX probes and remains fixture-only.

The same socket boundary applies to relayed dialogs: Teams-bound egress is
forced through the 5061 TLS socket and PBX-bound egress through the 15061 TLS
socket before `record_route()`. The node FQDN and the corresponding listener
port are explicitly selected as the advertised identity, so Record-Route/Via
generation and later loose routing preserve the correct interface boundary.

These generated-config properties are locally testable; peer behavior is not.
An OpenSIPS parse or successful activation does **not** prove that Microsoft or
the PBX received an OPTIONS request, authenticated the certificate/FQDN, or
returned 200. Timestamped request/response traces and authenticated peer
identity from each live endpoint remain external Direct Routing acceptance
evidence and are deliberately absent from local signed health gates.

The renderer is pinned to the OpenSIPS 3.6.8 contracts for
[`timer_route`](https://github.com/OpenSIPS/opensips/blob/3.6.8/docs/manual/Script-Routes.md#timer_route),
[`t_new_request`](https://github.com/OpenSIPS/opensips/blob/3.6.8/modules/tm/README.md#t_new_request-method-ruri-from-to--body-ctx),
`local_route`, and
[`force_send_socket`](https://github.com/OpenSIPS/opensips/blob/3.6.8/docs/manual/Script-CoreFunctions.md#force_send_socketprotoaddressport).
The one-minute cadence, OPTIONS identities, and Contact requirement follow the
Microsoft Direct Routing
[availability](https://learn.microsoft.com/en-us/microsoftteams/direct-routing-monitor-and-troubleshoot#monitoring-availability-of-session-border-controllers-using-session-initiation-protocol-sip-options-messages)
and [SIP protocol](https://learn.microsoft.com/en-us/microsoftteams/direct-routing-protocols-sip#processing-the-incoming-request-finding-the-tenant-and-user)
specifications. A change of either pinned implementation or external protocol
contract requires renderer and live-acceptance requalification.

The compiler artifact and compile evidence remain strict in both profiles:
`rtpengine-tenant.conf` must be byte-canonical `privateIpv4!publicIpv4` and its
digest must match the verifier/compiler handoff. Only after that validation may
the fixed root renderer derive the synthetic private advertisement from the
root-owned runtime authority. Activation evidence records `runtimeProfile`,
`rtpAdvertisedIpv4`, and the matching profile-specific health gate.

Profile migration never rewrites an active synthetic node. The reviewed path
stages a distinct generation-2-or-later replacement with
`deploy/playbooks/transition-direct-routing-replacement.yml`, installs and
activates its signed Direct Routing candidate transactionally, and deliberately
leaves the predecessor synthetic fleet untouched as the rollback LKG. DNS and
Microsoft tenant cutover remain separate explicit actions; before cutover,
rollback is abandonment or deallocation of the replacement. The transition
playbook records `DIRECT_ROUTING_REPLACEMENT_STAGED_NO_CUTOVER` evidence and
refuses a reused synthetic authority, a same-host predecessor, missing exact
acknowledgements, or an unpreserved predecessor contract.

Every rendered TLS domain is fixed to TLS 1.2 and an exact profile-selected
forward-secret AEAD list. Both public server domains and every Direct Routing
client domain use only
`ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256`. The public listener
certificate therefore remains RSA even though ECDHE provides ephemeral key
agreement. Only the two synthetic outbound client domains use
`ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256`, because the CP1
fixture servers present P-256 ECDSA leaves. In TLS 1.2 that ECDSA suite suffix
selects the server-authentication key type; it does not weaken the independent
mutual-authentication requirement for the Edge fixture client certificate.
No domain receives a combined, broad, or default cipher list. Microsoft media
arrives from the reviewed CIDRs with remote source
ports `3478-3481` or `49152-53247` and is accepted only into the tenant-local
RTPengine allocation (`20000-20255` here). Those Microsoft ranges are never
used as RTPengine bind ports. Both Azure and the runtime-owned host table use
an outbound default-deny policy. The Direct Routing profile permits media only
from the tenant allocation to those Microsoft CIDRs/ports and to the signed,
locally authorized PBX CIDRs on the separately signed PBX destination range.
PBX ingress is the inverse directional contract: only that remote source-port
range may reach the Edge-local tenant allocation. The reviewed Direct template
uses UDP 30000-30127; synthetic PBX media is fixed exactly to UDP 21000-21127,
while its distinct Teams-side fixture range is UDP 22000-22063. Neither profile
lets RTPengine send UDP to an arbitrary destination.

The shared egress catalogue is deliberately small: Azure WireServer DHCP and
agent ports, Azure DNS, IMDS, the fixed CP1 HTTPS address, TCP 80/443 for APT,
ACME and Azure APIs, and UDP 123 to two fixed anycast NTP `/32`s. All other
output falls through to `policy drop`; established replies and loopback remain
available. The bootstrap role pins `ntpsec` to the same two literal addresses,
so no unresolved NTP pool silently broadens the rule.

## Transaction and evidence behavior

Runtime releases live under immutable `slots/A` and `slots/B` directories. The
first run captures the prior live configuration as an immutable bootstrap
release. The three live config paths become fixed symlinks through one atomic
`active` release pointer.

Activation order is:

1. Validate verifier receipt, compile evidence, immutable node facts, local
   authority, source artifact digests, the complete receipt-bound local-health
   plan, typed compiler grammar, and TLS material.
2. Persist the replay floor, render an immutable candidate whose release digest
   binds the complete compile-evidence digest and health plan, then run pinned
   package-version, OpenSIPS offline parse, and nftables offline safeguards. A
   failure here emits canonical `ABORT_PENDING` evidence without live mutation;
   the failed sequence remains burned.
3. Persist the transaction journal.
4. Stop OpenSIPS/RTPengine, atomically switch the pointer, apply only the owned
   nftables table, and restart services.
5. Execute the exact signed gate plan in order. Every attempt has one monotonic
   aggregate 30-second deadline across all of that gate's commands. Artifact
   and OpenSIPS gates permit one attempt; the complete RTPengine gate permits
   at most three. Results preserve plan order, gate ID/type, actual attempts,
   and the fixed ordered proof maps. Exhaustion rolls back and never emits a
   partial or falsely passed signed result.
6. Emit canonical evidence. A healthy activation says `COMMIT_PENDING`; a
   failed activation restored to the prior last-known-good release says
   `ABORT_PENDING`.

Successful evidence places only the three exact signed result objects under
`healthGates`, embeds `localHealthGatePlan` and its digest, and records all
package, systemd, default-deny firewall, listener, and profile safeguards under
the separate ordered `runtimeChecks` array. Failure and rollback evidence has
an empty `healthGates` array. `liveTeamsInteroperability` remains
`NOT_ASSERTED`; OPTIONS responses and live peer identity are not local gates.

The nft renderer never uses `flush ruleset`; it destroys and recreates only
`inet vivolution_edge_filter`, preserving foreign tables. Crash recovery always
converges to the journaled prior last-known-good release. Manual rollback can
target only the exact protected previous candidate and returns
`RECONCILE_PROTECTED_STATE`, because the unprivileged agent must separately
reconcile its pending/committed state. If a crash occurs after the protected
state commit but before journal removal, recovery preserves the committed
healthy pointer, securely reloads and self-digest-validates the original
immutable success evidence selected by protected `lastEvidenceDigest`, and
returns its exact signed plan/results/digest. Fresh baseline checks are exposed
only as `runtimeChecks`; they can never substitute for the signed activation
results. Missing, relinked, permission-changed, or modified original evidence
leaves the journal intact and fails recovery closed.

`health` acquires the same protected runtime lock, validates the active release
and pointer, refuses to run while any transaction journal exists, and executes
the baseline systemd, OpenSIPS parse, owned-default-deny nftables, and
RTPengine NG safeguards. Its canonical `EdgeRuntimeHealth` result records them
as `runtimeChecks` bound to the exact active release and replay floor. It never performs
recovery or changes protected state.

## Required deployment integration

This directory deliberately does not install packages, certificates, systemd
units, sudo policy, or agent handoff code. Deployment must still:

- install this package and its compiler/schema imports in a root-owned Python
  location;
- provision all eight pinned TLS/CA files with the ownership and modes above;
- create the secure root-owned inbox handoff from the verifier/compiler output;
- install a root-owned executable wrapper and a narrowly scoped privilege rule
  exposing only this fixed CLI, with no caller-controlled import path or
  environment;
- make the Edge agent call `commit-pending --runtime-evidence-digest` only
  after securely reading and independently validating the exact immutable
  `RUNTIME_APPLIED_HEALTHY` evidence, or `abort-pending` after verified rollback
  evidence;
- invoke `recover` before processing a new pending candidate after boot; and
- preserve the expected OpenSIPS `3.6.8-1` and RTPengine
  `26.0.1.22-1~bpo13+1` package versions or explicitly revise and requalify the
  contract.

Before calling the POC turnkey, validate the generated files on the real Debian
13 images with the real OpenSIPS, nftables, systemd, socket, and RTPengine NG
gates, then run synthetic mutual-TLS SIP, bidirectional RTP, failure/rollback,
and CDR checks. Direct Routing must be qualified separately against Microsoft.

## Isolated tests

The tests use temporary paths, generated certificates, and a fake fixed-command
runner; they do not mutate host services or firewall state:

```text
/opt/homebrew/bin/python3 -m unittest discover -s edge/runtime/tests -p 'test_*.py' -v
```

They cover activation, exact ordered signed plan/results, aggregate monotonic
timeouts, bounded whole-gate retry, evidence ownership/self-digest recovery,
exact A/B rollback, crash recovery, replay-floor behavior, canonical preflight
abort, service failure rollback, TLS role separation, key mismatch, Direct
Routing hub failover, and symlink/hard-link/mode/config-injection rejection.
