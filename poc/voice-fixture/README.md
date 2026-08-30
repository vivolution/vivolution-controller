# Isolated no-PSTN voice fixture

This directory contains the first-tenant synthetic voice fixture used to prove
the private TLS/SIP/RTP path through SBC1 and SBC2 before any Microsoft 365 or
carrier attachment. It is deliberately incapable of registering to a carrier
or routing to the PSTN.

The fixture runs on CP1 at `10.20.1.4`. Asterisk represents the tenant PBX and
SIPp represents the Teams side. Both bind only CP1's private address. Runtime
systemd cgroup policy denies every destination except loopback, CP1 itself, and
the Edge subnet `10.20.2.0/24`; all configured SIP peers are the two fixed Edge
addresses. There is no default carrier, SIP registration, DNS target, public
listener, emergency route, or arbitrary command input.

SIPp is invoked with its explicit private-address bind flag and stdin control
disabled. Its built-in UDP control-socket setup is pinned to loopback; the
service's exact `SocketBindDeny`/`SocketBindAllow` policy deliberately denies
that unneeded socket, so no SIPp remote-control listener is created.

## Fixed allocation

| Purpose | CP1 fixture endpoint | Edge contract |
| --- | --- | --- |
| PBX signaling | Asterisk mTLS server `10.20.1.4:16061`; outbound source `16062` | Edge mTLS TCP `15061` |
| PBX media | UDP `21000-21127` | Tenant RTP UDP `20000-20255` |
| Teams signaling | SIPp TLS `10.20.1.4:25061`; transient UAC source `25062`; certificate probe source `25063` | Edge TLS TCP `5061` |
| Teams media | UAS UDP `22000`; transient UAC UDP `22032`, reserved `22000-22063` | Tenant RTP UDP `20000-20255` |

The fixture ports do not overlap CP1 HTTPS/PostgreSQL/PgBouncer, the Edge
listeners, or the tenant RTP allocation. The deliberately invalid UAE-format
fixture number `+9710000001001` is the only positive route. Its national part
starts with `0`, so it cannot be an assigned UAE E.164 number; the fixture also
has no carrier or public egress.

## Required network changes (not applied here)

Before setting `voice_fixture_firewall_contract_acknowledged: true`, make these
minimum changes in the reviewed CP1 firewall/IaC source. Do not add an Internet
source rule.

CP1 NSG and host input policy, source `10.20.2.0/24` only:

- TCP destination `16061` and `25061` to `10.20.1.4`.
- UDP destination `21000-21127` and `22000-22063` to `10.20.1.4`.
- Do not add input rules for outbound source ports `16062`, `25062`, or `25063`.

Each Edge NSG and host input policy, source `10.20.1.4/32` only:

- TCP destination `5061` for the synthetic Teams side.
- TCP destination `15061` for the synthetic PBX side.
- UDP destination `20000-20255`, not the rest of the outer cluster pool.

Stateful return traffic needs no additional rule. CP1's existing public rules
remain unchanged. The fixture services add a second enforcement layer with
`IPAddressDeny=any`, explicit private `IPAddressAllow` entries, fixed
`SocketBindAllow` entries, and no IPv6 address family.

The long-running SIPp UAS does not emit periodic statistics; its error log is
capped at 10 MiB. Per-run SIPp statistics, RTP counters, CDR deltas, and bounded
journal windows are retained with the test result instead.

For the current Bicep scaffold this means supplying `10.20.1.4/32` in
`syntheticTeamsSourcePrefixes`, `sbc1PbxSourcePrefixes`, and
`sbc2PbxSourcePrefixes`, then narrowing those private media rules to the fixed
first-tenant allocation `20000-20255`. CP1 needs the four private-source rules
above. This directory intentionally does not edit the project IaC or existing
controller firewall role.

## Edge certificate and route handoff

The install produces a private CA plus four seven-day leaves:

- `asterisk`: server/client EKU, SAN `pbx-fixture.invalid` and `10.20.1.4`.
- `sipp`: server/client EKU, SAN `teams-fixture.invalid` and `10.20.1.4`.
- `sbc1`: client EKU only, SAN `sbc1-fixture.invalid` and `10.20.2.4`.
- `sbc2`: client EKU only, SAN `sbc2-fixture.invalid` and `10.20.2.5`.

The Edge listeners on both TCP 5061 and 15061 always present their public ACME
server certificate. A private fixture leaf must never be installed as an Edge
server identity. Asterisk and SIPp trust the Debian system public CA bundle for
Edge server validation, present their fixture client leaf, and use static
FQDN-to-private-IP mappings so the test neither hairpins through a public IP nor
depends on DNS. The mappings are `sbc1.voice.vivolution.ae` -> `10.20.2.4` and
`sbc2.voice.vivolution.ae` -> `10.20.2.5`.

For Edge-to-CP1 calls, each node receives only its matching client-only fixture
certificate/key, trusts `fixture-ca.crt`, verifies the CP1 leaf and IP SAN, and
uses these exact routes:

- Teams-fixture egress: `sips:10.20.1.4:25061`.
- PBX-fixture egress: `sips:10.20.1.4:16061`.
- Synthetic Teams ingress remains Edge TCP `5061`.
- Synthetic PBX ingress remains Edge TCP `15061`.
- SDP offered to the fixture stays inside tenant RTP `20000-20255`; CP1 SDP
  advertises only `21000-21127` or `22000-22063` as applicable.
- The Edge `SYNTHETIC_PRIVATE` runtime binds and advertises each node's private
  IPv4 address (`private!private`). The fixture never opens cgroup, NSG, or host
  policy for Edge public-IP hairpin media.

The signed Edge synthetic profile must contain only these CP1 peers and the
exact `+9710000001001` route. It must have no carrier, registration, emergency,
or generic fallback route. Edge desired-state qualification owns that separate
assertion before either call runner is permitted to pass.

The node fixture leaf is an outbound client identity only. It is never served
on 5061 or 15061 and never replaces the publicly trusted Direct Routing server
certificate. A durable implementation should generate each node private key on
that node and sign a CSR; the CP1-generated export is a bounded POC bootstrap,
not a production key-lifecycle design.

The seven-day leaves are expiry-aware rather than one-shot. Three days before
any leaf expires, the role builds a complete protected PKI generation, reuses
the existing private keys, validates every chain/key/usage/validity contract,
and atomically selects the generation with one symlink replacement. The CA
certificate is renewed fourteen days before expiry with the same protected CA
key and subject, so both the previous and renewed CA certificates validate the
overlap while the two Edges are re-pinned serially. Prior generations are
retained root-only for rollback and are never overwritten.
The root-only CA serial counter is carried into each new generation and advanced
for every leaf. Renewed certificates therefore never reuse a serial under the
same CA subject/key, including during the overlap window.

`deploy/playbooks/rotate-synthetic-fixture-pki.yml` performs the complete
rotation transaction: refresh CP1, fetch only the current CA and node-specific
client pair into the ignored controller staging directory, verify exact
SHA-256 values, re-pin each Edge and its root-owned runtime authority one at a
time with crash rollback, then rerun readiness and both bidirectional call
paths. It requires the exact acknowledgement
`ROTATE_SYNTHETIC_FIXTURE_PKI_ON_BOTH_EDGES`; it refuses Direct Routing nodes or
an incomplete two-node fleet.

## Install

1. Merge and qualify the network rules above.
2. Copy `inventory.example.yml` outside the repository or adapt it to the
   generated project inventory. Keep SSH keys and secrets outside this tree.
3. Set `voice_fixture_firewall_contract_acknowledged: true` only after checking
   the effective NSG and nftables rules.
4. Run from this directory:

   ```sh
   ansible-playbook -i inventory.example.yml install.yml
   ```

The role refuses a host other than Debian 13 AMD64 with private address
`10.20.1.4`, refuses any allocation drift, and requires cgroup v2/systemd IP
filtering. Before installation it actively proves that the target kernel
enforces both socket-bind and IP-egress denial for a transient systemd cgroup.
It creates a 30-day private fixture CA and 7-day leaf certificates on CP1 and
automatically selects a renewed generation inside the guarded renewal windows.
Private keys are generated at deployment time with identity-specific
`0640` or root-only `0600` permissions; none are stored in Git. SBC1/SBC2 test
identities are exported under
`/var/lib/vivolution/voice-fixture/edge-export/` for a separate reviewed,
encrypted deployment to the matching node. Never copy those keys into the
repository or evidence. `CERTIFICATE-INVENTORY` records only subjects, issuer,
serials, expiry, and SHA-256 public-certificate fingerprints.

The runtime images are content-ID pinned in Quadlet after local builds.
Asterisk 22.10.1 is built from the upstream tag archive whose SHA-256 is fixed
in the Containerfile because Debian 13 does not ship an Asterisk binary
package. SIPp uses Debian 13's exact `sip-tester` package version. Runtime
containers use `Pull=never` and have no allowed path to package mirrors or the
Internet. The two one-time build commands use an IPv4-only `slirp4netns`
userspace network with host-loopback access disabled. This gives their pinned
package/source fetches DNS and HTTPS without weakening the controller's
default-drop forwarding chain or giving build steps the host network
namespace; it is not used by either runtime container.

## Readiness and calls

On CP1:

```sh
sudo /usr/local/libexec/vivolution-voice-fixture-readiness
sudo /usr/local/sbin/vivolution-voice-fixture-test sbc1
sudo /usr/local/sbin/vivolution-voice-fixture-test sbc2
```

Each test is serialized and runs both directions:

1. SIPp (Teams fixture) -> selected Edge TCP 5061 -> Asterisk TCP 16061.
2. Asterisk -> selected Edge TCP 15061 -> SIPp TCP 25061.

A run passes only if both TLS/SIP dialogs complete, the fixture receives valid
RTP through the selected Edge, and a new Asterisk CDR is captured. Results are
written to a new UTC/test-ID directory under
`/var/lib/vivolution/voice-fixture/results/`, with SIPp statistics, RTP JSON,
CDR delta, unit logs, an explicit `RESULT`, and SHA-256 manifest. No audio or
private key is captured. Edge RTPengine/session/CDR evidence must be collected
by the Edge/control-plane qualification in the same test window for complete
end-to-end reconciliation.

## Synthetic node-failover acceptance

After both generation-1 nodes have the same signed `SYNTHETIC_PRIVATE` tenant
allocation active, run the disruptive two-node acceptance workflow only with
the one-run acknowledgement:

```sh
ANSIBLE_ROLES_PATH=deploy/roles ansible-playbook \
  -i /absolute/private/poc-edge/hosts.yml \
  -e edge_synthetic_failover_acknowledgement=RUN_SYNTHETIC_SBC1_TO_SBC2_FAILOVER_WITHIN_120_SECONDS \
  deploy/playbooks/qualify-synthetic-node-failover.yml
```

The playbook refuses any fleet other than exact `sbc1`/`sbc2` generation 1 and
one fixture controller. It proves both nodes are healthy and hold the same
cluster/customer/M365-tenant/tenant-context/service/allocation route, places a
two-direction baseline call through SBC1, and starts the 120-second clock
before deliberately stopping both `opensips.service` and
`rtpengine-daemon.service` on SBC1. After CP1 observes SBC1 TCP 5061 closed, a
fresh call using the same fixed tenant number and both directions must pass
through SBC2 before the clock expires.

SBC1 restoration is in the unconditional recovery path: media starts before
signaling, the protected active runtime must remain identical, locked runtime
health must pass, and a fresh two-direction SBC1 call must succeed. Before the
stop, SBC1 persists a root-owned recovery marker. One protected node-local
injector atomically arms a 150-second systemd deadman before it stops OpenSIPS
and RTPengine, so runner or SSH loss cannot create an unprotected stop. The
deadman restores RTPengine before OpenSIPS. A safe rerun reconciles any retained
marker; it disarms and removes the marker only after active services, exact
runtime health/status, and a fresh post-recovery call all pass.

The alternate command has a 110-second hard timeout. The complete failure
interval uses `time.monotonic_ns()` and must not exceed 120,000 milliseconds.
The controller-side collector retrieves every bounded file in
all three manifests and rejects missing, extra, unverified, symlinked,
hard-linked, wrongly owned/mode, or digest-mismatched artifacts. It also binds
successful Edge-to-fixture CDR reconciliation for each phase; see
[`../synthetic-cdr-evidence.md`](../synthetic-cdr-evidence.md). The compiler
writes canonical non-secret evidence below the ignored private inventory path
`generated/synthetic-failover/<baseline-test-id>/acceptance.json` with status
`SYNTHETIC_NEW_CALL_FAILOVER_ACCEPTED`.

This is deliberately a private route-availability exercise. The runner is the
route selector: it targets SBC1 before the failure and SBC2 after detecting the
failure because SIPp is not Microsoft's routing service. It proves a new call
can use the alternate node for the same logical tenant allocation; it does not
prove Microsoft OPTIONS detection, Microsoft gateway selection, live Teams,
PSTN interworking, or active-call migration. Evidence therefore fixes
`liveM365Interoperability=NOT_ASSERTED` and
`activeCallMigration=NOT_TESTED_NOT_CLAIMED`.

## Teardown

The default teardown stops and removes only the two fixture units and their
Quadlets. It preserves PKI, results, CDRs, and images:

```sh
ansible-playbook -i inventory.example.yml teardown.yml
```

Image removal requires `voice_fixture_remove_images: true`. Result or PKI
destruction additionally requires the exact acknowledgements documented in
`roles/voice_fixture_teardown/defaults/main.yml`. Remove the private NSG and
host-firewall rules after the services are stopped. These operations do not
alter CP1 web/database services.

## Explicit limitations

- This is an isolated functional fixture, not Microsoft Teams, not the PSTN, a
  certified SBC, a carrier, or a regulatory/emergency-calling test.
- The private fixture CA is test-only and does not replace public Edge
  certificates required by Microsoft Direct Routing.
- It proves one first-tenant allocation. It does not prove hosted multi-tenant
  isolation, production capacity, codec transcoding, supplementary features,
  billing, lawful intercept, or an SLA.
- RTP evidence here proves packets reached the fixture. Complete bidirectional
  packet/accounting proof still requires the matching RTPengine evidence.
- Runtime isolation depends on the installed NSG/nftables rules and effective
  systemd cgroup-BPF IP policy; readiness fails if the service policy drifts.
