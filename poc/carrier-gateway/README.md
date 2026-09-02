# Vivolution bounded carrier gateway

This directory is a separate CP1-hosted carrier/PBX gateway for the first
tenant proof of concept. It does not modify, reuse, or weaken
`poc/voice-fixture`; the synthetic fixture remains an isolated no-PSTN system.

The implemented boundary is intentionally narrow:

- CP1 private listener: `10.20.1.4:5061/TLS`, certificate/SNI
  `carrier.vivolution.ae`. When a provider is armed, PJSIP advertises the exact CP1
  public NAT address `40.123.208.212` only to destinations outside
  `10.20.0.0/16`; the two Edge legs retain private Contact and SDP addresses.
- Generation-3 Edge peers only: `sbc1.vivolution.ae` at `10.20.2.6` and
  `sbc2.vivolution.ae` at `10.20.2.7`, each on PBX listener TCP `15061`.
- Carrier RTP/SRTP allocation is process-isolated: Common Teams Leg UDP
  `30000-30063`, Generic SIP Trunk Leg UDP `30064-30127`, and Edge-side source
  allocation UDP `20000-20255`.
- Asterisk `22.10.1` with bundled PJProject `2.17`, both downloaded by pinned
  SHA-256. The multi-stage build requires `libsrtp2-dev`, enables and verifies
  `res_srtp.so`, copies only resolved runtime libraries, and carries the two
  narrowly guarded PJProject kernel-autobind patches needed by the systemd
  socket boundary.
- Edge signaling uses mutual TLS with the common public CA bundle. The server
  certificate must have exactly one SAN, `carrier.vivolution.ae`, verify against
  the host public trust store, remain valid for at least 24 hours, and match a
  protected `root:10003 0440` key. Certificate rotation atomically maintains a
  byte-identical second pair at `root:10004 0440` in a separate egress-only PKI
  mount; neither runtime can read the other runtime's key path. Synthetic
  fixture keys and CAs are rejected by construction because no fixture path is
  mounted or rendered.
- Media encryption is SDES-SRTP on the Common Teams Leg and the currently
  supported Generic SIP Trunk Leg. TLS is fixed to TLS 1.2, excluding TLS
  1.0/1.1.

The module boundary is: **Common Teams Leg -> SBC Routing & Media -> Generic
SIP Trunk Leg -> per-customer provider profile**. The Teams-facing listener,
certificate, routing, failover, and media allocation do not change when the
customer selects another carrier. Provider profiles supply only the southbound
FQDN, reviewed IP authority, TLS port, media authority, authentication mode,
credentials, caller identity, and allowed destinations. Twilio is the first
example profile; it is not hard-coded into the application or host firewall.

This is an engineering POC using OpenSIPS/RTPengine/Asterisk, not a
Microsoft-certified SBC product. It makes no production-support claim.

## Runtime isolation

The gateway is a genuine rootless Podman workload, not merely a non-root
process in a root-owned container store. Installation creates the dedicated
locked account `vivolution-carrier` (`10003`), requires subordinate UID/GID
ranges, enables its user manager, and installs its Quadlet only below that
user's home. The Quadlet uses `UserNS=keep-id`, UID/GID `10003`, an immutable
content ID with `Pull=never`, a read-only root filesystem, all capabilities
dropped, and `NoNewPrivileges` inside the container.

A root-controlled `user-10003.slice` policy denies every IP and explicit bind,
then permits only loopback, CP1, the two exact Edge private IPs, TCP `5061`, and
UDP `30000-30063`. The distinct provider-egress UID `10004` receives only the
loopback handoff plus the active profile's exact public signaling and media
authority through nftables. The Asterisk/PJProject patches defer only outbound
zero-port binds to the kernel; an explicit port-zero bind remains denied.

The CP1 nftables rule is separate and opt-in through the existing controller
firewall role:

```yaml
cp_voice_fixture_enabled: true
cp_carrier_gateway_enabled: true
cp_carrier_gateway_source_ipv4_cidrs:
  - 10.20.2.6/32
  - 10.20.2.7/32
cp_carrier_gateway_tcp_port: 5061
cp_carrier_gateway_edge_media_source_port_range: 20000-20255
cp_carrier_gateway_ingress_rtp_port_range: 30000-30063
cp_carrier_gateway_egress_rtp_port_range: 30064-30127
cp_carrier_gateway_provider_enabled: true
cp_carrier_gateway_provider_signaling_ipv4_cidrs:
  - REPLACE_WITH_PROVIDER_SIGNALING_AUTHORITY
cp_carrier_gateway_provider_destination_ipv4_cidrs:
  - REPLACE_WITH_REVIEWED_TERMINATION_A_RECORD/32
cp_carrier_gateway_provider_signaling_port: 5061
cp_carrier_gateway_provider_media_ipv4_cidrs:
  - REPLACE_WITH_PROVIDER_MEDIA_AUTHORITY
cp_carrier_gateway_provider_remote_media_port_range: REPLACE_START-END
```

It admits signaling only from the two replacements and media only from Edge
source ports `20000-20255` to the Common Teams Leg at `30000-30063`. The
dedicated UID can send private traffic only to those Edge peers. When a profile is enabled,
nftables admits TLS only to its reviewed termination DNS `/32`s and SRTP only
between local UDP `30064-30127` and the profile's exact remote media authority;
inbound provider SIP remains denied. A final UID-specific drop
prevents all other carrier-process egress. Existing web, SSH, PostgreSQL,
PgBouncer, CP1 application, and synthetic fixture rules are unchanged.

Carrier activation is intentionally a two-stage firewall transition. First run
the controller deployment with `cp_voice_fixture_enabled: true` and
`cp_carrier_gateway_enabled: false`, and prove the generation-2 calls. That run
records the complete semantic policy digest in the protected active-profile
marker. A later carrier-enabled run refuses unless the live ruleset exactly
matches that recorded generation-2 profile (or the exact unrecorded baseline
on the one migration path). It renders the desired policy in an isolated
network namespace, applies it, and compares normalized `nft --json` output for
the entire rendered and live rulesets before publishing the new marker. Both
Provider-disabled and enabled profiles are exact; string/comment presence is not
accepted as firewall evidence. Only then set
`carrier_gateway_firewall_contract_acknowledged: true` for this installer.

## Automated public certificate prerequisite

The installer now issues and renews the public credential automatically. It
does not create root DNS authority. Before the first install, the separately
guarded root Direct Routing DNS/ACME deployment must already provide all of:

- `carrier.vivolution.ae` as one A record equal to CP1's reviewed static public
  IPv4;
- `_acme-challenge.carrier.vivolution.ae` as one CNAME to
  `_acme-challenge.acme-carrier.vivolution.ae`;
- the public NS delegation for `acme-carrier.vivolution.ae`, exactly matching
  the isolated Azure child zone;
- CP1's system-assigned managed identity as the sole workload assignment of
  the dedicated Direct POC TXT-only role on that child zone.

Set `carrier_certificate_azure_subscription_id`,
`carrier_certificate_azure_tenant_id`,
`carrier_certificate_expected_cp1_principal_id`, and
`carrier_certificate_acme_email` in the protected inventory. No client secret,
certificate, account key, or Azure credential belongs in inventory or Git.
Before every install or renewal, also run the controller-side read-only root
Direct DNS reconciliation in `carrier-rbac-receipt` mode. It inventories the
whole subscription, rejects broader/inherited or extra workload RBAC, and
signs a receipt valid for at most one hour with an Ed25519 seed kept outside
Git. Put the owner-only receipt and emitted canonical public key at the two
protected controller paths shown in `inventory.example.yml`; pin the reported
DER `signingPublicKeySha256` and key ID in that inventory. Issuance fails before
any TXT cleanup or ACME order unless this receipt is fresh and authentic, the
managed-identity token has the expected tenant/principal, Azure returns the
exact tagged zone, public A/CNAME/NS discovery agrees, and the challenge record
is absent.

The receipt command is read-only and must be rerun immediately before the
Ansible renewal. The exact generation-3 addresses and principals are the same
protected inputs used by the root Direct DNS authority workflow:

```bash
python3 ../../infra/azure-poc/reconcile_root_direct_dns_acme_authority.py \
  --mode carrier-rbac-receipt \
  --expected-subscription-id '<subscription-uuid>' \
  --expected-tenant-id '<tenant-uuid>' \
  --expected-carrier-public-ipv4 '<cp1-public-ipv4>' \
  --expected-sbc1-public-ipv4 '<g3-sbc1-public-ipv4>' \
  --expected-sbc2-public-ipv4 '<g3-sbc2-public-ipv4>' \
  --expected-cp1-principal-id '<cp1-principal-uuid>' \
  --expected-sbc1-principal-id '<g3-sbc1-principal-uuid>' \
  --expected-sbc2-principal-id '<g3-sbc2-principal-uuid>' \
  --receipt-signing-seed /protected/carrier-acme-rbac-ed25519.seed \
  --receipt-signing-key-id carrier-acme-rbac-2026-08 \
  --receipt-output /protected/carrier-acme-rbac-receipt.json \
  --receipt-public-key-output /protected/carrier-acme-rbac-signer.pem \
  --receipt-lifetime-seconds 900
```

The role downloads Lego `5.4.0` by a fixed archive SHA-256 into a dedicated
path. ACME account/certificate state remains below a `root:root 0700` directory
and is checked for links, ownership, modes, file count, and size. The order has
exactly one RSA-2048 SAN, `carrier.vivolution.ae`. Public trust, ordered chain,
server-auth EKU, key match, and at least fourteen days of remaining lifetime
must pass before activation.

Activation is a root-owned journaled transaction. It stages a validated pair,
stops rootless Asterisk only when already active, atomically installs both live
files as `root:10003 0440`, restarts the rootless unit, and requires full
gateway readiness. Any failure restores the protected previous pair and proves
readiness again; a later run recovers the same transaction after interruption.
The dedicated child-zone challenge is conditionally reconciled by ETag and
must be absent before activation. The hardened persistent systemd timer runs
daily with randomized delay, but deliberately fails closed after the short
controller receipt expires; the supported renewal path is a fresh receipt
followed by `renew-certificate.yml`. An unchanged certificate causes no
restart. Autonomous controller receipt delivery remains outside this bounded
host role.

## Install and qualify

Copy `inventory.example.yml` to a protected ignored inventory and use the
existing dedicated SSH key. Do not put passwords, private keys, Twilio tokens,
or actual telephone numbers in this repository.

```bash
cd poc/carrier-gateway
ansible-playbook --syntax-check -i /protected/inventory.yml install.yml
ansible-playbook -i /protected/inventory.yml install.yml
ansible-playbook -i /protected/inventory.yml qualify.yml
ansible-playbook -i /protected/inventory.yml renew-certificate.yml
```

The readiness gate verifies the rootless user service, immutable image ID,
read-only/capability-free container state, exact user-slice IP/bind sets,
listener exclusivity, mutual TLS handshake and hostname, loaded `res_srtp`,
tone/echo dialplan, no PJSIP registration objects, exact public NAT identity,
provider DNS/media authority, and provider absence/armed-without-call-authority
state.

The deterministic local routes are deliberately non-billable:

- `+9710000002001`: answers with a milliwatt tone after Teams/Edge reaches CP1.
- `+9710000002002`: answers with echo after Teams/Edge reaches CP1.
- local `9301`/`9302`: select SBC1/SBC2 and send the deliberately invalid test
  E.164 toward Microsoft; `9300` tries SBC1 then SBC2. These prove outbound
  Edge selection/signaling, but a Microsoft rejection is expected until an
  actual licensed test-user route is supplied by a separately reviewed test.

The root-only runner requires the exact acknowledgement and contains no provider
endpoint:

```bash
sudo /usr/local/sbin/vivolution-carrier-gateway-test \
  --acknowledge NON_BILLABLE_EDGE_SIGNALING_ONLY sbc1
```

Full acceptance still requires external calls through each Edge, post-call
readiness, reboot, N-1 new-call failover, and signed evidence. Offline/static
success is not a live-call claim.

## Generic SIP Trunk Leg and Twilio example

The provider leg is disabled by default. With the default variables, all provider
identity, addresses, prefixes, caller ID and secrets must be empty, and no auth,
AOR, endpoint, dialplan carrier route, public NAT advertisement, host-firewall
rule, or cgroup public-IP allowance is rendered.

This package has no inbound provider route and makes no DID or inbound-PSTN
claim. A DID is not required for the outbound test. Emergency/service
numbers and every non-allowed destination are rejected before carrier routing.

`provider-profiles/twilio.example.yml` maps Twilio to the same neutral contract.
Copy it into protected inventory, replace every placeholder, and keep the
completed file outside Git. A different customer profile uses the same keys;
the currently qualified common contract is outbound-only, TLS 1.2, no SIP
registration, digest authentication, and mandatory SDES-SRTP.

The Twilio example requires all of the following in a protected encrypted
inventory. Another provider supplies its own reviewed FQDN and network
authorities through the same neutral variable contract:

- exact acknowledgement `ENABLE_ONE_SHOT_SIP_PROVIDER_OUTBOUND_POC`;
- one `*.pstn.twilio.com` termination FQDN and its exact current public `/32`
  A-record set, each within Twilio's published signaling `/30`s;
- geo allowlist exactly `AE` and E.164 prefixes beginning `+971` only;
- one permitted verified E.164 caller ID;
- an exact `{username,password}` mapping, with the password restricted to a
  shell/config-inert alphabet;
- maximum duration at most 120 seconds, one call per authorization, a reviewed
  per-minute cost ceiling at most USD 1, and estimated per-call ceiling at most
  USD 2.

The provider authority was reviewed on 2026-08-31 against Twilio's current
[Elastic SIP Trunking IP list](https://www.twilio.com/docs/sip-trunking/ip-addresses).
The trunk is credentials-only and contains no registration object. Signaling
is TLS 1.2 on TCP 5061, media is mandatory SDES-SRTP, `Max-Forwards` is exactly
70, and the Request-URI, From user, caller ID, ANI and Contact user retain full
`+E.164` form. Twilio receives `40.123.208.212` in public signaling and SDP;
private Edge traffic remains private through PJSIP `local_net` handling.

Secrets are rendered only into the isolated `provider-auth.conf`, which is
`root:10004 0440`; the Common Teams Leg cannot read it and the Ansible tasks
handling it use `no_log`. Readiness and CDR evidence never emit the secret. The
local spend value is a conservative
evidence bound based on maximum duration and the operator-supplied rate ceiling;
it is not a substitute for Twilio account-level balance/geo controls.

Even after the trunk exists, no billable route is usable. Immediately before
one approved call, run `authorize-one-call.yml` with:

- exact acknowledgement `AUTHORIZE_EXACTLY_ONE_BILLABLE_PSTN_CALL`;
- a fresh non-secret request ID;
- one exact allowed E.164 destination;
- expiration 60-600 seconds in the future;
- duration and estimated-spend bounds no broader than installation.

The role refuses a pending or previously consumed request ID and creates one
`0600` authorization with `maximum_calls=1`. The AGI validates metadata,
destination, expiry, duration and spend, then atomically moves it to a
`.claimed` record before `Dial(PJSIP/...@provider)` becomes reachable. A failed
carrier attempt still consumes the authorization. Creating this file does not
dial; the actual provider call remains a separate, immediately approved action.

## CDR evidence

Asterisk writes protected custom CDRs. The installed normalizer accepts only
the three known account codes, bounded durations, safe evidence IDs, and one
regular single-link input below 8 MiB. It emits canonical JSON plus
`MANIFEST.sha256` into a brand-new `0700` directory. Telephone numbers, channel
names and Asterisk unique IDs are never exported; each complete source row is
bound only by SHA-256.

The basic normalizer is provider-neutral. Authorized billable-call evidence
also requires a provider-specific signed external receipt. The collector loads
`/usr/local/libexec/carrier_cdr_provider_adapters/<provider-profile>.py`, rejects
unsafe profile names and adapters writable by their group or others, and binds
the adapter source digest into the evidence. Each adapter declares the v1 API
and its profile, then implements `verify(context)` using the core's
protected-envelope signature verifier. Its exact receipt fields, schema, provider signing-key ID,
and billing bindings remain outside the collector core. Add another protected
adapter file to support a customer carrier; the core needs no provider registry
or code change.

The included `twilio.py` adapter is selected with `--provider-profile twilio`.
Authorized collection supplies neutral `--provider-receipt` and
`--provider-public-key` paths; only that adapter knows the Twilio receipt
schema and fields. A future customer carrier needs its own corroboration
adapter before it can make the same externally verified billing claim.

```bash
sudo /usr/local/libexec/vivolution-carrier-cdr-evidence \
  /var/lib/vivolution/carrier-gateway/asterisk-log/cdr-custom/VivolutionCarrier.csv \
  /var/lib/vivolution/carrier-gateway/results/one-new-directory
```

## Idempotence, rollback, and teardown

The immutable image revision builds only when absent, transfers through a
bounded protected OCI archive into the rootless store, and Quadlet uses its
content ID. Every reconfiguration first writes a root-only
`pending-config.tar`; an interrupted install leaves it visible and blocks a
rerun. The root-only bundle digest-binds provider enablement, profile/FQDN
configuration, isolated Quadlet, and the optional `root:10004 0440` credential;
its manifest contains only the credential digest and metadata, never its
plaintext. Exact readiness atomically promotes it to `previous-config.tar`.

Run `rollback.yml` with
`ROLLBACK_CARRIER_GATEWAY_TO_PROTECTED_PREVIOUS_CONFIG`. It validates an exact
bounded regular-file archive, quiesces both Asterisk processes, preserves the
current public PKI, and restores the complete provider binding while egress is
stopped. It restarts provider egress first, proves a new PID and its live TLS
transport, then restarts the Common Teams Leg and requires full readiness. If
the restored candidate fails, the rescue path puts the exact pre-rollback
configuration and credential back before reporting failure.

Configuration rollback deliberately preserves the currently accepted public
credential. It first gates renewal/activation, proves both certificate locks
quiescent, binds the exact live certificate/key digests, and refuses acceptance
unless those digests remain identical. Certificate rollback is independent
and automatic through its root-only backup and activation journal; do not copy
an older key from a configuration archive.

Teardown stops certificate scheduling and the gateway, proves their processes,
locks, units, container, listeners, and activation journal are absent, then
removes certificate launch code before deleting the acknowledged ACME state,
receipt trust anchor, rotation evidence/backups, and live PKI. It preserves
CDR/evidence/authorization history and the rootless image unless their separate
destructive acknowledgements are supplied. Finally rerun
the CP1 firewall role with `cp_carrier_gateway_enabled: false`; teardown accepts
completion only after both carrier nftables comments are absent and the exact
`HOST_FIREWALL_CARRIER_RULES_REMOVED` acknowledgement is supplied.
