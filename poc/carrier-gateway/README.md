# Vivolution bounded carrier gateway

This directory is a separate CP1-hosted carrier/PBX gateway for the first
tenant proof of concept. It does not modify, reuse, or weaken
`poc/voice-fixture`; the synthetic fixture remains an isolated no-PSTN system.

The implemented boundary is intentionally narrow:

- CP1 private listener: `10.20.1.4:5061/TLS`, certificate/SNI
  `carrier.vivolution.ae`.
- Generation-3 Edge peers only: `sbc1.vivolution.ae` at `10.20.2.6` and
  `sbc2.vivolution.ae` at `10.20.2.7`, each on PBX listener TCP `15061`.
- Carrier RTP/SRTP allocation: UDP `30000-30127`; Edge-side source allocation:
  UDP `20000-20255`.
- Asterisk `22.10.1` with bundled PJProject `2.17`, both downloaded by pinned
  SHA-256. The multi-stage build requires `libsrtp2-dev`, enables and verifies
  `res_srtp.so`, copies only resolved runtime libraries, and carries the two
  narrowly guarded PJProject kernel-autobind patches needed by the systemd
  socket boundary.
- Edge signaling uses mutual TLS with the common public CA bundle. The server
  certificate must have exactly one SAN, `carrier.vivolution.ae`, verify against
  the host public trust store, remain valid for at least 24 hours, and match a
  protected `root:10003 0440` key. Synthetic fixture keys and CAs are rejected
  by construction because no fixture path is mounted or rendered.
- Media encryption is SDES-SRTP on Edge and optional Twilio endpoints. TLS is
  fixed to TLS 1.2, which excludes TLS 1.0/1.1 and matches the bounded Twilio
  POC contract.

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
UDP `30000-30127`. When Twilio is enabled, the slice additionally admits only
the reviewed public `/32` addresses that exactly equal the live A records of
the configured `*.pstn.twilio.com` target. The Asterisk/PJProject patches defer
only outbound zero-port binds to the kernel; an explicit port-zero bind remains
denied.

The CP1 nftables rule is separate and opt-in through the existing controller
firewall role:

```yaml
cp_carrier_gateway_enabled: true
cp_carrier_gateway_source_ipv4_cidrs:
  - 10.20.2.6/32
  - 10.20.2.7/32
cp_carrier_gateway_tcp_port: 5061
cp_carrier_gateway_edge_media_source_port_range: 20000-20255
cp_carrier_gateway_udp_destination_port_range: 30000-30127
```

It admits signaling only from the two replacements and media only from Edge
source ports `20000-20255` to carrier destinations `30000-30127`. Existing web,
SSH, PostgreSQL, PgBouncer, CP1 application, and synthetic fixture rules are
unchanged. Run the normal CP1 deployment after setting this opt-in, inspect the
two nftables comments, then set
`carrier_gateway_firewall_contract_acknowledged: true` for this installer.

## Certificate prerequisite

Root DNS/ACME authority is a separate controlled phase. Before installation,
place the public certificate chain and private key on CP1 at:

```text
/etc/vivolution/carrier-gateway/pki/carrier.fullchain.pem  root:10003 0440
/etc/vivolution/carrier-gateway/pki/carrier.key            root:10003 0440
```

The role never generates a private CA, copies a fixture credential, or places a
key in Git. Certificate renewal must preserve the same owner/mode and restart
the rootless service only after the same identity/trust checks pass.

## Install and qualify

Copy `inventory.example.yml` to a protected ignored inventory and use the
existing dedicated SSH key. Do not put passwords, private keys, Twilio tokens,
or actual telephone numbers in this repository.

```bash
cd poc/carrier-gateway
ansible-playbook --syntax-check -i /protected/inventory.yml install.yml
ansible-playbook -i /protected/inventory.yml install.yml
ansible-playbook -i /protected/inventory.yml qualify.yml
```

The readiness gate verifies the rootless user service, immutable image ID,
read-only/capability-free container state, exact user-slice IP/bind sets,
listener exclusivity, mutual TLS handshake and hostname, loaded `res_srtp`,
tone/echo dialplan, and Twilio absence/armed-without-call-authority state.

The deterministic local routes are deliberately non-billable:

- `+9710000002001`: answers with a milliwatt tone after Teams/Edge reaches CP1.
- `+9710000002002`: answers with echo after Teams/Edge reaches CP1.
- local `9301`/`9302`: select SBC1/SBC2 and send the deliberately invalid test
  E.164 toward Microsoft; `9300` tries SBC1 then SBC2. These prove outbound
  Edge selection/signaling, but a Microsoft rejection is expected until an
  actual licensed test-user route is supplied by a separately reviewed test.

The root-only runner requires the exact acknowledgement and contains no Twilio
endpoint:

```bash
sudo /usr/local/sbin/vivolution-carrier-gateway-test \
  --acknowledge NON_BILLABLE_EDGE_SIGNALING_ONLY sbc1
```

Full acceptance still requires external calls through each Edge, post-call
readiness, reboot, N-1 new-call failover, and signed evidence. Offline/static
success is not a live-call claim.

## Optional Twilio outbound only

Twilio is disabled by default. With the default variables, all Twilio names,
addresses, prefixes, caller ID and secrets must be empty, and no Twilio auth,
AOR, endpoint, dialplan carrier route, or additional IP allowance is rendered.

This package has no inbound Twilio route and makes no DID or inbound-PSTN
claim. A Twilio DID is not required for the outbound test. Emergency/service
numbers and every non-allowed destination are rejected before carrier routing.

Enabling the dormant trunk requires all of the following in a protected
encrypted inventory:

- exact acknowledgement `ENABLE_ONE_SHOT_TWILIO_OUTBOUND_POC`;
- one `*.pstn.twilio.com` termination FQDN and its exact current public `/32`
  A-record set;
- geo allowlist exactly `AE` and E.164 prefixes beginning `+971` only;
- one permitted verified E.164 caller ID;
- an exact `{username,password}` mapping, with the password restricted to a
  shell/config-inert alphabet;
- maximum duration at most 120 seconds, one call per authorization, a reviewed
  per-minute cost ceiling at most USD 1, and estimated per-call ceiling at most
  USD 2.

Secrets are rendered only into `pjsip.conf`, which is `root:10003 0440`; the
Ansible tasks handling it use `no_log`. Readiness and CDR evidence never query
or emit the Twilio endpoint/auth object. The local spend value is a conservative
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
`.claimed` record before `Dial(PJSIP/...@twilio)` becomes reachable. A failed
carrier attempt still consumes the authorization. Creating this file does not
dial; the actual Twilio call remains a separate, immediately approved action.

## CDR evidence

Asterisk writes protected custom CDRs. The installed normalizer accepts only
the three known account codes, bounded durations, safe evidence IDs, and one
regular single-link input below 8 MiB. It emits canonical JSON plus
`MANIFEST.sha256` into a brand-new `0700` directory. Telephone numbers, channel
names and Asterisk unique IDs are never exported; each complete source row is
bound only by SHA-256.

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
rerun. Exact readiness atomically promotes it to `previous-config.tar`.

Run `rollback.yml` with
`ROLLBACK_CARRIER_GATEWAY_TO_PROTECTED_PREVIOUS_CONFIG`. It validates an exact
bounded regular-file archive, stops the rootless service, preserves the current
public PKI, swaps configuration under a protected recovery workspace, restarts
and requires readiness. If the restored candidate fails, the rescue path puts
the exact pre-rollback configuration back before reporting failure.

Teardown stops the service and removes any unconsumed call authorization first.
It preserves CDR/evidence/authorization history, PKI, and the rootless image
unless their separate destructive acknowledgements are supplied. Finally rerun
the CP1 firewall role with `cp_carrier_gateway_enabled: false`; teardown accepts
completion only after both carrier nftables comments are absent and the exact
`HOST_FIREWALL_CARRIER_RULES_REMOVED` acknowledgement is supplied.
