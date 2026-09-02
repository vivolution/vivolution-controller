# POC FQDN and Microsoft 365 tenant matrix

Status: selected single-tenant first POC as of 2026-08-31. Multi-tenant derived
trunks are deferred and must not be inferred from this acceptance run.

## Microsoft 365 tenant

- Organization: Vivolution Technologies LLC.
- Tenant ID: `151cd01a-1e81-40a9-b898-d8646e1a8760`.
- Administrator/test identity: `jay@vivolution.ae`.
- Domain: `vivolution.ae`; live verified-domain status must be rechecked after
  normal browser authorization.
- Entitlement: Jay reports Microsoft 365 E5 with Teams Phone. The live preflight
  must confirm license, Teams upgrade mode, enterprise voice, and user policy.
- Support boundary: OpenSIPS/RTPengine is accepted for this non-certified POC.

## Selected live FQDNs

| Role | FQDN | Target |
| --- | --- | --- |
| Direct Routing node 1 | `sbc1.vivolution.ae` | generation-3 SBC1 public IP |
| Direct Routing node 2 | `sbc2.vivolution.ae` | generation-3 SBC2 public IP |
| CP1 carrier gateway | `carrier.vivolution.ae` | replacement CP1 public IP |
| Controller after cutover | `controller.voice.vivolution.ae` | replacement CP1 public IP |

Each name has one static public IPv4 address. The two node FQDNs remain distinct
so Microsoft 365 can perform gateway selection and failover.

## DNS-01 authority

- `acme-sbc1.vivolution.ae` is delegated only to SBC1's isolated ACME zone.
- `acme-sbc2.vivolution.ae` is delegated only to SBC2's isolated ACME zone.
- `acme-carrier.vivolution.ae` is delegated only to CP1's isolated carrier ACME
  zone.
- Managed identities receive TXT mutation rights only in their matching child
  zone. Parent records, unrelated zones, and other nodes' challenges remain out
  of scope.

The public certificates use complete trusted chains and Server Authentication
EKU. Issuance, renewal, TXT cleanup, atomic installation, and dependent-service
reload are acceptance gates rather than manual runbook assumptions.

## Preserved generation-2 rollback names

- `sbc1.voice.vivolution.ae`
- `sbc2.voice.vivolution.ae`
- existing tenant wildcard names beneath those nodes

These identify the signed synthetic last-known-good environment. They are not
the selected Microsoft 365 Direct Routing gateways and stay intact until the
generation-3 path is accepted.

## Call fixtures

- `+9710000002001`: CP1 carrier tone probe; explicitly admitted by the exact
  nonbillable test route.
- `+9710000002002`: CP1 carrier echo probe; explicitly admitted by the exact
  nonbillable test route.
- Normal user assignments remain restricted to valid UAE E.164 numbers and do
  not admit the probe fixtures.
- A real Teams-to-PSTN call is outbound-only through Twilio. It requires a
  Twilio-owned or verified caller ID and immediate approval of destination,
  count, and maximum spend. No inbound call is claimed because there is no DID.

## Deferred hosted multi-tenant model

Future customer tenants may use derived node names and overlapping internal
extensions only after a separate-tenant Microsoft procedure is proven. That
work requires independent tenant/domain activation, exact Contact-based tenant
selection, customer-specific voice routes, certificate SAN policy, isolation,
and negative cross-tenant tests. None of those claims belongs to this
single-tenant POC.
