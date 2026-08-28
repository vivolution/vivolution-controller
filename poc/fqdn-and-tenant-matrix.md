# POC FQDN and Microsoft 365 Tenant Matrix

Status: Template only. Replace `.example` after Jay approves a lab domain and POC execution.

## Required tenants

### Vivolution/provider tenant

- Owns and activates the two base SBC domains.
- Contains only the two carrier/base Direct Routing gateways.
- Does not need Microsoft Calling Plan.

### Customer Tenant A

- Activates its two derived subdomains.
- Adds the derived trunks to its voice routes.
- Contains at least two Teams + Teams Phone test users.

### Customer Tenant B

- Same structure as Customer A but in an independent Entra/Microsoft 365 tenant.
- Uses deliberately overlapping synthetic numbers/extensions to prove isolation.

All three tenants must be in the same Microsoft cloud.

## FQDN template

| Role | Node 1 | Node 2 |
| --- | --- | --- |
| Provider/base | `sbc1.lab.voice.vivolution.example` | `sbc2.lab.voice.vivolution.example` |
| Customer A derived | `customer-a.sbc1.lab.voice.vivolution.example` | `customer-a.sbc2.lab.voice.vivolution.example` |
| Customer B derived | `customer-b.sbc1.lab.voice.vivolution.example` | `customer-b.sbc2.lab.voice.vivolution.example` |

- Every Node 1 name resolves to Edge 1's single static public IP.
- Every Node 2 name resolves to Edge 2's single static public IP.
- Do not place several public IPs behind one SBC FQDN; use the two distinct node FQDNs for failover.

## Certificate template

Node 1 RSA certificate:

- `sbc1.lab.voice.vivolution.example`
- `*.sbc1.lab.voice.vivolution.example`

Node 2 RSA certificate:

- `sbc2.lab.voice.vivolution.example`
- `*.sbc2.lab.voice.vivolution.example`

Use DNS-01, a complete trusted chain, Server Authentication EKU, automated validation, and staged replacement. Let’s Encrypt is a lab assumption only because Microsoft's future Client Authentication EKU requirement may require another certificate profile.

## Microsoft configuration behavior to prove

1. Register and activate the two base domains in the Vivolution/provider tenant.
2. Create only the two provider gateways there.
3. Register and activate each customer-derived subdomain in the appropriate customer tenant.
4. Add the derived FQDNs directly to that customer's voice routes; do not create separate customer gateways for them.
5. Put both derived node FQDNs in each customer's routes.
6. For SBC-to-Teams calls, present the exact customer-derived FQDN in Contact so Microsoft selects the intended customer tenant.
7. Capture the Teams-to-SBC INVITE/TLS behavior and document the stable trusted tenant selector before enabling Customer B.
8. Remember that base-trunk number translation rules do not automatically apply to derived trunks; generate any required customer-tenant translation policy explicitly.

## Example synthetic number fixtures

- Both Customer A and Customer B may use extension `1001` internally.
- Both may use the same non-routable lab E.164-like fixture.
- No route may reach a real PSTN carrier or emergency destination.

The overlapping fixtures are deliberate. Correct calls must depend on derived-trunk/peer identity, not digits.
