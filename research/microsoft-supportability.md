# Microsoft Supportability Notes

Verified: 2026-08-27

## What Microsoft supports

Microsoft documents Direct Routing with one SBC serving multiple Microsoft 365 tenants. The model is intended for Microsoft partners and PSTN carriers. The provider deploys and manages the SBC, connects customer tenants, and assumes end-to-end call-quality responsibility.

Only certified SBC products running supported firmware are supported for Teams Direct Routing. Support cases begin with the SBC vendor, and Microsoft may reject a case involving a non-certified implementation.

## Hosted tenant model

- The provider registers a base domain and carrier trunk in its own Microsoft 365 tenant.
- Every customer registers a unique subdomain of that base domain in the customer tenant.
- The subdomain must match the derived trunk FQDN and the FQDN presented in the SIP Contact header.
- A wildcard certificate for the provider base domain can authenticate multiple customer-derived FQDNs.
- Customer domain registration and activation require Customer Global Administrator participation and a qualifying licensed user or resource account using that FQDN.
- Provider and customer tenants must be in the same Microsoft cloud.
- Customers place the derived trunk FQDNs in their voice routes rather than registering independent gateways.
- Configuration, health, and drain state on a carrier trunk can propagate to derived trunks.
- Microsoft documents that carrier-trunk number translations do not currently propagate to derived trunks; translation may require customer-tenant configuration.

## User prerequisites

- Teams and Teams Phone entitlement; Microsoft Calling Plan is not required for Direct Routing.
- Users homed online, enabled for Direct Routing, and configured appropriately for Teams calling.
- Customer dial plans, voice routes, PSTN usages, voice-routing policies, numbers, and emergency-calling design.

## Availability design

- Use two distinct SBC FQDNs and public IPs for tenant failover.
- Add both customer-derived FQDNs to every customer's voice routes.
- Configure Microsoft public-cloud SIP endpoints and monitor SIP OPTIONS health.
- Use a public trusted certificate, TLS 1.2, and supported media/security settings.

## Product implication

For **Vivolution Certified Edge**, the Teams-facing component must be a licensed certified virtual SBC on supported firmware. Vivolution's proprietary value remains the control plane, isolation model, automation, observability, support, and service packaging.

For **Vivolution Open Edge**, an OpenSIPS/Kamailio implementation may interoperate technically but is outside Microsoft's certified support boundary. It must be contracted and marketed accordingly. Microsoft also states that inserting a third-party SIP proxy/UAS between its SIP proxy and the paired SBC is unsupported; an open-source proxy in front of a certified product does not make that overall call path certified.
