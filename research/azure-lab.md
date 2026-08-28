# Azure Lab Economics

Verified: 2026-08-27. Retail USD pay-as-you-go prices are indicative; Jay's subscription prices may differ.

Jay has an Azure subscription with USD 100 monthly credit that resets each month. This is useful for discovery, but it is not evidence that a production HA service can run for USD 100.

## UAE North reference prices

- Linux B1ms: approximately USD 0.025/hour or USD 18.25/month.
- Linux B2s: approximately USD 0.0499/hour or USD 36.43/month.
- Linux B2ms: approximately USD 0.0998/hour or USD 72.85/month.
- Linux D2as v5: approximately USD 0.106/hour or USD 77.38/month.
- Linux D2s v5: approximately USD 0.118/hour or USD 86.14/month.
- Standard static IPv4: approximately USD 3.65/month each.
- Standard SSD LRS: approximately USD 2.88/month for 32 GiB or USD 5.76/month for 64 GiB.
- Public DNS zone: approximately USD 0.50/month plus low query charges.

## Lab shapes

### Lean single-node functional lab

- One B2s, 64 GiB Standard SSD, static public IP, and DNS.
- Rough base cost: USD 46/month before logs, backup, and egress.
- Suitable for portal/signaling/media functionality at low traffic; not HA.

### Two-node topology lab

- Two B2s VMs, two 32 GiB disks, two static public IPs, and DNS.
- Rough base cost: USD 86/month before logs, backup, and egress.
- Fits narrowly inside the credit and can test two FQDNs and failover, but B-series CPU credits make it unsuitable for production capacity or SLA conclusions.

### Production-like compute

Two non-burstable D2-class nodes exceed USD 150/month in compute alone before storage, IPs, telemetry, backup, and bandwidth. Production sizing therefore requires a separate business case.

## Cost controls

- Use static Standard public IPs and NSGs directly; avoid Azure Firewall, NAT Gateway, load balancer, and managed database during early discovery.
- Set budgets and alerts before resources are created.
- Keep verbose SIP logs controlled; Log Analytics ingestion can exceed compute cost quickly.
- Do not use Spot or automatic VM deallocation for a continuity test.
- Media egress and transcoding load must be measured separately from signaling.

## Let's Encrypt

Microsoft's current Direct Routing planning guidance requires the SBC certificate to:

- contain the SBC FQDN in CN/SAN;
- chain to a CA in the Microsoft Trusted Root Program;
- include Server Authentication EKU;
- use an RFC 2818-compliant wildcard when a wildcard is used.

ISRG Root X1/X2 participate for Server Authentication, so a correctly chained Let's Encrypt certificate is a reasonable lab candidate. Request an **RSA** certificate to match Microsoft's currently documented Direct Routing cipher authentication profile. Use DNS-01 for node-level wildcards, include the base name and wildcard SAN (for example, `sbc1.example.ae` and `*.sbc1.example.ae`), distribute the full chain, automate renewal, alarm before expiry, validate before replacement, and reload TLS without interrupting calls.

Important lifecycle caveat: Let's Encrypt stopped issuing certificates with the TLS Client Authentication EKU in July 2026. Microsoft currently accepts SBC certificates without that EKU but has announced a future requirement for Client Authentication. Therefore Let's Encrypt should be treated as a current lab assumption—not the only production certificate strategy. Budget and test a commercial CA/profile capable of meeting Microsoft's future mTLS requirement.
