# Platform Shortlist

Status: Market preflight only. No vendor is selected and no commercial contact is authorized.

## Certified platforms to evaluate

Microsoft's multi-tenant hosting guidance links vendor instructions for AudioCodes, Oracle, Ribbon Communications, TE-Systems anynode, and Metaswitch. The current Microsoft certified-SBC list must be checked again at procurement time for exact products and firmware.

### AudioCodes Mediant virtual/container SBC

- Publishes a Teams Direct Routing Hosting Model configuration guide.
- Mature service-provider feature set and optional Microsoft 365 lifecycle/management products.
- Likely strong operational tooling, but licensing and management-suite cost must be tested carefully.

### AudioCodes Live Express / Live Hub

- Turnkey partner-service benchmarks for multi-customer Teams calling onboarding, management, analytics, and end-customer administration.
- Potentially the fastest way to test demand with less platform engineering.
- Must validate UAE points of presence, data residency, UAE carrier/number support, white-label rights, support boundaries, and commercial availability.

### TE-Systems anynode

- Software SBC with an explicit Microsoft Teams multi-tenancy proposition.
- Potentially simpler and more economical for an early hosted service.
- Must validate carrier-trunk hosting features, HA behavior, API/RBAC depth, support coverage, and commercial rights for managed-service resale.

### Ribbon SBC software/core variants

- Microsoft points to Ribbon carrier-hosting configuration guidance.
- Strong telecom pedigree and scale options.
- Need to identify the smallest certified product/firmware licensed for genuine hosting and quantify operational complexity.

### Oracle Communications SBC

- Certified enterprise/service-provider platform with strong carrier capabilities.
- Likely suitable technically, but may be heavier and more expensive than the first target segment requires.

### Other certified products

- Evaluate only if the exact product and firmware is on Microsoft's current list and the vendor contract explicitly permits multi-tenant managed hosting.

### 46 Labs PeerEdge

- Microsoft lists Peeredge Orchestrator as certified; the vendor positions it as voice-infrastructure orchestration across SIP trunking, Teams Direct Routing, and multiple carriers.
- Useful as a benchmark for buying the orchestration/control layer rather than building it.
- Validate UAE deployment locality, exact certified data path, partner economics, carrier neutrality, and support coverage.

## Optional supporting platforms

- Kamailio or OpenSIPS for policy/routing orchestration.
- RTPengine for media relay where justified.
- FreeSWITCH or Asterisk for defined media/application workloads.
- Sipwise or another multi-tenant voice platform as a control/service layer.

These are not substitutes for the certified Microsoft-facing SBC. A second SIP layer should be added only if it improves unit economics, automation, or feature delivery enough to justify the additional failure and support surface.

## Commercial questions for every certified vendor

- Is the exact Teams hosting model supported and contractually permitted?
- Licensing units: concurrent sessions, registered tenants, nodes, throughput, features, or usage?
- Minimum licenses for two-node HA and non-production lab?
- Per-tenant routing contexts, RBAC, API coverage, audit, CDR isolation, and backup/restore?
- Supported clouds/hypervisors and UAE deployment rights?
- NFR/trial availability and partner/MSP resale terms?
- 24/7 support, escalation, and certified-firmware lifecycle?
- Scale-up/scale-out limits and non-disruptive upgrades?

## Shortlist recommendation

For UAE self-hosting, price and technically score AudioCodes Mediant VE and anynode first, plus one carrier-grade alternative such as Ribbon. Benchmark them against a turnkey service such as AudioCodes Live Express/Hub or 46 Labs PeerEdge. The decision should be based on five-year unit economics, UAE/operator fit, and operational burden—not the lowest initial licence quote.
