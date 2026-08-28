# Commercial Model

Status: Brainstorming assumptions only.

## Recommended version 1 offer

**Vivolution Managed Direct Routing Edge — customer-owned trunk, PBX relay first**

- One-time customer onboarding and migration fee.
- Monthly tenant/platform fee.
- Included concurrent-call capacity.
- Capacity add-ons by concurrent session tier, not just user count.
- Optional PBX/contact-centre integration.
- Premium HA/DR, extended support, reporting retention, and managed change packages.
- Customer maintains the carrier contract and Microsoft Teams Phone licensing.
- UAE-licensed carrier remains provider of record and approves the hosted topology.
- Open Edge or Certified Edge chosen according to customer support/procurement requirements.
- Enhanced Isolation by default, or Dedicated Isolation with an exclusive two-node pair.

This separates Vivolution's managed-platform value from regulated PSTN supply and makes cost pooling visible to customers. It remains a hypothesis until the operator and UAE counsel confirm that the exact managed service is permitted.

## Unit-economics model

Model at least these cost pools:

- Open Edge engineering/operations cost or Certified Edge licences for production, HA, lab, features, and support.
- Compute, storage, public IPs, bandwidth, and media egress in two UAE failure domains.
- Monitoring, logging, SIEM, backups, certificates, and security controls.
- Engineering, onboarding, 24/7 incident response, vendor escalation, and planned maintenance.
- Billing, support desk, insurance, legal/regulatory work, and fraud exposure.
- Spare headroom for node or carrier failure.

Revenue should be tested against low, expected, and high utilization. Concurrent-call peaks—not average users—drive SBC capacity.

## Packaging idea

Keep three choices separate so pricing and promises remain clear:

- **Product track:** Open Edge or Certified Edge.
- **Isolation mode:** Enhanced shared cluster or Dedicated exclusive cluster.
- **Hosting model:** Vivolution Hosted, Customer Cloud, or Customer On-Premises; customer-hosted v0.1 is Dedicated only.
- **Support package:** Essential, Business, or Critical response/change/retention commitments.

An example offer could combine Open Edge + Enhanced + Business without creating a different technical product name. Dedicated pricing must cover the full pair, reserved N-1 capacity, public IP/media egress, monitoring, patching, and idle headroom.

Customer-Hosted Dedicated pricing can remove Vivolution compute/public-IP costs but adds onboarding, environment validation, shared-responsibility coordination, drift handling, and more constrained SLA language. It should not be priced as merely a cheaper VM option.

Exact prices should wait for vendor licence and UAE hosting quotations.

## Commercial risks

- Vendor minimums erase the expected saving at low customer count.
- A shared platform needs expensive operational discipline even when lightly used.
- Carrier contracts may prohibit hosting, aggregation, or resale.
- One fraud event or route error can consume margin quickly.
- Customer-specific customizations can turn a product into bespoke consulting.

The service should therefore standardize onboarding, supported trunk patterns, dial plans, capacity tiers, and change procedures from the beginning.
