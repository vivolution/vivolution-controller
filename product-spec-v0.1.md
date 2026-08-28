# Vivolution SBC — Product Specification v0.1

Status: Brainstorming baseline; not approved for production or a customer pilot.

## Product thesis

Vivolution SBC should be sold as a **managed Microsoft Teams voice edge**, not as a generic PBX and not merely as access to a SIP proxy. It gives a UAE customer with an existing PBX and carrier trunk a repeatable path to Teams Phone while Vivolution owns the difficult interconnection, change control, monitoring, and support work.

The first product should solve one narrow topology well:

```text
Microsoft Teams
  -> Vivolution Open or Certified Edge
  -> customer-owned PBX
  -> customer-owned du/e& or other approved SIP trunk
```

The customer keeps its numbers, carrier contract, PBX, and PSTN billing. Vivolution supplies the hosted Teams-facing edge, safe configuration, visibility, and operational support.

## Initial customer profile

- UAE organizations with approximately 25–300 Teams Phone users.
- An existing SIP-capable PBX and a customer-owned carrier trunk.
- No appetite for buying and operating a dedicated certified SBC.
- A need for controlled Teams migration, hybrid PBX coexistence, CDR visibility, or managed voice expertise.
- Standard calling requirements; contact-centre, emergency-calling, analogue-device, and complex recording integrations remain separately qualified.

The size band is a discovery hypothesis, not a final commercial restriction.

## Product tracks

### Vivolution Open Edge

- Kamailio or OpenSIPS signaling edge, RTPengine media anchoring, and optional Asterisk/FreeSWITCH workers.
- Fully Vivolution-branded portal and operating model.
- Lower software-licence cost.
- Explicitly described as Vivolution-engineered interoperability, not a Microsoft-certified SBC.
- Vivolution carries protocol regression, interoperability, and escalation responsibility.

### Vivolution Certified Edge

- The same portal and tenant model backed by pooled certified SBC capacity such as Ribbon, AudioCodes, or anynode.
- Intended for customers whose procurement, audit, or Microsoft support policy requires certification.
- Higher platform cost but a stronger vendor support boundary.

## Isolation modes

Isolation is selected when a customer service is created. The detailed v0.1 implementation below applies to Open Edge. A Certified Edge may advertise an equivalent mode only where the selected certified product natively proves the required partitioning, media, change-isolation, and support capabilities; adding an OpenSIPS/RTPengine layer must not invalidate its certified support boundary.

### Enhanced Isolation — v0.1 default

- Multiple Enhanced tenants may share one two-node cluster.
- Each tenant receives separate southbound PBX signaling identity/port, source policy, media block and RTPengine unit, routing partition, secrets, quotas, CDR/RBAC scope, and alerts.
- Microsoft-facing TLS 5061, the public IPs, node OS, and cluster-wide OpenSIPS ingress remain shared.
- Tenant-local changes must be atomic/hot-applied and must not restart the shared signaling process.
- This limits tenant-change and media-process blast radius but does not claim physical or whole-node failure isolation.

### Dedicated Isolation

- One customer receives an exclusive two-node Edge Cluster while retaining the common Vivolution control plane.
- The cluster is locked to that tenant before provisioning; a second tenant placement is technically rejected.
- This is the high-capacity, regulated, and exclusive tenant/blast-radius option. It does not by itself improve node, region, cloud-provider, or control-plane resilience beyond the selected HA design.

Changing a live customer between modes is a controlled blue/green migration to another cluster, never an in-place flag change.

## Hosting and availability models

Hosting is selected separately from isolation:

- **Vivolution Hosted:** Vivolution controls the cloud/substrate relationship. Enhanced and Dedicated are available.
- **Customer Cloud:** customer supplies VMs/networking in its cloud account. v0.1 is Dedicated only.
- **Customer On-Premises:** customer supplies VMs/networking on its own hypervisor/site. v0.1 is Dedicated only.

Availability is also explicit: Lab Single Node, HA Pair Single Site, or HA Pair Multiple Failure Domains. A single node is never sold as production HA. Customer-hosted nodes remain Vivolution Managed at launch; customer-operated/root-co-managed mode is deferred.

The provider-neutral Edge Agent makes these hosting models operationally consistent, but it does not transfer responsibility for customer power, hypervisor, ISP, public IP/NAT/firewall, or DNS to Vivolution.

Teams attachment is explicit:

- `HOSTED_DERIVED`: Vivolution/provider base gateways with customer-derived FQDNs; baseline for Vivolution Hosted Enhanced.
- `CUSTOMER_DIRECT`: the dedicated pair is registered directly in the customer's Microsoft tenant; v0.1 baseline for Customer-Hosted Dedicated with one Microsoft tenant.

Customer-hosted multiple-Microsoft-tenant attachment through hosted-derived trunks is deferred until its security, certificate and support boundary is separately proven.

## Connection modes

1. **PBX Relay — v0.1 focus.** Teams calls traverse Vivolution and then the customer's PBX; the PBX keeps the carrier interconnect.
2. **Direct BYOC — later and gated.** Vivolution terminates the customer's carrier trunk directly. This requires written carrier approval and regulatory classification for each topology.
3. **Hybrid — later.** Selected numbers or call types use the PBX while others use an approved direct connector.

Only PBX Relay should enter the first POC. Narrow scope is a feature: it reduces carrier, billing, emergency-calling, and number-ownership ambiguity.

## Tenant onboarding experience

1. Create the customer and record its Microsoft 365 tenant ID, approved domains, contacts, support tier, and retention policy.
2. Allocate two customer-derived SBC FQDNs and show the required DNS/certificate state.
3. Create a PBX connector using validated source identity, TLS policy, capacity, and allowed destinations.
4. Define normalized E.164 ranges, extensions, caller-ID rules, emergency-number behavior, and route priority.
5. Generate a reviewed Teams PowerShell onboarding package and rollback package.
6. Run automated DNS, TLS, SIP OPTIONS, route, and isolation tests.
7. Place controlled inbound and outbound test calls.
8. Require operator approval before activation; retain the exact configuration version and evidence.

For v0.1, the customer runs the generated Teams script under its own administrator account. Vivolution should not retain customer Global Administrator credentials. Delegated automation can be considered later.

The hosted/derived-trunk model also needs a Vivolution/provider Microsoft 365 tenant holding the base SBC trunks. A faithful two-customer POC therefore requires that provider tenant plus two independent customer tenants.

## Portal scope

### Vivolution operator screens

- Fleet health, Edge Clusters, enrolled nodes, capacity, maintenance, and active alerts.
- Tenants and service status.
- Teams endpoints and derived FQDNs.
- PBX/carrier connectors and health.
- Number normalization, dial plans, and routes.
- Capacity, concurrent-call, CPS, destination, and fraud policies.
- Certificates and expiry state.
- CDR, quality, and troubleshooting views.
- Configuration versions, approvals, rollback, and audit history.
- Onboarding test runner and evidence pack.

### Customer screens in v0.1

- Read-only service and trunk health.
- Searchable tenant-only CDRs and exports within policy.
- Current number/routing inventory.
- Certificate and incident notices relevant to the tenant.
- Change-request and approval workflow.

Raw SIP configuration and unrestricted routing changes must never be exposed. Safe self-service can be added after the policy compiler and negative test suite are mature.

## Roles

- **Platform Owner:** global security, platform policy, and emergency access.
- **Vivolution Operator:** tenant onboarding, approved changes, incident response.
- **Customer Administrator:** tenant data, reports, and change requests.
- **Customer Auditor:** read-only CDR, inventory, evidence, and audit history.

## Core data objects

CustomerAccount, M365Tenant, TenantContext, ServiceInstance, HostingProfile, AvailabilityProfile, IdentityEvidence, IntegrityEvidence, TrustPolicyStatus, TeamsAttachmentMode, EdgeCluster, EdgeNode, TenantAllocation, SignalingAllocation, MediaAllocation, CapacityReservation, PlacementDecision, TeamsEndpoint, Connector, NumberRange, TranslationRule, Route, DialPlan, Policy, CapacityLimit, CredentialReference, Certificate, RetentionPolicy, CDR, QualitySample, HealthObservation, Alert, AuditEvent, TestRun, MigrationPlan, ConfigArtifact, and ConfigurationVersion.

`customer_account_id` identifies the legal customer. `m365_tenant_id` identifies an Entra/Microsoft tenant. `tenant_context_id` is the immutable technical call-routing/reporting isolation context. Tenant-scoped objects carry the relevant account and technical context; explicitly global objects do not. Identity is established at the trusted connection boundary, never inferred from a telephone number alone.

The placement scheduler treats customer-account ownership, hosting/attachment model, region/residency, product/platform capability, isolation mode, topology/features, two-node health, listener/media availability, and N-1 capacity as hard constraints. It records why every rejected cluster was unsuitable and never silently downgrades service isolation. Conditional owner, allocation ownership, unique FQDN/port, non-overlapping media range, active-allocation, and capacity-reservation invariants are enforced in one serializable API/database transaction.

## Configuration lifecycle

```text
Draft -> schema validation -> cross-tenant safety tests -> peer review
      -> compile signed artifact -> canary/reload -> health check -> publish
      -> evidence and audit record
```

- Every publish has a known previous version and one-click operator rollback.
- Data-plane nodes use a locally cached last-known-good artifact.
- Calls and new call setup must continue when the portal or control-plane database is unavailable.
- Configuration is not built dynamically from the database for every call.

## Product boundaries

Vivolution v0.1 does not:

- sell telephone numbers, minutes, or pooled PSTN trunks;
- provide a general-purpose hosted PBX, voicemail, contact centre, or call recording;
- promise Microsoft support for Open Edge;
- claim that active calls survive a complete data-plane node failure;
- retain SIP payloads or audio indefinitely;
- allow cross-customer routing;
- automate live emergency calling before location, carrier, and customer responsibilities are documented.

## What the customer actually buys

- A tested Teams-to-PBX connection.
- Managed configuration and change control.
- Redundant edge capacity appropriate to the selected tier.
- Monitoring, alerting, and incident response.
- Tenant-isolated CDR and audit evidence.
- A support boundary spanning Teams routing, SIP interworking, and the customer PBX handoff.

The commercial model should ultimately combine an onboarding fee, a monthly tenant/platform fee, concurrent-session capacity, support tier, and optional retention tier. User count alone is not a reliable cost driver.
