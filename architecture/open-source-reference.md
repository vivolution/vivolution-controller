# Open-Source Reference Path

Status: Technical discovery design; not approved for deployment.

## Proposed data plane

```text
Microsoft Teams Direct Routing
  -> customer-a.sbc1 / customer-a.sbc2 derived FQDNs
  -> Kamailio or OpenSIPS signaling pair
  <-> RTPengine media pair
  -> optional Asterisk/FreeSWITCH workers
  -> customer PBX or carrier-approved BYOC trunk
```

The platform would be branded Vivolution SBC. FreePBX is not required and should not be the customer-facing control plane. Asterisk can run as an unbranded worker behind Vivolution's own portal when B2BUA behavior, transcoding, IVR, or difficult carrier normalization is needed.

## Signaling edge

Kamailio and OpenSIPS are both credible candidates. The POC working choice is **OpenSIPS 3.6 LTS** because database-backed TLS domains, dynamic-routing partitions, private JSON-RPC management, and its cluster framework fit the desired-state control plane. Kamailio remains the fallback if measured interoperability or operating experience shows an advantage. The edge must provide:

- TLS termination and public FQDN handling.
- SIP OPTIONS health and Microsoft endpoint failover.
- Tenant classification from the customer-derived FQDN and validated southbound trunk identity.
- Contact, Request-URI, Record-Route, History-Info, REFER/NOTIFY, Replaces, and early-media handling.
- Header/number normalization, topology hiding, ACLs, rate limits, CPS/session limits, and fraud controls.
- Dialog/accounting events, active-call state, health, and atomic route updates.

Tenant identity must never be inferred from a telephone number alone because number ranges and extensions can overlap.

## Media edge

Use RTPengine to anchor RTP/SRTP during early discovery, with Teams media bypass disabled. It can provide media address rewriting, RTP/SRTP bridging, ICE-related behavior, DTMF handling, statistics, and selected transcoding/repacketization.

Start with Teams-supported G.711 behavior and an RSA certificate/cipher profile matching Microsoft's current Direct Routing requirements. Do not use delayed-offer INVITEs. Validate the exact TLS, SIP OPTIONS, Contact, Record-Route, SDP, and transfer behavior against the current Microsoft protocol documentation during the POC.

Keep Asterisk or FreeSWITCH off the normal media path unless a call requires:

- B2BUA normalization.
- Codec or DTMF conversion beyond the media proxy's safe capability.
- Difficult transfer, early-media, forking, or PBX behavior.
- An explicit application such as IVR.

This reduces latency, shared state, and failure surface.

## Control plane

- Vivolution portal and API.
- PostgreSQL configuration store with tenant row-level isolation.
- Secret vault; never store plaintext carrier credentials.
- Route compiler with schema validation and cross-tenant negative checks.
- Versioned configuration, approval, atomic publish, and rollback.
- Job queue for DNS, certificate, validation, and reporting tasks.
- Locally cached runtime configuration so a portal/database outage does not stop calls.

Suggested primary objects:

- CustomerAccount, M365Tenant, TenantContext, ServiceInstance, UserRole, Connector, Trunk, Number, Route, DialPlan, Policy, CapacityLimit, Credential, Certificate, RetentionPolicy, CDR, QualitySample, Alert, AuditEvent, and ConfigurationVersion.

## High availability

- Two enrolled Linux nodes in approved distinct failure domains, with distinct static public IPs and base FQDNs. Azure is the first POC host, not a product dependency.
- Two derived FQDNs per tenant, both placed in Teams voice routes.
- No assumption that active media sessions migrate when a node fails; HA protects new calls.
- Replicate desired configuration, not unsafe live dialog state.
- Test certificate rotation, node loss, route rollback, portal outage, VM restart, node re-enrollment, and tenant-isolation attacks.

Enhanced tenants share the Teams-facing listener but receive separate PBX-facing signaling allocations and tenant-specific RTPengine units/media blocks. Dedicated services receive an exclusive pair. See [Provider-neutral fleet management](fleet-management.md).

## Branding and licensing

The service can be presented as Vivolution SBC without exposing FreePBX. Before distributing appliances or modified binaries, review each component's open-source licence and all FreePBX/Sangoma trademark and redistribution obligations. A hosted service still needs a software-bill-of-materials, patch process, notices, and vulnerability response.

## Support position

The Open Edge must be sold, if ever approved, as a Vivolution-engineered and supported interoperability service—not as a Microsoft-certified SBC. An upstream Microsoft protocol change or support refusal becomes Vivolution's operational responsibility.

The open-source proxy must be the paired edge in Open Edge. Inserting an additional third-party proxy between Microsoft and a purported certified SBC does not transform the design into a Microsoft-supported topology.
