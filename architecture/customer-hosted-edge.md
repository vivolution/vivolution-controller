# Customer-Hosted Edge

Status: Proposed product/deployment model; no customer deployment or production SLA is authorized.

## Product position

Customer hosting is separate from service isolation:

- `hosting_model`: `VIVOLUTION_HOSTED`, `CUSTOMER_CLOUD`, or `CUSTOMER_ON_PREMISES`.
- `isolation_mode`: `ENHANCED` or `DEDICATED`.
- `availability_profile`: `LAB_SINGLE_NODE`, `HA_PAIR_SINGLE_SITE`, or `HA_PAIR_MULTI_FAILURE_DOMAIN`.
- `management_model`: `VIVOLUTION_MANAGED` initially; customer-operated mode is deferred.
- `identity_evidence`: provider-signed instance document or independent manual-console verification.
- `integrity_evidence`: TPM/vTPM quote, measured/secure boot, or none.
- `trust_policy_status`: the resulting policy decision, recorded separately from either evidence type.

For v0.1, every customer-hosted production cluster is **Dedicated** and bound to immutable `customer_account_id`. Vivolution must never place unrelated customers on infrastructure another customer owns, funds, or can administratively inspect. The legal account is separate from each `m365_tenant_id`; database and agent authorization reject any Microsoft tenant owned by another account.

Customer-hosted v0.1 uses `CUSTOMER_DIRECT` attachment for one Microsoft tenant: both SBC FQDNs/gateways are registered directly in that customer tenant. Serving several Microsoft tenants owned by the same legal customer through `HOSTED_DERIVED` attachment is a later gated capability, not an automatic consequence of Dedicated hosting.

A suitable product name is **Vivolution Customer-Hosted Dedicated Edge**: the customer supplies compute and network; Vivolution supplies and operates the managed voice appliance.

## Supported shape

- Clean dedicated VM images on the exact supported OS/kernel/architecture; no multi-purpose server.
- Two nodes for production, each sized for the full N-1 reservation.
- Distinct hypervisors/failure domains, public IPs and FQDNs.
- Ideally separate power, network paths, firewalls, and ISPs.
- One node is lab-only and receives no production HA/SLA claim.

Two VMs behind the same firewall, power source, or ISP provide node redundancy—not site resilience. Geographic resilience requires two sites/failure domains and is a separate availability profile.

Failure-domain claims carry evidence provenance and state: `DECLARED` versus `VERIFIED`. Guest telemetry cannot independently prove hypervisor, site, ISP or power separation when the customer controls the substrate.

## Network prerequisites

- Stable public IP and public DNS FQDN per node.
- Publicly trusted SIP certificate matching each FQDN.
- Direct public addressing or supported static 1:1 NAT; no CGNAT, double NAT, or SIP ALG.
- Microsoft-facing TLS signaling, normally 5061, and capacity-sized media range restricted to then-current Microsoft endpoints.
- PBX-facing signaling/media restricted to the customer PBX, preferably over private VLAN or site-to-site VPN.
- Outbound HTTPS 443 to both controller endpoints.
- Reliable DNS/NTP, correct MTU, symmetric routing, and required certificate/ACME/revocation reachability.
- Prefer separate Teams-facing and PBX-facing NICs/networks on-premises.

v0.1 anchors all media through RTPengine and disables Teams media bypass. Both nodes must independently pass Teams-to-PBX signaling/media tests; two running VMs do not qualify as HA if the PBX/network can reach only one.

The control plane generates firewall requirements. The customer or an explicitly delegated provider role applies cloud/on-premises network rules. Host nftables remains the portable enforcement baseline.

## Trust boundary

A customer cloud/hypervisor administrator can clone disks, inspect memory, change networking, alter RTP/CDRs, or forge self-reported telemetry. Enrollment proves possession of a node key, not continued software integrity. Therefore customer-hosted nodes are trust-limited and carry an explicit evidence grade:

- prefer TPM/vTPM-bound non-exportable node keys;
- validate provider-signed instance identity where available;
- label manual/on-premises evidence as manually verified, not attested;
- detect duplicate node identity/heartbeats and quarantine clones;
- require a restored snapshot to enroll as a new node generation;
- expose no global fleet or other-customer secret to the node;
- prohibit platform-wide wildcard private keys, global carrier credentials, signing keys, or other-customer secrets; use node/cluster/customer-scoped SIP identities only;
- treat unapproved root/network changes as drift and a support-boundary event.
- stream CDRs promptly to Vivolution-controlled immutable storage where contracted; do not promise Vivolution-grade tamper-evident compliance from a manually verified customer node alone.

The Edge Agent is a managed-appliance reconciler, not unrestricted remote root. The customer portal cannot command nodes directly.

## Responsibility model

### Customer

- Cloud subscription/hypervisor, physical hardware, power and Internet.
- Substrate and console lifecycle: VM create/delete/resize, snapshots only under the managed change process, public IP/NAT, VPC/VLAN/firewall, DNS delegation and network paths.
- PBX, carrier trunk, Microsoft licences/tenant approvals and emergency-calling responsibilities.
- Coordinating snapshots, host maintenance, resizing, firewall, public-IP and network changes.

### Vivolution

- Exclusive management of the supported guest OS baseline, Edge Agent and voice application stack.
- OpenSIPS/RTPengine, host policy, routes, certificates where contracted, updates and rollback.
- Monitoring, configuration compiler, CDR ingestion, validation, audit and incident triage.
- Portal access to tenant health, CDRs, inventory, evidence and managed change requests.

Vivolution does not require customer cloud-admin credentials for the Agent-only model. Optional future provider integration must use a separate least-privilege role.

Customer OS patching, snapshot restore, root alteration or unmanaged package/service changes move the node to drift/unsupported state until revalidation. Snapshot restore enrolls as a new node generation; it is not normal recovery.

## SLA boundary

- Management-plane and voice data-plane availability are measured separately.
- Calls may continue when controllers/portal are unavailable.
- Vivolution can warrant its application/configuration only while both nodes meet prerequisites and remain reachable.
- Customer power, hypervisor, ISP, IP/NAT/firewall, DNS, PBX, carrier and Microsoft outages are outside the managed Edge software SLA.
- Unapproved root/network changes pause the managed SLA until validation passes.
- If a VM is offline, Vivolution can detect/advise but cannot power it on or repair the customer substrate without separately delegated access.

Loss of agent/controller reachability enters `UNMANAGED_DEGRADED`: last-known-good calls intentionally continue, alerts/timers start, managed SLA is suspended after the agreed threshold, and a customer-assisted containment runbook applies. Management-certificate revocation alone cannot stop a malicious or unreachable SBC; containment may require disabling Teams routes/gateways, DNS, PBX trunks or customer firewalls.

Authorized site egress is explicit: CDR metadata, health metrics, audit events and approved bounded diagnostics to the agreed regional ingestion service. RTP/audio and unrestricted SIP payloads do not leave the site by default. Blocking required telemetry/CDR egress changes the support/SLA state; retention and authorization are contractual.

Customer-operated/root-co-managed mode is deferred. If introduced later, it should carry a materially narrower or best-effort support commitment.

## POC additions

- Enroll one local or non-Azure VM to prove enrollment portability only; do not claim Customer-Hosted voice readiness from that test.
- Record attestation as provider/vTPM verified or honestly manual.
- Test clone/snapshot detection and new node generation.
- Detect unsupported OS, NAT, clock, firewall, IP and local-root drift.
- Disconnect controllers while calls continue and CDRs spool within limits.
- Fail Node A while Node B carries N-1 load.
- Produce and review the customer/Vivolution responsibility and SLA evidence pack.

A later Customer-Hosted voice-readiness test requires a genuine customer-controlled two-node network with static public IP/NAT, implemented firewall policy, both PBX paths, node failover, controller loss, customer-caused drift and end-to-end Teams calls.

Defer broad multi-distro/hypervisor support, customer root co-management, geographic HA, automatic cloud provisioning, production SLA claims, and customer self-service routing.
