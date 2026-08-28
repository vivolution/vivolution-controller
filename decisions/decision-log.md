# Decision Log

## D-001 — Discovery before POC

- Date: 2026-08-27
- Status: Satisfied for the local CP1 foundation; superseded by D-015 for that scope
- Decision: Keep Vivolution SBC in brainstorming and feasibility discovery. Do not begin a POC, buy licenses, contact customers, or start a pilot until Jay explicitly approves the next phase.
- Reason: Microsoft certification, vendor licensing, UAE telecom regulation, carrier dependencies, tenant isolation, and unit economics must be understood first.

## D-002 — Certified Teams edge

- Date: 2026-08-27
- Status: Superseded by D-004
- Decision: The initial research proposed a certified Teams edge as mandatory.
- Reason: Jay's prior working Asterisk implementation demonstrates that certification must be treated as a support/commercial boundary rather than technical feasibility.

## D-003 — Operator-partnered BYOC-first boundary

- Date: 2026-08-27
- Status: Proposed for legal and carrier validation
- Decision: Explore managed SBC-as-a-Service with the customer's own UAE-licensed carrier and a written operator-partner arrangement before considering PSTN resale or bundled minutes.
- Reason: It is the clearest initial separation between managed infrastructure and regulated public voice service, but TDRA's broad definition means written operator and regulatory confirmation remains mandatory.

## D-004 — Technical feasibility is separate from certification

- Date: 2026-08-27
- Status: Accepted as a discovery premise
- Decision: Treat an Asterisk/Kamailio/OpenSIPS Direct Routing edge as technically feasible. Do not equate absence of Microsoft certification with inability to interoperate.
- Evidence: Jay previously operated a patched/recompiled Asterisk/FreePBX system with Teams Direct Routing and Twilio PSTN calling.
- Boundary: The product must still distinguish an unsupported Vivolution Open Edge from a Microsoft-certified option and price the regression/support burden explicitly.

## D-005 — PBX relay as first customer scenario

- Date: 2026-08-27
- Status: Proposed for validation
- Decision: Design first for Teams -> Vivolution SBC -> customer on-premises PBX -> customer du/e& trunk. Keep direct carrier trunk termination as a separate mode requiring written carrier approval.
- Reason: This preserves the customer's existing carrier boundary and solves the SBC cost/skills problem with fewer commercial and interconnect changes.

## D-006 — Working POC data plane

- Date: 2026-08-27
- Status: Proposed; implementation requires Jay's separate POC approval
- Decision: Use OpenSIPS 3.6 LTS plus RTPengine as the working Open Edge POC data plane. Keep Kamailio as a fallback and Asterisk as the customer-side lab PBX/optional exceptional B2BUA, not the public product core.
- Reason: Database-backed TLS domains, dynamic-routing partitions, private JSON-RPC management, and coherent clustering fit a tenant desired-state compiler with less custom control glue.

## D-007 — True multi-customer POC requires three Microsoft 365 tenants

- Date: 2026-08-27
- Status: Proposed prerequisite
- Decision: Use one Vivolution/provider tenant for the base trunks plus two independent customer tenants for derived trunks. Two total tenants prove one hosted customer only and must be reported as a partial multi-tenancy test.
- Reason: Microsoft carrier/derived-trunk topology separates the provider base domain from every customer subdomain; two independent customers are needed to prove isolation.

## D-008 — Credit-aware staged POC

- Date: 2026-08-27
- Status: Planned, not authorized for deployment
- Decision: Sequence one B2s edge and one B1ms private portal/PBX host, then add a second B2s only for the final HA window. Target USD 90–95 Azure spend and stop for review at USD 90.
- Reason: This tests call correctness, tenant isolation, control-plane behavior, and new-call HA within Jay's USD 100 monthly credit while avoiding false production-capacity conclusions.

## D-009 — Enhanced Isolation is the v0.1 default

- Date: 2026-08-27
- Status: Accepted
- Decision: Every shared Open Edge customer receives separate southbound PBX signaling identity/port, source policy, per-tenant RTPengine unit/media block, routing/configuration, quotas, secrets, CDR/RBAC scope, and alerts. The Microsoft-facing 5061 listener, node OS, public IPs, and cluster-wide OpenSIPS ingress remain shared. Certified platforms require a native capability/support assessment before using the same service label.
- Boundary: Tenant-local changes must not restart the shared signaling process. The POC must prove no failed Tenant B calls and keep B setup/media quality within an agreed baseline tolerance while Tenant A is changed or its media unit is restarted.

## D-010 — Dedicated is an exclusive cluster placement mode

- Date: 2026-08-27
- Status: Accepted
- Decision: A Dedicated service creates or uses a zero-allocation two-node cluster whose owner tenant is atomically bound at creation. Enhanced and Dedicated use the same control plane and core cluster template, but the scheduler/database must technically reject any other tenant on that Dedicated cluster.
- Boundary: Tier changes require blue/green migration; they are never an in-place label change.

## D-011 — Provider-neutral enrollment is the fleet contract

- Date: 2026-08-27
- Status: Accepted as the v0.1 design baseline; implementation requires separate POC approval
- Decision: Separate infrastructure provisioning from cluster enrollment. Any supported pair of Linux VMs can join through a signed Vivolution Edge Agent using pinned server-authenticated TLS plus a one-time grant for claim, node-generated keys/proof of possession, explicit approval, then outbound node-specific mTLS, signed desired state, health gates, and last-known-good rollback. Azure/AWS/other provisioning integrations are optional adapters.
- Reason: No single VM-provisioning API exists across all clouds and on-premises environments. A common enrollment/operation protocol keeps the control plane portable without building a dangerous generic remote-execution system.

## D-012 — Edge Agent is a managed-appliance reconciler

- Date: 2026-08-27
- Status: Proposed; recommended for v0.1 implementation
- Decision: Offer a simple signed-package installation and interactive controller/token enrollment experience, but give the controller only typed, signed lifecycle authority through an unprivileged agent and narrow root helper. Permit approved install, reconcile, validate, drain, update, rollback, identity rotation, and bounded diagnostics; prohibit arbitrary remote shell/scripts/packages/filesystem access.
- Reason: This achieves provider-neutral lifecycle management without turning a controller compromise into unrestricted root access across the fleet.

## D-013 — Customer-hosted production is Dedicated

- Date: 2026-08-27
- Status: Proposed; recommended product boundary
- Decision: Model `CUSTOMER_CLOUD` and `CUSTOMER_ON_PREMISES` separately from isolation, but allow only Dedicated customer-hosted production clusters in v0.1. Require two nodes for production HA; single-node customer hosting remains lab-only.
- Reason: Vivolution must never place unrelated tenants on infrastructure another customer owns or can inspect. Customer substrate availability and changes also need a separate responsibility/SLA boundary.

## D-014 — Two controllers require separate state quorum

- Date: 2026-08-27
- Status: Proposed; POC sequencing decision pending
- Decision: Design CP1/CP2 as active application/API/agent-gateway replicas behind stable discovery. Automatic writable-state failover additionally requires managed PostgreSQL HA or a three-member distributed-configuration-store quorum (for example CP1, CP2 and an independent witness) plus role-aware DB routing/fencing. With exactly two DCS members, failover remains manual and fenced.
- Reason: Two application VMs improve endpoint availability but cannot safely distinguish peer failure from network partition. Loss of quorum must make the control plane read-only while Edge nodes continue from last-known-good state. Published manifests also carry a quorum-issued leader epoch so agents reject an isolated former leader.

## D-015 — Qualify CP1 locally before consuming Azure credit

- Date: 2026-08-27
- Status: Accepted and implemented for the foundation slice
- Decision: Build and repeatedly qualify CP1 in a disposable Debian 13 ARM64 UTM VM on Jay's Mac. Use Ansible plus systemd/Podman Quadlets as the deployment contract, then perform a final clean acceptance run on the Azure AMD64 VM.
- Reason: Local rebuild, reboot, database-outage, rollback, RLS, HTTPS, and resource tests are inexpensive and repeatable. The ARM64 lab cannot prove AMD64 image behavior, Azure networking, public certificate handling, or managed PostgreSQL integration, so it does not replace final Azure acceptance.

## D-016 — Start with one stateless controller and managed PostgreSQL

- Date: 2026-08-27
- Status: Accepted as staged POC architecture
- Decision: Begin with one CP1 application VM and Azure Database for PostgreSQL Flexible Server. Keep every application database connection behind loopback PgBouncer so the local and Azure profiles share one application contract. Add CP2 behind the stable controller FQDN only after measurements justify it.
- Boundary: A managed database is not automatically highly available; the selected Flexible Server HA mode determines the database SLA and cost. CP1 remains a management-plane single point of failure until CP2 is added, while Edge nodes must continue from last-known-good state.

## D-017 — Debian 13 is a POC target, not yet an Azure support claim

- Date: 2026-08-27
- Status: Accepted for local and Azure POC validation
- Decision: Qualify Debian 13.6 for the CP1 POC while retaining an explicit final Azure supportability gate. Use only maintained Debian packages plus digest-pinned multi-architecture controller images.
- Reason: Debian 13 is technically suitable for the selected stack, but local ARM64 qualification cannot establish Azure endorsement, guest-agent behavior, or production support on AMD64.

## D-018 — Local CP1 foundation qualification is complete

- Date: 2026-08-27
- Status: Satisfied for the Debian 13.6 ARM64 foundation slice
- Decision: Accept the local CP1 host/database/HTTPS/Django foundation as reproducibly qualified and retain its Ansible/UTM rebuild procedure as the baseline for final Azure acceptance.
- Evidence: `deploy/evidence/20260827T180455Z-19848` passed after the clean build exposed and the deployment repaired PgBouncer's first-boot configuration ordering. `deploy/evidence/20260827T183743Z-74252` then passed as an untouched clean first-pass regression, including a second installation with `changed=0`.
- Boundary: This is not Azure or full SBC product acceptance. Azure AMD64, PostgreSQL Flexible Server and public TLS acceptance remain pending, as do enrollment/PKI and the SIP/media data plane. Azure was untouched during local qualification, and no vulnerability scan was performed.
