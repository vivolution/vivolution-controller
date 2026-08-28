# Security and Tenant-Isolation Model

Status: POC design baseline; requires an independent review before any live customer pilot.

## Trust boundaries

1. Microsoft Teams signaling and media.
2. Vivolution public voice data plane.
3. Vivolution control plane and operators.
4. Each customer's PBX/private network.
5. Each customer's carrier/PSTN relationship.
6. Tenant reporting and archived records.
7. Edge Agent enrollment, desired-state distribution, and node identity.

Tenant isolation must exist independently in signaling, media, configuration, secrets, reporting, and operator access. A portal filter alone is not isolation.

## Tenant classification

### Teams side

Bind a validated customer-derived FQDN and its configured Microsoft 365 tenant relationship to an immutable internal `tenant_id`. Validate the exact Direct Routing behavior during the POC; do not rely on a user-controlled SIP header alone.

### PBX side

Prefer TLS and a tenant-specific certificate or another cryptographic peer identity. Where a PBX cannot support that, use a dedicated connector identity combining explicit IP ACL, unique listener/transport where required, SIP authentication, and a strict route policy. NAT-shared or dynamic peers require a separately tested design.

### Routing rule

Once established, the tenant context travels with the dialog and accounting record. Telephone numbers, extensions, caller names, Contact headers, and asserted identity never select the tenant by themselves.

## Required controls

- TLS for signaling and SRTP where the peer supports it; document every clear-RTP exception.
- Topology hiding and removal of internal infrastructure details.
- Default-deny peer ACLs and destination policies.
- Per-tenant concurrent-session, CPS, registration, and burst limits.
- E.164 normalization and explicit permitted destination classes.
- Toll-fraud detection, rapid tenant suspension, and platform-wide emergency block controls.
- Encrypted secret storage using Azure Key Vault or an equivalent vault; no plaintext credentials in the portal database or generated artifacts.
- Encryption at rest for databases, CDR archives, backups, and exports.
- Strong operator MFA, least privilege, time-limited emergency access, and full audit history.
- Tenant-scoped database queries plus PostgreSQL row-level security as a second barrier.
- Signed, versioned configuration artifacts and authenticated node retrieval.
- Separate short-lived one-time grants for each expected node slot, node-generated private keys, explicit fingerprint/attestation approval, and short-lived node-specific mTLS identity.
- Signed declarative desired state with replay/downgrade protection; no generic remote shell or arbitrary command facility in the fleet agent.
- Privilege separation between an unprivileged Edge Agent and an allow-listed local root helper restricted to Vivolution-owned units, paths, certificates, and firewall namespace.
- Separate enrollment CA, node-management identity, public SIP certificate, inter-node/workload identity, configuration signer, and software-release signer; no shared trust key across these roles.
- Immediate server-side node/certificate revocation checks, active-stream termination, scoped secret-lease revocation, and credential rotation for a compromised/replaced node.
- Patch inventory, SBOM, vulnerability monitoring, and repeatable rebuilds.
- Rate-limited troubleshooting capture; no permanent full SIP tracing.

## CDR and privacy

- Store operational CDRs for 12 months by default.
- Offer explicit 3-, 5-, or 7-year compliance retention tiers only when the customer has a documented purpose.
- Archive long-term records in immutable storage with tenant-specific retention and legal hold.
- Encrypt sensitive number fields and strictly audit search/export actions.
- Keep detailed SIP traces short-lived and incident-specific.
- Do not record RTP/audio by default.
- Define deletion, export, incident disclosure, and data-residency responsibilities contractually.

Keeping records forever is not automatically compliant; unnecessary retention raises privacy and breach impact.

## Configuration safety

- Schema-validate all numbers, domains, regular expressions, routes, and peer identities.
- Compile from structured objects; never concatenate untrusted portal text into executable SIP configuration.
- Reject ambiguous or cross-tenant routes before publish.
- Require two-person approval for global routes, emergency behavior, trust lists, and destructive tenant changes.
- Publish atomically, verify health, and roll back automatically on failed validation.
- Keep the last-known-good runtime configuration locally so control-plane failure does not interrupt new calls.
- Apply tenant-local changes without restarting the shared OpenSIPS process; roll global changes node-by-node with drain, health gates, and autonomous rollback.

## Enhanced and Dedicated isolation

Enhanced is the shared-cluster baseline. Each tenant has a separate southbound signaling allocation, source policy, RTPengine unit/media block, routing/configuration, secrets, quotas, CDR/RBAC scope, and alerts. It still shares the node OS, public IPs, and Teams-facing signaling process, so customer wording must not describe it as physical isolation.

Dedicated uses an exclusive two-node cluster and an immutable owner-tenant placement lock. The scheduler and database workflow must reject every other tenant. Changing modes requires a blue/green migration and fresh validation; an in-place label change is not permitted.

Customer-hosted nodes are Dedicated in v0.1 and carry an evidence grade. Provider/TPM attestation is preferred; manual/on-premises verification is labelled honestly. A snapshot restore or clone receives a new node generation, duplicate identities are quarantined, and unapproved customer root/network changes create drift and suspend the managed SLA until revalidation.

Customer-hosted nodes receive only customer/cluster/node-scoped SIP identities and secrets—never platform-wide wildcard private keys, global carrier credentials, signing keys, or other-customer material. Required off-site data is limited to authorized CDR metadata, health, audit and approved bounded diagnostics; no RTP/audio or unrestricted SIP payload is exported by default.

## POC attack and negative tests

- Reuse the same extension and E.164 test number in two tenants.
- Forge Contact, From, P-Asserted-Identity, Request-URI, and tenant-looking hostnames.
- Connect from an unknown IP and with the wrong/expired certificate.
- Attempt Tenant A destinations through Tenant B's connector.
- Exceed tenant CPS and concurrent-session limits.
- Attempt premium/international destinations outside policy.
- Use a Customer Administrator token to query another tenant's CDR or configuration.
- Submit malicious regular expressions and configuration payloads.
- Disconnect the portal/database and verify data-plane continuity.
- Rotate certificates and node credentials while test traffic runs.

Any cross-tenant call, media stream, CDR exposure, secret exposure, or configuration access is an automatic POC failure.
