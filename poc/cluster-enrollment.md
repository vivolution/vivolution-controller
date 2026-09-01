# Provider-Neutral Cluster Enrollment POC

Status: Bounded local enrollment/visibility v1 implemented; no VM, DNS,
certificate, or external tenant change has been made or authorized.

Implementation checkpoint (2026-09-01): the provider-neutral Edge join client,
hardened outbound service, and Controller API/admin flow now implement local
Ed25519 identity, display-once grant handling, authoritative scope claim,
fingerprint-bound Pending approval, signed status/heartbeat, exact lost-response
replay, bounded challenge retention, and hard revocation. This checkpoint is
enrollment/visibility only; mTLS, detailed capability inventory,
desired-state/secrets delivery, and broader lifecycle management remain open POC
gates. No VM, DNS, certificate, tenant, or carrier change was made.

## Objective

Prove that a two-node Edge Cluster on supported Linux VMs can securely join the Vivolution control plane, reconcile without a general remote shell, report health, roll back, revoke, and rebuild through a provider-decoupled contract.

The first voice POC may use manually created Azure VMs to stay inside the existing credit. An Azure-only run proves contract decoupling, not portability. Claim provider portability only after the same signed agent/enrollment flow succeeds on at least one temporary non-Azure or local VM; that node need not carry Teams traffic. No design claims that one API can create infrastructure in every provider.

## Minimum implementation

- A minimal cluster registry and two expected node slots.
- One-time 10–15 minute bootstrap grants scoped separately to slot A and slot B.
- A signed/digest-pinned Linux Edge Agent package with pinned server-authenticated TLS for claim and outbound mTLS after approval.
- Node-generated identity keys and a lean private CA such as step-ca.
- Explicit operator fingerprint approval.
- Signed, versioned desired-state bundles and a node-local last-known-good copy.
- Typed reconcile, drain, undrain, identity-rotation, and named-test operations; no arbitrary command execution.
- Host nftables baseline plus generated provider-firewall requirements.
- Standard node/OpenSIPS/RTPengine metrics, configuration checksum, and local CDR spool.
- Cluster and node health states in the operator console.
- Separate encrypted/quota-reserved CDR WAL and bounded telemetry queue, including disk-full behavior.

## POC cluster and tenancy

Cluster 01 runs in `SHARED_ENHANCED` mode and hosts Customer A and Customer B:

- shared Teams-facing TLS 5061 on each node;
- distinct customer PBX-facing TLS ports from a pre-created listener pool;
- distinct PBX source ACLs/credentials;
- separate media blocks and RTPengine units per tenant on both nodes;
- separate configuration artifacts, capacity reservations, CDR/RBAC scopes, and alerts.

The scheduler also creates a logical `EXCLUSIVE` cluster record for a Dedicated tenant, locks it to that tenant, and proves a second placement is rejected. A genuine Enhanced-to-Dedicated live migration needs another active pair and is outside the three-VM/USD 100 POC.

## Enrollment tests

1. Enroll valid slot A and B nodes with different grants and keys.
2. Reject an expired, reused, wrong-cluster, wrong-slot, or wrong-release grant.
3. Deliver the grant without argv, environment, shell-history, cloud-init/user-data, or log exposure; burn it on claim and require operator approval before issuing operational identity.
4. Reject an unknown signing root, mismatched manifest target, altered digest, replay, or downgrade.
5. Revoke one node and prove it can no longer retrieve configuration/secrets or report trusted telemetry.
6. Replace the revoked node with a new generation and repeat validation.
7. Disconnect the control plane and verify last-known-good calls continue while CDR/telemetry spool locally.
8. Publish a bad signed configuration and prove validation or autonomous rollback prevents sustained impact.
9. Drain, update, observe, and restore one node before touching the peer.
10. Verify no enrollment secret appears in reusable images, service logs, shell history, or portal exports.
11. Test stolen-token/wrong-key and simultaneous-claim races, slot-grant swap, CSR SAN/role injection, cloned image/key/machine-id, and replay from an old node generation.
12. Drop the first successful claim response and prove only the same CSR key can idempotently recover the pending claim; a different key is rejected.
13. Prove an unapproved node cannot obtain configuration, secrets, or trusted telemetry status.
14. Test active-stream revocation, renewal failure/expiry, CA and signer rotation, clock skew, tampered/deleted sequence/LKG state, server-side detection of snapshot rollback, disk-full CDR spool, and reboot after rollback.

## Enhanced-isolation tests

While Tenant B continuously places controlled calls:

- publish and roll back Tenant A's routing/configuration;
- restart only Tenant A's RTPengine unit;
- rotate Tenant A's connector identity;
- block or overload Tenant A within its quota;
- send traffic from A to B's PBX port/media block and vice versa;
- attempt wrong certificate, source IP, FQDN, port, route, and tenant object IDs;
- confirm no failed Tenant B calls and keep B setup latency, packet loss, jitter, and estimated MOS within a POC-defined tolerance from its baseline.

Any cross-tenant signaling, media, route, secret, configuration, CDR, or report exposure fails the POC. Any Tenant A-scoped operation that requires a whole-cluster OpenSIPS restart also fails the Enhanced operational objective and forces a listener/ingress redesign. Because tenants share host resources, the final tolerance must be measurable rather than claiming literally zero scheduler/network impact.

## Placement and capacity tests

- Reserve sessions, CPS, bandwidth, media ports, and per-tenant process overhead as a vector.
- Size admission against single-node/N-1 safe capacity.
- Reject a colliding signaling port or media block.
- Reject placement beyond any capacity dimension or service-mode constraint.
- Trigger an expansion alert at the initial 60–65% reserved threshold.
- Verify the scheduler never places an Enhanced service on an exclusive cluster or another tenant on a Dedicated cluster.
- Race two placement requests and verify conditional owner, allocation ownership, unique FQDN/port, non-overlapping media range, one-active-allocation, and capacity constraints hold under a serializable application transaction and database constraints.

## Deferred provider-adapter tests

After the common enrollment flow passes:

1. Add one Azure provisioning adapter as a convenience path.
2. Run the same enrollment against a manually created non-Azure or local lab VM before claiming portability.
3. Only then decide whether AWS/other adapters are worth building.

Cloud adapters may create VMs, networks, public IPs, DNS, and firewall rules. They do not receive node private keys and cannot bypass identity approval or desired-state validation.

## Success gates

- Both independently identified nodes enroll and the cluster becomes Available only after all gates pass.
- No public management port or generic remote-execution endpoint exists.
- A control-plane outage does not interrupt the last-known-good data plane.
- A safe signed lab artifact that fails a defined validation/health gate rolls back within the POC SLO; replay/downgrade cannot activate and evidence is complete.
- Tenant A-scoped changes/media-unit restart cause no failed Tenant B calls and remain within the defined B quality/setup tolerance.
- Dedicated exclusivity and Enhanced placement/capacity rules are enforced by transactional API logic plus CHECK/unique/exclusion/FK/RLS constraints for the application role.
- Node revoke, replacement, certificate rotation, drift detection, and evidence collection pass.
- Portability is reported as unproven unless one non-Azure/local enrollment also passes; the Azure voice path alone is not enough.
