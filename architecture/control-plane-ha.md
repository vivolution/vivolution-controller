# Control Plane High Availability

Status: Proposed architecture; no infrastructure deployment is authorized.

## Verdict

Two controller application nodes are the right production direction, but two VMs alone do not create a safe automatic-HA control plane. Portal/API availability, durable state, job ownership, PKI, secrets, artifacts, and telemetry each need an explicit failure model.

The voice data plane never depends on a live controller for call setup. When the control plane loses quorum or becomes unavailable, Edge nodes continue serving their signed last-known-good state and spool bounded CDRs locally.

## Recommended logical architecture

### Controller 1 and Controller 2

Both run:

- stateless operator/customer portal and API;
- Edge Agent enrollment and mTLS gateway;
- desired-state compiler and artifact distributor;
- orchestration worker able to acquire a lease;
- telemetry/CDR receiver;
- read-only health and inventory service during degraded operation.

Agents enroll through a stable bootstrap name that production resolves through an HA L4/L7 load balancer or multiple health-managed endpoints. After approval they receive a signed list of both controllers and reconnect to either. The POC installer accepts a primary plus recovery endpoint and avoids an expensive gateway; it must not depend permanently on one bootstrap host.

### Durable database and quorum

PostgreSQL stores tenant/cluster state, placement reservations, configuration generations, audit events, job leases, and idempotency keys.

Supported production patterns:

1. **Managed PostgreSQL HA** where the selected host provides an acceptable UAE/data-residency and cost model.
2. **Self-hosted PostgreSQL primary/standby** across CP1/CP2 under Patroni or an equivalent manager. Patroni's distributed configuration store uses a three-member quorum such as etcd/Consul on CP1, CP2 and a third small independent witness.

The PostgreSQL servers are not themselves voters. With only two distributed-configuration-store members, the system cannot safely distinguish a dead peer from a network partition. Automatic promotion requires the three-member quorum plus role-aware database routing and watchdog/fencing; a witness alone is insufficient. If only CP1 and CP2 exist, promotion remains manual and the old primary must be fenced before the standby becomes writable.

Loss of quorum favors consistency:

- portal/API health and existing inventory remain readable where safe;
- all configuration publication, placement, token issuance, certificate issuance, and destructive jobs stop;
- no controller may push a new generation;
- Edge nodes continue calls from last-known-good state.

Every published configuration has a monotonically increasing generation plus a quorum-issued leader epoch/fencing token. Signing/publication requires the current lease, and Edge nodes reject manifests from an obsolete epoch. A generation number alone cannot stop an isolated former leader from inventing a newer conflicting value.

## Job ownership

API replicas may be active-active. Orchestration is lease-controlled:

- PostgreSQL-backed queue and leader/worker leases;
- idempotent, generation-aware, at-least-once-safe jobs;
- tenant, cluster, node, and maintenance locks;
- one rollout owner at a time;
- peer takeover only after lease expiry and reconciliation;
- no simultaneous update of both Edge nodes.

Avoid adding Redis/RabbitMQ solely for the early fleet unless measured load requires it; every new stateful component creates another HA problem.

## PKI, secrets, and artifacts

- Keep the root CA and root release-signing keys offline or in KMS/HSM-backed custody.
- Use a protected issuing intermediate/registration authority for node identities. The bootstrap grant cannot mint certificates directly.
- Do not copy unprotected CA, release-signing, or master secret keys onto both controllers.
- Let’s Encrypt/public CA automation covers public portal/SIP certificates, not internal Edge Agent identity.
- A temporary issuing-service outage blocks new enrollments/renewals but does not invalidate existing Edge runtime state.
- Store immutable signed software/configuration artifacts in a canonical digest-pinned repository/object archive with tested backup. The POC may serve verified local caches from both controllers, but those caches are availability copies—not the durable source of record.
- Store secret references centrally; deliver node-scoped encrypted material only after current mTLS authorization.

Enrollment CA, public SIP CA material, agent-management identity, configuration signer, software-release signer, and secret-encryption roots remain separate.

## Monitoring and failure states

Monitor each controller and the control plane as a system:

- API/gateway health, agent connections, request/error latency;
- database primary/replica role, replication lag, quorum and fencing state;
- job lease age, queue depth, stuck/retried jobs and generation conflicts;
- certificate/issuer health, signing/audit operations and token issuance;
- artifact availability/checksum, CDR ingestion lag and disk usage;
- controller version/config drift and backup/restore evidence.

Control-plane state should be explicit: `HEALTHY`, `DEGRADED_READ_ONLY`, `NO_QUORUM`, `MAINTENANCE`, or `UNAVAILABLE`. It must never display a green average while publication is blocked.

## POC sequencing and budget

Two controller VMs plus a witness and two always-on Edge VMs are unlikely to fit comfortably inside the same USD 100 monthly credit after disks, IPs, DNS, and telemetry. Two safe sequences are available:

### Voice-evidence-first — current baseline

- One small controller/application VM.
- One public Edge for most of the month.
- Second Edge only during the HA test window.
- Add CP2/witness later to test management-plane failover.

This maximizes SIP, multi-tenant isolation, and Edge-Agent evidence per dollar.

### Controller-first — Jay’s new proposal

- CP1 + CP2 plus one very small independent witness.
- Enroll a local/on-premises disposable Edge VM first.
- Run the Azure voice edge and two-node HA test in a later credit cycle or a tightly staged window.

This validates the future operating platform earlier but extends the voice POC timeline.

The POC must not describe two controllers without a witness as automatic database HA. If exactly two machines are used, database failover remains a peer-reviewed manual operation.
