# Provider-Neutral Edge Fleet Management

Status: v0.1 design baseline; no infrastructure deployment is authorized.

## Decision

The control plane manages **Edge Clusters**, not Azure VMs. A production-capable Edge Cluster is a two-node signaling/media pair with a declared service mode, capacity policy, software baseline, network policy, and lifecycle state. The staged POC may temporarily contain one node while `DRAFT`, `ENROLLING`, or `VALIDATING`, but it can never become available for customers until both required slots pass validation.

Infrastructure creation and cluster enrollment are separate:

1. **Provision + Enroll:** an optional Azure, AWS, GCP, OCI, VMware, OpenStack, or other adapter creates the two VMs, networking, public IPs, and DNS, then starts the common enrollment flow.
2. **Enroll Existing Pair:** an operator creates two supported Linux VMs by any approved method and installs the same enrollment kit. This is the universal fallback and does not depend on Bicep, Terraform, CloudFormation, or any one cloud API.

There is no genuinely universal VM-creation API. The Vivolution product contract therefore begins at secure node enrollment; cloud provisioning is a replaceable convenience layer.

Hosting is an independent service axis:

- `VIVOLUTION_HOSTED`: Vivolution owns the cloud/substrate relationship; Enhanced or Dedicated is allowed.
- `CUSTOMER_CLOUD` or `CUSTOMER_ON_PREMISES`: the customer owns the substrate; v0.1 requires Dedicated so unrelated tenants never reside on customer-controlled infrastructure.

Availability and trust are also separate: single-node lab versus HA pair/site profile; provider/manual identity evidence; TPM/measured-boot integrity evidence; and a resulting trust-policy status. These evidence types can coexist and must not be collapsed into one enum. See [Customer-Hosted Edge](customer-hosted-edge.md).

## Customer and cluster service modes

`isolation_mode` belongs to a customer's `ServiceInstance`. In v0.1 these modes describe Open Edge. A Certified Edge platform may expose them only after its native partitioning, media, change-isolation, and support model passes a capability matrix; OpenSIPS/RTPengine must not be inserted in a way that defeats the certified support boundary.

- **Enhanced:** the default. The tenant can share a two-node cluster with other Enhanced tenants while retaining tenant-specific southbound signaling, media processes/ranges, firewall policy, routing, quotas, secrets, CDRs, and audit history.
- **Dedicated:** the service receives an exclusive two-node cluster. The cluster is atomically locked to one tenant before provisioning and rejects every other placement.

`cluster_mode` is stored separately:

- `SHARED_ENHANCED`
- `EXCLUSIVE`, with an immutable `exclusive_customer_account_id` assigned at creation

`exclusive_customer_account_id` is null only for `SHARED_ENHANCED`; it is non-null for every `EXCLUSIVE` cluster. “Empty exclusive cluster” means that its legal customer owner is already fixed but it has zero allocations. One account may have multiple Microsoft 365 tenants, each with its own technical tenant context/allocation, but database and agent policy reject any allocation whose `customer_account_id` differs from the exclusive owner. The scheduler may place Enhanced only on `SHARED_ENHANCED` clusters and Dedicated only on its own empty `EXCLUSIVE` cluster. It must never silently reduce isolation. Changing a live service between modes is a blue/green migration to another cluster, not an in-place flag change.

Enhanced isolation deliberately does **not** claim physical isolation. Tenants still share the node OS, kernel, NIC/queues, public IPs, and cluster-wide Teams-facing OpenSIPS process. A tenant-specific RTPengine unit gives user-space process/range separation, not a separate host or hypervisor. Enhanced limits tenant-change and media-process blast radius. Dedicated is the only mode that promises an exclusive SBC pair and signaling process boundary, but it still shares cloud fabric, Vivolution's control plane/PKI/telemetry, and operational staff unless a separate premium boundary is defined.

## Enhanced isolation baseline

Each Enhanced tenant allocation receives, on both nodes:

- two customer-derived Teams FQDNs tied to the selected cluster's base FQDNs;
- the shared Microsoft-facing TLS listener, normally port 5061, because derived trunks inherit the base trunk's signaling settings;
- a customer-specific PBX-facing TLS port, stable for the active allocation, from a cluster-managed listener pool;
- source IP/VPN ACLs and mTLS or connector credentials for the PBX leg;
- a dedicated RTPengine unit/container and a non-overlapping media block;
- a tenant routing partition, configuration artifact, secrets scope, CPS/session/bandwidth quota, CDR partition, alerts, and audit scope.

Microsoft endpoint ranges are permitted only to the shared Teams listener and applicable Teams media policy. Customer PBX ranges are permitted only to that tenant's southbound signaling port and media block.

Unique ports improve firewall containment but are not, by themselves, process isolation. Tenant changes must update tenant-scoped tables/artifacts atomically and must not restart shared OpenSIPS. A fixed southbound listener pool should be created when the cluster is built, or a tested tenant ingress adapter should terminate each allocated port while preserving trusted destination-port identity. The POC must measure listener-pool overhead and prove that onboarding/changing Tenant A does not reload or interrupt Tenant B's shared signaling path. A migration may require a new port; preserve the old value only when it is safely available on the target cluster.

Media blocks are capacity-sized, not fixed at 5,000 ports. The allocation manager should support policy blocks such as 128, 256, 512, or 1,024 UDP ports, reserve the same block on both nodes, include safety headroom, and refuse collisions. Initial sizing should assume up to four local RTP/RTCP ports per anchored two-leg audio call, then be replaced by measured RTPengine behavior for RTCP mux, early media, hold, and transfer. Each instance also needs distinct control/runtime identifiers and CPU/memory limits. Released ranges enter quarantine before reuse.

Host nftables is the portable enforcement baseline. Provider firewall rules are defense in depth and must be compiled, quota-checked, staged, and rolled back as a unit; the POC must measure rule scaling and safely update Microsoft's published endpoint ranges.

## Core fleet objects

### EdgeCluster

- Immutable cluster ID, name, service mode, and conditionally mandatory exclusive tenant owner.
- Provider, account/subscription reference, region, residency, and two required failure domains.
- Two node slots, public IPs, private addresses, base FQDNs, and shared Teams signaling policy.
- Southbound signaling pool, media pool, and allocation policy.
- Rated and measured N-1 capacity for sessions, CPS, bandwidth, RTP ports, CPU, memory, and per-tenant process overhead.
- Desired and observed software/configuration versions and checksums.
- Certificate, DNS, health, maintenance, drain, and lifecycle state.

### EdgeNode

- Immutable node ID, cluster ID, A/B slot, and node generation.
- Provider-neutral infrastructure reference, failure domain, addresses, and FQDN.
- Agent identity, mTLS certificate, attestation status, software inventory, and SBOM.
- Desired and observed state, heartbeat, drift, capacity, maintenance, and drain state.

### TenantAllocation

- Service instance, cluster, derived FQDNs, and lifecycle state.
- Reserved capacity vector and source/destination policy.
- Signaling allocation, media allocation, connector, certificate, and secret references.
- Active configuration version and activation evidence.

One service has exactly one `ACTIVE` allocation. The only exception is an authorized `MigrationPlan` with one source `ACTIVE` allocation and one fully reserved `SHADOW` target. Source capacity, endpoints, ports, secrets, and CDR reconciliation remain reserved until drain and migration completion.

## Placement policy

Hard constraints are evaluated before scoring:

- Enhanced/Dedicated compatibility and exclusivity.
- Region, data residency, product track, software baseline, topology, codecs, and features.
- Two healthy nodes in approved distinct failure domains.
- Free signaling listener and media block.
- PBX reachability and required source policy.
- Enough reserved N-1 capacity in every dimension.

Placement is one serializable transaction. Database constraints and application policy must enforce:

- `exclusive_customer_account_id IS NULL` exactly when mode is `SHARED_ENHANCED`, otherwise it is non-null;
- every Exclusive allocation belongs to its customer-account owner and every Shared allocation requests Enhanced;
- every non-Vivolution-hosted cluster is `EXCLUSIVE` with a non-null customer-account owner;
- unique active derived FQDNs and unique `(cluster_id, southbound_signaling_port)`;
- non-overlapping active media ranges per cluster;
- one active allocation per service except the explicit source-plus-shadow migration case;
- capacity, port, and tier reservation without races between schedulers.

These constraints protect the normal application role and concurrency path; privileged database administration remains separately controlled and audited.

HA capacity is based on what either surviving node can carry, not the sum of both nodes. Initial discovery thresholds are:

- Prefer placement at or below 60% of N-1 safe capacity after reservation.
- Open expansion work at 60–65% reserved or forecast capacity.
- Stop ordinary placement around 70%.
- Hard refuse at 75% in any dimension.

These are conservative starting values and must be calibrated by load and failure tests. The scheduler records candidate scores and exact rejection reasons. A large Enhanced tenant that dominates shared capacity should be moved to another shared cluster or offered Dedicated.

## Service migration

The immutable identities are `customer_account_id`, `m365_tenant_id`, technical `tenant_context_id`, and `service_instance_id`—not a particular cluster FQDN, public IP, signaling port, or media block. A move between clusters can change all network endpoints and must not be marketed as transparent.

1. Reserve target N-1 capacity, FQDNs, signaling/media allocations, certificates, ACLs, and secrets in a `SHADOW` allocation.
2. Have the customer firewall temporarily permit both pairs; preserve the southbound signaling port only if it is safely available on the target.
3. Install/validate target state, DNS, TLS/OPTIONS, and synthetic calls.
4. Add the target derived FQDNs to Teams voice routes and canary new calls by explicit route priority.
5. Stop new calls on the source, wait for active sessions up to a defined maximum, and reconcile CDRs. Active calls are not migrated.
6. Promote the target or restore source priority for rollback.
7. Release source resources only after evidence is complete, then quarantine old ports/FQDNs/secrets before reuse.

## Universal enrollment protocol

Every node runs a signed `vivolution-edge-agent` as a privilege-separated system service. The initial claim uses outbound TCP 443 with server-authenticated TLS and a pinned Vivolution trust root; node mTLS begins only after approval issues a client identity. SIP and RTP remain the only intended public inbound services. The agent exposes no public management API and provides no operator-supplied remote shell, free-form hook, script, package name, or diagnostic argument.

The installer experience should be simple without weakening the trust bootstrap:

1. Install a signed/digest-pinned DEB/RPM from the Vivolution package repository or an offline bundle.
2. Run `sudo vivolution-edge enroll --controller https://control.voice.vivolution.ae`.
3. The CLI reads the display-once token directly from `/dev/tty` with echo disabled; it never appears in argv, process lists, URLs, environment dumps, logs, or shell history. Unattended enrollment uses `--token-file /run/vivolution/enroll.token` with a root-owned `0600` tmpfs file that is erased after use.

The portal may generate a copy/paste sequence that downloads a fixed-version package plus signature/TUF metadata, verifies it against a pre-established signing key, and only then installs. Production does not use an unchecked `curl | sh`. Also provide signed APT/RPM and offline-bundle paths. Start with one exact supported Linux baseline; add distributions only after their complete preflight/update/rollback matrix passes.

The main agent runs unprivileged. A small local root helper exposes only fixed, schema-validated operations over a root-owned Unix socket. It independently verifies manifest signature, node/generation target, scope, monotonic sequence, and artifact digest; authenticates the caller with Unix peer credentials; and maps typed resource IDs to internal Vivolution-owned paths, users, service units, and one dedicated nftables table/chains. It never flushes the host firewall, changes customer SSH/access, or accepts raw paths, unit names, package URLs, nftables fragments, arbitrary commands, free-form packages, unrelated file access, or uploaded scripts.

Named diagnostics are tenant-scoped, duration/size-bounded, redacted, approval/audit controlled, and absolutely deny private keys/secrets. SIP/packet capture is an incident-only separately approved workflow, not a routine helper verb.

An existing node must first pass a support preflight: approved distro/kernel, root-assisted installation, static public-IP ownership or explicitly supported 1:1 NAT, required NIC/MTU/UDP behavior, accurate NTP, delegated DNS, no SIP ALG, host firewall capability, disk reservations, and documented customer/provider firewall responsibilities. Public IP and DNS endpoint objects are decoupled from a VM generation so a replacement can preserve them where the provider allows.

1. An operator creates a pending cluster blueprint containing its mode, capacity, region, two expected node slots, failure-domain policy, and software channel.
2. The control plane creates a different random one-time bootstrap grant for slot A and slot B. Each display-once grant is stored hashed, scoped to its cluster/slot/release, rate-limited/audited/redacted, and expires after 10–15 minutes.
3. A cryptographically signed, digest-pinned DEB/RPM or cloud image installs the Edge Agent with the control-plane URL and pinned trust-root fingerprint. Prohibit `curl | sh`. Deliver the grant through a root-only `0600` tmpfs file, stdin, or an approved cloud secret handoff—not argv, environment dumps, shell history, reusable images, or retained cloud-init/user-data—and erase it after claim.
4. The node creates its private identity key locally and submits its CSR/public-key fingerprint, nonce, inventory, instance identity, image digest, and available cloud/TPM evidence. After proof of possession, one atomic operation binds the grant to that exact CSR key and persists the claim handle before acknowledging success. Idempotent retries from the same key are allowed until approval/expiry; a different key is rejected. The claimant signs fresh server nonces while awaiting approval.
5. The node enters `PENDING_APPROVAL` and receives no desired state, trusted telemetry status, or secrets. Unattested metadata is labelled self-reported. Provider evidence is trusted only after validating issuer, audience, nonce/freshness, account/subscription, instance ID, expected slot, and image. For manual enrollment, the operator compares the CSR fingerprint through an independent cloud/VM console. Approval binds the exact CSR key, cluster, slot, generation, and evidence. Production and Dedicated enrollment require peer approval.
6. The control plane acts as registration authority and asks a maintained CA such as step-ca to issue a short-lived node-specific mTLS identity; the bootstrap grant never directly mints a certificate. CSR-requested SANs are ignored, and the approved node/cluster/slot/generation identity plus clientAuth EKU is inserted by policy. No certificate or credential is shared across nodes.
7. After mTLS authorization, the node pulls signed desired state and node-scoped secret references/leases, stages them, runs validation, applies the component changes in a defined order, and reports signed evidence. The cluster remains unavailable until both node slots pass.
8. Readiness is explicit: `INFRA_READY` requires identity, host, firewall, clock, capacity, and node/service gates. `TEAMS_READY` is conditional on `teams_attachment_mode`: `HOSTED_DERIVED` validates provider-tenant base gateways plus derived FQDN behavior; `CUSTOMER_DIRECT` validates gateways/FQDNs directly in the customer's Microsoft tenant. Both require stable public IPs, DNS, public SIP certificates, Microsoft OPTIONS, and a named internal/SIPp or licensed Teams synthetic test. `AVAILABLE_FOR_PLACEMENT` requires both nodes and scheduler eligibility. Each tenant allocation separately proves its FQDNs, PBX connector, routes, firewall, and controlled calls before activation.

Agents bootstrap through one stable control URL, then receive a signed endpoint set for Controller 1 and Controller 2 and reconnect to either. They never bind permanently to one controller. See [Control Plane High Availability](control-plane-ha.md).

Use step-ca behind the control plane as the lean POC CA and evaluate SPIFFE/SPIRE for production workload identity/attestation plugins. Cosign can sign artifacts; TUF-style metadata supplies update roles, freshness, threshold trust, and rollback/freeze protection. A POC may use signed manifests plus protected monotonic state, but production update security must not assume artifact signatures alone solve rollback/freeze attacks.

### Bounded enrollment v1 implementation note

The same-day v1 implementation stops deliberately before the full protocol
above. It uses the shared Controller HTTPS origin plus short-lived,
single-use Controller challenges and a node-local Ed25519 key for signed claim,
status, and heartbeat requests. The display-once grant is accepted only from an
echo-disabled terminal, stdin, or a root-owned `0600` tmpfs file and is never
persisted. mTLS/CA issuance remains deferred and must not be claimed for v1.

This increment proves provider-neutral join, Pending approval, fingerprint
approval/revocation, exact lost-response replay, and outbound fleet visibility
for node scope, agent/link health, boot/sequence, and inventory/release digests.
It does not yet upload detailed capabilities, deliver desired state or secrets,
or make the node fully manageable from the Controller. The exact implemented
boundary is documented in `edge/enrollment/API_CONTRACT.md`.

## Reconciliation and rollback

The agent pulls declarative desired state. It does not accept arbitrary commands, scripts, or uploaded shell fragments. Typed intents are limited to operations such as:

- reconcile a specific signed version;
- drain or undrain;
- rotate node identity;
- run a named, bounded health or synthetic test.

A manifest includes `scope=TENANT|CLUSTER`, immutable cluster/node/generation and optional tenant/allocation IDs, an allow-list of resources that scope may change, a monotonically increasing per-target sequence, issue/expiry time, previous digest, package/config digests, secret references, health gates, and rollback target. Tenant-scoped artifacts are structurally unable to alter binaries, shared listeners/routes/firewall/trust roots, or other tenants. Nodes persist the accepted sequence high-water mark in protected state; the controller retains the authoritative current sequence/generation and quarantines snapshot rollback or an older report. Nodes reject the wrong target/scope, expired new activation, digest mismatch, replay, or downgrade. Expiry blocks a new activation; it does not invalidate a committed last-known-good artifact during an outage. Every boot re-verifies its signature and digest. TPM anti-rollback can strengthen supported hosts; manual/customer-controlled hosts cannot claim that guarantee.

Configuration-only apply is stage -> signature/schema/offline validation -> drain where required -> atomic file/symlink activation or hot reload -> health gate -> commit as last-known-good. Multi-component changes are ordered and use compensating rollback; they are not one ACID transaction. Software/kernel/schema releases use separately signed immutable images/packages, compatibility rules for mixed versions, and only explicitly reversible migrations. Before any cluster rollout, prove the peer is healthy and can carry N-1 capacity, update the drained/lower-risk node first, observe it, then update the peer. Block rollout when the peer is degraded. Rollback is a new higher-sequence signed manifest referencing a compatible earlier artifact.

The control plane remains outside the real-time call path. If it is unavailable, nodes keep serving with last-known-good state. A separate encrypted, quota-reserved CDR write-ahead spool uses idempotent event IDs and reconciliation; high-water/disk-full behavior must alert and follow an explicit call-admission policy. Telemetry uses a bounded lossy queue with documented drop priority and backpressure, never an unbounded durability promise.

Management certificates have a defined lifetime/renewal window, overlap, server-side authorization, and root-rotation plan. The POC baseline can use a 24-hour client certificate renewed after half its lifetime. Every new connection and sensitive request checks current node status and certificate serial; revocation closes existing streams, invalidates renewal/session resumption, denies configuration/secrets/trusted telemetry, and rotates exposed credentials. Expired management identity blocks management and requires recovery/re-enrollment, but never deletes last-known-good state or abruptly stops calls.

Desired-state bundles contain secret references, never secret bytes. Secrets are released only after node authorization, envelope-encrypted to that node, scoped to cluster/tenant/unit, and cached only in encrypted or root/unit-readable storage. Management leases can expire during an outage; call-critical credentials need an explicitly longer offline-validity/rotation model so last-known-good calling remains truthful.

## Fleet monitoring

Reuse standard telemetry instead of inventing it: OpenTelemetry Collector or Grafana Alloy, Prometheus-compatible metrics, and bounded logs/traces sent outbound over mTLS. Observe:

- node heartbeat, identity, certificate expiry, version, SBOM, checksum, and drift;
- CPU, memory, disk, clock, DNS, network, and failure-domain state;
- OpenSIPS process, TLS/OPTIONS, dialogs, CPS, SIP response codes, reload results, and shared-ingress health;
- each tenant RTPengine unit, sessions, media-port utilization, packet loss, jitter, and estimated MOS unless RTCP-XR or active probes support a defensible measured score;
- tenant reserved/active sessions, CPS, bandwidth, failed calls, fraud/limit events, CDR lag, and reconciliation;
- cluster N-1 capacity, placement headroom, synthetic calls, maintenance, and expansion threshold.

Health is represented as explicit node, allocation, and cluster states—not a green average that hides a failed node.

## Existing-tool boundary

- Use pinned Ansible Core content locally during image build/provisioning for initial OS hardening, packages, and slow baseline changes. Do not fetch Galaxy/Git content from production nodes or expose Ansible through the enrolled agent.
- The current official AWX Operator expects Kubernetes, making supported operation disproportionate for this POC. Salt adds a second privileged generic execution/state plane and exposes its master/relay ports. Nomad/Consul, k3s, and Rudder add disproportionate platform complexity for the initial 2–20-node fleet.
- NetBird or WireGuard can later provide a private break-glass/diagnostic overlay; they are not the call path or orchestration system.
- Provider adapters may use native APIs, Bicep, CloudFormation, OpenTofu/Terraform, or manual runbooks. Each adapter runs in an isolated worker with least-privilege, preferably short-lived provider identity, idempotent jobs, vault-backed credentials, and no CA/signing/tenant-secret authority. It never gives cloud-admin credentials to an Edge Agent and never changes the common enrollment and management contract.

## Lifecycle

Node:

```text
DECLARED -> GRANT_ISSUED -> CLAIMED -> PENDING_APPROVAL -> ENROLLED
         -> BASELINING -> VALIDATING -> READY
READY <-> DRAINING <-> MAINTENANCE
VALIDATING/READY -> QUARANTINED -> REENROLL only for a non-identity policy fault
QUARANTINED -> REVOKED -> REPLACE for compromise, clone, integrity, or attestation failure
ANY -> REVOKED -> DECOMMISSIONED
```

Cluster:

```text
DRAFT -> ENROLLING -> VALIDATING -> AVAILABLE -> SERVING
      -> DEGRADED or MAINTENANCE -> DRAINED -> RETIRED
```

An integrity, attestation, clone, or signature failure quarantines and revokes the affected identity, blocks new secrets/configuration, and requires replacement. A simple control-plane outage does not. Replacement creates a new node generation; node identities are never recycled.

Routine decommissioning drains sessions, removes placements, revokes node identity/leases, rotates affected tenant credentials, records evidence, then destroys the VM through the provider adapter or an approved manual step. Suspected compromise reverses the priority: immediately quarantine/revoke, stop new calls, remove the node from Teams/DNS/routing/firewalls, rotate exposed voice/tenant secrets, and destroy it without waiting for graceful drain. The platform must never claim a remote wipe, provider deletion, or independent failure domain without external evidence.
