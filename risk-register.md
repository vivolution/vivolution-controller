# Risk Register

Status: Discovery baseline with an operational local CP1 and replacement
qualification in progress. Scores remain qualitative until the replacement
local, voice, and Azure POC stages produce evidence.

## R1 — Microsoft support boundary

- **Risk:** Microsoft may refuse support or change behavior that breaks Open Edge.
- **Impact:** High.
- **Control:** Clear Open/Certified product distinction, pinned regression suite, protocol monitoring, certified fallback, customer disclosure.
- **POC evidence:** Full SIP/media feature and failure matrix without a fragile private binary fork.

## R2 — Cross-tenant leakage or misrouting

- **Risk:** A shared edge routes signaling/media or exposes records across customers.
- **Impact:** Critical.
- **Control:** Trusted connection-derived tenant ID, immutable dialog context, DB row-level security, compiler checks, negative attack tests.
- **Stop condition:** Any unexplained cross-tenant route, media, secret, configuration, CDR, or report exposure.

## R3 — Toll fraud and abuse

- **Risk:** Stolen credentials, unsafe routes, or an open relay create carrier charges or abuse.
- **Impact:** Critical.
- **Control:** PBX relay first, default-deny destinations, ACL/TLS identity, CPS/session caps, anomaly detection, rapid tenant suspension, no live PSTN in POC.

## R4 — UAE carrier or regulatory classification

- **Risk:** A carrier rejects hosted relay/termination or authorities classify the offer differently than assumed.
- **Impact:** High.
- **Control:** Customer-owned trunk, PBX relay first, no numbers/minutes resale, written carrier/legal validation before live pilot.

## R5 — Emergency and caller-identity obligations

- **Risk:** Emergency routing, location, CLI, and failure behavior are incomplete.
- **Impact:** Critical.
- **Control:** Exclude from POC and first activation until responsibilities and tests are documented with customer/carrier.

## R6 — Certificate lifecycle

- **Risk:** Expiry, trust-chain, RSA/EKU, or future Microsoft mTLS requirements interrupt service.
- **Impact:** High.
- **Control:** RSA DNS-01 automation, base-plus-wildcard SANs, staged rotation, expiry alerts, commercial CA fallback, no unsupported workaround.

## R7 — Voice quality and failure radius

- **Risk:** Azure/PBX hairpin, media anchoring, node loss, or shared resource pressure degrades many customers.
- **Impact:** High.
- **Control:** UAE hosting, RTP metrics, per-tenant quotas, load evidence, two FQDNs/nodes, capacity headroom, dedicated tier.

## R8 — Excessive custom engineering

- **Risk:** Portal, CDR, HA, and interoperability work erases licence savings.
- **Impact:** High.
- **Control:** Reuse maintained SIP/media/observability components, bounded C5/LibreSBC checks, narrow v0.1, track staff time, pivot to Certified Edge when cheaper.

## R9 — CDR privacy and evidentiary quality

- **Risk:** Years of call metadata increase privacy exposure while proxy CDRs remain incomplete.
- **Impact:** High.
- **Control:** Defined retention tiers, encryption, immutable archive, export audit, PBX/carrier reconciliation, short-lived SIP traces, no audio by default.

## R10 — Unsupported PBX diversity

- **Risk:** Every customer PBX/NAT/codec combination becomes bespoke engineering.
- **Impact:** Medium/High.
- **Control:** Supported PBX/firmware matrix, standard TLS/VPN handoff profiles, onboarding test pack, paid exception engineering, reject unsafe peers.

## R11 — Control-plane compromise or outage

- **Risk:** Portal breach changes global routes; portal/database outage stops calls.
- **Impact:** Critical.
- **Control:** Private management plane, MFA/RBAC, signed versioned artifacts, two-person critical changes, last-known-good local runtime, audited rollback.

## R12 — Weak POC evidence

- **Risk:** One successful call is mistaken for product readiness.
- **Impact:** High.
- **Control:** Provider-plus-two-customer topology, overlapping numbers, attack tests, 100-call reconciliation, HA, restore, cost and soak gates.

## R13 — Bootstrap or fleet-agent compromise

- **Risk:** A stolen enrollment secret, forged node, compromised signing key, or overpowered agent gains control of shared voice infrastructure.
- **Impact:** Critical.
- **Control:** Different short-lived one-time grants per node slot, hashed token storage, node-generated keys, fingerprint/attestation approval, short-lived node-specific mTLS identity, separate artifact-signing trust, signed declarative state, replay/downgrade protection, scoped secret leases, no generic remote shell, and rapid revoke/quarantine.
- **Stop condition:** A reused/wrong-slot token enrolls, an unapproved node receives operational identity, an unsigned/replayed artifact activates, or the agent can run arbitrary control-plane commands.

## R14 — Enhanced tier overstated as dedicated isolation

- **Risk:** Customers interpret separate ports/media units as complete infrastructure isolation even though OS, public IPs, and shared Teams ingress remain common.
- **Impact:** High.
- **Control:** Explicit service wording, technical placement invariants, blast-radius tests, no whole-process restart for tenant changes, and Dedicated mode for an exclusive pair.

## R15 — Cloud-provider lock-in or adapter drift

- **Risk:** Cluster operations depend on Azure-specific tooling or inconsistent cloud adapters bypass identity, firewall, or lifecycle controls.
- **Impact:** High.
- **Control:** Universal Enroll Existing Pair flow, provider-neutral host firewall and agent contract, narrowly scoped optional adapters, identical enrollment gates after creation, and provider-specific conformance tests.

## R16 — Control-plane split brain or stale publication

- **Risk:** Two controllers/database replicas both believe they are writable or a recovered controller publishes an older generation.
- **Impact:** Critical.
- **Control:** Managed database HA or third quorum witness, fencing before promotion, consistency-first read-only mode without quorum, monotonic configuration generation, lease-controlled idempotent jobs, and stale-controller rejection at Edge nodes.

## R17 — Customer-hosted substrate and administrative drift

- **Risk:** Customer power/network/hypervisor failure, cloning, snapshot rollback, root changes, NAT/firewall changes, or key extraction breaks service or weakens trust.
- **Impact:** High.
- **Control:** Dedicated-only customer-hosted production, explicit evidence grade, TPM/vTPM/provider attestation where available, clone/generation detection, drift alerts/quarantine, two-node prerequisites, shared-responsibility matrix, and SLA pause after unapproved changes.

## R18 — Local CP1 evidence overstated as Azure or product readiness

- **Risk:** Passing the Debian 13.6 ARM64 controller-foundation suite is mistaken for Azure production acceptance or a working SBC product.
- **Impact:** High.
- **Control:** Preserve architecture- and scope-labelled evidence, require a clean Azure AMD64/Flexible Server/public TLS acceptance run, qualify enrollment/PKI separately, and retain independent SIP/media and tenant-isolation gates. Run and record a vulnerability scan before any production-readiness claim.
- **Current evidence:** Historical folders `deploy/evidence/20260827T180455Z-19848` and `deploy/evidence/20260827T183743Z-74252` retain bounded functional results. The August 28 audit withdrew their broader qualification conclusion because the reported `changed=0` recap hid PostgreSQL SCRAM changes and other security/evidence gaps.
- **Open exposure:** Replacement local qualification remains in progress. Azure remained untouched, and Azure AMD64/Flexible Server/public TLS, enrollment/PKI, and the SIP/media data plane remain unaccepted.
