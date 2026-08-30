# Turnkey first-tenant execution profile

Status: authorized and in progress as of 2026-08-30.

This profile narrows the broader product blueprint to the first deployable proof
of concept Jay authorized: one self-contained CP1 and two Open Edge nodes in UAE
North, prepared for Vivolution Technologies LLC as the first test tenant. It is
not a Microsoft-certified SBC, a production SLA, a multi-tenant-isolation claim,
or permission to route PSTN/emergency traffic.

## Fixed delivery boundary

- New project resource group: `rg-vivolution-sbc-poc-uaenorth`.
- Preserve `rg-vivolution-cp1-uaenorth` until replacement CP1 and restore tests
  pass; protect the group with the exact `CanNotDelete` lock
  `preserve-qualified-cp1-during-poc` and delete it only after cutover
  acceptance.
- Never modify or delete `DNS_Zones`, `NetworkWatcherRG`, `Telegram-Bot`,
  `OpenVPN`, or unrelated subscription resources.
- Region: UAE North.
- CP1: Debian 13 Gen2 AMD64, `Standard_D2as_v5` for build/qualification, 64 GiB
  Standard SSD, local PostgreSQL/PgBouncer/Caddy/Podman/Django.
- SBC1/SBC2: Debian 13 Gen2 AMD64, `Standard_B2als_v2`, 32 GiB Standard SSD,
  OpenSIPS 3.6.8 and userspace RTPengine 26.0.1.22.
- Each node has a static Standard public IPv4 address. Edge nodes share an
  aligned availability set; this is host-fault separation, not zone/regional HA.
- Key-only SSH is restricted to observed administrator `/32` addresses. No
  password login, public database, public management agent, TCP/UDP 5060,
  Docker daemon, Kubernetes, managed database, Azure Firewall, or load balancer.
- Core creation is admitted only after the read-only lifecycle guard proves the
  reviewed subscription/tenant, empty and exactly tagged UAE North POC group,
  USD 100 monthly budget with 75/90/100 actual-cost alerts, preserved-CP1 lock,
  and absence of every reserved POC DNS name/child zone.

## First-tenant port and trust allocation

- Shared Microsoft Teams listener: TLS TCP 5061, reachable only from current
  Microsoft Direct Routing CIDRs plus the private synthetic fixture during
  bounded pre-M365 qualification.
- First-tenant PBX listener: mTLS TCP 15061, reachable only from the approved PBX
  source. It must never collide with Teams TCP 5061.
- Outer Edge NSG RTP pool: UDP 20000-29999.
- First-tenant RTPengine allocation and host-firewall range: UDP 20000-20255.
- Synthetic PBX-side media destination/source range: exact UDP 21000-21127.
  Direct Routing instead uses the reviewed signed and node-bound PBX range
  (UDP 30000-30127 in the initial template); it is not the Edge-local range.
- RTPengine control: loopback only. The first POC uses one explicitly
  single-tenant instance per node; it does not claim multiple isolated media
  units yet.
- The signed compiler artifact remains `privateIpv4!publicIpv4`. The trusted
  `SYNTHETIC_PRIVATE` runtime deterministically renders `privateIpv4!privateIpv4`
  so CP1 fixture SDP stays inside the VNet; `DIRECT_ROUTING` alone retains the
  public advertised media address. No public-IP hairpin allowance is added.
- Initial no-PSTN fixture: private CP1 address `10.20.1.4/32`. It may emulate
  the Teams and PBX sides for TLS/SIP/RTP qualification without exposing another
  public endpoint or reaching a carrier.

Every signed tenant envelope is bound to the immutable cluster, node, slot,
generation, customer, Microsoft tenant, tenant context, service, allocation,
listener port, and media block. A node-local policy—not signed input alone—owns
the authorized listener/media allocation. Replay state separates the
highest-seen sequence, pending candidate, and active last-known-good version.
Only an explicit post-health commit may promote pending state.

## DNS and certificate target

- Controller: `controller.voice.vivolution.ae` after replacement cutover.
- Base nodes: `sbc1.voice.vivolution.ae` and
  `sbc2.voice.vivolution.ae`.
- Hosted customer-derived names, when a separate customer Microsoft 365 tenant
  is available: `vivolution.sbc1.voice.vivolution.ae` and
  `vivolution.sbc2.voice.vivolution.ae`.
- Each node certificate must contain its base FQDN and the matching wildcard
  derived-name SAN, have Server Authentication EKU, use a publicly trusted
  chain, and be obtained through DNS-01 without exposing HTTP on the Edge.
- Each SBC uses a separate delegated `acme-sbcN.voice.vivolution.ae` child
  zone. Its managed identity can mutate only that durable ACME zone; Lego may
  delete/recreate challenge TXT records without gaining parent-zone access or
  losing its renewal role. The two zones add roughly USD 1/month combined.
- Teardown uses the fail-closed `infra/azure-poc/teardown_dns_acme.py` workflow
  before core resource-group deletion. Read-only planning is the default;
  apply requires the freshly validated plan digest and exact confirmation. It
  removes only the POC parent records/delegations, child locks, node-specific
  RBAC, and tagged child zones—never the shared resource group or parent zone.
- Core teardown follows DNS teardown, requires all three VMs Azure-deallocated,
  binds a reviewed digest to the exact 17-resource tagged inventory, and may
  delete only `rg-vivolution-sbc-poc-uaenorth`. The preserved CP1 and shared DNS
  groups are explicit postconditions and never deletion targets.

If Vivolution has only one Microsoft 365 tenant, the first live call gate uses
the base node FQDNs as a direct Direct Routing POC. That proves the call path but
does not prove Microsoft's hosted multi-tenant derived-trunk procedure.

## Power and cost plan

Azure retail rates checked on 2026-08-30 are USD 0.106/hour for D2as-v5,
USD 0.0451/hour for B2als-v2, USD 0.005/hour for each Standard static IPv4,
USD 5.76/month for a 64 GiB Standard SSD, and USD 2.88/month for a 32 GiB
Standard SSD. Rates and Cost Management data can change or lag.

At 730 hours, the three-node infrastructure is approximately USD 165.70/month
before egress, DNS, backup, or unrelated subscription usage. It therefore must
not remain fully powered under a USD 100 credit. The execution sequence is:

1. Create all immutable network/disk/IP resources after ARM validation.
2. Immediately deallocate SBC2 until the HA window.
3. Qualify SBC1 packages, firewall, reboot, and fail-closed state first.
4. Build replacement CP1, restore the encrypted backup, and deallocate old CP1
   compute when the replacement reaches the recovery gate.
5. Power SBC2 only for mirrored deployment, node failover, and final soak.
6. After testing, deallocate both SBCs; delete the old CP1 group after accepted
   cutover. Keep a daily read-only spend/power-state guard at USD 75/90 levels.

Cost Management showed about USD 49.74 month-to-date across the full
subscription when this profile was written, including historical deleted labs
and unrelated workloads. That figure is not the POC's cost and may lag, but it
is the correct remaining-credit constraint for staging.

The isolated POC resource group also has an Azure Cost Management budget named
`viv-sbc-poc-monthly-usd100`, fixed at USD 100 per month with actual-cost email
notifications at 75%, 90%, and 100%. The budget is an alerting control rather
than an automatic shutdown; the daily read-only Telegram guard remains the
power-state backstop.

## External prerequisites

The platform, private synthetic calls, restore, rollback, and node-failure tests
can proceed without these. Live Teams onboarding cannot be truthfully completed
until all applicable items exist:

- confirmation whether Vivolution has one Microsoft 365 tenant or separate
  provider and customer tenants in the same Microsoft cloud;
- Global Administrator cooperation for every participating tenant;
- at least two test identities with Teams and Teams Phone entitlements;
- verified non-`onmicrosoft.com` domain activation for the selected Direct
  Routing topology;
- acceptance that OpenSIPS/RTPengine is a Vivolution-engineered POC and is not a
  Microsoft-certified or Microsoft-supported production SBC;
- an existing PBX endpoint only if Jay elects not to use the isolated CP1
  Asterisk/SIPp fixture. No license or service purchase is implicit.

A read-only Microsoft Graph check on 2026-08-30 confirmed the signed-in Entra
tenant, but neither `vivolution.ae` nor `voice.vivolution.ae` is currently in
that tenant's verified-domain set. Therefore the CP1 catalog keeps the M365
record `PENDING`, with no asserted primary domain. Adding and verifying the
Direct Routing domain is an explicit live-M365 gate, not something inferred
from Azure subscription ownership. The same read-only check returned no
subscribed Microsoft 365 SKUs, so there are currently no tenant licenses to
assign for the two live Teams/Teams Phone test identities. The POC will not buy
or start a trial subscription without Jay's explicit approval.

GitHub is optional for delivery. The local repository, signed evidence, and
rebuild automation remain authoritative until Jay explicitly authorizes and
provides access to a private GitHub destination.

## Turnkey acceptance gate

Delivery is complete only when all applicable gates have evidence:

1. Clean IaC rebuild and exact Azure inventory/NSG/Trusted Launch checks.
2. CP1 deploy, backup restore, HTTPS/admin login, RLS, recovery and N-1 rollback.
3. Both Edge nodes pass package, keyring, firewall-preservation, clock, reboot,
   service sandbox, fail-closed, and vulnerability checks.
4. Signed desired state rejects wrong node/slot/generation/allocation, altered
   bytes, invalid key, replay/downgrade, cross-scope state, and colliding ports;
   failed pending state leaves active last-known-good intact.
5. Private synthetic TLS/SIP/RTP calls pass in both directions with complete CDR
   reconciliation, expected negative cases, and no PSTN reachability.
6. Public DNS, certificate chain, OPTIONS, Teams-to-PBX and PBX-to-Teams calls
   pass when Microsoft 365 prerequisites are supplied.
7. The bounded private acceptance runner proves one baseline call through SBC1,
   begins the 120-second clock, stops the complete SBC1 data plane, observes its
   signaling listener closed from CP1, and completes a fresh same-route call
   through SBC2 before the gate expires. It then restores and re-tests the exact
   SBC1 runtime. A protected node-local injector arms the persisted systemd
   deadman before stopping either service, making restoration independent of
   the runner, and all three call phases require complete
   manifested artifacts plus Edge-to-fixture CDR reconciliation. The runner
   selects the private alternate itself, so this is not Microsoft
   OPTIONS/gateway-selection evidence; active calls are not claimed to migrate.
   CP1/database outage leaves the committed data plane on last-known-good state.
8. Signed evidence, exact versions/digests, actual cost, console access,
   operations/backup/recovery/certificate/tenant onboarding runbooks, known
   limitations, and deallocation/teardown steps are handed over.

Any live-call gate blocked only by missing external tenant/license access is
reported separately and cannot be relabelled as passed by synthetic traffic.
