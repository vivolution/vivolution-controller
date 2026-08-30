# Azure CP1 + SBC1 + SBC2 POC infrastructure

This Bicep scaffold creates the minimum Azure infrastructure for a three-node Vivolution SBC proof of concept in **UAE North**. It is intentionally limited to one resource group and does not deploy or change any existing Azure resource unless an operator explicitly runs the deployment commands.

The initial shape is one `Standard_D2as_v5` CP1 with a 64 GiB Standard SSD and two `Standard_B2als_v2` Edge nodes with 32 GiB Standard SSDs. Each Debian 13 Gen2 AMD64 node has its own static Standard IPv4 address and system-assigned managed identity. CP1 deliberately starts on the already-qualified size; resize it only after the complete controller suite passes on the smaller target. Full-size runtime is staged for the short build/qualification window rather than left running for a whole month.

`Standard_B2s` is not available to this Visual Studio subscription in UAE North as of 2026-08-30. `Standard_B2als_v2` is the verified regional fallback: x64, 2 vCPU, 4 GiB RAM, generation 2 capable, and currently USD 0.0451/hour for Linux consumption. Azure reports only an availability-zone restriction for zone 2, which does not prevent this non-zonal availability-set deployment. Re-check the subscription SKU restrictions immediately before creation.

## Topology

- `snet-management` contains CP1 at `10.20.1.4` by default.
- `snet-edge` contains SBC1 at `10.20.2.4` and SBC2 at `10.20.2.5` by default.
- SBC1 and SBC2 share an aligned availability set with two platform fault domains. This protects the POC from a single host fault; it is not a claim of availability-zone or regional resilience.
- CP1 permits public TCP 80/443 and TCP 22 only from explicit administrator CIDRs.
- In `DIRECT_ROUTING` only, SBC1 and SBC2 permit Microsoft TLS signaling on TCP 5061 and media only from the explicit reviewed Microsoft CIDRs. No Microsoft ingress rule exists in `SYNTHETIC_PRIVATE`.
- In `SYNTHETIC_PRIVATE` only, the private Teams-side simulator may reach TCP 5061 and the media pool for no-PSTN qualification. No synthetic ingress rule exists in `DIRECT_ROUTING`.
- The single bounded RTPengine UDP media range stays local at `20000-29999`. Microsoft ingress is accepted only from the reviewed Media Processor CIDRs with remote source ports `3478-3481` or `49152-53247`. In `DIRECT_ROUTING`, the reverse NSG allowance starts only from the first-tenant `20000-20255` allocation and reaches only those Microsoft CIDRs and destination ports. These remote Microsoft ranges are never used as RTPengine bind ports.
- Optional first-tenant PBX TLS 15061 and media rules are created independently per SBC only when that SBC's PBX source list is non-empty. The PBX listener is deliberately distinct from the shared Microsoft listener on 5061.
- SBC SSH is allowed only from the same explicit administrator CIDRs as CP1. Remove that rule after a separately qualified private management path exists; never copy a private SSH key onto CP1.
- Explicit priority-4096 deny rules block every other inbound and outbound flow before Azure's built-in NSG rules. There is no public TCP/UDP 5060, database, or agent-management rule.
- Common outbound rules are limited to Azure DHCP/DNS/WireServer/IMDS, the fixed CP1 HTTPS address, TCP 80/443 for APT/ACME/Azure APIs, and UDP 123 to the two fixed NTP `/32`s. `SYNTHETIC_PRIVATE` then permits signaling and media only to CP1's fixed fixture ports. `DIRECT_ROUTING` replaces those voice rules with Microsoft and authorized-PBX signaling/media rules; the two sets are never active together.

Azure Firewall, NAT Gateway, load balancer, managed database, and Log Analytics
workspace are intentionally absent. Public DNS/RBAC is isolated in the separate
post-compute template. Outbound access uses each VM's public IP.

## Files

- `main.bicep` composes the network, Edge availability set, node-specific NSG policies, and three VMs.
- `azure_lifecycle_contract.py` holds the exact subscription, tenant, resource,
  tag, budget, DNS, and preservation-lock contract shared by the offline-tested
  lifecycle guards.
- `predeploy_guard.py` is a strictly read-only admission gate for the empty,
  tagged, budgeted POC resource group and preserved existing CP1.
- `lockdown_os_disks.py` is the fail-closed, idempotent post-create step that
  disables disk public network access and reconciles exact ownership tags on
  the three marketplace-image OS disks before host configuration.
- `teardown_core_poc.py` is the plan-first, digest-confirmed deletion gate for
  only the exact quiesced core POC resource group.
- `modules/network.bicep` creates the single VNet and two subnets.
- `modules/linux-node.bicep` creates one Standard static public IP, NSG, NIC, managed disk, and Debian VM.
- `main.example.bicepparam` is a safe example containing documentation-only IP ranges and an invalid SSH-key placeholder.
- `dns-acme.bicep` is a separate post-compute subscription deployment for the
  two base/wildcard A records and least-privilege managed-identity ACME DNS.
  Each SBC receives its own delegated `acme-sbcN.voice.vivolution.ae` child
  zone and CNAME challenge target; the existing parent zone remains outside
  the Edge write boundary.
- `dns-acme.example.bicepparam` is deliberately non-deployable and must be
  populated only from the reviewed core deployment outputs.

## Required inputs

Before deployment, determine all of the following:

1. A valid ED25519 or RSA SSH **public** key. Never place a private key in a parameter file.
2. The operator's current public IPv4 CIDR, normally a `/32`.
3. The current Microsoft-published Direct Routing signaling and media IPv4 CIDRs. The set reviewed on 2026-08-30 is `52.112.0.0/14` and `52.120.0.0/14`; current `52.114.*` SIP-hub addresses are already contained by `52.112.0.0/14` (which spans `52.112.0.0` through `52.115.255.255`). Re-check Microsoft's documentation immediately before deployment; do not treat copied or historical address lists as permanent.
4. The real public or private source CIDRs for the test PBX. Leave the PBX arrays empty until these are known.
5. UAE North availability, quota, and Trusted Launch support for each selected VM size.

The Bicep contract fixes the POC's outer RTPengine cluster pool at `20000-29999` and the first-tenant PBX listener at TCP `15061`; a deployment cannot override either value to collide with a reserved port. The first tenant receives the fixed Edge-local `20000-20255` media allocation. Microsoft Media Processor ingress is directional: remote source ports `3478-3481` and `49152-53247` reach only the reviewed local cluster pool. In `DIRECT_ROUTING`, the explicit reverse allowance starts only from the narrower tenant allocation and reaches those same remote destination ranges on the reviewed Microsoft CIDRs. PBX media uses a separate, per-node canonical destination range: ingress accepts that range only as the PBX's remote source ports into `20000-20255`, while egress starts in `20000-20255` and reaches signed/validated PBX CIDRs only on the configured PBX-side destination range. The reviewed Direct template uses UDP `30000-30127`; synthetic nodes must use the exact fixture range UDP `21000-21127`. The host firewall, desired-state manifest, node facts, and NSG must agree exactly on both directional ranges.

In `SYNTHETIC_PRIVATE`, the mandatory no-PSTN CP1 fixture is private-only. Its NSG accepts TLS from the Edge subnet solely on TCP `16061` and `25061`, PBX fixture media on UDP `21000-21127`, and Teams-side fixture media on UDP `22000-22063`. These ports are never exposed from the Internet and remain subject to the CP1 host firewall and each fixture unit's systemd IP policy. `DIRECT_ROUTING` requires this fixture switch off and the synthetic source list empty.

The private address parameters are not automatically checked for subnet membership or overlap. If subnet prefixes are changed, update all three static private addresses as one reviewed change.

## Validate without deploying

### Subscription lifecycle admission

Before ARM validation, the empty `rg-vivolution-sbc-poc-uaenorth` group must
exist in UAE North with exactly these tags: `workload=vivolution-sbc`,
`environment=poc`, `region=uaenorth`, `managedBy=bicep`,
`owner=Vivolution Technologies LLC`, `purpose=SBC proof of concept`, and
`costProfile=monthly-credit-lab`. Its exact monthly budget
`viv-sbc-poc-monthly-usd100` must be active at USD 100 and contain exactly
three enabled `Actual` `GreaterThanOrEqualTo` email notifications at 75%, 90%,
and 100% to the reviewed operator address.

The preserved `rg-vivolution-cp1-uaenorth` group must have the exact
`CanNotDelete` lock `preserve-qualified-cp1-during-poc`, with notes:
`Preserve the qualified CP1 until replacement restore, rollback and cutover
acceptance complete.` Keep this lock until replacement acceptance; do not put
it on the new POC group.

Run the strictly read-only admission guard immediately before validation and
again immediately before create:

```bash
python3 predeploy_guard.py \
  --expected-subscription-id 'a806949c-240f-4541-8c61-fd97f6d1f953' \
  --expected-tenant-id 'efc3bcaa-8879-4366-a452-2b8efa76b16a'
```

The guard rejects a wrong account, tenant, region, tag, budget amount or alert,
missing preservation lock, any lock on the new POC group, any substantive
resource already in that group, any of the nine reserved POC names in the
shared parent DNS zone (regardless of record type), or either delegated ACME
child zone. It emits `POC_PREDEPLOY_GUARD_PASSED` plus an evidence SHA-256 and
contains no create, update, or delete path.

Run these commands from this directory:

```bash
az bicep build --file main.bicep
az bicep lint --file main.bicep
```

Then create a local parameter file and replace every placeholder:

```bash
cp main.example.bicepparam main.bicepparam
```

After signing in to the intended subscription, use Azure validation and What-If before creation:

```bash
az account show --output table
python3 preflight.py main.bicepparam \
  --approved-admin-cidr '<approved-public-ip>/32' \
  --expected-ssh-fingerprint 'SHA256:<approved-fingerprint>'
az deployment group validate \
  --resource-group '<resource-group>' \
  --parameters main.bicepparam
az deployment group what-if \
  --resource-group '<resource-group>' \
  --parameters main.bicepparam
```

The local preflight compiles the Bicep parameters, requires the separately
approved administrator `/32` set and SSH fingerprint, fixes the current
Microsoft Direct Routing CIDRs, and rejects wildcard/broad CIDRs, changed
VM/disk sizes, disabled Trusted Launch, changed Microsoft Media Processor port
ranges, or another SSH key. `SYNTHETIC_PRIVATE` requires all voice peers to be
the fixed CP1 `/32`; `DIRECT_ROUTING` instead requires the fixture off, no
synthetic source, and non-empty globally routable PBX CIDRs no broader than
`/24` for both SBCs.
The focused negative tests are under `tests/`.

Only after reviewing the selected subscription, resource group, parameters, and complete What-If should an authorized operator run:

```bash
az deployment group create \
  --name 'viv-sbc-poc-infra' \
  --resource-group '<resource-group>' \
  --parameters main.bicepparam
```

The VM API can create a generalized marketplace-image OS disk and apply the
Linux `osProfile`, but its `storageProfile.osDisk.managedDisk` contract does not
expose the disk resource's `publicNetworkAccess` or `networkAccessPolicy`
properties. Immediately after the group deployment returns—and before copying
secrets, restoring data, installing services, or running qualification—apply
the exact idempotent disk control:

```bash
python3 lockdown_os_disks.py \
  --expected-subscription-id '<approved-subscription-uuid>'
```

The helper refuses the wrong subscription, resource group, region, missing or
extra disks, wrong VM attachment, or a failed postcondition. It updates only
`viv-sbc-poc-{cp1,sbc1,sbc2}-osdisk`, then requires
`publicNetworkAccess=Disabled`, `networkAccessPolicy=DenyAll`, and
`provisioningState=Succeeded` plus the exact common/node ownership tags on all
three. Do not treat the infrastructure as qualified between VM creation and
this bounded remediation.

This is a resource-group-scoped template. Resource-group creation, budget alerts, and deletion remain explicit subscription-level operator actions.

After the three VM identities and static addresses exist, compile and review the
separate DNS/RBAC deployment. Lego removes an entire TXT record set after each
DNS-01 challenge, so record-scoped RBAC would be deleted or orphaned with that
ephemeral resource. The deployment instead creates one delegated ACME child
zone per SBC, points the public `_acme-challenge.sbcN` name to the isolated zone
with CNAME, and grants that node Reader plus DNS Zone Contributor only on its
own durable child zone. Challenge TXT records may then be deleted and recreated
without losing renewal authority. No VM can write the parent zone or the other
node's ACME zone, and no Azure client secret is stored on an Edge node. The two
small extra public DNS zones add roughly USD 1/month combined before queries.
Each child zone also has a `CanNotDelete` management lock: the deployment owner
must explicitly remove that lock during the bounded POC teardown, while the
Edge identity can continue updating challenge records.

```bash
az bicep build --file dns-acme.bicep
az bicep lint --file dns-acme.bicep
az deployment sub validate \
  --location uaenorth \
  --parameters dns-acme.bicepparam
az deployment sub what-if \
  --location uaenorth \
  --parameters dns-acme.bicepparam
```

## Bounded DNS/ACME teardown

Run the DNS teardown **before** deleting the core POC resource group. The
helper `teardown_dns_acme.py` defaults to read-only `plan` mode and never deletes `DNS_Zones`,
`voice.vivolution.ae`, `controller.voice.vivolution.ae`,
or any unrecognized record or zone. It is hard-bound to the reviewed
subscription, tenant, POC resource-group name/location, shared DNS
resource-group name, parent-zone name, child-zone names, ownership tags,
management-lock contract, RBAC roles/principals, record values, and child-zone
contents.

Copy the three public addresses and two managed-identity principal IDs from the
reviewed core deployment/DNS parameter evidence. First generate a plan:

```bash
python3 teardown_dns_acme.py \
  --expected-subscription-id 'a806949c-240f-4541-8c61-fd97f6d1f953' \
  --expected-tenant-id 'efc3bcaa-8879-4366-a452-2b8efa76b16a' \
  --expected-cp1-public-ipv4 '<reviewed-cp1-public-ipv4>' \
  --expected-sbc1-public-ipv4 '<reviewed-sbc1-public-ipv4>' \
  --expected-sbc2-public-ipv4 '<reviewed-sbc2-public-ipv4>' \
  --expected-sbc1-principal-id '<reviewed-sbc1-principal-uuid>' \
  --expected-sbc2-principal-id '<reviewed-sbc2-principal-uuid>'
```

Review every entry in `actions` and retain the emitted `planSha256`. Applying
requires the same inputs, an exact plan digest, and the fixed destructive
confirmation phrase. The helper re-reads and revalidates Azure immediately
before the first deletion, binds DNS deletions to their observed ETags, and
revalidates the full remaining state before deleting either child zone. Any
intervening change therefore invalidates approval:

```bash
python3 teardown_dns_acme.py \
  --mode apply \
  --expected-subscription-id 'a806949c-240f-4541-8c61-fd97f6d1f953' \
  --expected-tenant-id 'efc3bcaa-8879-4366-a452-2b8efa76b16a' \
  --expected-cp1-public-ipv4 '<reviewed-cp1-public-ipv4>' \
  --expected-sbc1-public-ipv4 '<reviewed-sbc1-public-ipv4>' \
  --expected-sbc2-public-ipv4 '<reviewed-sbc2-public-ipv4>' \
  --expected-sbc1-principal-id '<reviewed-sbc1-principal-uuid>' \
  --expected-sbc2-principal-id '<reviewed-sbc2-principal-uuid>' \
  --approved-plan-sha256 '<planSha256-from-immediately-preceding-plan>' \
  --confirmation 'DELETE-VIVOLUTION-SBC-POC-ACME-DNS'
```

The ordered deletion removes the nine exact POC parent record sets first,
then each exact child-zone lock, the node's two direct role assignments, and
finally the tagged child zone. A final read-only discovery must prove that no
target remains. If execution is interrupted, rerun plan mode and approve the
new digest for only the validated remainder. The helper accepts an already
absent expected target for this recovery path, but rejects altered values,
unexpected direct RBAC/locks, extra child-zone records, or a delegation whose
child zone has disappeared and can no longer prove its authoritative servers.

## Bounded core POC teardown

DNS/ACME teardown must run first and finish with no reserved POC parent name or
delegated child zone remaining. Azure-deallocate all three POC VMs—not merely
stop their guest operating systems—then generate the core teardown plan:

```bash
python3 teardown_core_poc.py \
  --expected-subscription-id 'a806949c-240f-4541-8c61-fd97f6d1f953' \
  --expected-tenant-id 'efc3bcaa-8879-4366-a452-2b8efa76b16a'
```

Plan mode is the default and is read-only. It requires the USD 100 budget,
preserved-CP1 lock, complete DNS cleanup, no lock on the POC group, exactly 17
tagged resources (VNet, Edge availability set, and five resources for each of
CP1/SBC1/SBC2), exact OS-disk-to-VM attachment, and
`PowerState/deallocated` for all three VMs. Review the single action and retain
its `planSha256`; any missing, extra, renamed, retagged, reattached, or powered
resource rejects the plan.

Apply only the immediately preceding plan:

```bash
python3 teardown_core_poc.py \
  --mode apply \
  --expected-subscription-id 'a806949c-240f-4541-8c61-fd97f6d1f953' \
  --expected-tenant-id 'efc3bcaa-8879-4366-a452-2b8efa76b16a' \
  --approved-plan-sha256 '<planSha256-from-immediately-preceding-plan>' \
  --confirmation 'DELETE-VIVOLUTION-SBC-POC-RESOURCE-GROUP'
```

The helper revalidates the complete plan immediately before its sole mutation,
can target only `rg-vivolution-sbc-poc-uaenorth`, waits for deletion, then
proves that group is absent while `rg-vivolution-cp1-uaenorth` and `DNS_Zones`
still exist, the CP1 lock remains exact, and the POC DNS names remain absent.
It has no command path capable of deleting either protected group or the shared
parent zone. An already absent POC group is an idempotent zero-action result.

## Security and operating boundary

- Password authentication is disabled in the VM model; the template accepts only an SSH public key.
- Trusted Launch, Secure Boot, vTPM, boot diagnostics, and the Azure Linux VM Agent are enabled by default. Set `enableTrustedLaunch` to `false` only after confirming that a chosen low-cost SKU does not support it and recording the exception.
- Managed identities receive no Azure role assignment from the core template.
  The separately reviewed `dns-acme.bicep` grants each identity access only to
  its own delegated ACME child zone as described above.

That deployment also creates the isolated `cp1-poc.voice.vivolution.ae` A
record for replacement-controller HTTPS qualification. It deliberately does
not modify the active `controller.voice.vivolution.ae` record; that record is
changed only after restore and acceptance, preserving the existing console
during the build.
- The NSGs are an outer control, not a host hardening replacement. Debian nftables, SSH hardening, patching, service binding, SIP flood controls, and certificate policy must be applied by the configuration-management layer.
- Each Edge NSG overrides Azure's permissive built-in outbound defaults with an exact priority-4096 deny. The preceding rules catalogue Debian update, ACME/Azure API, DNS, fixed NTP, Azure platform, CP1 control-plane, and profile-specific voice dependencies. The host nftables policy independently enforces the same bounded contract.
- The template emits resource names, assigned public/private IP addresses, and managed-identity principal IDs only. It does not output the SSH key, source CIDRs, tenant data, or credentials.

## Cost and capacity boundary

The initial D2as-v5 + two-B2als-v2 shape exceeds the USD 100 credit if all three VMs run continuously for a full month. It is affordable for a short qualification window: Azure-deallocate SBC2 outside the final HA tests, deallocate both Edge nodes when voice testing stops, and resize CP1 only after the smaller target passes the full controller suite. Disks and static IPv4 addresses continue billing while VMs are deallocated. Configure alerts at USD 75 and USD 90 and review actual cost daily.

B-series Edge CPU credits and 4 GiB RAM are suitable only for a low-call-volume functional POC. They are not evidence for production capacity, call quality under load, or an SLA. Resize either SBC if qualification shows memory pressure or depleted CPU credits.

## What this scaffold does not deliver

This directory provisions infrastructure only. The repository's separate
deployment layers install CP1, PostgreSQL, PgBouncer, Caddy, OpenSIPS,
RTPengine, the signed Edge runtime, certificates, host firewall policy, public
DNS, first-tenant routes, and the private test PBX/Teams fixture. Running this
Bicep template alone does none of that. Microsoft 365 Direct Routing changes
also remain a separate exact-acknowledgement workflow and cannot run until its
domain, license, user, number, and support-boundary prerequisites pass.
