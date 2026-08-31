# Direct Routing generation-3 Edge replacement IaC

This package defines two new, parallel Azure Edge VMs for the bounded Vivolution Direct Routing POC. It does not deploy CP1, change the VNet, modify the Edge subnet or availability set, rename DNS records, or delete/deallocate the active generation-2 synthetic SBCs.

No Azure deployment or query was performed while producing this package.

## Fixed topology

- Subscription: `a806949c-240f-4541-8c61-fd97f6d1f953`
- Resource group: `rg-vivolution-sbc-poc-uaenorth`
- Existing VNet/subnet: `viv-sbc-poc-vnet` (`10.20.0.0/16`) / `snet-edge` (`10.20.2.0/24`)
- Existing availability set: `viv-sbc-poc-edge-as`, Aligned, UAE North, 2 fault domains and 5 update domains
- SBC1 replacement: `viv-sbc-dr-sbc1-g3`, `10.20.2.6`
- SBC2 replacement: `viv-sbc-dr-sbc2-g3`, `10.20.2.7`
- Both nodes: Debian 13 Gen2, `Standard_B2als_v2`, 32 GiB Standard SSD, Trusted Launch, Secure Boot, vTPM, system-assigned identity, static Standard public IPv4
- Runtime authority: generation `3`, profile `DIRECT_ROUTING_PRIVATE_PBX_POC`

This distinct signed mode is the only authority for the private carrier/PBX wire contract below. Production `DIRECT_ROUTING` remains global-PBX only and must not be used with private CP1 address `10.20.1.4`.

The subscription-scoped template places both modules into the exact existing resource group. The VNet, subnet, and availability set are `existing` references. Resource names and private addresses are distinct from `viv-sbc-poc-sbc1` (`10.20.2.4`) and `viv-sbc-poc-sbc2` (`10.20.2.5`). An incremental deployment therefore adds replacement resources without targeting either synthetic VM.

## Network contract

Each replacement has a dedicated NIC NSG. Every nonlisted flow is rejected by explicit priority-4096 inbound and outbound denies.

Inbound allows only:

- SSH/TCP 22 from one to four separately approved public administrator `/32` prefixes.
- Microsoft Direct Routing TLS/TCP 5061 from the reviewed `52.112.0.0/14` and `52.120.0.0/14` sets.
- Microsoft UDP media from source ports `3478-3481` and `49152-53247` to the local RTPengine pool `20000-29999`.
- CP1 carrier/fixture TLS from the exact same-VNet private prefix `10.20.1.4/32` to the local PBX listener TCP 15061.
- CP1 carrier-gateway UDP media from source range `30000-30127` to the first-tenant local allocation `20000-20255`.

Outbound allows only:

- Azure DHCP, platform DNS (UDP/TCP 53), WireServer, and IMDS at their fixed platform addresses and ports.
- UDP 123 to the two fixed NTP anycast `/32` prefixes used by the Edge role.
- TCP 80/443 to Internet for Debian package retrieval, pinned artifacts, ACME, and Azure DNS API access.
- TCP 443 to private CP1 `10.20.1.4/32`.
- Microsoft TLS/TCP 5061 and first-tenant UDP media to the reviewed Microsoft CIDRs and media ports.
- Carrier/fixture TLS/TCP 5061 and UDP `30000-30127` to the exact private CP1 prefix `10.20.1.4/32`.

The carrier name remains `carrier.vivolution.ae` for certificate/SNI verification, but the replacement Edge runtime must resolve it to `10.20.1.4`. The activation gate must prove that exact private resolution and route before a call. The NSGs contain no CP1 public prefix and intentionally forbid a same-VNet public-IP hairpin.

The Microsoft CIDRs and ports were reviewed against the project’s current Direct Routing authority on 2026-08-31. Recheck the Microsoft documentation immediately before deployment. Any change requires a source review, tests, and a deliberate compiled-template digest re-pin.

## Files

- `direct-replacement.bicep` — exact, additive replacement topology and NSGs.
- `direct-replacement.example.bicepparam` — deliberately nondeployable placeholders plus all fixed parameters.
- `direct-replacement-preflight.py` — offline package guard plus read-only Azure topology, budget, provider, partial-resume, and what-if plan gate.
- `tests/test_direct_replacement.py` — fail-closed parameter, compiler/digest, topology, and NSG tests.

The existing `modules/linux-node.bicep` is reused. It provides the Standard static IPv4, NIC/NSG, managed disk, Trusted Launch VM, password-disabled ED25519 access, and managed identity. This package does not alter that shared module.

## Offline validation

Use Bicep CLI `0.46.1`. The preflight pins the exact compiled ARM template produced by that reviewed compiler; another version or any source drift is rejected until reviewed and re-pinned.

```bash
cd "/Users/jay/Projects/Active/Vivolution SBC"

az bicep lint \
  --file infra/azure-poc/direct-replacement.bicep

az bicep build \
  --file infra/azure-poc/direct-replacement.bicep \
  --stdout >/dev/null

az bicep build-params \
  --file infra/azure-poc/direct-replacement.example.bicepparam \
  --stdout >/dev/null

python3 -m unittest -v \
  infra/azure-poc/tests/test_direct_replacement.py
```

The example parameter file is supposed to compile but fail admission because it contains documentation IPs and no real ED25519 key.

## Prepare the adjacent protected parameter file

The Bicep `using './direct-replacement.bicep'` path is resolved relative to the parameter file. Therefore the real file must remain adjacent to the template, under the already reviewed `*.local.bicepparam` ignore rule. A copy under `deploy/.state/` is invalid because it resolves `using` against the wrong directory.

```bash
cp infra/azure-poc/direct-replacement.example.bicepparam \
  infra/azure-poc/direct-replacement.local.bicepparam
chmod 0600 infra/azure-poc/direct-replacement.local.bicepparam
```

Change only:

1. `administratorSourcePrefixes` to the separately verified current administrator public `/32` set.
2. `sshPublicKey` to the already approved single-line ED25519 public key. Never store a private key in a Bicep parameter file.
3. `parallelAcceptanceDeadlineUtc` once, to a canonical future UTC timestamp no more than 72 hours away. This deadline is compiled into the parameter digest and every replacement resource tag; never extend it after create begins.

Do not change `cp1PrivatePrefix`; it is fixed to `10.20.1.4/32`.

Then run the compiled-package guard with independently obtained expectations:

```bash
python3 infra/azure-poc/direct-replacement-preflight.py \
  infra/azure-poc/direct-replacement.local.bicepparam \
  --approved-admin-cidr '<ADMIN_IPV4>/32' \
  --expected-ssh-fingerprint 'SHA256:<APPROVED_FINGERPRINT>' \
  >deploy/.state/direct-replacement-preflight.json
```

Success is one canonical JSON object with status `DIRECT_REPLACEMENT_COMPILED_PACKAGE_VALID`. It binds the exact compiled-parameter digest, compiled-template digest, resource group, generation, replacement names/addresses, fixed CP1 private carrier prefix, and SSH public-key fingerprint. It never emits the public key value.

## Required live gates before any create

The offline guard intentionally makes no Azure call. Copy its `compiledParametersSha256` into the read-only live invocation:

```bash
python3 infra/azure-poc/direct-replacement-preflight.py \
  infra/azure-poc/direct-replacement.local.bicepparam \
  --approved-admin-cidr '<ADMIN_IPV4>/32' \
  --expected-ssh-fingerprint 'SHA256:<APPROVED_FINGERPRINT>' \
  --live-plan \
  --expected-subscription-id 'a806949c-240f-4541-8c61-fd97f6d1f953' \
  --expected-tenant-id 'efc3bcaa-8879-4366-a452-2b8efa76b16a' \
  --expected-bicep-version '<OFFLINE_BICEP_COMPILER_VERSION>' \
  --expected-compiled-parameters-sha256 '<OFFLINE_COMPILED_PARAMETER_SHA256>' \
  --expected-compiled-template-sha256 '<OFFLINE_COMPILED_TEMPLATE_SHA256>' \
  >deploy/.state/direct-replacement-live-plan.json
chmod 0400 deploy/.state/direct-replacement-live-plan.json
```

The live plan is read-only and must prove all of the following:

1. The authenticated subscription and tenant are the approved Azure authorities.
2. `Microsoft.Compute` and `Microsoft.Network` are registered, and the subscription what-if runs with provider validation (not template-only validation).
3. The resource group and VNet are exact; the Edge subnet has `defaultOutboundAccess=false`, no subnet NSG, route table, NAT gateway, delegation, service endpoint, private endpoint, or peering.
4. CP1 is healthy on static private `10.20.1.4`, the two predecessors are healthy on `10.20.2.4` and `.5`, and every NIC is statically allocated to its exact subnet, NSG, and public IP. The guard separately reads every NSG and public-IP resource: both must have their exact ID/name/location, `Succeeded` state, exact tags and single NIC/IP-configuration attachment; public IPs must be actual globally routable IPv4 values with Standard/Regional/Static authority.
5. The existing availability set is Aligned in UAE North with exactly 2 fault domains, 5 update domains, the two synthetic predecessors, and any already admitted replacement VMs from a partial run.
6. Each replacement node is either completely vacant or a complete healthy resource set on its exact static `.6`/`.7` address. Fragmented resource sets, collisions, wrong attachments, dynamic/private-IP drift, unhealthy provisioning, or orphan disks are rejected.
7. Any admitted replacement OS disk is either already tagged and network-locked (`publicNetworkAccess=Disabled`, `networkAccessPolicy=DenyAll`) or is an exact newly created attached disk explicitly marked pending for the guarded wrapper.
8. The exact resource-group-scoped USD 100 monthly budget is active, retains 75/90/100 actual-cost alerts, and its own exact USD `currentSpend` leaves at least USD 7.80 for the bounded parallel replacement window. This is project resource-group spend authority only; it does not claim subscription-wide cost or Azure-credit headroom.
9. The compiler, compiled parameter, and compiled template identities match the reviewed offline evidence.
10. Provider-level subscription what-if contains only Create/NoChange/Ignore for the two replacement node sets, their bounded nested deployments, and existing resource IDs already proven exact by the same live observation. Ignore is never accepted for an unknown identity, and Modify/Delete is never accepted for an existing topology authority.

At the create boundary the wrapper recompiles the Bicep package, requires both canonical digests to equal the separately reviewed values, materializes owner-only `0400` ARM template and parameter JSON in a private temporary directory, and submits those exact bytes to Azure. The writable `.bicepparam` and `.bicep` source paths are never passed to the mutating deployment command.

The emitted plan has a fresh `planSha256`; `authorizationExpiresUtc` is exactly the earlier of `observedAtUtc + 15 minutes` and the immutable parameter-bound deadline. Create additionally requires at least 60 minutes of deadline buffer. The plan binds exact runtime authority `{generation: 3, profile: DIRECT_ROUTING_PRIVATE_PBX_POC}`. Generation-2 SBCs remain available through generation-3 install, signed transition, calls, reboot, failover, rollback, and final acceptance. A new plan may refresh only the short create authorization while no replacement exists; once either replacement exists its exact deadline tag must equal the parameter and cannot be silently extended.

## Safe resume after a partial create

The deployment is incremental and uses the fixed name `viv-sbc-direct-replacement-g3`. Rerun the offline guard and live plan against the same protected parameter file and the same compiled-parameter digest. Safe resume admits only node-level partial completion: one whole healthy node may exist while the other remains completely vacant. A fragment within a node is fail-closed for operator reconciliation; the wrapper never guesses whether to adopt it. An exact newly created disk may be pending lockdown, which the same wrapper resumes idempotently. Resume with the same deployment name only after reviewing the new `planSha256`.

## Arm the external generation-3 deadman

Create is forbidden until a fresh receipt proves that one exact, enabled OpenClaw job is durably scheduled on the external Mac Gateway. The job runs at `parallelAcceptanceDeadlineUtc`, deallocates only the exact generation-3 replacement VM IDs if present, and never mutates CP1 or either generation-2 predecessor. Its command uses absolute `/opt/homebrew/bin/python3.13` and embeds the complete plan-bound Python source directly in the scheduler payload; it does not execute a later-mutable file. The source binds the exact bytes and resolved targets of Python, `/opt/homebrew/bin/az`, and `/opt/homebrew/bin/openclaw`, exact subscription/tenant/resource group, plan hash, deadline, protected predecessor IDs, and replacement IDs.

First prepare an optional owner-only review copy and a JSON document containing the exact `openclaw cron add` argv. The sealed file is evidence only; it is not runtime execution authority.

```bash
umask 077
python3 infra/azure-poc/direct-replacement-preflight.py \
  infra/azure-poc/direct-replacement.local.bicepparam \
  --approved-admin-cidr '<ADMIN_IPV4>/32' \
  --expected-ssh-fingerprint 'SHA256:<APPROVED_FINGERPRINT>' \
  --prepare-deadman-bundle-plan deploy/.state/direct-replacement-live-plan.json \
  --deadman-bundle-output deploy/.state/direct-replacement-deadman-sealed.py \
  --approved-plan-sha256 '<REVIEWED_PLAN_SHA256>' \
  --expected-subscription-id 'a806949c-240f-4541-8c61-fd97f6d1f953' \
  --expected-tenant-id 'efc3bcaa-8879-4366-a452-2b8efa76b16a' \
  --expected-bicep-version '<OFFLINE_BICEP_COMPILER_VERSION>' \
  --expected-compiled-parameters-sha256 '<OFFLINE_COMPILED_PARAMETER_SHA256>' \
  --expected-compiled-template-sha256 '<OFFLINE_COMPILED_TEMPLATE_SHA256>' \
  >deploy/.state/direct-replacement-deadman-preparation.json
chmod 0400 deploy/.state/direct-replacement-deadman-preparation.json
```

Review `scheduleCommandArgv`, then execute that exact argv without a shell and retain the returned canonical job ID:

```bash
/opt/homebrew/bin/python3.13 -c \
  'import json,subprocess; d=json.load(open("deploy/.state/direct-replacement-deadman-preparation.json",encoding="utf-8")); subprocess.run(d["scheduleCommandArgv"],check=True)'
```

The generated job is exact: isolated session, one-shot `at` schedule, `--exact`, delete after success, 900-second command limit, 300-second no-output limit, and success/failure announcement through account `default` to `telegram:-1004364314662`. Its embedded program emits secret-free progress, retries transient Azure account/inventory/deallocation/verification failures within an 840-second monotonic budget, and polls for a replacement that appears while a create is crossing the deadline.

While the live plan is still authorized, query that exact job and create the owner-only receipt:

```bash
python3 infra/azure-poc/direct-replacement-preflight.py \
  infra/azure-poc/direct-replacement.local.bicepparam \
  --approved-admin-cidr '<ADMIN_IPV4>/32' \
  --expected-ssh-fingerprint 'SHA256:<APPROVED_FINGERPRINT>' \
  --issue-deadman-scheduler-receipt-plan deploy/.state/direct-replacement-live-plan.json \
  --openclaw-cron-job-id '<CANONICAL_OPENCLAW_JOB_UUID>' \
  --deadman-scheduler-receipt-output deploy/.state/direct-replacement-deadman-scheduler-receipt.json \
  --approved-plan-sha256 '<REVIEWED_PLAN_SHA256>' \
  --expected-subscription-id 'a806949c-240f-4541-8c61-fd97f6d1f953' \
  --expected-tenant-id 'efc3bcaa-8879-4366-a452-2b8efa76b16a' \
  --expected-bicep-version '<OFFLINE_BICEP_COMPILER_VERSION>' \
  --expected-compiled-parameters-sha256 '<OFFLINE_COMPILED_PARAMETER_SHA256>' \
  --expected-compiled-template-sha256 '<OFFLINE_COMPILED_TEMPLATE_SHA256>'
```

The receipt is valid for at most five minutes. It proves the external Gateway identity, scheduler health, exact enabled job JSON, exact schedule, embedded command/program digests, delivery target, plan/deadline/subscription/tenant, and both protected and replacement VM ID sets. A fabricated receipt or missing, disabled, edited, stale, already-run, running, or rescheduled job is rejected.

Important residual: OpenClaw runs this local job only while the Mac Gateway is available. If the Mac is sleeping/offline at the deadline, the overdue job runs only when the Gateway restarts; there is no Azure-side redundant scheduler in this bounded POC. Keep the Mac powered and Gateway healthy, and choose a deadline shorter than the 72-hour maximum when practical so manual recovery remains inside the cost window.

## Guarded deployment sequence (not executed here)

After the live gates and deadman receipt pass, retain the reviewed `planSha256`, make the exact reviewed parameter bytes read-only with `chmod 0400 infra/azure-poc/direct-replacement.local.bicepparam`, and invoke only the guarded wrapper before both `authorizationExpiresUtc` and the receipt freshness limit:

```bash
python3 infra/azure-poc/direct-replacement-preflight.py \
  infra/azure-poc/direct-replacement.local.bicepparam \
  --approved-admin-cidr '<ADMIN_IPV4>/32' \
  --expected-ssh-fingerprint 'SHA256:<APPROVED_FINGERPRINT>' \
  --apply-plan deploy/.state/direct-replacement-live-plan.json \
  --approved-plan-sha256 '<REVIEWED_PLAN_SHA256>' \
  --expected-subscription-id 'a806949c-240f-4541-8c61-fd97f6d1f953' \
  --expected-tenant-id 'efc3bcaa-8879-4366-a452-2b8efa76b16a' \
  --expected-bicep-version '<OFFLINE_BICEP_COMPILER_VERSION>' \
  --expected-compiled-parameters-sha256 '<OFFLINE_COMPILED_PARAMETER_SHA256>' \
  --expected-compiled-template-sha256 '<OFFLINE_COMPILED_TEMPLATE_SHA256>' \
  --deadman-scheduler-receipt deploy/.state/direct-replacement-deadman-scheduler-receipt.json \
  --confirm-with-what-if
```

The wrapper revalidates the saved plan hash, exact authorization expiry, immutable deadline, 60-minute buffer, subscription, tenant, compiler, template, parameters, topology, actual NSG/public-IP bindings, and provider what-if. It also re-queries the live enabled OpenClaw job when apply begins and again immediately before Azure mutation, closing the receipt-to-create race. The entire interactive `az deployment sub create` command—not merely its invocation—must finish at least 120 seconds before the short authorization expires. On timeout the wrapper kills the CLI, issues an exact subscription-deployment cancellation, and refuses to return until the deployment is absent or terminal; the deadman remains armed for any exact partial replacement. At the Azure prompt, proceed immediately and only when it still shows the same two replacement node sets. The wrapper then proves both complete nodes, locks and ownership-tags their exact attached OS disks, and fails unless both disks finish with `publicNetworkAccess=Disabled` and `networkAccessPolicy=DenyAll`.

If create crosses the immutable deadline, the deadman may already have deallocated the replacement VMs. Apply deliberately accepts that exact deallocated state long enough to finish disk lockdown. If the runner or SSH dies after create but before lockdown, the post-deadline recovery mode can never deploy or start a VM; it requires both exact replacements to exist, permits their deallocated state, requires a no-Create what-if, and only locks/tags their disks:

```bash
python3 infra/azure-poc/direct-replacement-preflight.py \
  infra/azure-poc/direct-replacement.local.bicepparam \
  --approved-admin-cidr '<ADMIN_IPV4>/32' \
  --expected-ssh-fingerprint 'SHA256:<APPROVED_FINGERPRINT>' \
  --recover-disk-lockdown-plan deploy/.state/direct-replacement-live-plan.json \
  --approved-plan-sha256 '<REVIEWED_PLAN_SHA256>' \
  --expected-subscription-id 'a806949c-240f-4541-8c61-fd97f6d1f953' \
  --expected-tenant-id 'efc3bcaa-8879-4366-a452-2b8efa76b16a' \
  --expected-bicep-version '<OFFLINE_BICEP_COMPILER_VERSION>' \
  --expected-compiled-parameters-sha256 '<OFFLINE_COMPILED_PARAMETER_SHA256>' \
  --expected-compiled-template-sha256 '<OFFLINE_COMPILED_TEMPLATE_SHA256>' \
  --confirm-disk-lockdown-recovery
```

Direct `az deployment sub create` is outside this contract. Never add `--no-prompt`, never use complete mode, and never accept Delete/Modify/Unsupported against existing resources.

## Final acceptance and mandatory deadman disarm receipt

The deadline job protects service continuity: if acceptance is incomplete it deallocates generation 3 and leaves generation 2 running. It is not authority to deallocate predecessors. The qualified final-acceptance workflow must finish with a safe margin before the deadline, prove generation 3 accepted, then deallocate both exact generation-2 predecessors. Immediately afterward it must disable the exact job ID, query it again, and retain the owner-only disabled job JSON as the mandatory disarm receipt. That receipt must show `enabled=false` and still bind the same UUID, declaration key/plan hash, embedded command, deadline, and notification delivery before the job may be removed. If the workflow cannot complete this sequence before the deadline, it must leave generation 2 running and must not claim final cutover.

```bash
/opt/homebrew/bin/openclaw cron disable '<CANONICAL_OPENCLAW_JOB_UUID>'
umask 077
/opt/homebrew/bin/openclaw cron get '<CANONICAL_OPENCLAW_JOB_UUID>' \
  >deploy/.state/direct-replacement-deadman-disarm-receipt.json
chmod 0400 deploy/.state/direct-replacement-deadman-disarm-receipt.json
```

Never extend the immutable deadline. If the deadline job fires, re-enable/restart generation 3 only under a new reviewed operating decision after confirming generation 2 remains available.

VM creation is followed by the project’s replacement Edge install/transition playbooks and the exact private `carrier.vivolution.ae` resolution gate. DNS cutover, M365 gateway changes, Twilio configuration, and billable PSTN calls remain separate controlled phases.
