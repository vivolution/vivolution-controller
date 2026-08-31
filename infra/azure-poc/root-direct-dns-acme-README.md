# Root Direct Routing DNS and ACME authority

This package is the additive public-DNS authority for the bounded
`DIRECT_ROUTING_PRIVATE_PBX_POC` generation-3 fleet. It is deliberately
separate from the synthetic `voice.vivolution.ae` authority.

It owns only these root record sets in the existing public `vivolution.ae`
zone:

- `sbc1`, `sbc2`, and `carrier` A records, with TTL 60 and one reviewed static
  IPv4 each;
- `acme-sbc1`, `acme-sbc2`, and `acme-carrier` NS delegations, with TTL 3600;
- `_acme-challenge.sbc1`, `_acme-challenge.sbc2`, and
  `_acme-challenge.carrier` CNAME aliases into the isolated child zones.

There are no wildcard records. The three child zones are
`acme-sbc1.vivolution.ae`, `acme-sbc2.vivolution.ae`, and
`acme-carrier.vivolution.ae`. Each has the exact profile ownership tags and
only Azure's apex NS/SOA records plus a temporary `_acme-challenge` TXT set.
Each generation-3 SBC identity receives the dedicated TXT-only custom role on
its own zone; the CP1 identity receives it only on the carrier zone. The role
cannot change/delete a zone, mutate the root, or touch any non-TXT record.
Child-zone locks are forbidden because an inherited `CanNotDelete` lock would
also prevent Lego from deleting its challenge.

The package never creates, replaces, updates, or deletes the shared DNS
resource group, the root zone, unrelated root records, `voice.vivolution.ae`,
or either `acme-sbcN.voice.vivolution.ae` zone. Discovery fingerprints all
unrelated root record metadata and every record in those three preserved voice
zones. An apply refuses if that preservation evidence changes.

## Protected create plan and provider review

There is no direct deployment runbook. Create the exact owner-only parameter
file at `deploy/.state/root-direct-dns-acme.bicepparam` from the example, set
mode `0600`, and populate it only with the accepted generation-3 PIP addresses
and managed identities plus the current CP1 PIP and identity. Do not use
generation-2 SBC addresses or principals. Azure-deallocate CP1 and both g3
SBCs before planning so no ACME client can race authority creation.

From the project root, run the guarded planner with the same eight reviewed
bindings used by reconciliation:

```bash
python3 infra/azure-poc/deploy_root_direct_dns_acme.py plan \
  --expected-subscription-id a806949c-240f-4541-8c61-fd97f6d1f953 \
  --expected-tenant-id efc3bcaa-8879-4366-a452-2b8efa76b16a \
  --expected-carrier-public-ipv4 '<reviewed-current-cp1-ip>' \
  --expected-sbc1-public-ipv4 '<reviewed-g3-sbc1-ip>' \
  --expected-sbc2-public-ipv4 '<reviewed-g3-sbc2-ip>' \
  --expected-cp1-principal-id '<reviewed-cp1-principal>' \
  --expected-sbc1-principal-id '<reviewed-g3-sbc1-principal>' \
  --expected-sbc2-principal-id '<reviewed-g3-sbc2-principal>'
```

The planner recompiles and hashes the exact template and parameters, proves
the reserved root names are vacant for an initial create, fingerprints the
root and all preserved voice authority with ETags, inventories descendant and
Group RBAC, and requires a provider-level What-If containing exactly the 16
owned resources. It atomically writes the owner-only plan to
`deploy/.state/root-direct-dns-acme-create-plan.json`; the plan expires after
ten minutes. Review its resource state, normalized What-If and `planSha256`,
then execute only that plan:

```bash
python3 infra/azure-poc/deploy_root_direct_dns_acme.py execute \
  --plan-sha256 '<fresh-plan-sha256>' \
  --confirmation APPLY-VIVOLUTION-ROOT-DIRECT-DNS-ACME-AUTHORITY
```

Apply recompiles and reobserves everything before mutation, then proves the
exact complete postcondition. If the provider or runner stops, rerun plan
mode. A partial state is accepted only when every present owned object is
exact and the prior deployment record is bound to the same parameters. The
same exact partial state can instead be removed through the bounded teardown
workflow below. Never bypass the wrapper.

## Fail-closed authority reconciliation

The read-only default plan verifies the exact subscription/tenant, DNS groups,
root and preserved voice zones, all root values and ETags, exact child tags and
contents, zero locks, the dedicated role definition, exactly three role uses,
and no Group, other-principal, or record-descendant assignment,
the CP1/g3 VM identities, and each public address through its exact VM → NIC →
static Standard PIP attachment.

```bash
python3 reconcile_root_direct_dns_acme_authority.py \
  --expected-subscription-id a806949c-240f-4541-8c61-fd97f6d1f953 \
  --expected-tenant-id efc3bcaa-8879-4366-a452-2b8efa76b16a \
  --expected-carrier-public-ipv4 '<reviewed-current-cp1-ip>' \
  --expected-sbc1-public-ipv4 '<reviewed-g3-sbc1-ip>' \
  --expected-sbc2-public-ipv4 '<reviewed-g3-sbc2-ip>' \
  --expected-cp1-principal-id '<reviewed-cp1-principal>' \
  --expected-sbc1-principal-id '<reviewed-g3-sbc1-principal>' \
  --expected-sbc2-principal-id '<reviewed-g3-sbc2-principal>'
```

The qualified final status is
`ROOT_DIRECT_DNS_ACME_AUTHORITY_RECONCILED`, with zero actions. A stale
challenge produces only ETag-bound `DELETE_STALE_ACME_CHALLENGE_TXT` actions.
Before applying such a plan, Azure-deallocate the exact CP1 and both g3 VMs so
no ACME client can race cleanup. Review `actions` and retain `planSha256`, then
apply the fresh plan:

```bash
python3 reconcile_root_direct_dns_acme_authority.py \
  --mode apply \
  --expected-subscription-id a806949c-240f-4541-8c61-fd97f6d1f953 \
  --expected-tenant-id efc3bcaa-8879-4366-a452-2b8efa76b16a \
  --expected-carrier-public-ipv4 '<reviewed-current-cp1-ip>' \
  --expected-sbc1-public-ipv4 '<reviewed-g3-sbc1-ip>' \
  --expected-sbc2-public-ipv4 '<reviewed-g3-sbc2-ip>' \
  --expected-cp1-principal-id '<reviewed-cp1-principal>' \
  --expected-sbc1-principal-id '<reviewed-g3-sbc1-principal>' \
  --expected-sbc2-principal-id '<reviewed-g3-sbc2-principal>' \
  --approved-plan-sha256 '<fresh-plan-sha256>' \
  --confirmation RECONCILE-VIVOLUTION-ROOT-DIRECT-DNS-ACME-AUTHORITY
```

Every deletion is preceded by full rediscovery and exact remaining-action
suffix comparison. If an ETag changes or execution stops, rerun plan mode,
review the smaller plan and approve its new digest. Restart the VMs only after
the no-action reconciled status.

## Qualification inventory boundary

For this profile the protected controller inventory must define exactly:

```yaml
cp_azure_poc_direct_replacement_runtime_profile: DIRECT_ROUTING_PRIVATE_PBX_POC
cp_azure_poc_direct_dns_resource_group: DNS_Zones
cp_azure_poc_direct_dns_parent_zone: vivolution.ae
cp_azure_poc_direct_certificate_fqdns:
  - sbc1.vivolution.ae
  - sbc2.vivolution.ae
  - carrier.vivolution.ae
cp_azure_poc_direct_acme_child_zones:
  - acme-sbc1.vivolution.ae
  - acme-sbc2.vivolution.ae
  - acme-carrier.vivolution.ae
cp_azure_poc_direct_replacement_vm_names:
  - viv-sbc-dr-sbc1-g3
  - viv-sbc-dr-sbc2-g3
cp_azure_poc_direct_replacement_public_ip_names:
  - viv-sbc-dr-sbc1-g3-pip
  - viv-sbc-dr-sbc2-g3-pip
cp_azure_poc_direct_acme_role_definition_guid: c5498bfb-a31f-40dd-b636-0f53e530ed53
```

`cp_azure_poc_edge_runtime_profile` remains `SYNTHETIC_PRIVATE` for the
preserved generation-2 rollback fleet. The qualifier continues to prove that
fleet's legacy voice ACME authority, and independently uses the root plan only
to satisfy `cp_azure_poc_direct_replacement_runtime_profile`. Legacy voice
evidence therefore cannot satisfy the g3 root-DNS gate. The qualifier re-reads
the g3 VM principals and PIPs and passes those plus CP1's live
identity/address into the independent contract.

## Bounded teardown

Run teardown before deleting any g3 or CP1 VM. All three must be
Azure-deallocated. The default plan accepts a valid complete authority or any
exact partial create/teardown state whose present resources retain their full
values, ETags, tags and RBAC boundary. It orders stale TXT,
root CNAME/NS/A, role assignment, child-zone, then dedicated-role deletion.
Root/child DNS deletions carry their observed ETags. The root/shared group and
all preserved voice authority remain non-targets.

```bash
python3 teardown_root_direct_dns_acme.py \
  --expected-subscription-id a806949c-240f-4541-8c61-fd97f6d1f953 \
  --expected-tenant-id efc3bcaa-8879-4366-a452-2b8efa76b16a \
  --expected-carrier-public-ipv4 '<reviewed-current-cp1-ip>' \
  --expected-sbc1-public-ipv4 '<reviewed-g3-sbc1-ip>' \
  --expected-sbc2-public-ipv4 '<reviewed-g3-sbc2-ip>' \
  --expected-cp1-principal-id '<reviewed-cp1-principal>' \
  --expected-sbc1-principal-id '<reviewed-g3-sbc1-principal>' \
  --expected-sbc2-principal-id '<reviewed-g3-sbc2-principal>'
```

Review the plan and apply with the same inputs plus:

```text
--mode apply
--approved-plan-sha256 <fresh-plan-sha256>
--confirmation DELETE-VIVOLUTION-ROOT-DIRECT-DNS-ACME-AUTHORITY
```

If interrupted, rerun plan mode and approve only the new remaining suffix. The
terminal read-only status is `ROOT_DIRECT_DNS_ACME_AUTHORITY_ABSENT`.
