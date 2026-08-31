# CP1 carrier NSG overlay

This package adds the only two CP1 inbound rules needed by the bounded
generation-3 private-PBX Direct Routing POC. It does not change the ordinary
three-node template, any SBC NSG, a VM, DNS, or a subnet.

The two child rules on the existing `viv-sbc-poc-cp1-nsg` are exact:

- priority 320: TCP from `10.20.2.6/32` and `10.20.2.7/32` to
  `10.20.1.4/32:5061`;
- priority 330: UDP source ports `20000-20255` from those same two /32s to
  `10.20.1.4/32:30000-30127`.

All other traffic continues to meet the existing priority-4096 inbound deny.
The base CP1 rules at priorities 100, 200, 210, 300, 310, and 4096 remain
unchanged, which preserves the generation-2 synthetic fixture path.

## Safety boundary

`main.bicep` and `preflight.py` remain permanently limited to
`SYNTHETIC_PRIVATE` and `DIRECT_ROUTING`. Do not deploy `main.bicep` while this
overlay exists: its module owns the complete CP1 rule array and a redeployment
could remove these independently managed child rules. This is an explicit
temporary redeploy freeze, not shared ownership.

The guard refuses unless it proves:

- the exact enabled Azure subscription and tenant, UAE North resource group,
  CP1 VM-to-NIC-to-static-`10.20.1.4` binding, and CP1 NSG attachment;
- both generation-3 VM-to-NIC bindings at static `10.20.2.6` and `.7`, with
  their profile/generation tags and the required power state;
- both generation-2 VMs running, their fixed `.4` and `.5` identities, and
  every byte of their 17-rule synthetic NSG contracts;
- the exact six-rule CP1 synthetic base policy and either no overlay or both
  exact overlay rules—never a partial or extra-rule state;
- the exact USD 100 budget, 75/90/100 alerts, and month-to-date spend not over
  budget (the overlay itself adds USD 0.00 of metered resources);
- pinned Bicep compiler, compiled template, and compiled parameter digests;
- for apply, a fresh Provider-level What-If containing only the two child-rule
  `Create` or `NoChange` results.

No plan mutates Azure. Execution re-observes the complete protected state and
What-If, compares it with the saved plan, deploys only through the provider,
then proves the exact postcondition. A plan is valid for ten minutes and its
SHA-256 and confirmation phrase are separate mandatory inputs.

## Apply

Use the pinned Bicep CLI already installed on the deployment runner. Save the
single-line plan only at the ignored protected path expected by the guard:

```bash
umask 077
/opt/homebrew/bin/python3.13 infra/azure-poc/cp1_carrier_nsg_overlay.py plan --action apply \
  > deploy/.state/cp1-carrier-nsg-overlay-plan.json
chmod 0600 deploy/.state/cp1-carrier-nsg-overlay-plan.json
```

Review the complete JSON. Then supply its exact `planSha256`:

```bash
/opt/homebrew/bin/python3.13 infra/azure-poc/cp1_carrier_nsg_overlay.py execute \
  --plan deploy/.state/cp1-carrier-nsg-overlay-plan.json \
  --plan-sha256 REPLACE_WITH_REVIEWED_PLAN_SHA256 \
  --confirm APPLY-VIVOLUTION-CP1-CARRIER-NSG-OVERLAY
```

The only accepted success marker is
`CP1_CARRIER_NSG_OVERLAY_APPLIED` with `overlayState` equal to `EXACT`.

## Guarded teardown and rollback

Teardown is intentionally unavailable while either generation-3 VM is
running. First deallocate both generation-3 VMs. Keep CP1 and both generation-2
VMs running, then run the existing outbound and inbound synthetic fixture
calls through SBC1 and SBC2. This proves the old path is independent before
removing carrier ingress.

Generate and review a new teardown plan:

```bash
umask 077
/opt/homebrew/bin/python3.13 infra/azure-poc/cp1_carrier_nsg_overlay.py plan --action teardown \
  > deploy/.state/cp1-carrier-nsg-overlay-plan.json
chmod 0600 deploy/.state/cp1-carrier-nsg-overlay-plan.json

/opt/homebrew/bin/python3.13 infra/azure-poc/cp1_carrier_nsg_overlay.py execute \
  --plan deploy/.state/cp1-carrier-nsg-overlay-plan.json \
  --plan-sha256 REPLACE_WITH_REVIEWED_PLAN_SHA256 \
  --confirm TEARDOWN-VIVOLUTION-CP1-CARRIER-NSG-OVERLAY
```

Deletion uses each exact planned child-rule ETag. An interrupted teardown can
resume from the same still-fresh plan only when the remaining child rule and
ETag are unchanged. Success requires `CP1_CARRIER_NSG_OVERLAY_REMOVED` and a
fresh observation of the original six-rule CP1 policy.

After teardown, rerun both generation-2 synthetic calls while generation 3
remains deallocated. Record that evidence before lifting the `main.bicep`
redeploy freeze. Do not claim Teams/PSTN or active-call migration from this
rollback test.
