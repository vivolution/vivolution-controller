# CP1 carrier NSG overlay

This package adds an exact default-deny CP1 child-rule overlay for the bounded
generation-3 private-PBX Direct Routing POC. The reviewed disabled mode has 14
rules. The reviewed enabled mode has 17 and adds exactly three Twilio rules.
It does not change the ordinary three-node template, any SBC NSG, a VM, DNS,
or a subnet.

The child rules on the existing `viv-sbc-poc-cp1-nsg` are exact:

- priority 320: TCP from `10.20.2.6/32` and `10.20.2.7/32` to
  `10.20.1.4/32:5061`;
- priority 330: UDP source ports `20000-20255` from those same two /32s to
  `10.20.1.4/32:30000-30127`;
- priorities 1000-1060: CP1's required DHCP, Azure DNS, WireServer, IMDS,
  resolver-selected UDP/123 time, and TCP 80/443 package/ACME/Azure API flows;
- priorities 1100-1110: the preserved generation-2 synthetic fixture signaling
  and both exact fixture media allocations to `10.20.2.4/32` and `.5/32`;
- priorities 1120-1130: carrier signaling and media from CP1 to the exact
  generation-3 `.6/32` and `.7/32` allocations;
- priority 4096: an explicit outbound deny, preventing Azure's default
  `AllowInternetOutbound` from bypassing this catalogue.

Only enabled mode also emits:

- priority 340: inbound SRTP from Twilio's global `168.86.128.0/18`, remote
  UDP `10000-60000`, to local UDP `30000-30127`;
- priority 1200: outbound TLS/5061 from CP1 to Twilio's eight published
  Elastic SIP Trunking signaling `/30` ranges;
- priority 1210: outbound SRTP from local UDP `30000-30127` to
  `168.86.128.0/18`, remote UDP `10000-60000`.

The Twilio authorities were reviewed on 2026-08-31 against the current
[Elastic SIP Trunking IP address list](https://www.twilio.com/docs/sip-trunking/ip-addresses),
which was last modified by Twilio on 2026-03-09. The NSG admits only published
provider ranges. CP1 nftables and the root-enforced service cgroup narrow
signaling further to the exact reviewed `/32` A records of the configured
termination FQDN. There is deliberately no new inbound Twilio SIP/DID rule.

All other traffic meets the existing priority-4096 inbound deny and the new
priority-4096 outbound deny.
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
- the exact six-rule CP1 synthetic base policy and only the 14 disabled-mode
  rules or 17 enabled-mode rules selected by the reviewed package—never an
  unrecognized extra-rule state;
- the exact USD 100 budget, 75/90/100 alerts, and month-to-date spend not over
  budget (the overlay itself adds USD 0.00 of metered resources);
- pinned Bicep compiler and compiled template digest, plus separate pinned
  compiled-parameter digests for disabled and enabled mode;
- for apply, a fresh Provider-level What-If containing every target child rule
  as `Create` or `NoChange` and nothing else.

No plan mutates Azure. Execution re-observes the complete protected state and
What-If, compares it with the saved plan, deploys only through the provider,
then proves the exact postcondition. Disabling an already-enabled overlay also
binds the three Twilio rule ETags into `conditionalDeletes`; execution removes
only those rules after the incremental deployment. A plan is valid for ten
minutes and its SHA-256 and confirmation phrase are separate mandatory inputs.

## Apply

Use the pinned Bicep CLI already installed on the deployment runner. Save the
single-line plan only at the ignored protected path expected by the guard:

```bash
umask 077
/opt/homebrew/bin/python3.13 infra/azure-poc/cp1_carrier_nsg_overlay.py plan --action apply \
  --twilio-mode disabled \
  --direct-replacement-plan-sha256 REPLACE_WITH_REVIEWED_G3_PLAN_SHA256 \
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

To enable Twilio later, generate a fresh plan with `--twilio-mode enabled`.
The guard compiles the separate tracked enabled parameter artifact, verifies
its pinned digest, and requires Provider What-If to show the three conditional
rules as `Create` (or `NoChange` on an idempotent run). To disable Twilio while
retaining carrier authority, generate a fresh apply plan with
`--twilio-mode disabled`; the saved plan must contain the live ETags of exactly
the three conditional rules, and the postcondition must contain all 14
disabled-mode rules with no Twilio authority.

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
  --twilio-mode disabled \
  --direct-replacement-plan-sha256 REPLACE_WITH_REVIEWED_G3_PLAN_SHA256 \
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
