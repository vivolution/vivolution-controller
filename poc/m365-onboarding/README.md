# Vivolution first-tenant Microsoft 365 onboarding

This package is a reviewable, single-tenant Microsoft Teams Direct Routing POC
configuration. It pairs these two gateways with the one expected Entra tenant:

- `sbc1.voice.vivolution.ae:5061`
- `sbc2.voice.vivolution.ae:5061`
- tenant `151cd01a-1e81-40a9-b898-d8646e1a8760`

The only outbound voice route matches `^\+971[1-9][0-9]{7,8}$`. It therefore
does not match short emergency/service codes or non-UAE E.164 numbers. It uses a
dedicated PSTN usage and per-user policy for exactly two explicitly supplied
test users. Nothing in this package creates a domain, user, license, trial,
subscription, PSTN service, or emergency-calling configuration.

## Important support boundary

The Vivolution Edge uses OpenSIPS/RTPengine. It is **not a Microsoft-certified
SBC and is not supported by Microsoft**. Microsoft documents that Direct
Routing support is limited to certified SBCs and may reject cases involving a
noncertified device. This package is suitable only for the accepted engineering
POC; it is not evidence of Microsoft certification or production support.

The earlier 2026-08-30 read-only result came from the Azure subscription's
guest directory and is not evidence about Vivolution's Microsoft 365 tenant.
Public Microsoft tenant discovery binds `vivolution.ae` to the tenant above,
but registered-domain, SKU, user-license, Teams-homing, and number state remain
unverified until the isolated live preflight authenticates as
`jay@vivolution.ae`. Do not weaken that preflight or infer readiness from the
Azure subscription login.

## Managed objects

| Type | Exact identity/value |
| --- | --- |
| Global PSTN usage member | `Vivolution-POC-UAE` |
| Voice route | `Vivolution-POC-UAE-Plus971` |
| Voice routing policy | `Vivolution-POC-UAE` |
| Gateways, in failover order | `sbc1.voice.vivolution.ae`, `sbc2.voice.vivolution.ae` |
| User numbers | two distinct, explicitly supplied `+971` E.164 numbers |

The scripts never replace the tenant's global PSTN usage list. They call
`Set-CsOnlinePstnUsage` with `Add` for apply and `Remove` for rollback. An
existing managed gateway, route, policy, number, or assignment is accepted only
when it is exact; divergence stops the run. Unmanaged routes, policies, or users
that reference the managed usage/gateways/policy also stop the run. Each gateway
uses the documented 10-second failover timer and `408,503,504` failover response
codes so an unavailable first node can advance to the second configured trunk.

## Prerequisites

1. PowerShell 7.2 or later and MicrosoftTeams PowerShell 7.0 or later.
2. An operator authorized to read the tenant and manage Direct Routing, voice
   routing, phone-number assignments, and per-user policy grants.
3. The exact `voice.vivolution.ae` subdomain registered in the expected tenant.
   A parent `vivolution.ae` registration alone is intentionally insufficient.
4. Two enabled users in that subdomain with `Teams` and `PhoneSystem` feature
   types, `TeamsUpgradeEffectiveMode=TeamsOnly`, an `infra.lync.com` registrar,
   and no on-premises LineURI.
5. Two distinct test Direct Routing numbers matching the fixed `+971` pattern.
6. Public SBC DNS, certificate, TLS, SIP OPTIONS, and media qualification must
   already have passed the separate infrastructure runbook. These scripts do
   not pretend to validate the data plane from Microsoft 365.

## Prepare the explicit configuration

Keep the live configuration and state out of Git:

```powershell
Copy-Item ./config.example.psd1 ./config.psd1
```

Replace all four placeholders in `Users`. The module rejects placeholder UPNs,
placeholder numbers, duplicates, other UPN domains, other country codes, and
changes to any locked tenant/gateway/routing value.

## Read-only preflight

The preflight connects to the explicitly named tenant, then verifies the tenant
ID, exact registered subdomain, user license features/readiness, number
availability/ownership, and non-divergence of all existing managed objects. It
makes no tenant changes.

```powershell
./Invoke-Preflight.ps1 -ConfigPath ./config.psd1
```

`-SkipConnect` may be used only when a MicrosoftTeams session already exists;
the script still obtains and compares the connected tenant ID.

## Review and apply

First run the mutation path with `-WhatIf`. The exact acknowledgement is still
required so copied commands cannot silently target another workflow:

```powershell
./Invoke-Apply.ps1 `
  -ConfigPath ./config.psd1 `
  -Acknowledge 'APPLY VIVOLUTION DIRECT ROUTING POC TO 151cd01a-1e81-40a9-b898-d8646e1a8760' `
  -WhatIf
```

After reviewing the output, remove only `-WhatIf`. Apply records the exact
pre-existing state in `.state/apply-state.json` with restrictive local
permissions **before** its first Microsoft 365 mutation. It then adds the
dedicated usage, creates only absent exact objects, assigns the two numbers with
`NumberType DirectRouting`, grants the POC policy, and requires an exact
read-back. Rerunning with the same state/configuration is idempotent; a changed
configuration or rolled-back journal is refused.

If apply stops part way through, do not delete or edit the journal. Rerun apply
with the same configuration to converge, or run the journal-driven rollback.

## Read-only verification

```powershell
./Invoke-Verify.ps1 -ConfigPath ./config.psd1
```

Verification requires both exact enabled gateways, the dedicated usage, exact
route and policy, the two Direct Routing number assignments, the two policy
grants, and `EnterpriseVoiceEnabled` on both users. A successful configuration
read-back does not by itself prove SIP OPTIONS or calls; retain call/CDR evidence
from the end-to-end qualification run.

## Exact rollback

Review the rollback plan first:

```powershell
./Invoke-Rollback.ps1 `
  -ConfigPath ./config.psd1 `
  -StatePath ./.state/apply-state.json `
  -Acknowledge 'ROLL BACK VIVOLUTION DIRECT ROUTING POC FROM 151cd01a-1e81-40a9-b898-d8646e1a8760' `
  -WhatIf
```

Then remove only `-WhatIf`. Rollback refuses a mismatched tenant/configuration,
divergent managed object, or a new unmanaged reference. It reverses user grants
and assignments first, then removes only objects and the global usage member
recorded as absent before apply. Anything that predated apply is left intact and
must still match its original exact state. The retained journal is marked
`RolledBack`, making repeated rollback a read-only verification rather than a
second deletion pass.

## Static tests

The tests need Python only; they do not connect to Microsoft 365:

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

## Official Microsoft references

Checked against Microsoft Learn on 2026-08-30:

- [Configure Direct Routing](https://learn.microsoft.com/en-us/microsoftteams/direct-routing-configure)
- [Connect the SBC and validate the connection](https://learn.microsoft.com/en-us/microsoftteams/direct-routing-connect-the-sbc)
- [Enable users for Direct Routing](https://learn.microsoft.com/en-us/microsoftteams/direct-routing-enable-users)
- [Configure voice routing](https://learn.microsoft.com/en-us/microsoftteams/direct-routing-voice-routing)
- [`New-CsOnlinePSTNGateway`](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/new-csonlinepstngateway?view=teams-ps)
- [`Set-CsOnlinePstnUsage`](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-csonlinepstnusage?view=teams-ps)
- [`New-CsOnlineVoiceRoute`](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/new-csonlinevoiceroute?view=teams-ps)
- [`New-CsOnlineVoiceRoutingPolicy`](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/new-csonlinevoiceroutingpolicy?view=teams-ps)
- [`Set-CsPhoneNumberAssignment`](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/set-csphonenumberassignment?view=teams-ps)
- [`Remove-CsPhoneNumberAssignment`](https://learn.microsoft.com/en-us/powershell/module/microsoftteams/remove-csphonenumberassignment?view=teams-ps)
