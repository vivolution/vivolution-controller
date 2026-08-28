# POC Decision Gates

## Go to controlled pilot planning

All of the following must be true:

- Two independent Microsoft 365 tenants operate concurrently with zero cross-tenant leakage.
- PBX Relay works for the agreed core call and supplementary-feature set.
- Configuration publish, rollback, certificate rotation, and control-plane outage behavior pass.
- CDRs reconcile completely and tenant-scoped access is proven.
- The chosen open-source platform is rebuildable, observable, patchable, and supportable by Vivolution.
- Estimated production cost leaves credible margin after HA, support, media egress, monitoring, retention, and on-call operations.
- Open Edge's unsupported-by-Microsoft position can be stated honestly and accepted by the target customer segment.
- Carrier and UAE regulatory questions have a funded validation path before live traffic.

## Pivot to Certified Edge

Pivot if the protocol works but one or more of these dominates:

- target customers require a Microsoft-certified SBC for procurement/support;
- Teams changes create unacceptable regression risk;
- open-source engineering/on-call cost approaches pooled certified licensing;
- required features depend on vendor interworking or escalation;
- carrier acceptance is materially easier with a certified platform.

The Vivolution portal, tenant model, evidence, and operating workflows should survive this pivot.

## Repeat the POC with changes

Repeat only when failures are bounded and correctable, for example:

- platform resource footprint is too high but architecture is sound;
- one supplementary feature needs an Asterisk/FreeSWITCH worker;
- certificate automation or configuration rollout needs redesign;
- one platform fails but the other bake-off lane remains credible.

## Stop

Stop or substantially redesign if:

- any cross-tenant leak/misroute cannot be eliminated confidently;
- the service becomes an open relay or fraud exposure under realistic conditions;
- carrier terms prohibit the PBX-relay topology;
- required UAE authorization is incompatible with the model;
- Microsoft 365 onboarding cannot be made repeatable and supportable;
- production HA, telemetry, retention, and 24/7 support make the target price uneconomic;
- certificate/mTLS requirements cannot be met sustainably.

## Evidence before decision

- Complete test report and failure log.
- Actual Azure bill plus full-month production projection.
- Staff time per tenant onboarding and per routine change.
- Known compatibility matrix for Teams, PBX, codec, and feature behavior.
- Threat-model review and unresolved-risk list.
- Proposed support/RACI and customer disclosure for Open versus Certified Edge.
- Written carrier/regulatory validation plan.
