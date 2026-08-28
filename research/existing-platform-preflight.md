# Existing Platform Preflight

Status: Discovery shortlist; validate licences, current releases, resource requirements, and Teams behavior before selection.

The first engineering question is not “Can we write a portal?” It is “Which maintained platform already supplies safe multi-tenancy, provisioning, accounting, and operations without forcing an unsuitable PBX or commercial model?”

## Sipwise C5 Community Edition

What it offers:

- A current open-source carrier softswitch built around Kamailio and RTPengine.
- Administrator and customer web interfaces.
- API provisioning, subscriber/tenant concepts, CDR/accounting, monitoring, and rating foundations.
- A documented path to commercial Sipwise editions if operations outgrow Community Edition.

Why it matters:

It overlaps strongly with the infrastructure Vivolution would otherwise build. It is the leading **accelerator/reference-platform candidate** for the POC.

Questions to prove:

- Can Teams-derived trunks and PBX relay connectors be represented cleanly without fighting subscriber/PBX assumptions?
- Can Vivolution branding and a constrained customer experience be layered without licence or upgrade problems?
- Is its operational footprint practical on the Azure lab budget?
- Can its APIs support a separate Vivolution portal while preserving upgrades?

## Thin OpenSIPS/RTPengine stack

What it offers:

- The smallest and most controllable call path.
- Exact tenant classification, routing, security, and branding behavior.
- No inherited PBX feature surface.

What it costs:

- Vivolution must build and maintain provisioning, configuration validation, CDR processing, RBAC, audit, monitoring, upgrades, and recovery.
- Direct Routing regressions and edge cases become an internal product responsibility.

This is the strongest **custom product candidate**. OpenSIPS 3.6 LTS is the preferred POC signaling engine because its database-backed TLS domains, dynamic routing partitions, JSON-RPC management, and cluster framework map cleanly to a multi-tenant desired-state compiler. Kamailio remains an excellent fallback if measured interoperability or operating experience favors it.

## OpenSIPS and OpenSIPS Control Panel

OpenSIPS is a credible alternative signaling engine with strong dynamic routing, clustering, dialog, and management capabilities. Its Control Panel is useful for operator administration, but it should not be mistaken for the complete tenant-safe Vivolution customer portal.

The POC should compare configuration ergonomics, runtime reloads, accounting events, HA behavior, community evidence for Teams interworking, and staff familiarity—not raw packet-forwarding performance alone.

## dSIPRouter

dSIPRouter is a useful direct market comparator: it demonstrates demand for a managed Kamailio edge. Its Microsoft Teams Direct Routing, programmatic API, HA, and advanced CDR capabilities are subscription features, and the current Core price is above the entire Azure credit per instance. It also does not remove the need for a deliberately constrained tenant portal. Do not use it as the free POC base unless Jay separately approves paid evaluation.

## LibreSBC

LibreSBC is a current MIT-licensed SBC with REST/UI management, routing, TLS/SRTP, CPS/session controls, CDR delivery, HA, and HOMER integration. It is worth a tightly timeboxed interoperability check, but it has no complete customer/tenant/RBAC model or packaged Teams recipe. A successful call would not eliminate the Vivolution control plane.

## Routr

Routr is an active MIT-licensed, programmable multi-domain SIP proxy with gRPC management, PostgreSQL, TLS, HA, and RTPengine middleware. It has no web application or complete SBC/compliance product and is less established than OpenSIPS/Kamailio. Keep it as a future experiment, not the default POC path.

## FusionPBX

- Mature domain-based multi-tenancy on FreeSWITCH.
- Useful as a lab PBX or for customers that genuinely want a hosted PBX.
- Broader PBX feature set than the proposed managed edge needs.
- White-label and API economics/terms must be checked; they may undermine the low-cost thesis.

FusionPBX should not become the default customer-facing core merely because it already has screens.

## Wazo

- API-driven, multi-tenant, white-label communications platform with BYOC capabilities.
- Broader UC/application platform than the SBC-first scope.
- Its maintained platform is primarily an Asterisk UC/PBX system; its C4 SBC/router repositories are archived. Avoid it as the Teams edge and borrow API ideas only.

## CGRateS

Useful later for rating, quotas, fraud controls, and commercial policy. It adds complexity and is unnecessary for the first two-tenant technical proof. Capture trustworthy CDRs first; add real-time charging only if the commercial model needs it.

## HOMER/HEP

Excellent for bounded SIP troubleshooting and interoperability analysis. It is not the long-term compliance CDR store. Packet captures can contain credentials, numbers, identities, and message bodies, so default retention must be short and access tightly controlled.

## Recommendation

Run a short sequential bake-off rather than committing prematurely:

1. Use OpenSIPS 3.6 LTS + RTPengine as the working POC data plane.
2. Give Sipwise C5 CE a bounded one-day API/UX benchmark; optionally give LibreSBC a similarly bounded call-path check.
3. Score each on onboarding effort, tenant isolation, Teams behavior, safe configuration changes, CDR completeness, HA, resource use, branding/API fit, and upgradeability.
4. Change the working choice only if a candidate removes substantial backend work without forcing unsafe or PBX/carrier semantics.

Do not build the full portal during the checks. Use a minimal operator console/configuration compiler so data-plane evidence—not UI sunk cost—drives the choice.

## Fleet-management preflight

No one existing tool cleanly combines provider-neutral VM creation, secure enrollment, and SIP-aware staged/drained lifecycle. Keep infrastructure creation and ongoing cluster management separate.

- **Thin Vivolution Edge Agent:** preferred product seam. A static signed agent uses outbound mTLS 443, pulls signed desired state, exposes only typed reconcile/drain/rollback/test operations, reports health, and never provides arbitrary remote execution.
- **Ansible Core / ansible-pull:** useful for reviewed host bootstrap and slow OS baseline changes. Git/cron lacks one-use enrollment, approval, health gates, SIP-aware canary/rollback, and safe real-time state, so it is not the fleet protocol.
- **AWX:** useful generic inventory/RBAC/jobs later, but Kubernetes-based and excessive for the POC control VM.
- **Salt:** has mature minion identity/state/event capabilities but adds a privileged general command plane and master/firewall surface that duplicates Vivolution desired state.
- **Nomad/Consul and k3s:** add scheduler/quorum/networking complexity with little benefit for host-networked OpenSIPS and public RTP ranges. k3s HA itself needs at least three server nodes.
- **NetBird/Headscale/WireGuard:** optional management/break-glass overlay, not provisioning or the voice path.
- **Rudder:** credible later for broader patch/compliance evidence, but too heavy and not SIP-aware for the initial fleet.

Use a common Enroll Existing Pair flow on every provider. Optional Azure, AWS, on-premises, or other adapters may create VMs/networking and pass short-lived enrollment context, but they cannot bypass the same identity, approval, desired-state, and validation gates.
