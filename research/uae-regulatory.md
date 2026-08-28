# UAE Regulatory Boundary

Status: Initial regulatory risk screen, not legal advice.

Verified: 2026-08-27

## Initial finding

TDRA describes VoIP services as telecommunications services. Offering VoIP services to subscribers is a regulated activity that requires an appropriate licence or exemption. TDRA also distinguishes this from an IT/telecom consultancy deploying VoIP hardware or software inside a customer's private telecommunications network, provided the consultancy is not itself supplying the regulated VoIP service.

TDRA's published material also indicates that third parties may offer VoIP only in collaboration with a UAE licensee or with TDRA approval, and that a non-licensed/international provider seeking to terminate VoIP traffic in the UAE must work with a UAE licensee. VoIP-capable hardware may be subject to type-approval requirements. A shared managed platform could be treated differently from one-off private-network integration, so the product should not rely on the consultancy exception without a written classification.

## Practical boundary for Vivolution

The most defensible initial commercial shape to validate appears to be:

- Vivolution supplies and manages the SBC layer and portal as an IT/managed infrastructure service.
- Each customer contracts directly with a UAE-licensed carrier for numbers, SIP/PSTN connectivity, and regulated voice service.
- Vivolution operates the platform under a written wholesale, managed-service, or approved partner arrangement with that operator.
- The carrier remains provider of record for PSTN, numbers, emergency service, caller identity, interconnection, and regulatory duties.
- Vivolution does not independently sell telephone numbers, minutes, or public voice termination.
- Carrier interconnection and hosted use of the customer's SIP trunk are approved in writing.

This positioning still requires written UAE legal/regulatory advice and carrier validation before a POC involving live PSTN traffic or any customer pilot. Product naming cannot override the substance of the service.

## Topology risk ranking

1. **PBX relay:** Teams -> Vivolution SBC -> customer PBX -> customer du/e& trunk. The customer remains the carrier subscriber and its PBX remains the carrier-facing B2BUA. This is the strongest initial private-network/managed-infrastructure argument, although it is not a guaranteed exemption.
2. **Direct BYOC:** Teams -> Vivolution SBC -> customer du/e& trunk. This requires explicit approval for Azure IPs/FQDNs, third-party hosted termination, emergency/CLI treatment, and the service classification.
3. **Operator partnership:** a formal managed-service or wholesale relationship in which the UAE licensee remains provider of record. This is the strongest long-term commercial boundary.

Do not pool customer trunks, assign or port numbers, charge by minute, or allow cross-tenant routing.

## Additional compliance areas

- Validate TDRA type approval for the exact virtual or physical SBC SKU and any media gateway, and whether supplier/importer registration applies.
- Validate caller-ID and Kashif processes; enforce carrier-approved From and P-Asserted-Identity values and verify number ownership per tenant.
- Treat CDRs, SIP headers, numbers, IP addresses, traces, and recordings as sensitive/personal data. Apply UAE PDPL controls for purpose, access, retention, deletion, incident response, processor terms, and cross-border support access.
- UAE hosting is prudent for latency and customer assurance, but no blanket federal local-hosting requirement should be claimed without a source applicable to the customer and data.

## Questions requiring written confirmation

- Does operating a shared multi-tenant SBC for third parties constitute provision of VoIP services or another licensed activity?
- Is the answer different for BYOC, managed infrastructure, wholesale carrier partnership, and resale models?
- May enterprise SIP trunks from e&, du, or another UAE licensee terminate on a shared hosted SBC?
- Who is accountable for CLI, numbering, emergency calls, lawful interception, retention, fraud, and customer identity?
- Are the SBC software/virtual appliance and any gateways subject to TDRA type approval?
- What data-localization, privacy, cybersecurity, logging, and evidence-retention rules apply to CDRs and SIP traces?
- What wording is permitted in marketing and contracts without implying unlicensed public telephony service?
- Does TDRA collaboration with a licensee suffice, or is a separate approval, licence, or exemption required for this exact service?

## Gate

Do not sell minutes, port numbers, connect live UAE PSTN traffic, or advertise Vivolution as a voice operator until UAE counsel, TDRA where appropriate, and the intended licensed carrier have confirmed the model in writing.
