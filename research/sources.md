# Research Sources

Official Microsoft, vendor, UAE regulator, carrier, and open-source references are recorded here with short findings. Links verified on 2026-08-27 unless otherwise stated.

## Microsoft

- [Configure an SBC for multiple tenants](https://learn.microsoft.com/en-us/microsoftteams/direct-routing-sbc-multiple-tenants) — Microsoft explicitly supports one certified SBC serving multiple customer tenants; documents base domains, customer-derived FQDNs, wildcard certificates, Contact-header tenant classification, carrier trunks, derived trunks, and multi-SBC failover.
- [Certified SBCs for Direct Routing](https://learn.microsoft.com/en-us/microsoftteams/direct-routing-border-controllers) — current certified products/firmware and Microsoft/vendor support boundary.
- [Plan Direct Routing](https://learn.microsoft.com/en-us/microsoftteams/direct-routing-plan) — licensing, FQDN, public certificate, networking, carrier, and tenant prerequisites.
- [Connect the SBC](https://learn.microsoft.com/en-us/microsoftteams/direct-routing-connect-the-sbc) — SBC connection, signaling, certificates, and availability requirements.
- [Enable users for Direct Routing](https://learn.microsoft.com/en-us/microsoftteams/direct-routing-enable-users) — user licensing and enablement.
- [Monitor and troubleshoot Direct Routing](https://learn.microsoft.com/en-us/microsoftteams/direct-routing-monitor-and-troubleshoot) — health and operational monitoring.
- [Direct Routing SIP protocol](https://learn.microsoft.com/en-us/microsoftteams/direct-routing-protocols-sip) — SIP behavior an interoperable edge must implement and test.
- [Direct Routing media protocol](https://learn.microsoft.com/en-us/microsoftteams/direct-routing-protocols-media) — media, SRTP, ICE, and related behavior.
- [What's new for Direct Routing](https://learn.microsoft.com/en-us/microsoftteams/direct-routing-whats-new) — current certificate and protocol lifecycle notices.
- [Operator Connect directory](https://microsoftpartners.microsoft.com/abs/Operator-Directory/) — current provider/country availability must be checked during market validation rather than assumed.

## Certified vendor examples

- [AudioCodes Teams Direct Routing Hosting Model configuration note](https://www.audiocodes.com/media/13161/connecting-audiocodes-sbc-to-microsoft-teams-direct-routing-hosting-model-configuration-note.pdf) — published hosting-model configuration and provider/customer domain structure.
- [AudioCodes Live Express](https://www.audiocodes.com/news/press-releases/news/audiocodes-live-express-simplifies-direct-routing-onboarding-and-management-for-microsoft-teams-partners) — partner-oriented multi-customer Direct Routing onboarding and management benchmark.
- [AudioCodes Live Hub](https://www.audiocodes.com/platforms/audiocodes-live-hub/audiocodes-live-hub-for-microsoft-teams) — turnkey service benchmark for portal, automation, analytics, and commercial comparison.
- [anynode multi-tenancy](https://www.anynode.de/multi-tenancy/) — vendor states one Microsoft-certified software SBC can serve multiple Teams tenants.
- [46 Labs PeerEdge](https://www.46labs.com/peeredge) — orchestration-first voice-infrastructure benchmark; exact UAE/certification topology requires validation.
- Microsoft also links current hosting guidance for Oracle, Ribbon, and Metaswitch from its multi-tenant article.

## Open-source building blocks

- [Kamailio](https://www.kamailio.org/) — SIP signaling/router candidate.
- [OpenSIPS](https://www.opensips.org/) — alternative SIP signaling/router candidate.
- [OpenSIPS TLS management](https://opensips.org/html/docs/modules/3.6.x/tls_mgm.html) — database-backed TLS domains, certificate selection, and runtime reload behavior used in the POC decision.
- [OpenSIPS dynamic routing](https://opensips.org/html/docs/modules/3.6.x/drouting.html) — route partitions, gateways, rules, and reload behavior.
- [OpenSIPS clusterer](https://opensips.org/html/docs/modules/3.6.x/clusterer.html) — cluster membership, synchronization, and HA primitives.
- [OpenSIPS Control Panel](https://controlpanel.opensips.org/) — internal engineering console candidate; not a tenant portal.
- [Sipwise RTPengine](https://github.com/sipwise/rtpengine) — media proxy and RTP/SRTP candidate.
- [Sipwise C5 Community Edition](https://www.sipwise.com/spce) — integrated Kamailio/RTPengine carrier platform and one-day API/UX benchmark.
- [LibreSBC](https://github.com/hnimminh/libresbc) — current open SBC candidate for a bounded interoperability check.
- [dSIPRouter pricing](https://dsiprouter.org/pricing/) — direct market comparator; Teams/API/HA subscription cost exceeds the free-lab premise.
- [Routr](https://github.com/fonoster/routr) — programmable multi-domain SIP proxy candidate, not a complete product.
- [FusionPBX](https://github.com/fusionpbx/fusionpbx) — multi-tenant PBX/reference and possible lab PBX, not the product edge.
- [CGRateS](https://github.com/cgrates/cgrates) — optional future rating/quota/fraud engine, intentionally excluded from POC.
- [HOMER](https://github.com/sipcapture/homer-app) — SIP/RTC troubleshooting and observability candidate with short, controlled trace retention.
- Asterisk or FreeSWITCH — optional B2BUA/media workers, not required as the customer-facing portal.

## Azure and certificates

- [Azure Retail Prices API](https://prices.azure.com/api/retail/prices) — UAE North reference compute, IP, disk, network, and logging rates.
- [Azure region and Availability Zone support](https://learn.microsoft.com/en-us/azure/reliability/availability-zones-region-support) — current UAE region/zone capabilities.
- [Let's Encrypt certificate compatibility](https://letsencrypt.org/docs/certificate-compatibility/) — ISRG trust-chain behavior.
- [Let's Encrypt TLS Client Authentication change](https://letsencrypt.org/2025/05/14/ending-tls-client-authentication) — client-authentication EKU removal completed in 2026; relevant to Microsoft's announced future Direct Routing mTLS requirement.

## UAE regulator

- [TDRA FAQs — VoIP section](https://tdra.gov.ae/en/FAQs) — regulatory distinction between providing VoIP services and consultancy/private-network deployment, UAE-licensee collaboration, and type-approval considerations.
- [TDRA Voice over Internet Protocol Regulatory Policy](https://tdra.gov.ae/-/media/About/regulations-and-ruling/EN/Voice-over-internet-protocol-Regulatory-policy-pdf.ashx) — public VoIP regulatory framework and licensee responsibilities.
- [TDRA telecom-service licensing](https://tdra.gov.ae/en/services/issue-licences-to-provide-telecommunication-services) — public-network/service licensing process and information requirements.
- [TDRA equipment registration](https://tdra.gov.ae/en/services/equipment-registration) — type-approval and supplier-registration process.
- [TDRA Kashif](https://tdra.gov.ae/en/initiatives/kashif) — UAE caller-name/identity initiative implemented with service providers.
- [UAE Personal Data Protection Law](https://uaelegislation.gov.ae/en/legislations/1972) — federal personal-data framework relevant to CDRs, traces, identifiers, recordings, and cross-border support access.

## Evidence still required

- Written certified-vendor hosting, licensing, API/RBAC, HA, and MSP/resale terms.
- Written UAE carrier confirmation for hosted enterprise SIP trunks and responsibility boundaries.
- Written UAE legal/regulatory opinion for each proposed commercial model.
- Current, filtered Microsoft Operator Connect availability for UAE numbers and services.
