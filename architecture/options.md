# Architecture Options

This document compares candidate architectures during discovery. No option is approved for implementation.

## Option A — Shared certified SBC cluster

One highly available certified virtual SBC cluster serves multiple customer tenants. Each tenant has separate signaling identity, routing context, carrier/PBX trunks, quotas, records, and access controls.

**Strength:** best capacity pooling and likely lowest mature per-tenant cost.  
**Risk:** largest shared blast radius and hardest isolation/change-control problem.

## Option B — Dedicated logical or virtual SBC per customer

Customers share the underlying compute platform but receive a dedicated SBC partition or instance. Isolation and troubleshooting are simpler, but vendor and infrastructure costs may be higher.

**Strength:** clearer containment, support, and customer-specific maintenance.  
**Risk:** licence and compute minimums may undermine the hosted-service economics.

## Option C — Certified Teams edge plus shared SIP service layer

A certified SBC remains the Microsoft-facing edge. A separate SIP routing/media layer provides scalable customer policy, carrier interconnection, automation, or analytics where this remains supported and operationally justified.

**Strength:** flexible service logic and potential vendor independence behind the edge.  
**Risk:** more components, failure modes, latency, skills, and support boundaries.

## Option D — Vivolution open-source Teams edge

A highly available Kamailio or OpenSIPS pair terminates Teams SIP/TLS, with RTPengine for media anchoring and Asterisk/FreeSWITCH workers only where B2BUA, transcoding, or difficult interworking is needed.

**Strength:** lowest licensing cost, complete Vivolution branding/control, strong automation potential, and freedom to optimize the product.  
**Risk:** not Microsoft-certified; Vivolution owns protocol regression, incident diagnosis, compatibility changes, security, and every escalation path.

## Working recommendation

Run discovery economics for two paths: Option D as the low-cost Vivolution-owned platform and Option A/B as the supported commercial alternative. Keep the portal and tenant model data-plane-neutral so the product is not locked to either decision.

## Important support boundary

A custom or open-source SBC can be technically interoperable, but it must not be described as Microsoft-supported unless the exact product and firmware appears on Microsoft's certified-SBC list.
