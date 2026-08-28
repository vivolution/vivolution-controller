# POC Test Matrix

Every test records tenant, direction, configuration version, timestamps, SIP outcome, CDR ID, media result, expected behavior, actual behavior, and evidence location.

## 1. Provisioning and identity

- Configure the Vivolution/provider tenant and onboard Customer Tenant A and Customer Tenant B from clean state.
- Validate both base FQDNs and all customer-derived FQDNs, DNS, certificate chain, CN/SAN, and ServerAuth EKU.
- Generate and review Teams PowerShell apply and rollback packages.
- Reject an unverified tenant/domain/FQDN relationship.
- Prove that every Teams and PBX connector maps to exactly one immutable tenant ID.
- Capture the actual Teams SIP behavior and prove the stable tenant-classification rule before Customer Tenant B is enabled.
- Enroll cluster node slots A and B using pinned server-authenticated TLS, distinct one-time grants, proof of key possession, explicit approval, and then node-specific mTLS; reject expired, reused, wrong-slot, unapproved, raced, or cloned claims.

## 2. Core calls — each tenant

- Teams user -> PBX extension.
- Teams user -> simulated PSTN/E.164 destination through PBX.
- PBX extension -> Teams user.
- Simulated PSTN ingress -> PBX -> Teams user.
- Calling line identity and privacy variants.
- Ringing/early media, answer, normal release, busy, reject, no-answer, and unreachable.
- Hold/resume.
- DTMF in both directions.
- Blind and attended transfer; REFER/NOTIFY/Replaces behavior as applicable.
- Call forwarding and simultaneous ring where in scope.
- Codec negotiation and any required transcoding/repacketization.

## 3. Tenant isolation

- Give both tenants extension `1001` and an overlapping E.164 fixture.
- Attempt every core call concurrently for both tenants.
- Verify that Tenant A can never reach PBX B or see Tenant B CDRs, health, secrets, routes, or audit records.
- Forge From, Contact, Request-URI, P-Asserted-Identity, Diversion, and History-Info values resembling the other tenant.
- Send valid numbers on the wrong southbound connector.
- Attempt portal/API access using another tenant's object IDs and export endpoints.

Automatic failure: any cross-tenant signaling, media, route, configuration, secret, CDR, report, or export exposure.

## 4. Security and fraud

- Unknown source IP and unauthorized TLS peer.
- Wrong, revoked, expired, and hostname-mismatched certificates.
- SIP scanner, malformed message, oversized header, and unsupported method.
- CPS burst and concurrent-session limit per tenant.
- Unauthorized international/premium destination class.
- Repeated authentication failure and credential rotation.
- Malicious route expression/configuration payload.
- Attempted open relay between arbitrary peers.
- Platform emergency block and single-tenant suspension.

## 5. Failure and recovery

- Stop signaling node 1 and confirm new calls use node 2.
- Stop RTPengine on the selected node.
- Stop the portal and control-plane database; new calls must continue on last-known-good configuration.
- Restart an Azure VM and verify deterministic recovery.
- Disconnect PBX A without affecting Tenant B.
- Change and roll back Tenant A while Tenant B generates calls; Tenant A's action must not restart shared OpenSIPS or affect B.
- Restart only Tenant A's RTPengine unit and verify Tenant B setup/media/CDRs remain unaffected.
- Publish an invalid configuration and prove it cannot become active.
- Publish a valid but operationally bad test route, then roll back.
- Rotate the TLS certificate under test traffic.
- Expire DNS cache/change a test record and observe behavior.
- Revoke and replace one Edge Agent identity and confirm the revoked node cannot obtain desired state or secrets.
- Replay, downgrade, mistarget, or alter a signed node/configuration artifact and prove it cannot activate.

Active calls are not expected to migrate during complete node failure. Record their actual outcome; the HA commitment is for new calls.

## 6. CDR, observability, and retention

- Reconcile every generated call attempt with the expected CDR disposition.
- Verify tenant, direction, calling/called numbers, answer/release times, duration, node, route, and termination cause.
- Verify failed and rejected attempts are distinguishable from answered calls.
- Verify tenant-only search and export.
- Expire a short test retention class and confirm deletion/archive behavior.
- Confirm SIP troubleshooting capture is disabled by default, bounded when enabled, and access-audited.
- Verify no RTP/audio is stored.

## 7. Quality and load

- At least 100 consecutive low-load core call attempts per tenant across both directions after stabilization.
- Controlled concurrent-call ramp to the declared POC limit.
- Record setup time, packet loss, jitter, round-trip/one-way estimates, RTPengine CPU, and any transcoding cost.
- Soak for at least four hours with periodic call generation and health checks.

The POC does not establish production capacity. B-series throttling and synthetic endpoints must be called out in results.

## Acceptance thresholds

- Zero tenant-isolation failures.
- All mandatory call features pass for both tenants or have a documented, commercially acceptable limitation.
- 100% expected CDR reconciliation for the controlled test corpus.
- At least 99% successful low-load calls after the environment is declared stable, excluding intentional negative tests.
- New calls recover through the alternate node within 120 seconds of a tested node failure.
- Portal/database outage does not stop new calls using the last-known-good configuration.
- Bad configuration is rejected or rolled back within five minutes.
- Certificate replacement completes without an avoidable service outage.
- No critical or high unresolved security finding.
- Actual base Azure lab spend remains within Jay's approved ceiling and the USD 100 credit target.

These thresholds are POC gates, not a customer SLA.
