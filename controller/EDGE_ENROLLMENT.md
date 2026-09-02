# Bounded Edge enrollment v1

This release implements the Controller half of a provider-neutral Edge join POC.
It lets an operator declare an expected node, issue a short-lived display-once
grant, approve the exact Ed25519 key fingerprint proved by that node, see signed
status and heartbeat updates, and revoke the node identity.

It does **not** issue mTLS certificates, deliver desired configuration or
secrets, expose remote execution, provision a VM, or configure Teams, a carrier,
OpenSIPS, or RTPengine. Those remain separate release gates.

## Operator flow

1. In Django admin, create an Edge cluster and an expected Edge node. Choose its
   immutable cluster, name, architecture, and HA slot A (1) or B (2).
2. Select exactly that node and run **Issue a display-once enrollment grant**.
   Review the release-bound enrollment-client source digest, confirm, then copy
   the Controller shared URL and one-time grant directly to the protected Edge
   installer prompt. The grant is shown once and expires in 10 minutes.
3. The Edge creates its Ed25519 key locally, proves possession against a fresh
   Controller challenge, and enters `PENDING_APPROVAL`. The grant cannot claim a
   different cluster, node, slot, generation, key, or release digest.
4. Independently compare the pending claim fingerprint with the value shown on
   the VM/cloud console. Select the node and run **Approve pending enrollment
   claim** only after the exact node, claim ID, generation, and fingerprint match.
5. The approved client reports a monotonic signed heartbeat. Node status becomes
   `ONLINE` or `DEGRADED`; runtime identity/status fields are read-only in admin.
6. **Revoke current node identity** immediately blocks every new challenge and
   every signed claim, status, or heartbeat request, including exact retries.

## Public HTTPS API

All endpoints accept canonical JSON by `POST` only and are limited to 16 KiB at
both Caddy and Django:

- `/api/edge/v1/enrollment/challenge`
- `/api/edge/v1/enrollment/claim`
- `/api/edge/v1/node/challenge`
- `/api/edge/v1/enrollment/status`
- `/api/edge/v1/node/heartbeat`

The initial two endpoints use `Authorization: Vivolution-Enrollment <grant>`.
After claim, requests use no bearer credential: they prove the node's Ed25519
key against a 60-second, hash-only, single-use challenge scoped to the exact
HTTPS Controller audience, method, path, node, generation, key, and payload.
Exact lost-response retries are idempotent; altered replays fail closed.

The Controller database contains only an HMAC-SHA-256 grant digest made with the
required, independent `EDGE_ENROLLMENT_TOKEN_PEPPER`. Raw grants, challenge nonces, and
private node keys are never stored by the Controller. Challenge rows older than
the fixed 72-hour replay-retention window are pruned per node as new challenges
are created; grants, claims, approvals, revocations, and audit events remain.

The supported Edge identity is release-bound in
`cp1/edge_release.py`. It is a deterministic digest of the exact eight-file
enrollment-client source set. It is not a signature or a digest of the full SBC
runtime. Publication must keep that Controller constant, the Edge role pin, and
the recomputed source digest identical.

## Required Controller configuration

- `VIVOLUTION_CONTROLLER_ORIGIN` is the canonical shared public origin, such as
  `https://controller.voice.example.com`: HTTPS, DNS FQDN, port 443, no path,
  query, fragment, user information, or IP literal.
- `EDGE_ENROLLMENT_TOKEN_PEPPER` is an independent 32-byte secret encoded as 64
  lowercase hexadecimal characters. Do not reuse the RLS signing key.
- `DJANGO_TRUST_X_FORWARDED_PROTO=true` is required behind the managed Caddy
  ingress. The Gunicorn listener must remain unreachable from outside the host.

The complete wire schema and canonical-signature rules are documented in
`../edge/enrollment/API_CONTRACT.md`.
