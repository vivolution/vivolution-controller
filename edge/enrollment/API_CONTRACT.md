# Edge enrollment API v1 contract

Status: bounded enrollment/visibility contract. This version uses
server-authenticated HTTPS plus Ed25519 signed challenges. It does **not** claim
mTLS, certificate issuance, desired-state delivery, secret delivery, remote
execution, or full configuration management.

The audience is the exact shared origin `https://<canonical-fqdn>` on TCP 443,
with no path, query, fragment, user information, IP literal, or alternate port.
All calls are `POST`, have no query, and carry bounded JSON.

## Grant and identity

The display-once grant is exactly:

```text
v1.<canonical-lowercase-UUID-selector>.<unpadded-base64url-32-byte-secret>
```

It appears only in `Authorization: Vivolution-Enrollment <grant>` on the
enrollment challenge and claim. It is never used for status or heartbeat and
is never persisted by the Edge. The Controller stores only a peppered digest
of the secret and binds the selector to node, cluster, slot, generation, and
release scope.

The Edge creates one raw Ed25519 key locally. Its public key is canonical
unpadded base64url of 32 bytes. Its fingerprint is lowercase
`sha256:<64-hex>` over those raw public-key bytes.

## Signed request

The outer body contains exactly `signedRequest` and `signature`. The
`signedRequest` contains exactly:

```text
apiVersion, audience, challengeExpiresAt, challengeId, challengeNonce,
keyFingerprint, method, path, payload, requestId
```

`apiVersion` is `edge.vivolution.ae/signed-node-request/v1`, `method` is
`POST`, and `requestId` is a fresh canonical lowercase UUID. Signature bytes
are:

```text
edge.vivolution.ae/SignedNodeRequest/v1\0 || canonical_json(signedRequest)
```

Canonical JSON uses UTF-8, sorted ASCII member names, no insignificant
whitespace, no trailing newline, no floating-point/non-finite values, and
integers inside the interoperable ±(2^53−1) range. The signature is unpadded
base64url of the raw 64-byte Ed25519 signature. Audience, method, exact path,
challenge ID/nonce/expiry, fingerprint, request ID, and payload are therefore
all cryptographically bound.

Challenges are single-use, expire after 60 seconds, and are bound server-side
to their exact purpose and scope. A first claim whose HTTP response is lost is
first discovered through a signed status challenge without the grant. If the
Controller has no committed claim, recovery replays the exact protected signed
envelope with the same/reissued grant; a fresh challenge/request is not
substituted.

`releaseDigest` is not copied blindly from the Controller. The installed role
pins a root-owned digest of the exact fixed Edge enrollment Python source
manifest. The client recalculates that digest before network use, requires it
to equal the grant-bound Controller challenge, and reports the same locally
verified value in claim and heartbeat.

## Endpoints

- `/api/edge/v1/enrollment/challenge` accepts exactly
  `apiVersion`, `clientNonce`, and `publicKey`, authenticated by the display-once
  grant. It returns the exact audience/challenge fields and authoritative
  `grantId`, `clusterId`, `nodeId`, slot `A|B`, generation, and release digest.
- `/api/edge/v1/enrollment/claim` accepts the signed claim and the same grant.
  Its payload contains exactly `apiVersion`, `clientNonce`, `clusterId`,
  `generation`, `grantId`, `inventoryDigest`, `nodeId`, `publicKey`,
  `releaseDigest`, and `slot`. It returns `PENDING_APPROVAL`.
- `/api/edge/v1/node/challenge` accepts exactly `apiVersion`, `generation`,
  `keyFingerprint`, `nodeId`, and purpose `STATUS|HEARTBEAT`. It returns a
  fresh purpose-bound node challenge.
- `/api/edge/v1/enrollment/status` accepts the signed exact `apiVersion`,
  `generation`, and `nodeId` payload. Status is
  `PENDING_APPROVAL|APPROVED` while the node remains authorized. A revoked
  identity cannot obtain the preceding node challenge: the Controller returns
  generic HTTP 403 with `node_revoked` before a signed status request is
  possible.
- `/api/edge/v1/node/heartbeat` accepts the signed exact `agentSequence`,
  `apiVersion`, `bootId`, `generation`, `health`, `inventoryDigest`, `nodeId`,
  `observedReleaseDigest`, and `sentAt` payload. Health is the agent/link
  self-report `HEALTHY|DEGRADED`; it is not voice-path readiness. Sequence is
  monotonically increasing, boot ID is the Linux canonical UUID, and sent time
  is whole-second UTC.

Unknown/missing fields, wrong scope/key/audience/path/purpose, malformed or
expired challenges, replay (except the exact idempotent claim recovery),
non-monotonic heartbeat, revocation, and contract/version mismatch fail closed.
