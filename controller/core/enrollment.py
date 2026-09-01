import base64
import hashlib
import hmac
import json
import re
import secrets
from datetime import datetime, timedelta
from datetime import timezone as datetime_timezone
from functools import wraps
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from .models import (
    AuditEvent,
    EdgeNode,
    EnrollmentChallenge,
    EnrollmentClaim,
    EnrollmentGrant,
)
from .rls import operator_scope

SIGNED_REQUEST_PREFIX = b"edge.vivolution.ae/SignedNodeRequest/v1\0"
SIGNED_REQUEST_VERSION = "edge.vivolution.ae/signed-node-request/v1"
ENROLLMENT_CHALLENGE_REQUEST_VERSION = (
    "edge.vivolution.ae/enrollment-challenge-request/v1"
)
ENROLLMENT_CHALLENGE_VERSION = "edge.vivolution.ae/enrollment-challenge/v1"
ENROLLMENT_CLAIM_VERSION = "edge.vivolution.ae/enrollment-claim/v1"
ENROLLMENT_CLAIM_RESPONSE_VERSION = "edge.vivolution.ae/enrollment-claim-result/v1"
NODE_CHALLENGE_REQUEST_VERSION = "edge.vivolution.ae/node-challenge-request/v1"
NODE_CHALLENGE_VERSION = "edge.vivolution.ae/node-challenge/v1"
ENROLLMENT_STATUS_VERSION = "edge.vivolution.ae/enrollment-status/v1"
ENROLLMENT_STATUS_RESPONSE_VERSION = "edge.vivolution.ae/enrollment-status-result/v1"
HEARTBEAT_VERSION = "edge.vivolution.ae/heartbeat/v1"
HEARTBEAT_RESPONSE_VERSION = "edge.vivolution.ae/heartbeat-result/v1"

ENROLLMENT_CHALLENGE_PATH = "/api/edge/v1/enrollment/challenge"
ENROLLMENT_CLAIM_PATH = "/api/edge/v1/enrollment/claim"
NODE_CHALLENGE_PATH = "/api/edge/v1/node/challenge"
ENROLLMENT_STATUS_PATH = "/api/edge/v1/enrollment/status"
HEARTBEAT_PATH = "/api/edge/v1/node/heartbeat"

GRANT_AUTH_SCHEME = "Vivolution-Enrollment"
MAX_SAFE_JSON_INTEGER = (1 << 53) - 1
MAX_ACTIVE_CHALLENGES = 5
MAX_CLOCK_SKEW_SECONDS = 300
NEXT_HEARTBEAT_SECONDS = 30
CHALLENGE_RETENTION_SECONDS = 72 * 60 * 60

_B64URL_32_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_B64URL_64_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_GRANT_TOKEN_RE = re.compile(
    r"^v1\.([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.([A-Za-z0-9_-]{43})$"
)


class EdgeAPIError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _reject_float(_value):
    raise ValueError("floating point values are not permitted")


def _parse_safe_integer(value):
    parsed = int(value)
    if abs(parsed) > MAX_SAFE_JSON_INTEGER:
        raise ValueError("JSON integer is outside the interoperable safe range")
    return parsed


def _reject_constant(_value):
    raise ValueError("non-finite numbers are not permitted")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def parse_json_bytes(raw_body):
    if len(raw_body) > settings.EDGE_API_MAX_BODY_BYTES:
        raise EdgeAPIError(413, "body_too_large", "Request body is too large.")
    try:
        text = raw_body.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_int=_parse_safe_integer,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise EdgeAPIError(400, "invalid_json", "Request body is not strict JSON.") from exc
    if not isinstance(value, dict):
        raise EdgeAPIError(400, "invalid_object", "Request body must be a JSON object.")
    if canonical_json_bytes(value) != raw_body:
        raise EdgeAPIError(
            400,
            "noncanonical_json",
            "Request body must use canonical JSON encoding.",
        )
    return value


def canonical_json_bytes(value):
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise EdgeAPIError(400, "invalid_json", "Request contains an invalid JSON value.") from exc


def require_exact_members(value, names, *, where="request"):
    if not isinstance(value, dict) or set(value) != set(names):
        raise EdgeAPIError(
            400,
            "invalid_schema",
            f"{where} has missing or unknown members.",
        )


def _decode_b64url(value, *, size, regex, field):
    if not isinstance(value, str) or not regex.fullmatch(value):
        raise EdgeAPIError(400, "invalid_schema", f"{field} is invalid.")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise EdgeAPIError(400, "invalid_schema", f"{field} is invalid.") from exc
    if len(decoded) != size or _b64url(decoded) != value:
        raise EdgeAPIError(400, "invalid_schema", f"{field} is invalid.")
    return decoded


def _b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _uuid(value, field):
    if not isinstance(value, str):
        raise EdgeAPIError(400, "invalid_schema", f"{field} must be a UUID.")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise EdgeAPIError(400, "invalid_schema", f"{field} must be a UUID.") from exc
    if str(parsed) != value:
        raise EdgeAPIError(400, "invalid_schema", f"{field} must be a canonical UUID.")
    return parsed


def _digest(value, field, *, allow_empty=False):
    if allow_empty and value == "":
        return value
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise EdgeAPIError(400, "invalid_schema", f"{field} must be a SHA-256 digest.")
    return value


def _positive_integer(value, field):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise EdgeAPIError(400, "invalid_schema", f"{field} must be a positive integer.")
    return value


def _slot(value):
    if value not in {"A", "B"}:
        raise EdgeAPIError(400, "invalid_schema", "slot must be A or B.")
    return 1 if value == "A" else 2


def _slot_name(node_index):
    return "A" if node_index == 1 else "B"


def _fingerprint(public_key_bytes):
    return "sha256:" + hashlib.sha256(public_key_bytes).hexdigest()


def _utc_string(value):
    normalized = value.astimezone(datetime_timezone.utc).replace(microsecond=0)
    return normalized.isoformat().replace("+00:00", "Z")


def _parse_utc(value, field):
    if not isinstance(value, str):
        raise EdgeAPIError(400, "invalid_schema", f"{field} must be a UTC timestamp.")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime_timezone.utc
        )
    except ValueError as exc:
        raise EdgeAPIError(400, "invalid_schema", f"{field} must be a UTC timestamp.") from exc
    return parsed


def _sha256_hex(value):
    return hashlib.sha256(value).hexdigest()


def _pepper_bytes():
    try:
        return bytes.fromhex(settings.EDGE_ENROLLMENT_TOKEN_PEPPER)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("EDGE_ENROLLMENT_TOKEN_PEPPER is not configured") from exc


def _grant_digest(token):
    return hmac.new(_pepper_bytes(), token.encode("ascii"), hashlib.sha256).hexdigest()


def _parse_grant_token(token):
    if not isinstance(token, str):
        raise EdgeAPIError(401, "invalid_grant", "Enrollment grant is invalid.")
    match = _GRANT_TOKEN_RE.fullmatch(token)
    if not match:
        raise EdgeAPIError(401, "invalid_grant", "Enrollment grant is invalid.")
    grant_id = _uuid(match.group(1), "grant")
    _decode_b64url(match.group(2), size=32, regex=_B64URL_32_RE, field="grant")
    return grant_id, _grant_digest(token)


def issue_enrollment_grant(*, node, actor, release_digest, ttl_seconds=600):
    _digest(release_digest, "release_digest")
    if ttl_seconds < 600 or ttl_seconds > 900:
        raise ValueError("enrollment grants must live for 10 through 15 minutes")

    now = timezone.now().replace(microsecond=0)
    with transaction.atomic(), operator_scope():
        locked_node = EdgeNode.objects.select_for_update().select_related("cluster").get(pk=node.pk)
        if locked_node.status not in {EdgeNode.Status.EXPECTED, EdgeNode.Status.OFFLINE}:
            raise EdgeAPIError(
                409,
                "node_not_enrollable",
                "The node is not in an enrollable state.",
            )
        if EnrollmentClaim.objects.filter(
            node=locked_node,
            generation=locked_node.generation,
        ).exists():
            raise EdgeAPIError(
                409,
                "generation_already_claimed",
                "The current node generation already has a claim.",
            )
        if EnrollmentGrant.objects.filter(
            node=locked_node,
            claimed_at__isnull=True,
            revoked_at__isnull=True,
            expires_at__gt=now,
        ).exists():
            raise EdgeAPIError(
                409,
                "active_grant_exists",
                "An unexpired enrollment grant already exists for this node.",
            )

        grant = EnrollmentGrant(
            node=locked_node,
            expected_release_digest=release_digest,
            expires_at=now + timedelta(seconds=ttl_seconds),
            issued_by=actor,
        )
        secret = secrets.token_bytes(32)
        token = f"v1.{grant.id}.{_b64url(secret)}"
        grant.token_digest = _grant_digest(token)
        grant.save(force_insert=True)
        AuditEvent.objects.create(
            actor=actor,
            action="edge.enrollment_grant.issued",
            target_type="EdgeNode",
            target_id=str(locked_node.id),
            detail={
                "grant_id": str(grant.id),
                "cluster_id": str(locked_node.cluster_id),
                "slot": _slot_name(locked_node.node_index),
                "generation": locked_node.generation,
                "release_digest": release_digest,
                "expires_at": _utc_string(grant.expires_at),
            },
        )
    return grant, token


def _locked_grant(token):
    grant_id, presented_digest = _parse_grant_token(token)
    try:
        grant = (
            EnrollmentGrant.objects.select_for_update()
            .select_related("node__cluster")
            .get(pk=grant_id)
        )
    except EnrollmentGrant.DoesNotExist as exc:
        raise EdgeAPIError(401, "invalid_grant", "Enrollment grant is invalid.") from exc
    if not hmac.compare_digest(grant.token_digest, presented_digest):
        raise EdgeAPIError(401, "invalid_grant", "Enrollment grant is invalid.")
    return grant


def _ensure_grant_usable(grant, *, allow_claimed=False):
    now = timezone.now()
    if grant.revoked_at is not None:
        raise EdgeAPIError(401, "invalid_grant", "Enrollment grant is invalid.")
    if grant.claimed_at is not None and not allow_claimed:
        raise EdgeAPIError(409, "grant_already_used", "Enrollment grant was already used.")
    if grant.expires_at <= now:
        raise EdgeAPIError(410, "grant_expired", "Enrollment grant has expired.")


def _new_challenge(*, node, purpose, key_fingerprint, grant=None, claim=None, client_nonce=None):
    now = timezone.now().replace(microsecond=0)
    EnrollmentChallenge.objects.filter(
        node=node,
        expires_at__lt=now - timedelta(seconds=CHALLENGE_RETENTION_SECONDS),
    ).delete()
    active_count = EnrollmentChallenge.objects.filter(
        node=node,
        purpose=purpose,
        consumed_at__isnull=True,
        expires_at__gt=now,
    ).count()
    if active_count >= MAX_ACTIVE_CHALLENGES:
        raise EdgeAPIError(429, "challenge_rate_limited", "Too many active challenges.")
    nonce = secrets.token_bytes(32)
    challenge = EnrollmentChallenge.objects.create(
        node=node,
        purpose=purpose,
        grant=grant,
        claim=claim,
        nonce_digest=_sha256_hex(nonce),
        client_nonce_digest=_sha256_hex(client_nonce) if client_nonce is not None else "",
        key_fingerprint=key_fingerprint,
        audience=settings.VIVOLUTION_CONTROLLER_ORIGIN,
        expires_at=now + timedelta(seconds=settings.EDGE_CHALLENGE_TTL_SECONDS),
    )
    return challenge, _b64url(nonce)


def create_enrollment_challenge(*, grant_token, request_data):
    require_exact_members(
        request_data,
        ("apiVersion", "clientNonce", "publicKey"),
    )
    if request_data["apiVersion"] != ENROLLMENT_CHALLENGE_REQUEST_VERSION:
        raise EdgeAPIError(400, "unsupported_version", "Unsupported API version.")
    client_nonce = _decode_b64url(
        request_data["clientNonce"],
        size=32,
        regex=_B64URL_32_RE,
        field="clientNonce",
    )
    public_key = _decode_b64url(
        request_data["publicKey"],
        size=32,
        regex=_B64URL_32_RE,
        field="publicKey",
    )
    fingerprint = _fingerprint(public_key)

    with transaction.atomic(), operator_scope():
        grant = _locked_grant(grant_token)
        _ensure_grant_usable(grant)
        node = EdgeNode.objects.select_for_update().get(pk=grant.node_id)
        if node.status not in {EdgeNode.Status.EXPECTED, EdgeNode.Status.OFFLINE}:
            raise EdgeAPIError(409, "node_not_enrollable", "The node is not enrollable.")
        if node.generation < 1:
            raise EdgeAPIError(409, "invalid_generation", "The node generation is invalid.")
        challenge, nonce = _new_challenge(
            node=node,
            purpose=EnrollmentChallenge.Purpose.CLAIM,
            key_fingerprint=fingerprint,
            grant=grant,
            client_nonce=client_nonce,
        )

    return {
        "apiVersion": ENROLLMENT_CHALLENGE_VERSION,
        "audience": challenge.audience,
        "challengeExpiresAt": _utc_string(challenge.expires_at),
        "challengeId": str(challenge.id),
        "challengeNonce": nonce,
        "clusterId": str(grant.node.cluster_id),
        "generation": grant.node.generation,
        "grantId": str(grant.id),
        "nodeId": str(grant.node_id),
        "releaseDigest": grant.expected_release_digest,
        "slot": _slot_name(grant.node.node_index),
    }


def _signed_parts(envelope, *, payload_members, payload_version):
    require_exact_members(envelope, ("signature", "signedRequest"), where="signed envelope")
    signed = envelope["signedRequest"]
    require_exact_members(
        signed,
        (
            "apiVersion",
            "audience",
            "challengeExpiresAt",
            "challengeId",
            "challengeNonce",
            "keyFingerprint",
            "method",
            "path",
            "requestId",
            "payload",
        ),
        where="signedRequest",
    )
    if signed["apiVersion"] != SIGNED_REQUEST_VERSION:
        raise EdgeAPIError(400, "unsupported_version", "Unsupported signed-request version.")
    require_exact_members(signed["payload"], payload_members, where="payload")
    if signed["payload"].get("apiVersion") != payload_version:
        raise EdgeAPIError(400, "unsupported_version", "Unsupported payload version.")
    signature = _decode_b64url(
        envelope["signature"],
        size=64,
        regex=_B64URL_64_RE,
        field="signature",
    )
    return signed, signed["payload"], signature


def _validate_signed_challenge(*, signed, challenge, path, purpose):
    if challenge.purpose != purpose:
        raise EdgeAPIError(403, "wrong_challenge_scope", "Challenge scope is invalid.")
    challenge_id = _uuid(signed["challengeId"], "challengeId")
    request_id = _uuid(signed["requestId"], "requestId")
    nonce = _decode_b64url(
        signed["challengeNonce"],
        size=32,
        regex=_B64URL_32_RE,
        field="challengeNonce",
    )
    if (
        challenge_id != challenge.id
        or signed["audience"] != challenge.audience
        or signed["challengeExpiresAt"] != _utc_string(challenge.expires_at)
        or signed["keyFingerprint"] != challenge.key_fingerprint
        or signed["method"] != "POST"
        or signed["path"] != path
        or not hmac.compare_digest(challenge.nonce_digest, _sha256_hex(nonce))
    ):
        raise EdgeAPIError(403, "invalid_proof_scope", "Signed request scope is invalid.")
    if challenge.consumed_at is None and challenge.expires_at <= timezone.now():
        raise EdgeAPIError(410, "challenge_expired", "Challenge has expired.")
    return request_id


def _verify_signature(*, signed, signature, public_key):
    message = SIGNED_REQUEST_PREFIX + canonical_json_bytes(signed)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError) as exc:
        raise EdgeAPIError(401, "invalid_signature", "Node proof is invalid.") from exc


def _claim_response(claim, *, created):
    return (
        {
            "apiVersion": ENROLLMENT_CLAIM_RESPONSE_VERSION,
            "claimId": str(claim.id),
            "generation": claim.generation,
            "keyFingerprint": claim.public_key_fingerprint,
            "nodeId": str(claim.node_id),
            "status": "PENDING_APPROVAL",
        },
        201 if created else 200,
    )


def claim_enrollment(*, grant_token, envelope, raw_body):
    signed, payload, signature = _signed_parts(
        envelope,
        payload_members=(
            "apiVersion",
            "clientNonce",
            "clusterId",
            "generation",
            "grantId",
            "inventoryDigest",
            "nodeId",
            "publicKey",
            "releaseDigest",
            "slot",
        ),
        payload_version=ENROLLMENT_CLAIM_VERSION,
    )
    challenge_id = _uuid(signed["challengeId"], "challengeId")
    public_key = _decode_b64url(
        payload["publicKey"], size=32, regex=_B64URL_32_RE, field="publicKey"
    )
    fingerprint = _fingerprint(public_key)
    client_nonce = _decode_b64url(
        payload["clientNonce"], size=32, regex=_B64URL_32_RE, field="clientNonce"
    )
    body_digest = _sha256_hex(raw_body)
    signature_value = envelope["signature"]

    try:
        with transaction.atomic(), operator_scope():
            grant = _locked_grant(grant_token)
            try:
                challenge = (
                    EnrollmentChallenge.objects.select_for_update()
                    .select_related("node__cluster")
                    .get(pk=challenge_id)
                )
            except EnrollmentChallenge.DoesNotExist as exc:
                raise EdgeAPIError(404, "unknown_challenge", "Challenge was not found.") from exc

            request_id = _validate_signed_challenge(
                signed=signed,
                challenge=challenge,
                path=ENROLLMENT_CLAIM_PATH,
                purpose=EnrollmentChallenge.Purpose.CLAIM,
            )
            if challenge.grant_id != grant.id or challenge.key_fingerprint != fingerprint:
                raise EdgeAPIError(403, "wrong_challenge_scope", "Challenge scope is invalid.")
            _verify_signature(signed=signed, signature=signature, public_key=public_key)

            if challenge.consumed_at is not None:
                if (
                    challenge.request_body_digest == body_digest
                    and challenge.request_signature == signature_value
                    and challenge.request_id == request_id
                    and challenge.result_claim_id is not None
                ):
                    claim = EnrollmentClaim.objects.get(pk=challenge.result_claim_id)
                    _validate_current_claim(claim)
                    return _claim_response(claim, created=False)
                raise EdgeAPIError(409, "challenge_already_used", "Challenge was already used.")

            _ensure_grant_usable(grant)
            if challenge.expires_at <= timezone.now():
                raise EdgeAPIError(410, "challenge_expired", "Challenge has expired.")
            if EnrollmentChallenge.objects.filter(request_id=request_id).exclude(
                pk=challenge.pk
            ).exists():
                raise EdgeAPIError(409, "request_replayed", "Request ID was already used.")

            node = EdgeNode.objects.select_for_update().get(pk=grant.node_id)
            cluster_id = _uuid(payload["clusterId"], "clusterId")
            node_id = _uuid(payload["nodeId"], "nodeId")
            grant_id = _uuid(payload["grantId"], "grantId")
            generation = _positive_integer(payload["generation"], "generation")
            node_index = _slot(payload["slot"])
            inventory_digest = _digest(payload["inventoryDigest"], "inventoryDigest")
            release_digest = _digest(payload["releaseDigest"], "releaseDigest")
            if (
                node_id != node.id
                or cluster_id != node.cluster_id
                or grant_id != grant.id
                or node_index != node.node_index
                or generation != node.generation
                or release_digest != grant.expected_release_digest
                or signed["keyFingerprint"] != fingerprint
                or not hmac.compare_digest(
                    challenge.client_nonce_digest,
                    _sha256_hex(client_nonce),
                )
            ):
                raise EdgeAPIError(403, "wrong_claim_scope", "Claim scope is invalid.")

            claim = EnrollmentClaim.objects.create(
                grant=grant,
                node=node,
                generation=generation,
                public_key=payload["publicKey"],
                public_key_fingerprint=fingerprint,
                request_body_digest=body_digest,
                request_signature=signature_value,
                client_nonce_digest=_sha256_hex(client_nonce),
                inventory_digest=inventory_digest,
                release_digest=release_digest,
            )
            now = timezone.now()
            grant.claimed_at = now
            grant.save(update_fields=["claimed_at", "updated_at"])
            node.status = EdgeNode.Status.PENDING_APPROVAL
            node.save(update_fields=["status", "updated_at"])
            challenge.consumed_at = now
            challenge.request_body_digest = body_digest
            challenge.request_signature = signature_value
            challenge.request_id = request_id
            challenge.result_claim_id = claim.id
            challenge.result_status = "PENDING_APPROVAL"
            challenge.save(
                update_fields=[
                    "consumed_at",
                    "request_body_digest",
                    "request_signature",
                    "request_id",
                    "result_claim_id",
                    "result_status",
                    "updated_at",
                ]
            )
            AuditEvent.objects.create(
                action="edge.enrollment.claimed",
                target_type="EdgeNode",
                target_id=str(node.id),
                detail={
                    "claim_id": str(claim.id),
                    "cluster_id": str(node.cluster_id),
                    "slot": _slot_name(node.node_index),
                    "generation": node.generation,
                    "public_key_fingerprint": fingerprint,
                    "inventory_digest": inventory_digest,
                    "release_digest": release_digest,
                },
            )
            return _claim_response(claim, created=True)
    except IntegrityError as exc:
        raise EdgeAPIError(
            409,
            "claim_conflict",
            "The node generation was claimed concurrently.",
        ) from exc


def create_node_challenge(*, request_data):
    require_exact_members(
        request_data,
        ("apiVersion", "generation", "keyFingerprint", "nodeId", "purpose"),
    )
    if request_data["apiVersion"] != NODE_CHALLENGE_REQUEST_VERSION:
        raise EdgeAPIError(400, "unsupported_version", "Unsupported API version.")
    node_id = _uuid(request_data["nodeId"], "nodeId")
    generation = _positive_integer(request_data["generation"], "generation")
    fingerprint = _digest(request_data["keyFingerprint"], "keyFingerprint")
    purpose = request_data["purpose"]
    if purpose not in {
        EnrollmentChallenge.Purpose.STATUS,
        EnrollmentChallenge.Purpose.HEARTBEAT,
    }:
        raise EdgeAPIError(400, "invalid_schema", "purpose is invalid.")

    with transaction.atomic(), operator_scope():
        try:
            claim = (
                EnrollmentClaim.objects.select_for_update()
                .select_related("node__cluster")
                .get(
                    node_id=node_id,
                    generation=generation,
                    public_key_fingerprint=fingerprint,
                )
            )
        except EnrollmentClaim.DoesNotExist as exc:
            raise EdgeAPIError(404, "unknown_node", "Node identity was not found.") from exc
        node = EdgeNode.objects.select_for_update().get(pk=node_id)
        if claim.revoked_at is not None or node.status == EdgeNode.Status.REVOKED:
            raise EdgeAPIError(403, "node_revoked", "Node identity is revoked.")
        if generation != node.generation:
            raise EdgeAPIError(409, "stale_generation", "Node generation is stale.")
        if purpose == EnrollmentChallenge.Purpose.STATUS:
            allowed = {
                EdgeNode.Status.PENDING_APPROVAL,
                EdgeNode.Status.APPROVED,
                EdgeNode.Status.ONLINE,
                EdgeNode.Status.DEGRADED,
            }
        else:
            allowed = {
                EdgeNode.Status.APPROVED,
                EdgeNode.Status.ONLINE,
                EdgeNode.Status.DEGRADED,
            }
        if node.status not in allowed:
            raise EdgeAPIError(403, "node_not_authorized", "Node is not authorized.")
        challenge, nonce = _new_challenge(
            node=node,
            purpose=purpose,
            key_fingerprint=fingerprint,
            claim=claim,
        )

    return {
        "apiVersion": NODE_CHALLENGE_VERSION,
        "audience": challenge.audience,
        "challengeExpiresAt": _utc_string(challenge.expires_at),
        "challengeId": str(challenge.id),
        "challengeNonce": nonce,
        "generation": claim.generation,
        "keyFingerprint": claim.public_key_fingerprint,
        "nodeId": str(claim.node_id),
        "purpose": purpose,
    }


def _load_signed_node_request(
    *, envelope, raw_body, payload_members, payload_version, purpose, path
):
    signed, payload, signature = _signed_parts(
        envelope,
        payload_members=payload_members,
        payload_version=payload_version,
    )
    challenge_id = _uuid(signed["challengeId"], "challengeId")
    body_digest = _sha256_hex(raw_body)
    signature_value = envelope["signature"]
    try:
        challenge = (
            EnrollmentChallenge.objects.select_for_update()
            .select_related("claim__node__cluster")
            .get(pk=challenge_id)
        )
    except EnrollmentChallenge.DoesNotExist as exc:
        raise EdgeAPIError(404, "unknown_challenge", "Challenge was not found.") from exc
    request_id = _validate_signed_challenge(
        signed=signed,
        challenge=challenge,
        path=path,
        purpose=purpose,
    )
    claim = challenge.claim
    if claim is None or signed["keyFingerprint"] != claim.public_key_fingerprint:
        raise EdgeAPIError(403, "wrong_challenge_scope", "Challenge scope is invalid.")
    public_key = _decode_b64url(
        claim.public_key,
        size=32,
        regex=_B64URL_32_RE,
        field="publicKey",
    )
    _verify_signature(signed=signed, signature=signature, public_key=public_key)
    return signed, payload, challenge, claim, request_id, body_digest, signature_value


def _idempotent_challenge_result(
    *, challenge, request_id, body_digest, signature_value
):
    if challenge.consumed_at is None:
        return False
    if (
        challenge.request_id == request_id
        and challenge.request_body_digest == body_digest
        and challenge.request_signature == signature_value
    ):
        return True
    raise EdgeAPIError(409, "challenge_already_used", "Challenge was already used.")


def _validate_current_claim(claim):
    node = EdgeNode.objects.select_for_update().get(pk=claim.node_id)
    if claim.revoked_at is not None or node.status == EdgeNode.Status.REVOKED:
        raise EdgeAPIError(403, "node_revoked", "Node identity is revoked.")
    if claim.generation != node.generation:
        raise EdgeAPIError(409, "stale_generation", "Node generation is stale.")
    return node


def _map_request_id_conflict(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except IntegrityError as exc:
            raise EdgeAPIError(
                409,
                "request_replayed",
                "Request ID was already used.",
            ) from exc

    return wrapped


@_map_request_id_conflict
def get_enrollment_status(*, envelope, raw_body):
    with transaction.atomic(), operator_scope():
        (
            _signed,
            payload,
            challenge,
            claim,
            request_id,
            body_digest,
            signature_value,
        ) = _load_signed_node_request(
            envelope=envelope,
            raw_body=raw_body,
            payload_members=("apiVersion", "generation", "nodeId"),
            payload_version=ENROLLMENT_STATUS_VERSION,
            purpose=EnrollmentChallenge.Purpose.STATUS,
            path=ENROLLMENT_STATUS_PATH,
        )
        node_id = _uuid(payload["nodeId"], "nodeId")
        generation = _positive_integer(payload["generation"], "generation")
        if node_id != claim.node_id or generation != claim.generation:
            raise EdgeAPIError(403, "wrong_node_scope", "Node scope is invalid.")
        _validate_current_claim(claim)

        is_retry = _idempotent_challenge_result(
            challenge=challenge,
            request_id=request_id,
            body_digest=body_digest,
            signature_value=signature_value,
        )
        if is_retry:
            status = challenge.result_status
            approved_at = challenge.result_approved_at
            revoked_at = challenge.result_revoked_at
        else:
            if claim.approved_at is not None:
                status = "APPROVED"
            else:
                status = "PENDING_APPROVAL"
            approved_at = claim.approved_at
            revoked_at = claim.revoked_at

        if not is_retry:
            if EnrollmentChallenge.objects.filter(request_id=request_id).exclude(
                pk=challenge.pk
            ).exists():
                raise EdgeAPIError(409, "request_replayed", "Request ID was already used.")
            now = timezone.now()
            claim.last_status_at = now
            claim.save(update_fields=["last_status_at", "updated_at"])
            challenge.consumed_at = now
            challenge.request_body_digest = body_digest
            challenge.request_signature = signature_value
            challenge.request_id = request_id
            challenge.result_status = status
            challenge.result_approved_at = approved_at
            challenge.result_revoked_at = revoked_at
            challenge.save(
                update_fields=[
                    "consumed_at",
                    "request_body_digest",
                    "request_signature",
                    "request_id",
                    "result_status",
                    "result_approved_at",
                    "result_revoked_at",
                    "updated_at",
                ]
            )
        return {
            "apiVersion": ENROLLMENT_STATUS_RESPONSE_VERSION,
            "approvedAt": _utc_string(approved_at) if approved_at else None,
            "claimId": str(claim.id),
            "generation": claim.generation,
            "keyFingerprint": claim.public_key_fingerprint,
            "nodeId": str(claim.node_id),
            "revokedAt": _utc_string(revoked_at) if revoked_at else None,
            "status": status,
        }


@_map_request_id_conflict
def accept_heartbeat(*, envelope, raw_body):
    with transaction.atomic(), operator_scope():
        (
            _signed,
            payload,
            challenge,
            claim,
            request_id,
            body_digest,
            signature_value,
        ) = _load_signed_node_request(
            envelope=envelope,
            raw_body=raw_body,
            payload_members=(
                "agentSequence",
                "apiVersion",
                "bootId",
                "generation",
                "health",
                "inventoryDigest",
                "nodeId",
                "observedReleaseDigest",
                "sentAt",
            ),
            payload_version=HEARTBEAT_VERSION,
            purpose=EnrollmentChallenge.Purpose.HEARTBEAT,
            path=HEARTBEAT_PATH,
        )
        node_id = _uuid(payload["nodeId"], "nodeId")
        generation = _positive_integer(payload["generation"], "generation")
        sequence = _positive_integer(payload["agentSequence"], "agentSequence")
        boot_id = _uuid(payload["bootId"], "bootId")
        inventory_digest = _digest(payload["inventoryDigest"], "inventoryDigest")
        release_digest = _digest(
            payload["observedReleaseDigest"], "observedReleaseDigest"
        )
        if payload["health"] not in {EdgeNode.Health.HEALTHY, EdgeNode.Health.DEGRADED}:
            raise EdgeAPIError(400, "invalid_schema", "health is invalid.")
        sent_at = _parse_utc(payload["sentAt"], "sentAt")
        if abs((timezone.now() - sent_at).total_seconds()) > MAX_CLOCK_SKEW_SECONDS:
            raise EdgeAPIError(409, "clock_skew", "Heartbeat timestamp is outside tolerance.")
        if node_id != claim.node_id or generation != claim.generation:
            raise EdgeAPIError(403, "wrong_node_scope", "Node scope is invalid.")
        node = _validate_current_claim(claim)
        if inventory_digest != claim.inventory_digest:
            raise EdgeAPIError(
                409,
                "inventory_drift",
                "Heartbeat inventory digest differs from the approved claim.",
            )
        if release_digest != claim.release_digest:
            raise EdgeAPIError(
                409,
                "release_drift",
                "Heartbeat release digest differs from the approved claim.",
            )

        if _idempotent_challenge_result(
            challenge=challenge,
            request_id=request_id,
            body_digest=body_digest,
            signature_value=signature_value,
        ):
            return {
                "apiVersion": HEARTBEAT_RESPONSE_VERSION,
                "acceptedSequence": sequence,
                "generation": claim.generation,
                "nextHeartbeatSeconds": NEXT_HEARTBEAT_SECONDS,
                "nodeId": str(claim.node_id),
                "serverTime": _utc_string(challenge.consumed_at),
                "status": challenge.result_status,
            }

        if EnrollmentChallenge.objects.filter(request_id=request_id).exclude(
            pk=challenge.pk
        ).exists():
            raise EdgeAPIError(409, "request_replayed", "Request ID was already used.")
        if node.status not in {
            EdgeNode.Status.APPROVED,
            EdgeNode.Status.ONLINE,
            EdgeNode.Status.DEGRADED,
        }:
            raise EdgeAPIError(403, "node_not_approved", "Node is not approved.")
        if sequence <= node.last_heartbeat_sequence:
            raise EdgeAPIError(409, "sequence_replayed", "Heartbeat sequence is not newer.")

        now = timezone.now()
        node.last_heartbeat_sequence = sequence
        node.last_boot_id = boot_id
        node.last_seen_at = now
        node.observed_inventory_digest = inventory_digest
        node.observed_release_digest = release_digest
        node.observed_health = payload["health"]
        result_status = (
            EdgeNode.Status.ONLINE
            if payload["health"] == EdgeNode.Health.HEALTHY
            else EdgeNode.Status.DEGRADED
        )
        node.status = result_status
        node.save(
            update_fields=[
                "last_heartbeat_sequence",
                "last_boot_id",
                "last_seen_at",
                "observed_inventory_digest",
                "observed_release_digest",
                "observed_health",
                "status",
                "updated_at",
            ]
        )
        challenge.consumed_at = now
        challenge.request_body_digest = body_digest
        challenge.request_signature = signature_value
        challenge.request_id = request_id
        challenge.result_status = result_status
        challenge.save(
            update_fields=[
                "consumed_at",
                "request_body_digest",
                "request_signature",
                "request_id",
                "result_status",
                "updated_at",
            ]
        )
        return {
            "apiVersion": HEARTBEAT_RESPONSE_VERSION,
            "acceptedSequence": sequence,
            "generation": claim.generation,
            "nextHeartbeatSeconds": NEXT_HEARTBEAT_SECONDS,
            "nodeId": str(node.id),
            "serverTime": _utc_string(now),
            "status": result_status,
        }


def approve_enrollment_claim(*, claim, actor):
    with transaction.atomic(), operator_scope():
        locked_claim = (
            EnrollmentClaim.objects.select_for_update()
            .select_related("node")
            .get(pk=claim.pk)
        )
        node = EdgeNode.objects.select_for_update().get(pk=locked_claim.node_id)
        if locked_claim.revoked_at is not None or node.status == EdgeNode.Status.REVOKED:
            raise EdgeAPIError(409, "node_revoked", "A revoked claim cannot be approved.")
        if locked_claim.generation != node.generation:
            raise EdgeAPIError(409, "stale_generation", "A stale generation cannot be approved.")
        if locked_claim.approved_at is not None:
            return locked_claim
        if node.status != EdgeNode.Status.PENDING_APPROVAL:
            raise EdgeAPIError(409, "claim_not_pending", "The claim is not pending approval.")
        now = timezone.now()
        locked_claim.approved_at = now
        locked_claim.approved_by = actor
        locked_claim.save(update_fields=["approved_at", "approved_by", "updated_at"])
        node.status = EdgeNode.Status.APPROVED
        node.save(update_fields=["status", "updated_at"])
        AuditEvent.objects.create(
            actor=actor,
            action="edge.enrollment.approved",
            target_type="EdgeNode",
            target_id=str(node.id),
            detail={
                "claim_id": str(locked_claim.id),
                "generation": locked_claim.generation,
                "public_key_fingerprint": locked_claim.public_key_fingerprint,
            },
        )
        return locked_claim


def revoke_enrollment_claim(*, claim, actor, reason):
    if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 240:
        raise ValueError("revocation reason must contain 1 through 240 characters")
    with transaction.atomic(), operator_scope():
        locked_claim = (
            EnrollmentClaim.objects.select_for_update()
            .select_related("node")
            .get(pk=claim.pk)
        )
        node = EdgeNode.objects.select_for_update().get(pk=locked_claim.node_id)
        if locked_claim.revoked_at is not None:
            return locked_claim
        now = timezone.now()
        locked_claim.revoked_at = now
        locked_claim.revoked_by = actor
        locked_claim.revocation_reason = reason.strip()
        locked_claim.save(
            update_fields=["revoked_at", "revoked_by", "revocation_reason", "updated_at"]
        )
        EnrollmentGrant.objects.filter(
            node=node,
            revoked_at__isnull=True,
            claimed_at__isnull=True,
        ).update(revoked_at=now, updated_at=now)
        EnrollmentChallenge.objects.filter(
            node=node,
            consumed_at__isnull=True,
        ).update(
            consumed_at=now,
            result_status=EdgeNode.Status.REVOKED,
            updated_at=now,
        )
        if locked_claim.generation == node.generation:
            node.status = EdgeNode.Status.REVOKED
            node.save(update_fields=["status", "updated_at"])
        AuditEvent.objects.create(
            actor=actor,
            action="edge.enrollment.revoked",
            target_type="EdgeNode",
            target_id=str(node.id),
            detail={
                "claim_id": str(locked_claim.id),
                "generation": locked_claim.generation,
                "public_key_fingerprint": locked_claim.public_key_fingerprint,
                "reason": locked_claim.revocation_reason,
            },
        )
        return locked_claim
