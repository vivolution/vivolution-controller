#!/usr/bin/env python3
"""Outbound-only Ed25519 challenge/response enrollment state machine."""

from __future__ import annotations

import base64
import binascii
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from .core import (
    GRANT_RE,
    STATE_API_VERSION,
    EnrollmentError,
    EnrollmentMetadata,
    ProtectedState,
    canonical_json_bytes,
    fixed_inventory,
    normalize_controller_url,
    validate_enrollment_grant,
)
from .http_client import HTTPSJSONTransport
from .protocol import (
    BASE64URL_64_RE,
    ENROLLMENT_CHALLENGE_PATH,
    ENROLLMENT_CLAIM_PATH,
    ENROLLMENT_STATUS_PATH,
    NODE_CHALLENGE_PATH,
    NODE_HEARTBEAT_PATH,
    Challenge,
    _base64url_32,
    _canonical_uuid,
    _utc,
    build_signed_envelope,
    sha256_digest,
    signed_request_bytes,
)
from .release import DIGEST_RE as RELEASE_DIGEST_RE
from .release import ReleaseIdentityError, load_installed_release_digest

ENROLLMENT_CHALLENGE_REQUEST_API = (
    "edge.vivolution.ae/enrollment-challenge-request/v1"
)
ENROLLMENT_CHALLENGE_API = "edge.vivolution.ae/enrollment-challenge/v1"
ENROLLMENT_CLAIM_API = "edge.vivolution.ae/enrollment-claim/v1"
ENROLLMENT_CLAIM_RESULT_API = "edge.vivolution.ae/enrollment-claim-result/v1"
NODE_CHALLENGE_REQUEST_API = "edge.vivolution.ae/node-challenge-request/v1"
NODE_CHALLENGE_API = "edge.vivolution.ae/node-challenge/v1"
ENROLLMENT_STATUS_API = "edge.vivolution.ae/enrollment-status/v1"
ENROLLMENT_STATUS_RESULT_API = "edge.vivolution.ae/enrollment-status-result/v1"
HEARTBEAT_API = "edge.vivolution.ae/heartbeat/v1"
HEARTBEAT_RESULT_API = "edge.vivolution.ae/heartbeat-result/v1"
STATE_KEYS = {
    "agent_sequence",
    "api_version",
    "claim_id",
    "client_nonce",
    "controller_url",
    "inventory",
    "inventory_digest",
    "metadata",
    "pending_claim",
    "public_key",
    "public_key_fingerprint",
    "status",
}
STATE_STATUSES = {
    "LOCAL_IDENTITY_READY",
    "PENDING_APPROVAL",
    "APPROVED",
    "ONLINE",
    "DEGRADED",
    "REVOKED",
}


def _exact(value: Mapping[str, Any], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise EnrollmentError("{} fields do not match the v1 contract".format(label))


def _positive_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= (1 << 53) - 1:
        raise EnrollmentError("{} must be a positive safe integer".format(field))
    return value


def _nullable_utc(value: object, field: str) -> str | None:
    if value is None:
        return None
    _utc(value, field)
    return str(value)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _whole_second_utc(now: datetime) -> str:
    if now.tzinfo is None:
        raise EnrollmentError("current time must be timezone-aware")
    return now.astimezone(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _read_boot_id(path: Path = Path("/proc/sys/kernel/random/boot_id")) -> str:
    try:
        value = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise EnrollmentError("cannot read the Linux boot ID") from exc
    return _canonical_uuid(value, "bootId")


@dataclass(frozen=True)
class EnrollmentChallenge:
    challenge: Challenge
    metadata: EnrollmentMetadata
    grant_id: str


class EnrollmentClient:
    """Persist no display-once grant and expose no inbound management socket."""

    def __init__(
        self,
        *,
        controller_url: str,
        state: ProtectedState,
        transport: HTTPSJSONTransport | Any | None = None,
        now: Callable[[], datetime] = _now_utc,
        boot_id: Callable[[], str] = _read_boot_id,
        installed_release_digest: str | None = None,
    ) -> None:
        self.controller_url = normalize_controller_url(controller_url)
        self.state = state
        self.transport = transport or HTTPSJSONTransport(self.controller_url)
        self.now = now
        self.boot_id = boot_id
        try:
            self.installed_release_digest = (
                load_installed_release_digest()
                if installed_release_digest is None
                else installed_release_digest
            )
        except ReleaseIdentityError as exc:
            raise EnrollmentError(str(exc)) from exc
        if not RELEASE_DIGEST_RE.fullmatch(self.installed_release_digest):
            raise EnrollmentError("installed Edge release digest is invalid")
        self.identity, _ = state.load_or_create_identity()

    def _new_state(self) -> dict[str, Any]:
        inventory = fixed_inventory()
        return {
            "agent_sequence": 0,
            "api_version": STATE_API_VERSION,
            "claim_id": None,
            "client_nonce": base64.urlsafe_b64encode(secrets.token_bytes(32))
            .rstrip(b"=")
            .decode("ascii"),
            "controller_url": self.controller_url,
            "inventory": inventory,
            "inventory_digest": sha256_digest(canonical_json_bytes(inventory)),
            "metadata": None,
            "pending_claim": None,
            "public_key": self.identity.public_key_base64url,
            "public_key_fingerprint": self.identity.fingerprint,
            "status": "LOCAL_IDENTITY_READY",
        }

    def _validated_state(self, *, create: bool) -> dict[str, Any]:
        value = self.state.read_state()
        if value is None:
            if not create:
                raise EnrollmentError("this Edge has not started enrollment")
            value = self._new_state()
            self.state.write_state(value)
        _exact(value, STATE_KEYS, "protected enrollment state")
        if value["controller_url"] != self.controller_url:
            raise EnrollmentError("protected state is bound to a different controller URL")
        if value["public_key"] != self.identity.public_key_base64url:
            raise EnrollmentError("protected state public key does not match node identity")
        if value["public_key_fingerprint"] != self.identity.fingerprint:
            raise EnrollmentError("protected state fingerprint does not match node identity")
        _base64url_32(value["client_nonce"], "clientNonce")
        if not isinstance(value["inventory"], dict):
            raise EnrollmentError("protected inventory is invalid")
        if value["inventory_digest"] != sha256_digest(
            canonical_json_bytes(value["inventory"])
        ):
            raise EnrollmentError("protected inventory digest does not match inventory")
        if value["status"] not in STATE_STATUSES:
            raise EnrollmentError("protected enrollment status is invalid")
        sequence = value["agent_sequence"]
        if (
            isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or not 0 <= sequence <= (1 << 53) - 1
        ):
            raise EnrollmentError("protected agent sequence is invalid")
        if value["claim_id"] is not None:
            _canonical_uuid(value["claim_id"], "claimId")
        if value["metadata"] is not None:
            _exact(
                value["metadata"],
                {"cluster_id", "generation", "node_id", "release_digest", "slot"},
                "protected enrollment metadata",
            )
            EnrollmentMetadata(**value["metadata"])
            if value["metadata"]["release_digest"] != self.installed_release_digest:
                raise EnrollmentError(
                    "protected scope differs from the installed Edge release"
                )
        if value["pending_claim"] is not None:
            self._validate_pending_claim(value)
        if value["status"] != "LOCAL_IDENTITY_READY" and (
            value["claim_id"] is None or value["metadata"] is None
        ):
            raise EnrollmentError("protected enrollment lifecycle state is incomplete")
        return value

    def _expected_claim_payload(
        self, local: Mapping[str, Any], grant_id: str
    ) -> dict[str, Any]:
        metadata = local["metadata"]
        return {
            "apiVersion": ENROLLMENT_CLAIM_API,
            "clientNonce": local["client_nonce"],
            "clusterId": metadata["cluster_id"],
            "generation": metadata["generation"],
            "grantId": grant_id,
            "inventoryDigest": local["inventory_digest"],
            "nodeId": metadata["node_id"],
            "publicKey": local["public_key"],
            "releaseDigest": metadata["release_digest"],
            "slot": metadata["slot"],
        }

    def _validate_pending_claim(self, local: Mapping[str, Any]) -> None:
        envelope = local["pending_claim"]
        if not isinstance(envelope, dict):
            raise EnrollmentError("protected pending claim is invalid")
        _exact(envelope, {"signature", "signedRequest"}, "protected pending claim")
        signed = envelope["signedRequest"]
        if not isinstance(signed, dict):
            raise EnrollmentError("protected pending signed request is invalid")
        # signed_request_bytes enforces the exact field set/canonical domain.
        signed_bytes = signed_request_bytes(signed)
        if (
            signed["apiVersion"] != "edge.vivolution.ae/signed-node-request/v1"
            or signed["audience"] != self.controller_url
            or signed["method"] != "POST"
            or signed["path"] != ENROLLMENT_CLAIM_PATH
            or signed["keyFingerprint"] != local["public_key_fingerprint"]
            or local["metadata"] is None
            or not isinstance(signed["payload"], dict)
        ):
            raise EnrollmentError("protected pending claim is bound incorrectly")
        Challenge(
            signed["audience"],
            signed["challengeId"],
            signed["challengeNonce"],
            signed["challengeExpiresAt"],
        )
        _canonical_uuid(signed["requestId"], "requestId")
        if not isinstance(envelope["signature"], str) or not BASE64URL_64_RE.fullmatch(
            envelope["signature"]
        ):
            raise EnrollmentError("protected pending claim signature encoding is invalid")
        grant_id = signed["payload"].get("grantId")
        _canonical_uuid(grant_id, "grantId")
        if signed["payload"] != self._expected_claim_payload(local, grant_id):
            raise EnrollmentError("protected pending claim payload differs from local state")
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

            signature = base64.urlsafe_b64decode(envelope["signature"] + "==")
            public_key = Ed25519PrivateKey.from_private_bytes(
                self.identity.private_seed
            ).public_key()
            public_key.verify(signature, signed_bytes)
        except (binascii.Error, InvalidSignature, ValueError, TypeError) as exc:
            raise EnrollmentError("protected pending claim signature is invalid") from exc

    @staticmethod
    def _grant_id(grant: str) -> str:
        match = GRANT_RE.fullmatch(grant.encode("ascii"))
        if match is None:
            raise EnrollmentError("one-time enrollment grant is invalid")
        return match.group(1).decode("ascii")

    def _parse_enrollment_challenge(
        self, response: Mapping[str, Any], grant: str
    ) -> EnrollmentChallenge:
        _exact(
            response,
            {
                "apiVersion",
                "audience",
                "challengeExpiresAt",
                "challengeId",
                "challengeNonce",
                "clusterId",
                "generation",
                "grantId",
                "nodeId",
                "releaseDigest",
                "slot",
            },
            "enrollment challenge response",
        )
        if response["apiVersion"] != ENROLLMENT_CHALLENGE_API:
            raise EnrollmentError("controller enrollment challenge version is unsupported")
        challenge = Challenge(
            audience=response["audience"],
            challenge_id=response["challengeId"],
            challenge_nonce=response["challengeNonce"],
            challenge_expires_at=response["challengeExpiresAt"],
        )
        if challenge.audience != self.controller_url:
            raise EnrollmentError("controller challenge audience does not match shared URL")
        challenge.require_fresh(now=self.now())
        metadata = EnrollmentMetadata(
            node_id=response["nodeId"],
            cluster_id=response["clusterId"],
            slot=response["slot"],
            generation=response["generation"],
            release_digest=response["releaseDigest"],
        )
        if metadata.release_digest != self.installed_release_digest:
            raise EnrollmentError(
                "controller grant expects a different installed Edge release"
            )
        grant_id = _canonical_uuid(response["grantId"], "grantId")
        match = GRANT_RE.fullmatch(grant.encode("ascii"))
        if match is None or match.group(1).decode("ascii") != grant_id:
            raise EnrollmentError("controller challenge does not match the supplied grant")
        return EnrollmentChallenge(challenge, metadata, grant_id)

    def _persist_server_scope(
        self, value: dict[str, Any], metadata: EnrollmentMetadata
    ) -> None:
        if value["metadata"] is not None and value["metadata"] != metadata.as_dict():
            raise EnrollmentError("controller changed the grant-bound node scope")
        value["metadata"] = metadata.as_dict()
        self.state.write_state(value)

    def enroll(self, grant: str) -> dict[str, Any]:
        grant = validate_enrollment_grant(grant)
        local = self._validated_state(create=True)
        if local["claim_id"] is not None:
            # The display-once grant is no longer an authentication mechanism
            # after a claim result was stored. Use node proof-of-possession.
            return self.poll_status()
        if local["pending_claim"] is not None:
            pending_grant_id = local["pending_claim"]["signedRequest"]["payload"][
                "grantId"
            ]
            if self._grant_id(grant) != pending_grant_id:
                raise EnrollmentError(
                    "the re-supplied grant does not match the pending exact claim"
                )
            _, result = self.transport.post(
                ENROLLMENT_CLAIM_PATH,
                local["pending_claim"],
                expected_statuses=(200, 201),
                enrollment_grant=grant,
            )
            return self._accept_claim_result(local, result)
        challenge_request = {
            "apiVersion": ENROLLMENT_CHALLENGE_REQUEST_API,
            "clientNonce": local["client_nonce"],
            "publicKey": local["public_key"],
        }
        _, response = self.transport.post(
            ENROLLMENT_CHALLENGE_PATH,
            challenge_request,
            expected_statuses=(201,),
            enrollment_grant=grant,
        )
        issued = self._parse_enrollment_challenge(response, grant)
        self._persist_server_scope(local, issued.metadata)
        claim_payload = self._expected_claim_payload(local, issued.grant_id)
        envelope = build_signed_envelope(
            identity=self.identity,
            controller_url=self.controller_url,
            challenge=issued.challenge,
            path=ENROLLMENT_CLAIM_PATH,
            payload=claim_payload,
            now=self.now(),
        )
        local["pending_claim"] = envelope
        self.state.write_state(local)
        _, result = self.transport.post(
            ENROLLMENT_CLAIM_PATH,
            envelope,
            expected_statuses=(200, 201),
            enrollment_grant=grant,
        )
        return self._accept_claim_result(local, result)

    def _accept_claim_result(
        self, local: dict[str, Any], result: Mapping[str, Any]
    ) -> dict[str, Any]:
        metadata = local["metadata"]
        _exact(
            result,
            {"apiVersion", "claimId", "generation", "keyFingerprint", "nodeId", "status"},
            "enrollment claim result",
        )
        if (
            result["apiVersion"] != ENROLLMENT_CLAIM_RESULT_API
            or result["status"] != "PENDING_APPROVAL"
            or result["nodeId"] != metadata["node_id"]
            or result["generation"] != metadata["generation"]
            or result["keyFingerprint"] != self.identity.fingerprint
        ):
            raise EnrollmentError("controller claim result does not match this node")
        local["claim_id"] = _canonical_uuid(result["claimId"], "claimId")
        local["pending_claim"] = None
        local["status"] = "PENDING_APPROVAL"
        self.state.write_state(local)
        return self.public_status(local)

    def _node_challenge(
        self, local: Mapping[str, Any], purpose: str
    ) -> Challenge:
        if purpose not in ("STATUS", "HEARTBEAT"):
            raise EnrollmentError("node challenge purpose is invalid")
        metadata = local["metadata"]
        request = {
            "apiVersion": NODE_CHALLENGE_REQUEST_API,
            "generation": metadata["generation"],
            "keyFingerprint": local["public_key_fingerprint"],
            "nodeId": metadata["node_id"],
            "purpose": purpose,
        }
        _, response = self.transport.post(
            NODE_CHALLENGE_PATH, request, expected_statuses=(201,)
        )
        _exact(
            response,
            {
                "apiVersion",
                "audience",
                "challengeExpiresAt",
                "challengeId",
                "challengeNonce",
                "generation",
                "keyFingerprint",
                "nodeId",
                "purpose",
            },
            "node challenge response",
        )
        if (
            response["apiVersion"] != NODE_CHALLENGE_API
            or response["audience"] != self.controller_url
            or response["generation"] != metadata["generation"]
            or response["keyFingerprint"] != local["public_key_fingerprint"]
            or response["nodeId"] != metadata["node_id"]
            or response["purpose"] != purpose
        ):
            raise EnrollmentError("controller node challenge does not match this node")
        challenge = Challenge(
            response["audience"],
            response["challengeId"],
            response["challengeNonce"],
            response["challengeExpiresAt"],
        )
        challenge.require_fresh(now=self.now())
        return challenge

    def poll_status(self) -> dict[str, Any]:
        local = self._validated_state(create=False)
        recovering_lost_claim = (
            local["claim_id"] is None and local["pending_claim"] is not None
        )
        if not recovering_lost_claim and local["status"] not in (
            "PENDING_APPROVAL",
            "APPROVED",
            "ONLINE",
            "DEGRADED",
            "REVOKED",
        ):
            raise EnrollmentError("enrollment claim has not completed")
        challenge = self._node_challenge(local, "STATUS")
        metadata = local["metadata"]
        payload = {
            "apiVersion": ENROLLMENT_STATUS_API,
            "generation": metadata["generation"],
            "nodeId": metadata["node_id"],
        }
        envelope = build_signed_envelope(
            identity=self.identity,
            controller_url=self.controller_url,
            challenge=challenge,
            path=ENROLLMENT_STATUS_PATH,
            payload=payload,
            now=self.now(),
        )
        _, result = self.transport.post(
            ENROLLMENT_STATUS_PATH, envelope, expected_statuses=(200,)
        )
        _exact(
            result,
            {
                "apiVersion",
                "approvedAt",
                "claimId",
                "generation",
                "keyFingerprint",
                "nodeId",
                "revokedAt",
                "status",
            },
            "enrollment status result",
        )
        approved_at = _nullable_utc(result["approvedAt"], "approvedAt")
        revoked_at = _nullable_utc(result["revokedAt"], "revokedAt")
        if (
            result["apiVersion"] != ENROLLMENT_STATUS_RESULT_API
            or result["generation"] != metadata["generation"]
            or result["keyFingerprint"] != local["public_key_fingerprint"]
            or result["nodeId"] != metadata["node_id"]
            or result["status"] not in ("PENDING_APPROVAL", "APPROVED", "REVOKED")
        ):
            raise EnrollmentError("controller status result does not match this node")
        result_claim_id = _canonical_uuid(result["claimId"], "claimId")
        if local["claim_id"] is not None and result_claim_id != local["claim_id"]:
            raise EnrollmentError("controller status result changed the claim identity")
        if result["status"] == "PENDING_APPROVAL" and (approved_at or revoked_at):
            raise EnrollmentError("pending status contains an approval or revocation time")
        if result["status"] == "APPROVED" and (not approved_at or revoked_at):
            raise EnrollmentError("approved status timestamps are inconsistent")
        if result["status"] == "REVOKED" and not revoked_at:
            raise EnrollmentError("revoked status lacks a revocation time")
        local["claim_id"] = result_claim_id
        local["pending_claim"] = None
        local["status"] = result["status"]
        self.state.write_state(local)
        return self.public_status(local)

    def heartbeat(self, health: str = "HEALTHY") -> dict[str, Any]:
        local = self._validated_state(create=False)
        if local["status"] not in ("APPROVED", "ONLINE", "DEGRADED"):
            raise EnrollmentError("only an approved node may report heartbeat")
        if health not in ("HEALTHY", "DEGRADED"):
            raise EnrollmentError("heartbeat health must be HEALTHY or DEGRADED")
        challenge = self._node_challenge(local, "HEARTBEAT")
        metadata = local["metadata"]
        sequence = local["agent_sequence"] + 1
        if sequence > (1 << 53) - 1:
            raise EnrollmentError("heartbeat sequence is exhausted")
        # Persist before sending so a lost response cannot cause nonce/sequence
        # reuse. Gaps are safe; replay is not.
        local["agent_sequence"] = sequence
        self.state.write_state(local)
        payload = {
            "agentSequence": sequence,
            "apiVersion": HEARTBEAT_API,
            "bootId": _canonical_uuid(self.boot_id(), "bootId"),
            "generation": metadata["generation"],
            "health": health,
            "inventoryDigest": local["inventory_digest"],
            "nodeId": metadata["node_id"],
            "observedReleaseDigest": metadata["release_digest"],
            "sentAt": _whole_second_utc(self.now()),
        }
        envelope = build_signed_envelope(
            identity=self.identity,
            controller_url=self.controller_url,
            challenge=challenge,
            path=NODE_HEARTBEAT_PATH,
            payload=payload,
            now=self.now(),
        )
        _, result = self.transport.post(
            NODE_HEARTBEAT_PATH, envelope, expected_statuses=(200,)
        )
        _exact(
            result,
            {
                "acceptedSequence",
                "apiVersion",
                "generation",
                "nextHeartbeatSeconds",
                "nodeId",
                "serverTime",
                "status",
            },
            "heartbeat result",
        )
        _utc(result["serverTime"], "serverTime")
        if (
            result["apiVersion"] != HEARTBEAT_RESULT_API
            or result["acceptedSequence"] != sequence
            or result["generation"] != metadata["generation"]
            or result["nodeId"] != metadata["node_id"]
            or result["status"] not in ("ONLINE", "DEGRADED")
            or not 5 <= _positive_integer(
                result["nextHeartbeatSeconds"], "nextHeartbeatSeconds"
            ) <= 3600
        ):
            raise EnrollmentError("controller heartbeat result does not match this node")
        local["status"] = result["status"]
        self.state.write_state(local)
        return self.public_status(local)

    def service_once(self) -> dict[str, Any]:
        local = self._validated_state(create=False)
        if local["pending_claim"] is not None or local["status"] == "PENDING_APPROVAL":
            status = self.poll_status()
            if status["status"] != "APPROVED":
                return status
        if self._validated_state(create=False)["status"] in (
            "APPROVED",
            "ONLINE",
            "DEGRADED",
        ):
            return self.heartbeat()
        return self.public_status(self._validated_state(create=False))

    def public_status(self, local: Mapping[str, Any]) -> dict[str, Any]:
        metadata = local["metadata"]
        return {
            "agentSequence": local["agent_sequence"],
            "apiVersion": "edge.vivolution.ae/local-enrollment-status/v1",
            "claimId": local["claim_id"],
            "controllerUrl": local["controller_url"],
            "inventoryDigest": local["inventory_digest"],
            "installedReleaseDigest": self.installed_release_digest,
            "keyFingerprint": local["public_key_fingerprint"],
            "metadata": metadata,
            "status": local["status"],
        }
