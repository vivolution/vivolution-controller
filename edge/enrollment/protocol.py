#!/usr/bin/env python3
"""Exact v1 Edge enrollment proof contract shared with the Controller."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from .core import (
    SIGNED_REQUEST_PREFIX,
    EnrollmentError,
    Identity,
    canonical_json_bytes,
    normalize_controller_url,
)

SIGNED_REQUEST_API_VERSION = "edge.vivolution.ae/signed-node-request/v1"
ENROLLMENT_CHALLENGE_PATH = "/api/edge/v1/enrollment/challenge"
ENROLLMENT_CLAIM_PATH = "/api/edge/v1/enrollment/claim"
NODE_CHALLENGE_PATH = "/api/edge/v1/node/challenge"
ENROLLMENT_STATUS_PATH = "/api/edge/v1/enrollment/status"
NODE_HEARTBEAT_PATH = "/api/edge/v1/node/heartbeat"
SIGNED_PATHS = frozenset(
    {ENROLLMENT_CLAIM_PATH, ENROLLMENT_STATUS_PATH, NODE_HEARTBEAT_PATH}
)
BASE64URL_32_RE = re.compile(r"\A[A-Za-z0-9_-]{43}\Z")
BASE64URL_64_RE = re.compile(r"\A[A-Za-z0-9_-]{86}\Z")
FINGERPRINT_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


def _canonical_uuid(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise EnrollmentError("{} must be a canonical UUID".format(field))
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise EnrollmentError("{} must be a canonical UUID".format(field)) from exc
    if str(parsed) != value:
        raise EnrollmentError("{} must be a canonical lowercase UUID".format(field))
    return value


def _base64url_32(value: object, field: str) -> str:
    if not isinstance(value, str) or not BASE64URL_32_RE.fullmatch(value):
        raise EnrollmentError("{} must be canonical unpadded base64url".format(field))
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (binascii.Error, ValueError) as exc:
        raise EnrollmentError("{} must be canonical unpadded base64url".format(field)) from exc
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise EnrollmentError("{} must encode exactly 32 bytes".format(field))
    return value


def _utc(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        raise EnrollmentError("{} must be a whole-second UTC timestamp".format(field))
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise EnrollmentError("{} is invalid".format(field)) from exc
    return parsed


@dataclass(frozen=True)
class Challenge:
    audience: str
    challenge_id: str
    challenge_nonce: str
    challenge_expires_at: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "audience", normalize_controller_url(self.audience))
        object.__setattr__(
            self,
            "challenge_id",
            _canonical_uuid(self.challenge_id, "challengeId"),
        )
        object.__setattr__(
            self,
            "challenge_nonce",
            _base64url_32(self.challenge_nonce, "challengeNonce"),
        )
        _utc(self.challenge_expires_at, "challengeExpiresAt")

    def require_fresh(
        self, *, now: datetime | None = None, maximum_lifetime_seconds: int = 120
    ) -> None:
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            raise EnrollmentError("current time must be timezone-aware")
        expires = _utc(self.challenge_expires_at, "challengeExpiresAt")
        if expires <= current:
            raise EnrollmentError("controller challenge has expired")
        if expires > current + timedelta(seconds=maximum_lifetime_seconds):
            raise EnrollmentError("controller challenge lifetime exceeds the v1 limit")


def signed_request_bytes(signed_request: Mapping[str, Any]) -> bytes:
    expected = {
        "apiVersion",
        "audience",
        "challengeExpiresAt",
        "challengeId",
        "challengeNonce",
        "keyFingerprint",
        "method",
        "path",
        "payload",
        "requestId",
    }
    if set(signed_request) != expected:
        raise EnrollmentError("signedRequest fields do not match the v1 contract")
    return SIGNED_REQUEST_PREFIX + canonical_json_bytes(signed_request)


def build_signed_envelope(
    *,
    identity: Identity,
    controller_url: str,
    challenge: Challenge,
    path: str,
    payload: Mapping[str, Any],
    request_id: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Bind one exact payload to its origin, path, nonce and node identity."""

    audience = normalize_controller_url(controller_url)
    if challenge.audience != audience:
        raise EnrollmentError("controller challenge audience does not match shared URL")
    challenge.require_fresh(now=now)
    if path not in SIGNED_PATHS:
        raise EnrollmentError("request path is outside the signed v1 endpoint set")
    if not FINGERPRINT_RE.fullmatch(identity.fingerprint):
        raise EnrollmentError("node identity fingerprint is invalid")
    canonical_payload = canonical_json_bytes(payload)
    # Reparse to ensure callers cannot supply exotic mapping subclasses whose
    # iteration changes between the signed and transmitted representations.
    import json

    stable_payload = json.loads(canonical_payload.decode("utf-8"))
    request_uuid = _canonical_uuid(
        request_id or str(uuid.uuid4()), "requestId"
    )
    signed_request = {
        "apiVersion": SIGNED_REQUEST_API_VERSION,
        "audience": audience,
        "challengeExpiresAt": challenge.challenge_expires_at,
        "challengeId": challenge.challenge_id,
        "challengeNonce": challenge.challenge_nonce,
        "keyFingerprint": identity.fingerprint,
        "method": "POST",
        "path": path,
        "payload": stable_payload,
        "requestId": request_uuid,
    }
    signature = identity.sign_bytes(signed_request_bytes(signed_request))
    if not BASE64URL_64_RE.fullmatch(signature):
        raise EnrollmentError("node signature encoding is invalid")
    return {"signature": signature, "signedRequest": signed_request}


def sha256_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()
