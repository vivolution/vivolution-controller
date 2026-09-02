from __future__ import annotations

import base64
import hashlib
import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from edge.enrollment.core import (
    SIGNED_REQUEST_PREFIX,
    EnrollmentError,
    Identity,
    canonical_json_bytes,
)
from edge.enrollment.protocol import (
    ENROLLMENT_CLAIM_PATH,
    NODE_HEARTBEAT_PATH,
    Challenge,
    build_signed_envelope,
)


def utc(seconds: int = 0) -> str:
    value = datetime(2026, 9, 1, 6, 0, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


class SignedRequestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = Identity.generate()
        self.challenge = Challenge(
            audience="https://controller.example.com",
            challenge_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            challenge_nonce=base64.urlsafe_b64encode(b"n" * 32)
            .rstrip(b"=")
            .decode(),
            challenge_expires_at=utc(60),
        )
        self.now = datetime(2026, 9, 1, 6, 0, tzinfo=timezone.utc)

    def test_exact_envelope_signature_binds_origin_path_challenge_and_payload(self) -> None:
        envelope = build_signed_envelope(
            identity=self.identity,
            controller_url="https://controller.example.com",
            challenge=self.challenge,
            path=ENROLLMENT_CLAIM_PATH,
            payload={"apiVersion": "edge.vivolution.ae/enrollment-claim/v1"},
            request_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            now=self.now,
        )
        self.assertEqual(set(envelope), {"signature", "signedRequest"})
        signed = envelope["signedRequest"]
        self.assertEqual(signed["path"], ENROLLMENT_CLAIM_PATH)
        self.assertEqual(signed["method"], "POST")
        signature = base64.urlsafe_b64decode(envelope["signature"] + "==")
        key = Ed25519PrivateKey.from_private_bytes(self.identity.private_seed)
        key.public_key().verify(
            signature,
            SIGNED_REQUEST_PREFIX + canonical_json_bytes(signed),
        )

    def test_rejects_wrong_audience_expired_or_overlong_challenge_and_path(self) -> None:
        cases = (
            {
                "controller_url": "https://other.example.com",
                "challenge": self.challenge,
                "path": ENROLLMENT_CLAIM_PATH,
            },
            {
                "controller_url": "https://controller.example.com",
                "challenge": Challenge(
                    self.challenge.audience,
                    self.challenge.challenge_id,
                    self.challenge.challenge_nonce,
                    utc(-1),
                ),
                "path": ENROLLMENT_CLAIM_PATH,
            },
            {
                "controller_url": "https://controller.example.com",
                "challenge": Challenge(
                    self.challenge.audience,
                    self.challenge.challenge_id,
                    self.challenge.challenge_nonce,
                    utc(121),
                ),
                "path": ENROLLMENT_CLAIM_PATH,
            },
            {
                "controller_url": "https://controller.example.com",
                "challenge": self.challenge,
                "path": "/api/edge/v1/not-allowed",
            },
        )
        for case in cases:
            with self.subTest(case=case), self.assertRaises(EnrollmentError):
                build_signed_envelope(
                    identity=self.identity,
                    payload={},
                    request_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    now=self.now,
                    **case,
                )

    def test_same_payload_has_different_request_id_and_signature(self) -> None:
        first = build_signed_envelope(
            identity=self.identity,
            controller_url=self.challenge.audience,
            challenge=self.challenge,
            path=NODE_HEARTBEAT_PATH,
            payload={},
            now=self.now,
        )
        second = build_signed_envelope(
            identity=self.identity,
            controller_url=self.challenge.audience,
            challenge=self.challenge,
            path=NODE_HEARTBEAT_PATH,
            payload={},
            now=self.now,
        )
        self.assertNotEqual(
            first["signedRequest"]["requestId"], second["signedRequest"]["requestId"]
        )
        self.assertNotEqual(first["signature"], second["signature"])

    def test_controller_produced_shared_signature_vector(self) -> None:
        identity = Identity.from_seed(bytes(range(32)))
        self.assertEqual(
            identity.public_key_base64url,
            "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
        )
        self.assertEqual(
            identity.fingerprint,
            "sha256:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c",
        )
        challenge = Challenge(
            audience="https://controller.example.test",
            challenge_id="11111111-1111-4111-8111-111111111111",
            challenge_nonce="IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
            challenge_expires_at="2026-09-01T12:00:00Z",
        )
        envelope = build_signed_envelope(
            identity=identity,
            controller_url="https://controller.example.test",
            challenge=challenge,
            path="/api/edge/v1/enrollment/status",
            payload={
                "apiVersion": "edge.vivolution.ae/enrollment-status/v1",
                "generation": 1,
                "nodeId": "33333333-3333-4333-8333-333333333333",
            },
            request_id="22222222-2222-4222-8222-222222222222",
            now=datetime(2026, 9, 1, 11, 59, 30, tzinfo=timezone.utc),
        )
        self.assertEqual(
            envelope["signature"],
            "RcgBkTDREldDFJLBux7qAc5tXEqmZ0AefE1u6kkXdFWr04GuzIJUaGNoiJE_haakjJctq9-VIHH8X_wygXPkDg",
        )
        signed_message = SIGNED_REQUEST_PREFIX + canonical_json_bytes(
            envelope["signedRequest"]
        )
        self.assertEqual(
            hashlib.sha256(signed_message).hexdigest(),
            "7b010088b8aa2b6c45bdcf0a2c1a3dc55c1a3d5d3f5270914361bfd2794bac3a",
        )


if __name__ == "__main__":
    unittest.main()
