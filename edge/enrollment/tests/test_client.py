from __future__ import annotations

import base64
import copy
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from edge.enrollment.client import EnrollmentClient
from edge.enrollment.core import (
    SIGNED_REQUEST_PREFIX,
    EnrollmentError,
    ProtectedState,
    canonical_json_bytes,
)
from edge.enrollment.protocol import (
    ENROLLMENT_CHALLENGE_PATH,
    ENROLLMENT_CLAIM_PATH,
    ENROLLMENT_STATUS_PATH,
    NODE_CHALLENGE_PATH,
    NODE_HEARTBEAT_PATH,
)

NOW = datetime(2026, 9, 1, 6, 0, tzinfo=timezone.utc)
NODE_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
CLUSTER_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
GRANT_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
CLAIM_ID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
CHALLENGE_ID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
BOOT_ID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
RELEASE_DIGEST = "sha256:" + "1" * 64


def token() -> str:
    secret = base64.urlsafe_b64encode(b"g" * 32).rstrip(b"=").decode()
    return "v1.{}.{}".format(GRANT_ID, secret)


def nonce(character: bytes = b"n") -> str:
    return base64.urlsafe_b64encode(character * 32).rstrip(b"=").decode()


def expires() -> str:
    return (NOW + timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ")


class ContractTransport:
    def __init__(self) -> None:
        self.calls = []
        self.status = "APPROVED"
        self.fail_claim_once = False
        self.commit_on_failure = True
        self.claim_committed = False
        self.fail_heartbeat_once = False
        self.claim_payloads = []

    def post(
        self,
        path,
        body,
        *,
        expected_statuses=(200,),
        enrollment_grant=None,
    ):
        self.calls.append((path, copy.deepcopy(body), enrollment_grant))
        if path == ENROLLMENT_CHALLENGE_PATH:
            self.assert_grant(enrollment_grant)
            return 201, {
                "apiVersion": "edge.vivolution.ae/enrollment-challenge/v1",
                "audience": "https://controller.example.com",
                "challengeExpiresAt": expires(),
                "challengeId": CHALLENGE_ID,
                "challengeNonce": nonce(),
                "clusterId": CLUSTER_ID,
                "generation": 1,
                "grantId": GRANT_ID,
                "nodeId": NODE_ID,
                "releaseDigest": RELEASE_DIGEST,
                "slot": "A",
            }
        if path == ENROLLMENT_CLAIM_PATH:
            self.assert_grant(enrollment_grant)
            self.verify_envelope(body, path)
            self.claim_payloads.append(copy.deepcopy(body["signedRequest"]["payload"]))
            if self.fail_claim_once:
                self.fail_claim_once = False
                self.claim_committed = self.commit_on_failure
                raise EnrollmentError("simulated lost response")
            self.claim_committed = True
            return 201, {
                "apiVersion": "edge.vivolution.ae/enrollment-claim-result/v1",
                "claimId": CLAIM_ID,
                "generation": 1,
                "keyFingerprint": body["signedRequest"]["keyFingerprint"],
                "nodeId": NODE_ID,
                "status": "PENDING_APPROVAL",
            }
        if path == NODE_CHALLENGE_PATH:
            self.assertIsNone(enrollment_grant)
            if not self.claim_committed:
                raise EnrollmentError("controller has no committed claim")
            purpose = body["purpose"]
            return 201, {
                "apiVersion": "edge.vivolution.ae/node-challenge/v1",
                "audience": "https://controller.example.com",
                "challengeExpiresAt": expires(),
                "challengeId": CHALLENGE_ID,
                "challengeNonce": nonce(b"h" if purpose == "HEARTBEAT" else b"s"),
                "generation": 1,
                "keyFingerprint": body["keyFingerprint"],
                "nodeId": NODE_ID,
                "purpose": purpose,
            }
        if path == ENROLLMENT_STATUS_PATH:
            self.assertIsNone(enrollment_grant)
            self.verify_envelope(body, path)
            approved = "2026-09-01T06:00:00Z" if self.status == "APPROVED" else None
            revoked = "2026-09-01T06:00:01Z" if self.status == "REVOKED" else None
            return 200, {
                "apiVersion": "edge.vivolution.ae/enrollment-status-result/v1",
                "approvedAt": approved,
                "claimId": CLAIM_ID,
                "generation": 1,
                "keyFingerprint": body["signedRequest"]["keyFingerprint"],
                "nodeId": NODE_ID,
                "revokedAt": revoked,
                "status": self.status,
            }
        if path == NODE_HEARTBEAT_PATH:
            self.assertIsNone(enrollment_grant)
            self.verify_envelope(body, path)
            if self.fail_heartbeat_once:
                self.fail_heartbeat_once = False
                raise EnrollmentError("simulated lost heartbeat response")
            payload = body["signedRequest"]["payload"]
            return 200, {
                "acceptedSequence": payload["agentSequence"],
                "apiVersion": "edge.vivolution.ae/heartbeat-result/v1",
                "generation": 1,
                "nextHeartbeatSeconds": 30,
                "nodeId": NODE_ID,
                "serverTime": "2026-09-01T06:00:01Z",
                "status": "ONLINE" if payload["health"] == "HEALTHY" else "DEGRADED",
            }
        raise AssertionError("unexpected path {}".format(path))

    def assert_grant(self, value) -> None:
        if value != token():
            raise AssertionError("missing exact enrollment grant")

    def assertIsNone(self, value) -> None:
        if value is not None:
            raise AssertionError("grant escaped the claim endpoints")

    def verify_envelope(self, body, path) -> None:
        if set(body) != {"signature", "signedRequest"}:
            raise AssertionError("outer envelope differs")
        signed = body["signedRequest"]
        if signed["path"] != path or signed["audience"] != "https://controller.example.com":
            raise AssertionError("signed origin/path differs")
        public_raw = base64.urlsafe_b64decode(
            self.calls[0][1]["publicKey"] + "="
        )
        signature = base64.urlsafe_b64decode(body["signature"] + "==")
        Ed25519PublicKey.from_public_bytes(public_raw).verify(
            signature, SIGNED_REQUEST_PREFIX + canonical_json_bytes(signed)
        )


class EnrollmentClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name) / "enrollment"
        self.transport = ContractTransport()
        self.state = ProtectedState(self.directory, expected_uid=os.geteuid())
        self.client = EnrollmentClient(
            controller_url="https://controller.example.com",
            state=self.state,
            transport=self.transport,
            now=lambda: NOW,
            boot_id=lambda: BOOT_ID,
            installed_release_digest=RELEASE_DIGEST,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_enroll_persists_pending_state_but_never_grant(self) -> None:
        status = self.client.enroll(token())
        self.assertEqual(status["status"], "PENDING_APPROVAL")
        self.assertEqual(status["metadata"]["slot"], "A")
        raw_state = (self.directory / "state.json").read_text(encoding="utf-8")
        self.assertNotIn(token(), raw_state)
        self.assertNotIn("enrollment_token", raw_state.lower())
        self.assertNotIn("grantId", raw_state)
        self.assertEqual(
            [call[2] is not None for call in self.transport.calls], [True, True]
        )

    def test_lost_claim_response_retries_same_key_nonce_and_payload(self) -> None:
        self.transport.fail_claim_once = True
        with self.assertRaisesRegex(EnrollmentError, "lost response"):
            self.client.enroll(token())
        first_envelope = self.transport.calls[1][1]
        first_payload = self.transport.claim_payloads[0]
        first_fingerprint = self.client.identity.fingerprint
        result = self.client.enroll(token())
        self.assertEqual(result["status"], "PENDING_APPROVAL")
        self.assertEqual(len(self.transport.calls), 3)
        replayed_envelope = self.transport.calls[2][1]
        self.assertEqual(first_envelope, replayed_envelope)
        self.assertEqual(first_payload, self.transport.claim_payloads[1])
        self.assertEqual(first_fingerprint, self.client.identity.fingerprint)

    def test_lost_committed_claim_is_recovered_by_signed_status_without_grant(self) -> None:
        self.transport.fail_claim_once = True
        self.transport.commit_on_failure = True
        with self.assertRaisesRegex(EnrollmentError, "lost response"):
            self.client.enroll(token())
        recovered = self.client.poll_status()
        self.assertEqual(recovered["claimId"], CLAIM_ID)
        self.assertEqual(recovered["status"], "APPROVED")
        protected = self.state.read_state()
        self.assertIsNone(protected["pending_claim"])
        self.assertEqual(protected["claim_id"], CLAIM_ID)
        status_calls = [
            call for call in self.transport.calls if call[0] == ENROLLMENT_STATUS_PATH
        ]
        self.assertEqual(len(status_calls), 1)
        self.assertIsNone(status_calls[0][2])

    def test_lost_uncommitted_claim_keeps_exact_replay_until_grant_resupplied(self) -> None:
        self.transport.fail_claim_once = True
        self.transport.commit_on_failure = False
        with self.assertRaisesRegex(EnrollmentError, "lost response"):
            self.client.enroll(token())
        first_envelope = copy.deepcopy(self.state.read_state()["pending_claim"])
        with self.assertRaisesRegex(EnrollmentError, "no committed claim"):
            self.client.poll_status()
        self.assertEqual(self.state.read_state()["pending_claim"], first_envelope)
        recovered = self.client.enroll(token())
        self.assertEqual(recovered["status"], "PENDING_APPROVAL")
        replay = [
            body
            for path, body, _ in self.transport.calls
            if path == ENROLLMENT_CLAIM_PATH
        ][-1]
        self.assertEqual(replay, first_envelope)

    def test_approval_then_heartbeat_reports_digest_status_and_sequence(self) -> None:
        self.client.enroll(token())
        approved = self.client.poll_status()
        self.assertEqual(approved["status"], "APPROVED")
        online = self.client.heartbeat()
        self.assertEqual(online["status"], "ONLINE")
        self.assertEqual(online["agentSequence"], 1)
        heartbeat = [
            body
            for path, body, _ in self.transport.calls
            if path == NODE_HEARTBEAT_PATH
        ][0]["signedRequest"]["payload"]
        self.assertEqual(heartbeat["bootId"], BOOT_ID)
        self.assertEqual(heartbeat["health"], "HEALTHY")
        self.assertEqual(heartbeat["observedReleaseDigest"], RELEASE_DIGEST)
        self.assertEqual(heartbeat["inventoryDigest"], online["inventoryDigest"])

    def test_lost_heartbeat_response_advances_sequence_before_retry(self) -> None:
        self.client.enroll(token())
        self.client.poll_status()
        self.transport.fail_heartbeat_once = True
        with self.assertRaisesRegex(EnrollmentError, "lost heartbeat"):
            self.client.heartbeat()
        self.assertEqual(self.state.read_state()["agent_sequence"], 1)
        result = self.client.heartbeat()
        self.assertEqual(result["agentSequence"], 2)

    def test_revocation_blocks_heartbeat(self) -> None:
        self.client.enroll(token())
        self.transport.status = "REVOKED"
        revoked = self.client.poll_status()
        self.assertEqual(revoked["status"], "REVOKED")
        with self.assertRaisesRegex(EnrollmentError, "approved node"):
            self.client.heartbeat()

    def test_existing_state_rejects_different_controller_origin(self) -> None:
        self.client.enroll(token())
        other = EnrollmentClient(
            controller_url="https://other.example.com",
            state=self.state,
            transport=self.transport,
            now=lambda: NOW,
            boot_id=lambda: BOOT_ID,
            installed_release_digest=RELEASE_DIGEST,
        )
        with self.assertRaisesRegex(EnrollmentError, "different controller"):
            other.poll_status()

    def test_controller_expected_release_must_match_installed_release(self) -> None:
        mismatch = EnrollmentClient(
            controller_url="https://controller.example.com",
            state=self.state,
            transport=self.transport,
            now=lambda: NOW,
            boot_id=lambda: BOOT_ID,
            installed_release_digest="sha256:" + "2" * 64,
        )
        with self.assertRaisesRegex(EnrollmentError, "different installed Edge release"):
            mismatch.enroll(token())
        self.assertFalse(
            any(path == ENROLLMENT_CLAIM_PATH for path, _, _ in self.transport.calls)
        )


if __name__ == "__main__":
    unittest.main()
