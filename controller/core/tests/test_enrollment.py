import base64
import hashlib
import json
import threading
from datetime import timedelta
from uuid import UUID, uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from django.db import close_old_connections, connection
from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from core.enrollment import (
    ENROLLMENT_CLAIM_PATH,
    ENROLLMENT_CLAIM_VERSION,
    ENROLLMENT_STATUS_PATH,
    ENROLLMENT_STATUS_VERSION,
    HEARTBEAT_PATH,
    HEARTBEAT_VERSION,
    SIGNED_REQUEST_PREFIX,
    SIGNED_REQUEST_VERSION,
    EdgeAPIError,
    approve_enrollment_claim,
    canonical_json_bytes,
    claim_enrollment,
    create_enrollment_challenge,
    issue_enrollment_grant,
    revoke_enrollment_claim,
)
from core.models import (
    AuditEvent,
    EdgeCluster,
    EdgeNode,
    EnrollmentChallenge,
    EnrollmentClaim,
)

PEPPER = "31" * 32
RELEASE_DIGEST = "sha256:" + "a1" * 32
INVENTORY_DIGEST = "sha256:" + "b2" * 32
CONTROLLER_ORIGIN = "https://controller.example.test"


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def canonical_body(value):
    return canonical_json_bytes(value)


def private_key(seed_byte=7):
    return Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)


def public_key_value(key):
    return b64url(
        key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )


def fingerprint(key):
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return "sha256:" + hashlib.sha256(public).hexdigest()


def signed_envelope(*, key, challenge, path, payload, request_id=None):
    signed_request = {
        "apiVersion": SIGNED_REQUEST_VERSION,
        "audience": challenge["audience"],
        "challengeExpiresAt": challenge["challengeExpiresAt"],
        "challengeId": challenge["challengeId"],
        "challengeNonce": challenge["challengeNonce"],
        "keyFingerprint": fingerprint(key),
        "method": "POST",
        "path": path,
        "payload": payload,
        "requestId": request_id or str(uuid4()),
    }
    signature = key.sign(SIGNED_REQUEST_PREFIX + canonical_json_bytes(signed_request))
    return {"signature": b64url(signature), "signedRequest": signed_request}


@override_settings(
    EDGE_ENROLLMENT_TOKEN_PEPPER=PEPPER,
    VIVOLUTION_CONTROLLER_ORIGIN=CONTROLLER_ORIGIN,
)
class EnrollmentAPITests(TestCase):
    def setUp(self):
        self.operator = get_user_model().objects.create_superuser(
            username="operator",
            email="operator@example.test",
            password="test-only-password",
        )
        self.cluster = EdgeCluster.objects.create(
            name="edge-cluster",
            service_mode=EdgeCluster.ServiceMode.SHARED_ENHANCED,
        )
        self.node = EdgeNode.objects.create(
            cluster=self.cluster,
            name="edge-a",
            node_index=1,
            architecture=EdgeNode.Architecture.AMD64,
        )
        self.key = private_key()
        self.grant, self.token = issue_enrollment_grant(
            node=self.node,
            actor=self.operator,
            release_digest=RELEASE_DIGEST,
        )

    def post(self, path, value, *, grant=None):
        headers = {}
        if grant is not None:
            headers["HTTP_AUTHORIZATION"] = f"Vivolution-Enrollment {grant}"
        return self.client.generic(
            "POST",
            path,
            data=canonical_body(value),
            content_type="application/json",
            **headers,
        )

    def enrollment_challenge(self, *, key=None, token=None):
        key = key or self.key
        response = self.post(
            "/api/edge/v1/enrollment/challenge",
            {
                "apiVersion": "edge.vivolution.ae/enrollment-challenge-request/v1",
                "clientNonce": b64url(bytes([4]) * 32),
                "publicKey": public_key_value(key),
            },
            grant=token or self.token,
        )
        self.assertEqual(response.status_code, 201, response.content)
        return response.json()

    def claim_payload(self, challenge, *, key=None, **changes):
        key = key or self.key
        payload = {
            "apiVersion": ENROLLMENT_CLAIM_VERSION,
            "clientNonce": b64url(bytes([4]) * 32),
            "clusterId": str(self.cluster.id),
            "generation": 1,
            "grantId": str(self.grant.id),
            "inventoryDigest": INVENTORY_DIGEST,
            "nodeId": str(self.node.id),
            "publicKey": public_key_value(key),
            "releaseDigest": RELEASE_DIGEST,
            "slot": "A",
        }
        payload.update(changes)
        return signed_envelope(
            key=key,
            challenge=challenge,
            path=ENROLLMENT_CLAIM_PATH,
            payload=payload,
        )

    def claim(self):
        challenge = self.enrollment_challenge()
        envelope = self.claim_payload(challenge)
        response = self.post(ENROLLMENT_CLAIM_PATH, envelope, grant=self.token)
        self.assertEqual(response.status_code, 201, response.content)
        return response.json(), envelope

    def node_challenge(self, purpose):
        response = self.post(
            "/api/edge/v1/node/challenge",
            {
                "apiVersion": "edge.vivolution.ae/node-challenge-request/v1",
                "generation": 1,
                "keyFingerprint": fingerprint(self.key),
                "nodeId": str(self.node.id),
                "purpose": purpose,
            },
        )
        self.assertEqual(response.status_code, 201, response.content)
        return response.json()

    def status_envelope(self, challenge, request_id=None):
        return signed_envelope(
            key=self.key,
            challenge=challenge,
            path=ENROLLMENT_STATUS_PATH,
            payload={
                "apiVersion": ENROLLMENT_STATUS_VERSION,
                "generation": 1,
                "nodeId": str(self.node.id),
            },
            request_id=request_id,
        )

    def heartbeat_envelope(self, challenge, *, sequence, **changes):
        payload = {
            "agentSequence": sequence,
            "apiVersion": HEARTBEAT_VERSION,
            "bootId": str(UUID("11111111-1111-4111-8111-111111111111")),
            "generation": 1,
            "health": "HEALTHY",
            "inventoryDigest": INVENTORY_DIGEST,
            "nodeId": str(self.node.id),
            "observedReleaseDigest": RELEASE_DIGEST,
            "sentAt": timezone.now().replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        payload.update(changes)
        return signed_envelope(
            key=self.key,
            challenge=challenge,
            path=HEARTBEAT_PATH,
            payload=payload,
        )

    def test_claim_binds_key_scope_and_exact_retry(self):
        result, envelope = self.claim()
        self.assertEqual(result["status"], "PENDING_APPROVAL")
        self.assertEqual(result["keyFingerprint"], fingerprint(self.key))
        self.node.refresh_from_db()
        self.assertEqual(self.node.status, EdgeNode.Status.PENDING_APPROVAL)
        claim = EnrollmentClaim.objects.get(node=self.node, generation=1)
        self.assertEqual(claim.public_key_fingerprint, fingerprint(self.key))
        self.assertFalse(self.grant.token_digest == self.token)
        self.assertNotIn(self.token, json.dumps(AuditEvent.objects.first().detail))

        retry = self.post(ENROLLMENT_CLAIM_PATH, envelope, grant=self.token)
        self.assertEqual(retry.status_code, 200, retry.content)
        self.assertEqual(retry.json(), result)
        self.assertEqual(EnrollmentClaim.objects.count(), 1)

    def test_claim_rejects_wrong_scope_and_different_key(self):
        challenge = self.enrollment_challenge()
        wrong_scope = self.claim_payload(challenge, slot="B")
        response = self.post(ENROLLMENT_CLAIM_PATH, wrong_scope, grant=self.token)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["code"], "wrong_claim_scope")
        self.assertEqual(EnrollmentClaim.objects.count(), 0)

        other_key = private_key(8)
        different_key = self.claim_payload(challenge, key=other_key)
        response = self.post(ENROLLMENT_CLAIM_PATH, different_key, grant=self.token)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["code"], "invalid_proof_scope")

    def test_expired_grant_and_challenge_fail_closed(self):
        past = timezone.now() - timedelta(minutes=20)
        type(self.grant).objects.filter(pk=self.grant.pk).update(
            created_at=past,
            expires_at=past + timedelta(minutes=10),
        )
        response = self.post(
            "/api/edge/v1/enrollment/challenge",
            {
                "apiVersion": "edge.vivolution.ae/enrollment-challenge-request/v1",
                "clientNonce": b64url(bytes([4]) * 32),
                "publicKey": public_key_value(self.key),
            },
            grant=self.token,
        )
        self.assertEqual(response.status_code, 410)
        self.assertEqual(response.json()["code"], "grant_expired")

        self.grant.expires_at = timezone.now() + timedelta(minutes=10)
        self.grant.save(update_fields=["expires_at"])
        challenge = self.enrollment_challenge()
        challenge_created = timezone.now() - timedelta(minutes=2)
        EnrollmentChallenge.objects.filter(pk=challenge["challengeId"]).update(
            created_at=challenge_created,
            expires_at=challenge_created + timedelta(minutes=1),
        )
        expired = dict(challenge)
        expired["challengeExpiresAt"] = (
            challenge_created + timedelta(minutes=1)
        ).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
        envelope = self.claim_payload(expired)
        response = self.post(ENROLLMENT_CLAIM_PATH, envelope, grant=self.token)
        self.assertEqual(response.status_code, 410)
        self.assertEqual(response.json()["code"], "challenge_expired")

    def test_new_challenge_prunes_only_expired_rows_outside_replay_retention(self):
        old_challenge = self.enrollment_challenge()
        old_created_at = timezone.now() - timedelta(hours=74)
        EnrollmentChallenge.objects.filter(pk=old_challenge["challengeId"]).update(
            created_at=old_created_at,
            expires_at=old_created_at + timedelta(minutes=1),
        )

        recent_challenge = self.enrollment_challenge()
        self.assertFalse(
            EnrollmentChallenge.objects.filter(pk=old_challenge["challengeId"]).exists()
        )
        self.assertTrue(
            EnrollmentChallenge.objects.filter(pk=recent_challenge["challengeId"]).exists()
        )

    def test_status_requires_proof_and_reports_explicit_approval(self):
        result, _ = self.claim()
        challenge = self.node_challenge("STATUS")
        envelope = self.status_envelope(challenge)
        pending = self.post(ENROLLMENT_STATUS_PATH, envelope)
        self.assertEqual(pending.status_code, 200, pending.content)
        self.assertEqual(
            pending.json(),
            {
                "apiVersion": "edge.vivolution.ae/enrollment-status-result/v1",
                "approvedAt": None,
                "claimId": result["claimId"],
                "generation": 1,
                "keyFingerprint": fingerprint(self.key),
                "nodeId": str(self.node.id),
                "revokedAt": None,
                "status": "PENDING_APPROVAL",
            },
        )

        claim = EnrollmentClaim.objects.get(pk=result["claimId"])
        approve_enrollment_claim(claim=claim, actor=self.operator)
        challenge = self.node_challenge("STATUS")
        approved = self.post(
            ENROLLMENT_STATUS_PATH,
            self.status_envelope(challenge),
        )
        self.assertEqual(approved.status_code, 200, approved.content)
        self.assertEqual(approved.json()["status"], "APPROVED")
        self.assertIsNotNone(approved.json()["approvedAt"])

    def test_heartbeat_is_monotonic_and_requires_approved_baseline(self):
        result, _ = self.claim()
        claim = EnrollmentClaim.objects.get(pk=result["claimId"])
        approve_enrollment_claim(claim=claim, actor=self.operator)
        challenge = self.node_challenge("HEARTBEAT")
        envelope = self.heartbeat_envelope(challenge, sequence=1)
        response = self.post(HEARTBEAT_PATH, envelope)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["status"], "ONLINE")
        self.node.refresh_from_db()
        self.assertEqual(self.node.last_heartbeat_sequence, 1)
        self.assertEqual(self.node.status, EdgeNode.Status.ONLINE)

        retry = self.post(HEARTBEAT_PATH, envelope)
        self.assertEqual(retry.status_code, 200)
        self.assertEqual(retry.json(), response.json())

        challenge = self.node_challenge("HEARTBEAT")
        replay = self.post(
            HEARTBEAT_PATH,
            self.heartbeat_envelope(challenge, sequence=1),
        )
        self.assertEqual(replay.status_code, 409)
        self.assertEqual(replay.json()["code"], "sequence_replayed")

        challenge = self.node_challenge("HEARTBEAT")
        drift = self.post(
            HEARTBEAT_PATH,
            self.heartbeat_envelope(
                challenge,
                sequence=2,
                observedReleaseDigest="sha256:" + "cc" * 32,
            ),
        )
        self.assertEqual(drift.status_code, 409)
        self.assertEqual(drift.json()["code"], "release_drift")

    def test_revoke_blocks_new_and_idempotent_node_requests(self):
        result, claim_envelope = self.claim()
        claim = EnrollmentClaim.objects.get(pk=result["claimId"])
        approve_enrollment_claim(claim=claim, actor=self.operator)
        challenge = self.node_challenge("HEARTBEAT")
        envelope = self.heartbeat_envelope(challenge, sequence=1)
        accepted = self.post(HEARTBEAT_PATH, envelope)
        self.assertEqual(accepted.status_code, 200)
        status_challenge = self.node_challenge("STATUS")
        status_envelope = self.status_envelope(status_challenge)
        accepted_status = self.post(ENROLLMENT_STATUS_PATH, status_envelope)
        self.assertEqual(accepted_status.status_code, 200)

        revoke_enrollment_claim(
            claim=claim,
            actor=self.operator,
            reason="Test revocation",
        )
        retry = self.post(HEARTBEAT_PATH, envelope)
        self.assertEqual(retry.status_code, 403)
        self.assertEqual(retry.json()["code"], "node_revoked")
        claim_retry = self.post(
            ENROLLMENT_CLAIM_PATH,
            claim_envelope,
            grant=self.token,
        )
        self.assertEqual(claim_retry.status_code, 403)
        self.assertEqual(claim_retry.json()["code"], "node_revoked")
        status_retry = self.post(ENROLLMENT_STATUS_PATH, status_envelope)
        self.assertEqual(status_retry.status_code, 403)
        self.assertEqual(status_retry.json()["code"], "node_revoked")
        for purpose in ("STATUS", "HEARTBEAT"):
            challenge_response = self.post(
                "/api/edge/v1/node/challenge",
                {
                    "apiVersion": "edge.vivolution.ae/node-challenge-request/v1",
                    "generation": 1,
                    "keyFingerprint": fingerprint(self.key),
                    "nodeId": str(self.node.id),
                    "purpose": purpose,
                },
            )
            self.assertEqual(challenge_response.status_code, 403)
            self.assertEqual(challenge_response.json()["code"], "node_revoked")

    def test_strict_json_and_bounded_errors(self):
        response = self.client.generic(
            "POST",
            "/api/edge/v1/enrollment/challenge",
            data=b'{"apiVersion":"x", "apiVersion":"y"}',
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Vivolution-Enrollment {self.token}",
        )
        self.assertEqual(response.status_code, 400)
        error = response.json()
        self.assertEqual(set(error), {"apiVersion", "code", "message", "requestId"})
        UUID(error["requestId"])

        noncanonical = self.client.generic(
            "POST",
            "/api/edge/v1/enrollment/challenge",
            data=(
                b'{"apiVersion":"edge.vivolution.ae/enrollment-challenge-request/v1", '
                b'"clientNonce":"x","publicKey":"x"}'
            ),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Vivolution-Enrollment {self.token}",
        )
        self.assertEqual(noncanonical.status_code, 400)
        self.assertEqual(noncanonical.json()["code"], "noncanonical_json")

        invalid_unicode = self.client.generic(
            "POST",
            "/api/edge/v1/enrollment/challenge",
            data=b'{"apiVersion":"\\ud800","clientNonce":"x","publicKey":"x"}',
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Vivolution-Enrollment {self.token}",
        )
        self.assertEqual(invalid_unicode.status_code, 400)
        self.assertEqual(invalid_unicode.json()["code"], "invalid_json")

        oversized = b"x" * 16385
        response = self.client.generic(
            "POST",
            "/api/edge/v1/enrollment/challenge",
            data=oversized,
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Vivolution-Enrollment {self.token}",
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["code"], "body_too_large")

        malformed_length = self.client.generic(
            "POST",
            "/api/edge/v1/enrollment/challenge",
            data=b"{}",
            content_type="application/json",
            CONTENT_LENGTH="not-an-integer",
            HTTP_AUTHORIZATION=f"Vivolution-Enrollment {self.token}",
        )
        self.assertEqual(malformed_length.status_code, 400)
        self.assertEqual(malformed_length.json()["code"], "invalid_content_length")

    def test_non_post_methods_return_the_bounded_api_error_contract(self):
        path = "/api/edge/v1/enrollment/challenge"
        for method in ("get", "options", "put"):
            with self.subTest(method=method):
                response = getattr(self.client, method)(path)
                self.assertEqual(response.status_code, 405)
                self.assertEqual(response.headers["Allow"], "POST")
                self.assertEqual(
                    set(response.json()),
                    {"apiVersion", "code", "message", "requestId"},
                )
                self.assertEqual(response.json()["code"], "method_not_allowed")
                self.assertIn("no-store", response.headers["Cache-Control"])
                self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

        head = self.client.head(path)
        self.assertEqual(head.status_code, 405)
        self.assertEqual(head.headers["Allow"], "POST")
        self.assertIn("no-store", head.headers["Cache-Control"])

    @override_settings(
        TESTING=False,
        SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"),
    )
    def test_public_api_requires_https_from_the_managed_proxy(self):
        request_data = {
            "apiVersion": "edge.vivolution.ae/enrollment-challenge-request/v1",
            "clientNonce": b64url(bytes([4]) * 32),
            "publicKey": public_key_value(self.key),
        }
        direct = self.post(
            "/api/edge/v1/enrollment/challenge",
            request_data,
            grant=self.token,
        )
        self.assertEqual(direct.status_code, 400)
        self.assertEqual(direct.json()["code"], "https_required")

        proxied = self.client.generic(
            "POST",
            "/api/edge/v1/enrollment/challenge",
            data=canonical_body(request_data),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Vivolution-Enrollment {self.token}",
            HTTP_X_FORWARDED_PROTO="https",
        )
        self.assertEqual(proxied.status_code, 201, proxied.content)

    def test_shared_edge_signature_vector_is_stable(self):
        """This same fixed vector is asserted by the separately packaged Edge client."""

        key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        signed_request = {
            "apiVersion": SIGNED_REQUEST_VERSION,
            "audience": CONTROLLER_ORIGIN,
            "challengeExpiresAt": "2026-09-01T12:00:00Z",
            "challengeId": "11111111-1111-4111-8111-111111111111",
            "challengeNonce": "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI",
            "keyFingerprint": (
                "sha256:56475aa75463474c0285df5dbf2bcab7"
                "3da651358839e9b77481b2eab107708c"
            ),
            "method": "POST",
            "path": ENROLLMENT_STATUS_PATH,
            "payload": {
                "apiVersion": ENROLLMENT_STATUS_VERSION,
                "generation": 1,
                "nodeId": "33333333-3333-4333-8333-333333333333",
            },
            "requestId": "22222222-2222-4222-8222-222222222222",
        }
        message = SIGNED_REQUEST_PREFIX + canonical_json_bytes(signed_request)
        self.assertEqual(
            hashlib.sha256(message).hexdigest(),
            "7b010088b8aa2b6c45bdcf0a2c1a3dc55c1a3d5d3f5270914361bfd2794bac3a",
        )
        self.assertEqual(
            b64url(key.sign(message)),
            "RcgBkTDREldDFJLBux7qAc5tXEqmZ0AefE1u6kkXdFWr04GuzIJUaGNoiJE_haak"
            "jJctq9-VIHH8X_wygXPkDg",
        )


@override_settings(
    EDGE_ENROLLMENT_TOKEN_PEPPER=PEPPER,
    VIVOLUTION_CONTROLLER_ORIGIN=CONTROLLER_ORIGIN,
)
class PostgreSQLClaimRaceTests(TransactionTestCase):
    reset_sequences = True

    def test_simultaneous_different_key_claim_race_has_one_winner(self):
        if connection.vendor != "postgresql":
            self.skipTest("PostgreSQL concurrency integration test")
        operator = get_user_model().objects.create_superuser(
            username="race-operator",
            email="race@example.test",
            password="test-only-password",
        )
        cluster = EdgeCluster.objects.create(
            name="race-cluster",
            service_mode=EdgeCluster.ServiceMode.SHARED_ENHANCED,
        )
        node = EdgeNode.objects.create(
            cluster=cluster,
            name="race-node",
            node_index=1,
            architecture=EdgeNode.Architecture.AMD64,
        )
        grant, token = issue_enrollment_grant(
            node=node,
            actor=operator,
            release_digest=RELEASE_DIGEST,
        )
        candidates = []
        for seed in (21, 22):
            key = private_key(seed)
            challenge = create_enrollment_challenge(
                grant_token=token,
                request_data={
                    "apiVersion": "edge.vivolution.ae/enrollment-challenge-request/v1",
                    "clientNonce": b64url(bytes([seed]) * 32),
                    "publicKey": public_key_value(key),
                },
            )
            payload = {
                "apiVersion": ENROLLMENT_CLAIM_VERSION,
                "clientNonce": b64url(bytes([seed]) * 32),
                "clusterId": str(cluster.id),
                "generation": 1,
                "grantId": str(grant.id),
                "inventoryDigest": INVENTORY_DIGEST,
                "nodeId": str(node.id),
                "publicKey": public_key_value(key),
                "releaseDigest": RELEASE_DIGEST,
                "slot": "A",
            }
            envelope = signed_envelope(
                key=key,
                challenge=challenge,
                path=ENROLLMENT_CLAIM_PATH,
                payload=payload,
            )
            candidates.append((envelope, canonical_body(envelope)))

        barrier = threading.Barrier(2)
        results = []

        def attempt(candidate):
            close_old_connections()
            barrier.wait(timeout=5)
            try:
                claim_enrollment(
                    grant_token=token,
                    envelope=candidate[0],
                    raw_body=candidate[1],
                )
            except EdgeAPIError as exc:
                results.append(("error", exc.status))
            else:
                results.append(("success", 201))
            finally:
                close_old_connections()

        threads = [threading.Thread(target=attempt, args=(item,)) for item in candidates]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual([item[0] for item in results].count("success"), 1)
        self.assertEqual(EnrollmentClaim.objects.count(), 1)
