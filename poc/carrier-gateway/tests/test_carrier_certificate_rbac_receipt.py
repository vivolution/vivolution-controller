from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = (
    ROOT
    / "roles/carrier_certificate/files/verify_carrier_acme_rbac_receipt.py"
)
SPEC = importlib.util.spec_from_file_location(
    "carrier_certificate_rbac_receipt", VERIFIER_PATH
)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)

INFRA_ROOT = ROOT.parents[1] / "infra/azure-poc"
sys.path.insert(0, str(INFRA_ROOT))
PRODUCER_SPEC = importlib.util.spec_from_file_location(
    "carrier_rbac_receipt_producer",
    INFRA_ROOT / "reconcile_root_direct_dns_acme_authority.py",
)
assert PRODUCER_SPEC is not None and PRODUCER_SPEC.loader is not None
producer = importlib.util.module_from_spec(PRODUCER_SPEC)
PRODUCER_SPEC.loader.exec_module(producer)

NOW = datetime(2026, 8, 31, 8, 0, tzinfo=timezone.utc)
SUBSCRIPTION = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
TENANT = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
PRINCIPAL = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
ASSIGNMENT = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
KEY_ID = "carrier-acme-rbac-2026-08"
ZONE = "acme-carrier.vivolution.ae"
RESOURCE_GROUP = "DNS_Zones"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


class CarrierCertificateRbacReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key_pem = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        public_der = self.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_digest = hashlib.sha256(public_der).hexdigest()

    def receipt(
        self,
        *,
        payload_updates: dict[str, object] | None = None,
        issued_at: datetime = NOW,
        expires_at: datetime | None = None,
    ) -> bytes:
        zone_id = (
            f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{RESOURCE_GROUP}/"
            f"providers/Microsoft.Network/dnsZones/{ZONE}"
        )
        payload: dict[str, object] = {
            "assignmentId": (
                zone_id
                + "/providers/Microsoft.Authorization/roleAssignments/"
                + ASSIGNMENT
            ),
            "authorityDiscoverySha256": "1" * 64,
            "cp1PrincipalId": PRINCIPAL,
            "dnsResourceGroup": RESOURCE_GROUP,
            "expiresAt": (expires_at or issued_at + timedelta(minutes=15)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "humanSubscriptionAdministrationEvaluated": False,
            "issuedAt": issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "roleActions": sorted(verifier.ROLE_ACTIONS),
            "roleDefinitionGuid": verifier.ROLE_GUID,
            "roleDefinitionId": (
                f"/subscriptions/{SUBSCRIPTION}/providers/"
                f"Microsoft.Authorization/roleDefinitions/{verifier.ROLE_GUID}"
            ),
            "roleDescription": verifier.ROLE_DESCRIPTION,
            "roleName": verifier.ROLE_NAME,
            "signingKeyId": KEY_ID,
            "signingPublicKeySha256": self.public_digest,
            "subscriptionId": SUBSCRIPTION,
            "tenantId": TENANT,
            "zone": ZONE,
            "zoneResourceId": zone_id,
        }
        payload.update(payload_updates or {})
        signed: dict[str, object] = {
            "apiVersion": verifier.API_VERSION,
            "kind": verifier.KIND,
            "payload": payload,
            "payloadSha256": hashlib.sha256(_canonical(payload)).hexdigest(),
            "signatureAlgorithm": "Ed25519",
        }
        signature = self.private_key.sign(_canonical(signed))
        return _canonical(
            {**signed, "signature": base64.b64encode(signature).decode("ascii")}
        ) + b"\n"

    def validate(self, receipt: bytes) -> dict[str, object]:
        return verifier.validate_receipt(
            receipt,
            self.public_key_pem,
            expected_subscription_id=SUBSCRIPTION,
            expected_tenant_id=TENANT,
            expected_cp1_principal_id=PRINCIPAL,
            expected_resource_group=RESOURCE_GROUP,
            expected_zone=ZONE,
            expected_signing_key_id=KEY_ID,
            expected_public_key_sha256=self.public_digest,
            maximum_lifetime_seconds=3600,
            minimum_remaining_seconds=60,
            now=NOW,
        )

    def test_exact_fresh_signed_exclusive_rbac_receipt_passes(self) -> None:
        evidence = self.validate(self.receipt())
        self.assertEqual(evidence["status"], "CARRIER_ACME_RBAC_RECEIPT_VALID")
        self.assertFalse(evidence["humanSubscriptionAdministrationEvaluated"])
        self.assertEqual(evidence["signingPublicKeySha256"], self.public_digest)

    def test_stale_future_and_overlong_receipts_are_rejected(self) -> None:
        cases = (
            self.receipt(
                issued_at=NOW - timedelta(hours=2),
                expires_at=NOW - timedelta(minutes=1),
            ),
            self.receipt(issued_at=NOW + timedelta(minutes=1)),
            self.receipt(expires_at=NOW + timedelta(hours=2)),
        )
        for receipt in cases:
            with self.subTest(receipt=receipt[:32]), self.assertRaisesRegex(
                verifier.RbacReceiptError, "stale, future-dated, or overlong"
            ):
                self.validate(receipt)

    def test_role_drift_or_human_administration_is_rejected(self) -> None:
        cases = (
            {"roleActions": sorted(verifier.ROLE_ACTIONS | {"Microsoft.Authorization/*"})},
            {"humanSubscriptionAdministrationEvaluated": True},
            {"cp1PrincipalId": ASSIGNMENT},
        )
        for update in cases:
            with self.subTest(update=update), self.assertRaisesRegex(
                verifier.RbacReceiptError, "Azure bindings differ"
            ):
                self.validate(self.receipt(payload_updates=update))

    def test_tamper_and_wrong_pinned_key_are_rejected(self) -> None:
        receipt = bytearray(self.receipt())
        receipt[receipt.index(b"authorityDiscoverySha256") + 30] ^= 1
        with self.assertRaises(verifier.RbacReceiptError):
            self.validate(bytes(receipt))

        wrong_key = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with self.assertRaisesRegex(
            verifier.RbacReceiptError, "signing trust anchor differs"
        ):
            verifier.validate_receipt(
                self.receipt(),
                wrong_key,
                expected_subscription_id=SUBSCRIPTION,
                expected_tenant_id=TENANT,
                expected_cp1_principal_id=PRINCIPAL,
                expected_resource_group=RESOURCE_GROUP,
                expected_zone=ZONE,
                expected_signing_key_id=KEY_ID,
                expected_public_key_sha256=self.public_digest,
                maximum_lifetime_seconds=3600,
                minimum_remaining_seconds=60,
                now=NOW,
            )

    def test_controller_publishes_the_matching_canonical_signer_key(self) -> None:
        seed = bytes(range(32))
        public_pem = producer._signing_public_key_pem(seed)
        public_key = serialization.load_pem_public_key(public_pem)
        self.assertIsInstance(public_key, ed25519.Ed25519PublicKey)
        self.assertEqual(
            public_pem,
            public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "signer.pem"
            digest = producer._write_owner_file(output, public_pem, "signer public key")
            self.assertEqual(output.read_bytes(), public_pem)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(output.stat().st_uid, os.getuid())
            self.assertEqual(digest, hashlib.sha256(public_pem).hexdigest())


if __name__ == "__main__":
    unittest.main()
