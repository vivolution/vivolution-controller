from __future__ import annotations

import base64
import json
import subprocess
import sys
import unittest
import urllib.error
from pathlib import Path

FILES = Path(__file__).resolve().parents[1] / "roles/carrier_certificate/files"
sys.path.insert(0, str(FILES))
import reconcile_carrier_acme_challenge as cleanup
import verify_carrier_acme_authority as authority

SUBSCRIPTION_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
TENANT_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
PRINCIPAL_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
RESOURCE_GROUP = "DNS_Zones"
ZONE = "acme-carrier.vivolution.ae"
SERVER = "carrier.vivolution.ae"
ALIAS = "_acme-challenge.carrier.vivolution.ae"
TARGET = "_acme-challenge.acme-carrier.vivolution.ae"
PUBLIC_IPV4 = "40.123.208.212"
RESOLVER = "168.63.129.16"
NOW = 1_000_000


def _segment(value: object) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(value, separators=(",", ":")).encode()
    ).decode().rstrip("=")


TOKEN = ".".join(
    (
        _segment({"alg": "RS256", "typ": "JWT"}),
        _segment(
            {
                "aud": "https://management.azure.com/",
                "exp": NOW + 3600,
                "oid": PRINCIPAL_ID,
                "tid": TENANT_ID,
            }
        ),
        "x" * 86,
    )
)


class Response:
    def __init__(self, url: str, *, status: int = 200, content: bytes = b"") -> None:
        self._url = url
        self.status = status
        self._content = content

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def geturl(self) -> str:
        return self._url

    def read(self, _limit: int) -> bytes:
        return self._content


def token_response(url: str) -> Response:
    return Response(url, content=json.dumps({"access_token": TOKEN}).encode())


def zone_payload() -> dict[str, object]:
    return {
        "id": (
            f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/"
            f"providers/Microsoft.Network/dnsZones/{ZONE}"
        ),
        "location": "global",
        "name": ZONE,
        "properties": {
            "nameServers": [
                "ns1-01.azure-dns.com.",
                "ns2-01.azure-dns.net.",
                "ns3-01.azure-dns.org.",
                "ns4-01.azure-dns.info.",
            ]
        },
        "tags": authority.EXPECTED_TAGS,
        "type": "Microsoft.Network/dnsZones",
    }


def dig_runner(values: dict[tuple[str, str], list[str]]):
    def run(argv, **_kwargs):
        name, record_type = argv[-2:]
        output = "".join(value + "\n" for value in values[(name, record_type)])
        return subprocess.CompletedProcess(argv, 0, output, "")

    return run


class CarrierAuthorityTests(unittest.TestCase):
    def opener(self, request, *, timeout):
        self.assertEqual(timeout, 5)
        if request.full_url == authority.IMDS_TOKEN_URL:
            return token_response(request.full_url)
        if request.full_url == authority._zone_url(
            SUBSCRIPTION_ID, RESOURCE_GROUP, ZONE
        ):
            return Response(
                request.full_url, content=json.dumps(zone_payload()).encode()
            )
        if request.full_url == authority._txt_url(
            SUBSCRIPTION_ID, RESOURCE_GROUP, ZONE
        ):
            raise urllib.error.HTTPError(
                request.full_url, 404, "absent", {}, None
            )
        self.fail(f"unexpected request: {request.full_url}")

    def validate(self, dns_values):
        return authority.validate_authority(
            subscription_id=SUBSCRIPTION_ID,
            tenant_id=TENANT_ID,
            expected_principal_id=PRINCIPAL_ID,
            resource_group=RESOURCE_GROUP,
            zone=ZONE,
            certificate_name=SERVER,
            challenge_alias=ALIAS,
            challenge_target=TARGET,
            expected_public_ipv4=PUBLIC_IPV4,
            resolver=RESOLVER,
            opener=self.opener,
            dig_runner=dig_runner(dns_values),
            now=NOW,
        )

    def test_exact_managed_identity_zone_and_public_dns_pass(self) -> None:
        evidence = self.validate(
            {
                (SERVER, "A"): [PUBLIC_IPV4],
                (ALIAS, "CNAME"): [TARGET + "."],
                (ZONE, "NS"): [
                    "ns4-01.azure-dns.info.",
                    "ns2-01.azure-dns.net.",
                    "ns1-01.azure-dns.com.",
                    "ns3-01.azure-dns.org.",
                ],
            }
        )
        self.assertEqual(evidence["status"], "CARRIER_ACME_AUTHORITY_BOUND")
        self.assertEqual(evidence["managedIdentityPrincipalId"], PRINCIPAL_ID)

    def test_wrong_challenge_alias_target_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            authority.AuthorityVerificationError, "challenge CNAME differs"
        ):
            self.validate(
                {
                    (SERVER, "A"): [PUBLIC_IPV4],
                    (ALIAS, "CNAME"): ["wrong.example.invalid."],
                    (ZONE, "NS"): [
                        "ns1-01.azure-dns.com.",
                        "ns2-01.azure-dns.net.",
                        "ns3-01.azure-dns.org.",
                        "ns4-01.azure-dns.info.",
                    ],
                }
            )


class CarrierChallengeCleanupTests(unittest.TestCase):
    def test_exact_record_is_conditionally_deleted_and_absence_proved(self) -> None:
        url = cleanup._record_url(SUBSCRIPTION_ID, RESOURCE_GROUP, ZONE)
        record = {
            "etag": 'W/"bounded-etag"',
            "id": url.split("?", 1)[0],
            "name": "_acme-challenge",
            "properties": {
                "TTL": 60,
                "TXTRecords": [{"value": ["A" * 43]}],
            },
            "type": "Microsoft.Network/dnsZones/TXT",
        }
        arm_calls = 0

        def opener(request, *, timeout):
            nonlocal arm_calls
            self.assertEqual(timeout, 5)
            if request.full_url == cleanup.IMDS_TOKEN_URL:
                return token_response(request.full_url)
            arm_calls += 1
            if arm_calls == 1:
                self.assertEqual(request.get_method(), "GET")
                return Response(url, content=json.dumps(record).encode())
            if arm_calls == 2:
                self.assertEqual(request.get_method(), "DELETE")
                self.assertEqual(request.get_header("If-match"), 'W/"bounded-etag"')
                return Response(url, status=204)
            raise urllib.error.HTTPError(url, 404, "absent", {}, None)

        result = cleanup.reconcile_challenge(
            SUBSCRIPTION_ID,
            TENANT_ID,
            PRINCIPAL_ID,
            RESOURCE_GROUP,
            ZONE,
            mode="reconcile",
            opener=opener,
            sleeper=lambda _seconds: self.fail("absence must not sleep"),
            now=NOW,
        )
        self.assertEqual(result, "CARRIER_ACME_CHALLENGE_RECONCILED")
        self.assertEqual(arm_calls, 3)

    def test_malformed_record_is_never_deleted(self) -> None:
        url = cleanup._record_url(SUBSCRIPTION_ID, RESOURCE_GROUP, ZONE)
        record = {
            "etag": 'W/"bounded-etag"',
            "id": url.split("?", 1)[0],
            "name": "_acme-challenge",
            "properties": {
                "TTL": 300,
                "TXTRecords": [{"value": ["not-lego"]}],
            },
            "type": "Microsoft.Network/dnsZones/TXT",
        }
        methods = []

        def opener(request, *, timeout):
            self.assertEqual(timeout, 5)
            if request.full_url == cleanup.IMDS_TOKEN_URL:
                return token_response(request.full_url)
            methods.append(request.get_method())
            return Response(url, content=json.dumps(record).encode())

        with self.assertRaisesRegex(
            cleanup.ChallengeReconciliationError, "bounded Lego challenge shape"
        ):
            cleanup.reconcile_challenge(
                SUBSCRIPTION_ID,
                TENANT_ID,
                PRINCIPAL_ID,
                RESOURCE_GROUP,
                ZONE,
                mode="reconcile",
                opener=opener,
                now=NOW,
            )
        self.assertEqual(methods, ["GET"])


if __name__ == "__main__":
    unittest.main()
