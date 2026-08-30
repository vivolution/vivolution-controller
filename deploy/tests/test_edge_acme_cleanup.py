from __future__ import annotations

import json
import sys
import unittest
import urllib.error
from pathlib import Path


ROLE_FILES = Path(__file__).resolve().parents[1] / "roles" / "edge_certificate" / "files"
sys.path.insert(0, str(ROLE_FILES))
import verify_acme_cleanup as cleanup  # noqa: E402


SUBSCRIPTION_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
RESOURCE_GROUP = "DNS_Zones"
ZONE = "acme-sbc1.voice.example.invalid"


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


def token_response() -> Response:
    return Response(
        cleanup.IMDS_TOKEN_URL,
        content=json.dumps({"access_token": "x" * 64}).encode(),
    )


class EdgeAcmeCleanupTests(unittest.TestCase):
    def test_absent_record_is_accepted_without_leaking_token(self) -> None:
        requests = []

        def opener(request, *, timeout):
            self.assertEqual(timeout, 5)
            requests.append(request)
            if len(requests) == 1:
                self.assertEqual(request.get_header("Metadata"), "true")
                return token_response()
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(request.get_header("Authorization"), "Bearer " + "x" * 64)
            raise urllib.error.HTTPError(request.full_url, 404, "absent", {}, None)

        cleanup.verify_absent(
            SUBSCRIPTION_ID,
            RESOURCE_GROUP,
            ZONE,
            opener=opener,
            sleeper=lambda _seconds: self.fail("absence must not sleep"),
        )
        self.assertEqual(len(requests), 2)
        self.assertNotIn("x" * 64, cleanup._record_url(SUBSCRIPTION_ID, RESOURCE_GROUP, ZONE))

    def test_remaining_record_fails_after_exact_bounded_poll(self) -> None:
        arm_calls = 0
        sleeps = []

        def opener(request, *, timeout):
            nonlocal arm_calls
            self.assertEqual(timeout, 5)
            if request.full_url == cleanup.IMDS_TOKEN_URL:
                return token_response()
            arm_calls += 1
            return Response(request.full_url, status=200)

        with self.assertRaisesRegex(
            cleanup.CleanupVerificationError, "record set remains"
        ):
            cleanup.verify_absent(
                SUBSCRIPTION_ID,
                RESOURCE_GROUP,
                ZONE,
                opener=opener,
                sleeper=sleeps.append,
            )
        self.assertEqual(arm_calls, cleanup.MAX_ATTEMPTS)
        self.assertEqual(sleeps, [cleanup.RETRY_SECONDS] * (cleanup.MAX_ATTEMPTS - 1))

    def test_authorization_failure_is_immediately_rejected(self) -> None:
        def opener(request, *, timeout):
            self.assertEqual(timeout, 5)
            if request.full_url == cleanup.IMDS_TOKEN_URL:
                return token_response()
            raise urllib.error.HTTPError(request.full_url, 403, "forbidden", {}, None)

        with self.assertRaisesRegex(
            cleanup.CleanupVerificationError, "unexpected cleanup status"
        ):
            cleanup.verify_absent(
                SUBSCRIPTION_ID,
                RESOURCE_GROUP,
                ZONE,
                opener=opener,
                sleeper=lambda _seconds: self.fail("403 must not retry"),
            )

    def test_redirected_final_404_is_rejected(self) -> None:
        redirected_url = "https://redirected.example.invalid/missing"

        def opener(request, *, timeout):
            self.assertEqual(timeout, 5)
            if request.full_url == cleanup.IMDS_TOKEN_URL:
                return token_response()
            raise urllib.error.HTTPError(
                redirected_url, 404, "redirected absence", {}, None
            )

        with self.assertRaisesRegex(
            cleanup.CleanupVerificationError, "redirected"
        ):
            cleanup.verify_absent(
                SUBSCRIPTION_ID,
                RESOURCE_GROUP,
                ZONE,
                opener=opener,
                sleeper=lambda _seconds: self.fail("redirect must not retry"),
            )

    def test_transient_arm_failures_are_bounded_and_absence_still_wins(self) -> None:
        statuses = [429, 503, 404]
        sleeps = []

        def opener(request, *, timeout):
            self.assertEqual(timeout, 5)
            if request.full_url == cleanup.IMDS_TOKEN_URL:
                return token_response()
            status = statuses.pop(0)
            raise urllib.error.HTTPError(request.full_url, status, "bounded", {}, None)

        cleanup.verify_absent(
            SUBSCRIPTION_ID,
            RESOURCE_GROUP,
            ZONE,
            opener=opener,
            sleeper=sleeps.append,
        )
        self.assertEqual(statuses, [])
        self.assertEqual(sleeps, [cleanup.RETRY_SECONDS, cleanup.RETRY_SECONDS])

    def test_malformed_token_and_unsafe_inputs_are_rejected(self) -> None:
        def malformed_token(_request, *, timeout):
            self.assertEqual(timeout, 5)
            return Response(cleanup.IMDS_TOKEN_URL, content=b'{"access_token":"short"}')

        with self.assertRaisesRegex(cleanup.CleanupVerificationError, "malformed"):
            cleanup.verify_absent(
                SUBSCRIPTION_ID,
                RESOURCE_GROUP,
                ZONE,
                opener=malformed_token,
            )

        for values, message in (
            (("not-a-uuid", RESOURCE_GROUP, ZONE), "subscription"),
            ((SUBSCRIPTION_ID, "unsafe/group", ZONE), "resource-group"),
            ((SUBSCRIPTION_ID, RESOURCE_GROUP, "UPPER.example"), "zone"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(cleanup.CleanupVerificationError, message):
                    cleanup.verify_absent(*values, opener=malformed_token)


if __name__ == "__main__":
    unittest.main()
