from __future__ import annotations

import base64
import email.message
import io
import unittest
import urllib.error

from edge.enrollment.core import EnrollmentError
from edge.enrollment.http_client import HTTPSJSONTransport, parse_response_json


class FakeResponse:
    def __init__(self, status: int, content: bytes, content_type: str = "application/json"):
        self.status = status
        self._stream = io.BytesIO(content)
        self.headers = email.message.Message()
        self.headers["Content-Type"] = content_type

    def read(self, size: int) -> bytes:
        return self._stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None


class FakeOpener:
    def __init__(self, response):
        self.response = response
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response


class ResponseParsingTests(unittest.TestCase):
    def test_rejects_duplicate_float_nan_large_integer_and_non_object(self) -> None:
        for raw in (
            b'{"a":1,"a":2}',
            b'{"a":1.5}',
            b'{"a":NaN}',
            b'{"a":9007199254740992}',
            b'[]',
        ):
            with self.subTest(raw=raw), self.assertRaises(EnrollmentError):
                parse_response_json(raw)


class TransportTests(unittest.TestCase):
    @staticmethod
    def grant() -> str:
        secret = base64.urlsafe_b64encode(b"s" * 32).rstrip(b"=").decode()
        return "v1.aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa." + secret

    def test_posts_canonical_json_with_exact_grant_scheme(self) -> None:
        opener = FakeOpener(FakeResponse(201, b'{"status":"ok"}'))
        transport = HTTPSJSONTransport(
            "https://controller.example.com", opener=opener
        )
        status, value = transport.post(
            "/api/edge/v1/enrollment/challenge",
            {"z": 2, "a": 1},
            expected_statuses=(201,),
            enrollment_grant=self.grant(),
        )
        self.assertEqual(status, 201)
        self.assertEqual(value, {"status": "ok"})
        request, timeout = opener.requests[0]
        self.assertEqual(request.full_url, "https://controller.example.com/api/edge/v1/enrollment/challenge")
        self.assertEqual(request.data, b'{"a":1,"z":2}')
        self.assertEqual(
            request.get_header("Authorization"),
            "Vivolution-Enrollment " + self.grant(),
        )
        self.assertEqual(timeout, 15)

    def test_http_error_is_sanitized_without_reflected_body(self) -> None:
        grant = self.grant()
        error = urllib.error.HTTPError(
            "https://controller.example.com/api/edge/v1/enrollment/challenge",
            403,
            "Forbidden " + grant,
            {},
            io.BytesIO(grant.encode("ascii")),
        )
        transport = HTTPSJSONTransport(
            "https://controller.example.com", opener=FakeOpener(error)
        )
        with self.assertRaisesRegex(EnrollmentError, "HTTP status 403") as raised:
            transport.post("/api/edge/v1/enrollment/challenge", {})
        self.assertNotIn(grant, str(raised.exception))
        self.assertNotIn("forbidden", str(raised.exception).lower())

    def test_rejects_redirect_status_content_type_and_oversized_response(self) -> None:
        cases = (
            FakeResponse(302, b"{}"),
            FakeResponse(200, b"{}", "text/plain"),
            FakeResponse(200, b"x" * (64 * 1024 + 1)),
        )
        for response in cases:
            with self.subTest(status=response.status):
                transport = HTTPSJSONTransport(
                    "https://controller.example.com", opener=FakeOpener(response)
                )
                with self.assertRaises(EnrollmentError):
                    transport.post("/api/edge/v1/enrollment/status", {})


if __name__ == "__main__":
    unittest.main()
