from __future__ import annotations

import base64
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from edge.enrollment import cli


def grant() -> str:
    secret = base64.urlsafe_b64encode(b"g" * 32).rstrip(b"=").decode()
    return "v1.aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa." + secret


class FakeClient:
    received_grant = None

    def __init__(self, *, controller_url, state):
        self.controller_url = controller_url
        self.state = state

    def enroll(self, value):
        type(self).received_grant = value
        return {
            "apiVersion": "edge.vivolution.ae/local-enrollment-status/v1",
            "controllerUrl": self.controller_url,
            "status": "PENDING_APPROVAL",
        }


class CliTests(unittest.TestCase):
    def test_parser_has_no_token_value_option(self) -> None:
        parser = cli._parser()
        error_output = io.StringIO()
        with redirect_stderr(error_output), self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "enroll",
                    "--controller",
                    "https://controller.example.com",
                    "--token",
                    grant(),
                ]
            )
        self.assertNotIn(grant(), error_output.getvalue())
        self.assertNotIn("unrecognized arguments", error_output.getvalue())
        help_text = parser.format_help()
        self.assertNotIn("--token ", help_text)
        self.assertNotIn("environment", help_text.lower())
        self.assertIn("Edge enrollment client/placeholder", help_text)
        for excluded in ("SBC", "SIP", "RTP", "Teams", "carrier"):
            self.assertIn(excluded, help_text)

    def test_stdin_grant_reaches_client_but_not_output_or_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stdout = io.StringIO()
            stderr = io.StringIO()
            FakeClient.received_grant = None
            with mock.patch.object(cli, "EnrollmentClient", FakeClient):
                result = cli.main(
                    [
                        "--state-dir",
                        str(Path(temporary) / "enrollment"),
                        "enroll",
                        "--controller",
                        "https://controller.example.com",
                        "--token-stdin",
                    ],
                    expected_uid=os.geteuid(),
                    stdin=io.BytesIO((grant() + "\n").encode()),
                    stdout=stdout,
                    stderr=stderr,
                )
            self.assertEqual(result, 0)
            self.assertEqual(FakeClient.received_grant, grant())
            self.assertNotIn(grant(), stdout.getvalue())
            self.assertNotIn(grant(), stderr.getvalue())
            for path in Path(temporary).rglob("*"):
                if path.is_file():
                    self.assertNotIn(grant(), path.read_text(errors="ignore"))

    def test_stdin_requires_explicit_controller_to_avoid_stream_collision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stderr = io.StringIO()
            result = cli.main(
                [
                    "--state-dir",
                    str(Path(temporary) / "enrollment"),
                    "enroll",
                    "--token-stdin",
                ],
                expected_uid=os.geteuid(),
                stdin=io.BytesIO((grant() + "\n").encode()),
                stdout=io.StringIO(),
                stderr=stderr,
            )
            self.assertEqual(result, 1)
            self.assertIn("--controller is required", stderr.getvalue())
            self.assertNotIn(grant(), stderr.getvalue())

    def test_default_grant_source_is_echo_disabled_tty_helper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stdout = io.StringIO()
            with (
                mock.patch.object(cli, "EnrollmentClient", FakeClient),
                mock.patch.object(cli, "read_token_tty", return_value=grant()) as tty,
            ):
                result = cli.main(
                    [
                        "--state-dir",
                        str(Path(temporary) / "enrollment"),
                        "enroll",
                        "--controller",
                        "https://controller.example.com",
                    ],
                    expected_uid=os.geteuid(),
                    stdout=stdout,
                    stderr=io.StringIO(),
                )
            self.assertEqual(result, 0)
            tty.assert_called_once_with()
            self.assertNotIn(grant(), stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
