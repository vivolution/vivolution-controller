#!/usr/bin/env python3
"""Operator CLI for secure provider-neutral Edge enrollment."""

from __future__ import annotations

import argparse
import os
import pwd
import sys
from pathlib import Path
from typing import BinaryIO, Sequence, TextIO

from .client import EnrollmentClient
from .core import (
    EnrollmentError,
    ProtectedState,
    StateSecurityError,
    canonical_json_bytes,
    consume_root_token_file,
    normalize_controller_url,
    read_text_tty,
    read_token_stream,
    read_token_tty,
)

DEFAULT_STATE_DIRECTORY = Path("/var/lib/vivolution-edge/enrollment")
AGENT_ACCOUNT = "vivolution-edge-agent"


class _SafeArgumentParser(argparse.ArgumentParser):
    """Reject invalid argv without reflecting a mistakenly pasted grant."""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, "{}: error: invalid command-line arguments\n".format(self.prog))


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="vivolution-edge-join",
        allow_abbrev=False,
        description=(
            "Enroll this host as an Edge enrollment client/placeholder with a shared "
            "HTTPS Controller. This does not configure SBC, SIP, RTP, Teams, or carrier "
            "services. The display-once grant is never accepted in argv or env."
        ),
    )
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=DEFAULT_STATE_DIRECTORY,
        help=argparse.SUPPRESS,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    enroll = commands.add_parser(
        "enroll",
        allow_abbrev=False,
        help="create/reuse local identity and claim a slot",
    )
    enroll.add_argument(
        "--controller",
        help="shared Controller HTTPS origin; prompted from /dev/tty when omitted",
    )
    sources = enroll.add_mutually_exclusive_group()
    sources.add_argument(
        "--token-stdin",
        action="store_true",
        help="read one display-once grant from stdin",
    )
    sources.add_argument(
        "--token-file",
        type=Path,
        help="consume/unlink a root-owned 0600 grant file on tmpfs",
    )

    commands.add_parser(
        "poll", allow_abbrev=False, help="check Pending approval with a signed request"
    )
    commands.add_parser(
        "status", allow_abbrev=False, help="show protected local non-secret status"
    )
    heartbeat = commands.add_parser(
        "heartbeat", allow_abbrev=False, help="send one signed heartbeat"
    )
    heartbeat.add_argument(
        "--health", choices=("HEALTHY", "DEGRADED"), default="HEALTHY"
    )
    commands.add_parser(
        "service-once",
        allow_abbrev=False,
        help="poll Pending approval or send one approved heartbeat",
    )
    return parser


def _agent_uid(explicit: int | None) -> int:
    if explicit is not None:
        return explicit
    try:
        uid = pwd.getpwnam(AGENT_ACCOUNT).pw_uid
    except KeyError as exc:
        raise StateSecurityError(
            "the vivolution-edge-agent service account is not installed"
        ) from exc
    if os.geteuid() not in (0, uid):
        raise StateSecurityError(
            "run as root or the dedicated vivolution-edge-agent account"
        )
    return uid


def _controller_from_state(state: ProtectedState) -> str:
    value = state.read_state()
    if value is None or not isinstance(value.get("controller_url"), str):
        raise EnrollmentError("this Edge has not started enrollment")
    return normalize_controller_url(value["controller_url"])


def main(
    argv: Sequence[str] | None = None,
    *,
    expected_uid: int | None = None,
    stdin: BinaryIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    args = _parser().parse_args(argv)
    input_stream = stdin or sys.stdin.buffer
    output = stdout or sys.stdout
    errors = stderr or sys.stderr
    try:
        uid = _agent_uid(expected_uid)
        state = ProtectedState(args.state_dir, expected_uid=uid)
        if args.command == "enroll":
            if args.token_stdin and args.controller is None:
                raise EnrollmentError(
                    "--controller is required when the grant is read from stdin"
                )
            controller = normalize_controller_url(
                args.controller
                if args.controller is not None
                else read_text_tty("Controller shared HTTPS URL: ")
            )
            if args.token_file is not None:
                grant = consume_root_token_file(args.token_file)
            elif args.token_stdin:
                grant = read_token_stream(input_stream)
            else:
                grant = read_token_tty()
            try:
                result = EnrollmentClient(
                    controller_url=controller, state=state
                ).enroll(grant)
            finally:
                # Python strings cannot be guaranteed securely erased; remove
                # the reference immediately. The source is never persisted.
                del grant
        else:
            client = EnrollmentClient(
                controller_url=_controller_from_state(state), state=state
            )
            if args.command == "poll":
                result = client.poll_status()
            elif args.command == "heartbeat":
                result = client.heartbeat(args.health)
            elif args.command == "service-once":
                result = client.service_once()
            else:
                result = client.public_status(client._validated_state(create=False))
        output.buffer.write(canonical_json_bytes(result) + b"\n") if hasattr(
            output, "buffer"
        ) else output.write(canonical_json_bytes(result).decode("utf-8") + "\n")
        return 0
    except (EnrollmentError, OSError, UnicodeError, ValueError) as exc:
        print("ERROR: {}".format(exc), file=errors)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
