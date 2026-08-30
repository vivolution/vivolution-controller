#!/usr/bin/env python3
"""Verify the fixture's exact host mapping and local DNS-stub answers."""

from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import subprocess
import sys


HOSTS_PATH = Path("/etc/hosts")
RESOLVED_DROP_IN = Path(
    "/etc/systemd/resolved.conf.d/99-vivolution-voice-fixture-private-edge.conf"
)
RESOLVED_DROP_IN_CONTENT = "[Resolve]\nReadEtcHosts=yes\n"
RESOLVER = ("127.0.0.53", 53)
MARKER_BEGIN = "# BEGIN VIVOLUTION VOICE FIXTURE PRIVATE EDGE DNS"
MARKER_END = "# END VIVOLUTION VOICE FIXTURE PRIVATE EDGE DNS"
EXPECTED = (
    ("sbc1.voice.vivolution.ae", ipaddress.IPv4Address("10.20.2.4")),
    ("sbc2.voice.vivolution.ae", ipaddress.IPv4Address("10.20.2.5")),
)
EXPECTED_BLOCK = tuple(f"{address} {name}" for name, address in EXPECTED)
TARGET_NAMES = frozenset(name for name, _address in EXPECTED)


class VerificationError(RuntimeError):
    """The bounded private-resolution contract was not met."""


def _normalized_host_token(value: str) -> str:
    return value.lower().rstrip(".")


def _read_hosts(path: Path, *, verify_metadata: bool) -> list[str]:
    try:
        metadata = os.lstat(path)
        payload = path.read_bytes()
    except OSError as error:
        raise VerificationError("hosts_file_unreadable") from error

    if verify_metadata:
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise VerificationError("hosts_file_type_or_links_invalid")
        if metadata.st_uid != 0 or metadata.st_gid != 0:
            raise VerificationError("hosts_file_owner_invalid")
        if stat.S_IMODE(metadata.st_mode) != 0o644:
            raise VerificationError("hosts_file_mode_invalid")
    if b"\x00" in payload or b"\r" in payload:
        raise VerificationError("hosts_file_encoding_invalid")
    try:
        return payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise VerificationError("hosts_file_encoding_invalid") from error


def _active_target_lines(lines: list[str]) -> list[tuple[int, str]]:
    matches: list[tuple[int, str]] = []
    for number, raw_line in enumerate(lines, start=1):
        active = raw_line.split("#", 1)[0].strip()
        if not active:
            continue
        fields = active.split()
        if any(_normalized_host_token(field) in TARGET_NAMES for field in fields[1:]):
            matches.append((number, raw_line))
    return matches


def verify_hosts(path: Path, expected_state: str, *, verify_metadata: bool) -> None:
    lines = _read_hosts(path, verify_metadata=verify_metadata)
    begin = [index for index, line in enumerate(lines) if line == MARKER_BEGIN]
    end = [index for index, line in enumerate(lines) if line == MARKER_END]
    active_targets = _active_target_lines(lines)

    if expected_state in {"absent", "pre"} and not begin and not end:
        if active_targets:
            raise VerificationError("unmanaged_private_edge_mapping")
        return

    if len(begin) != 1 or len(end) != 1 or end[0] <= begin[0]:
        raise VerificationError("managed_private_edge_markers_invalid")
    if tuple(lines[begin[0] + 1 : end[0]]) != EXPECTED_BLOCK:
        raise VerificationError("managed_private_edge_block_invalid")
    if active_targets != [
        (begin[0] + 2, EXPECTED_BLOCK[0]),
        (begin[0] + 3, EXPECTED_BLOCK[1]),
    ]:
        raise VerificationError("private_edge_mapping_not_exclusive")
    if expected_state == "absent":
        raise VerificationError("managed_private_edge_mapping_present")


def _encode_name(name: str) -> bytes:
    labels = name.encode("ascii").split(b".")
    if not labels or any(not label or len(label) > 63 for label in labels):
        raise VerificationError("dns_query_name_invalid")
    return b"".join(bytes((len(label),)) + label for label in labels) + b"\x00"


def _decode_name(payload: bytes, offset: int) -> tuple[str, int]:
    labels: list[bytes] = []
    resume: int | None = None
    visited: set[int] = set()
    while True:
        if offset >= len(payload) or offset in visited:
            raise VerificationError("dns_name_invalid")
        visited.add(offset)
        length = payload[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(payload):
                raise VerificationError("dns_name_invalid")
            pointer = ((length & 0x3F) << 8) | payload[offset + 1]
            if pointer >= len(payload):
                raise VerificationError("dns_name_invalid")
            if resume is None:
                resume = offset + 2
            offset = pointer
            continue
        if length & 0xC0:
            raise VerificationError("dns_name_invalid")
        offset += 1
        if length == 0:
            break
        if offset + length > len(payload):
            raise VerificationError("dns_name_invalid")
        labels.append(payload[offset : offset + length])
        offset += length
    try:
        name = b".".join(labels).decode("ascii").lower()
    except UnicodeDecodeError as error:
        raise VerificationError("dns_name_invalid") from error
    return name, resume if resume is not None else offset


def _parse_record(payload: bytes, offset: int) -> tuple[str, int, int, bytes, int]:
    name, offset = _decode_name(payload, offset)
    if offset + 10 > len(payload):
        raise VerificationError("dns_record_truncated")
    record_type, record_class, _ttl, size = struct.unpack_from("!HHIH", payload, offset)
    offset += 10
    if offset + size > len(payload):
        raise VerificationError("dns_record_truncated")
    return name, record_type, record_class, payload[offset : offset + size], offset + size


def query_stub(name: str, expected: ipaddress.IPv4Address) -> None:
    query_id = secrets.randbits(16)
    question_name = _encode_name(name)
    query = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    query += question_name + struct.pack("!HH", 1, 1)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as resolver:
            resolver.settimeout(3)
            resolver.connect(RESOLVER)
            resolver.send(query)
            payload = resolver.recv(4096)
    except OSError as error:
        raise VerificationError("local_dns_stub_unreachable") from error

    if len(payload) < 12:
        raise VerificationError("dns_response_truncated")
    response_id, flags, questions, answers, authorities, additional = struct.unpack_from(
        "!HHHHHH", payload
    )
    if (
        response_id != query_id
        or flags & 0x8000 == 0
        or flags & 0x7800
        or flags & 0x0200
        or flags & 0x000F
        or questions != 1
        or answers != 1
    ):
        raise VerificationError("dns_response_header_invalid")

    question, offset = _decode_name(payload, 12)
    if offset + 4 > len(payload):
        raise VerificationError("dns_question_truncated")
    question_type, question_class = struct.unpack_from("!HH", payload, offset)
    offset += 4
    if question != name or question_type != 1 or question_class != 1:
        raise VerificationError("dns_question_invalid")

    owner, record_type, record_class, record_data, offset = _parse_record(payload, offset)
    if (
        owner != name
        or record_type != 1
        or record_class != 1
        or len(record_data) != 4
        or ipaddress.IPv4Address(record_data) != expected
    ):
        raise VerificationError("dns_private_edge_answer_invalid")

    for _unused in range(authorities + additional):
        _name, _type, _class, _data, offset = _parse_record(payload, offset)
    if offset != len(payload):
        raise VerificationError("dns_response_trailing_data")


def verify_stub() -> None:
    for name, address in EXPECTED:
        query_stub(name, address)


def verify_resolved_configuration() -> None:
    try:
        metadata = os.lstat(RESOLVED_DROP_IN)
        content = RESOLVED_DROP_IN.read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise VerificationError("resolved_drop_in_unreadable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o644
        or content != RESOLVED_DROP_IN_CONTENT
    ):
        raise VerificationError("resolved_drop_in_invalid")
    try:
        result = subprocess.run(
            [
                "/usr/bin/systemd-analyze",
                "cat-config",
                "systemd/resolved.conf",
            ],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise VerificationError("resolved_effective_config_unavailable") from error

    section = ""
    effective: list[str] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if section == "resolve" and "=" in line:
            key, value = line.split("=", 1)
            if key.strip().lower() == "readetchosts":
                effective.append(value.strip().lower())
    if not effective or effective[-1] != "yes":
        raise VerificationError("resolved_read_etc_hosts_not_enabled")


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "mode",
        choices=(
            "hosts-pre",
            "hosts-post",
            "hosts-absent",
            "resolved-effective",
            "stub",
        ),
    )
    parser.add_argument("path", nargs="?", type=Path, default=HOSTS_PATH)
    args = parser.parse_args()
    try:
        if args.mode in {"resolved-effective", "stub"}:
            if args.path != HOSTS_PATH:
                raise VerificationError("unexpected_path")
            if args.mode == "stub":
                verify_stub()
                print("PRIVATE_EDGE_DNS_OK")
            else:
                verify_resolved_configuration()
                print("PRIVATE_EDGE_RESOLVED_CONFIG_OK")
        else:
            expected_state = {
                "hosts-pre": "pre",
                "hosts-post": "present",
                "hosts-absent": "absent",
            }[args.mode]
            verify_hosts(
                args.path,
                expected_state,
                verify_metadata=args.path == HOSTS_PATH,
            )
            print("PRIVATE_EDGE_HOSTS_OK")
    except VerificationError as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
