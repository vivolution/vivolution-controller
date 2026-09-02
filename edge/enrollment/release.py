#!/usr/bin/env python3
"""Deterministic identity for the installed Edge enrollment client release."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Sequence

RELEASE_PREFIX = b"edge.vivolution.ae/EnrollmentClientRelease/v1\0"
RELEASE_FILES = (
    "__init__.py",
    "__main__.py",
    "cli.py",
    "client.py",
    "core.py",
    "http_client.py",
    "protocol.py",
    "release.py",
)
MAX_SOURCE_BYTES = 1024 * 1024
DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
INSTALLED_SOURCE_ROOT = Path("/usr/lib/vivolution-edge/python/edge/enrollment")
INSTALLED_DIGEST_PATH = Path(
    "/usr/lib/vivolution-edge/config/enrollment-release-digest"
)


class ReleaseIdentityError(RuntimeError):
    """The installed enrollment artifact does not match its immutable identity."""


def _read_regular(
    path: Path,
    *,
    expected_uid: int | None,
    expected_mode: int | None,
    maximum_bytes: int,
) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseIdentityError("cannot securely read installed release metadata") from exc
    try:
        record = os.fstat(descriptor)
        if (
            not stat.S_ISREG(record.st_mode)
            or record.st_nlink != 1
            or (expected_uid is not None and record.st_uid != expected_uid)
            or (
                expected_mode is not None
                and stat.S_IMODE(record.st_mode) != expected_mode
            )
            or not 1 <= record.st_size <= maximum_bytes
        ):
            raise ReleaseIdentityError(
                "installed release metadata violates its file contract"
            )
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) != record.st_size or len(content) > maximum_bytes:
            raise ReleaseIdentityError("installed release metadata changed while read")
        return content
    finally:
        os.close(descriptor)


def calculate_release_digest(
    source_root: Path,
    *,
    expected_uid: int | None = None,
    expected_mode: int | None = None,
) -> str:
    """Hash the exact fixed source inventory with names and per-file digests."""

    material = bytearray(RELEASE_PREFIX)
    for name in RELEASE_FILES:
        content = _read_regular(
            source_root / name,
            expected_uid=expected_uid,
            expected_mode=expected_mode,
            maximum_bytes=MAX_SOURCE_BYTES,
        )
        material.extend(name.encode("ascii"))
        material.extend(b"\0")
        material.extend(hashlib.sha256(content).digest())
    return "sha256:" + hashlib.sha256(bytes(material)).hexdigest()


def load_installed_release_digest(
    *,
    digest_path: Path = INSTALLED_DIGEST_PATH,
    source_root: Path = INSTALLED_SOURCE_ROOT,
    expected_uid: int = 0,
    expected_mode: int = 0o444,
) -> str:
    """Verify the root-installed digest file against the executable sources."""

    content = _read_regular(
        digest_path,
        expected_uid=expected_uid,
        expected_mode=expected_mode,
        maximum_bytes=72,
    )
    try:
        expected = content.decode("ascii").strip()
    except UnicodeError as exc:
        raise ReleaseIdentityError("installed release digest is not ASCII") from exc
    if not DIGEST_RE.fullmatch(expected):
        raise ReleaseIdentityError("installed release digest is malformed")
    actual = calculate_release_digest(
        source_root, expected_uid=expected_uid, expected_mode=expected_mode
    )
    if actual != expected:
        raise ReleaseIdentityError(
            "installed enrollment client differs from its release digest"
        )
    return actual


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Calculate Edge enrollment release digest")
    parser.add_argument("source_root", type=Path)
    args = parser.parse_args(argv)
    print(calculate_release_digest(args.source_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
