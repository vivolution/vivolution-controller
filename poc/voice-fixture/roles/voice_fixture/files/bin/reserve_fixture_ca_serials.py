#!/usr/bin/env python3
"""Durably reserve unique synthetic fixture CA leaf serial numbers."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import secrets
import stat
import sys
from typing import Any


API_VERSION = "edge.vivolution.ae/synthetic-fixture-ca-serial-reservation/v0.1"
STATE_ROOT = Path("/var/lib/vivolution/voice-fixture/pki-issuer-state")
COUNTER = STATE_ROOT / "ca.srl"
LOCK = STATE_ROOT / "reservation.lock"
CURRENT_COUNTER = Path("/etc/vivolution/voice-fixture/pki-current/ca.srl")
MAX_COUNTER_BYTES = 128
MAX_SERIAL = (1 << 160) - 1
ROOT_UID = 0
ROOT_GID = 0


class SerialReservationError(ValueError):
    """The durable issuer serial authority is missing or unsafe."""


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


def _assert_root_directory(path: Path, mode: int) -> None:
    value = path.lstat()
    if (
        not stat.S_ISDIR(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or value.st_uid != ROOT_UID
        or value.st_gid != ROOT_GID
        or stat.S_IMODE(value.st_mode) != mode
    ):
        raise SerialReservationError(f"unsafe issuer-state directory {path}")


def _prepare_root() -> None:
    if not STATE_ROOT.exists():
        STATE_ROOT.mkdir(mode=0o700, parents=False)
        os.chown(STATE_ROOT, ROOT_UID, ROOT_GID)
        os.chmod(STATE_ROOT, 0o700)
    _assert_root_directory(STATE_ROOT, 0o700)


def _read_counter(path: Path, *, required: bool) -> int | None:
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        )
    except FileNotFoundError:
        if required:
            raise SerialReservationError(f"issuer counter is absent: {path}")
        return None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != ROOT_UID
            or before.st_gid != ROOT_GID
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 1 <= before.st_size <= MAX_COUNTER_BYTES
        ):
            raise SerialReservationError(f"unsafe issuer counter {path}")
        raw = os.read(descriptor, MAX_COUNTER_BYTES + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(raw) != before.st_size
        or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    ):
        raise SerialReservationError(f"issuer counter changed while read: {path}")
    try:
        text = raw.decode("ascii").strip()
        if not text or len(text) > 40 or any(character not in "0123456789abcdefABCDEF" for character in text):
            raise ValueError
        value = int(text, 16)
    except (UnicodeDecodeError, ValueError) as exc:
        raise SerialReservationError(f"issuer counter is not bounded hexadecimal: {path}") from exc
    if not 0 < value <= MAX_SERIAL:
        raise SerialReservationError(f"issuer counter is outside the X.509 serial bound: {path}")
    return value


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write_counter(value: int) -> None:
    content = (format(value, "X") + "\n").encode("ascii")
    temporary = COUNTER.with_name(f".{COUNTER.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, ROOT_UID, ROOT_GID)
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    os.replace(temporary, COUNTER)
    _fsync_directory(STATE_ROOT)


def reserve(count: int) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise SerialReservationError("serial reservation must run as root")
    if not 1 <= count <= 64:
        raise SerialReservationError("serial reservation count is outside its fixed bound")
    _prepare_root()
    lock_descriptor = os.open(
        LOCK,
        os.O_RDWR
        | os.O_CREAT
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        lock_state = os.fstat(lock_descriptor)
        if not stat.S_ISREG(lock_state.st_mode) or lock_state.st_nlink != 1:
            raise SerialReservationError("issuer serial reservation lock is unsafe")
        os.fchmod(lock_descriptor, 0o600)
        os.fchown(lock_descriptor, ROOT_UID, ROOT_GID)
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        current_generation = _read_counter(CURRENT_COUNTER, required=False)
        high_water = _read_counter(COUNTER, required=False)
        if high_water is None:
            high_water = current_generation or secrets.randbits(128) or 1
        elif current_generation is not None and current_generation > high_water:
            raise SerialReservationError(
                "selected generation counter is ahead of durable issuer authority"
            )
        final = high_water + count
        if final > MAX_SERIAL:
            raise SerialReservationError("issuer serial space is exhausted")
        # Reservation is committed and fsynced before any certificate is signed.
        # A crash may skip values, but can never cause their reuse.
        _atomic_write_counter(final)
    finally:
        os.close(lock_descriptor)
    serials = ["0x" + format(value, "X") for value in range(high_water + 1, final + 1)]
    return {
        "apiVersion": API_VERSION,
        "count": count,
        "firstSerial": serials[0],
        "lastSerial": serials[-1],
        "serials": serials,
        "status": "FIXTURE_CA_SERIALS_RESERVED_DURABLY",
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--count", type=int, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        record = reserve(args.count)
    except (OSError, SerialReservationError) as exc:
        print(f"fixture CA serial reservation rejected: {exc}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_bytes(record))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
