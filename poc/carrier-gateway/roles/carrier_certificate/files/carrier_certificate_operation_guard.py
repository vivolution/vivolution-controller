#!/usr/bin/python3
"""Serialize carrier certificate maintenance with renewal and activation."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


STATE_ROOT = Path("/var/lib/vivolution-carrier-certificate")
ACME_ROOT = STATE_ROOT / "acme"
ROTATION_ROOT = STATE_ROOT / "rotation"
PKI_ROOT = Path("/etc/vivolution/carrier-gateway/pki")
LIVE_CERT = PKI_ROOT / "carrier.fullchain.pem"
LIVE_KEY = PKI_ROOT / "carrier.key"
EGRESS_PKI_ROOT = Path("/etc/vivolution/carrier-gateway/egress-pki")
EGRESS_LIVE_CERT = EGRESS_PKI_ROOT / "carrier.fullchain.pem"
EGRESS_LIVE_KEY = EGRESS_PKI_ROOT / "carrier.key"
MAINTENANCE_GATE = STATE_ROOT / "maintenance.json"
RENEW_LOCK = ACME_ROOT / "renew.lock"
ROTATION_LOCK = ROTATION_ROOT / "rotation.lock"
ROTATION_JOURNAL = ROTATION_ROOT / "transaction.json"
ROOT_UID = 0
ROOT_GID = 0
RUNTIME_GID = 10003
EGRESS_RUNTIME_GID = 10004
MAX_MARKER_BYTES = 4096
MAX_PEM_BYTES = 1024 * 1024
SCHEMA = "carrier.vivolution.ae/certificate-maintenance/v0.1"
PURPOSES = {"configuration-rollback", "teardown"}


class GuardError(RuntimeError):
    pass


class MaintenanceBlocked(GuardError):
    pass


def _canonical(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _fsync_dir(path: Path) -> None:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _assert_dir(path: Path, mode: int, gid: int | None = None) -> None:
    expected_gid = ROOT_GID if gid is None else gid
    try:
        record = path.lstat()
    except OSError as exc:
        raise GuardError(f"certificate guard directory is unavailable: {path}") from exc
    if (
        not stat.S_ISDIR(record.st_mode)
        or stat.S_ISLNK(record.st_mode)
        or record.st_uid != ROOT_UID
        or record.st_gid != expected_gid
        or stat.S_IMODE(record.st_mode) != mode
    ):
        raise GuardError(f"certificate guard directory metadata is unsafe: {path}")


def _secure_read(
    path: Path,
    *,
    mode: int,
    uid: int,
    gid: int,
    maximum: int,
) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise GuardError(f"certificate guard cannot read {path}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != uid
            or before.st_gid != gid
            or stat.S_IMODE(before.st_mode) != mode
            or not 0 < before.st_size <= maximum
        ):
            raise GuardError(f"certificate guard file metadata is unsafe: {path}")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    fingerprint = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
    )
    if (
        fingerprint(before) != fingerprint(after)
        or len(content) != before.st_size
        or len(content) > maximum
    ):
        raise GuardError(f"certificate guard file changed during read: {path}")
    return content


def _marker(purpose: str) -> bytes:
    if purpose not in PURPOSES:
        raise GuardError("certificate maintenance purpose is invalid")
    return _canonical(
        {
            "kind": "CarrierCertificateMaintenance",
            "purpose": purpose,
            "schema": SCHEMA,
        }
    )


def _read_marker(purpose: str) -> None:
    if _secure_read(
        MAINTENANCE_GATE,
        mode=0o400,
        uid=ROOT_UID,
        gid=ROOT_GID,
        maximum=MAX_MARKER_BYTES,
    ) != _marker(purpose):
        raise GuardError("certificate maintenance gate differs from its exact purpose")


def begin_maintenance(purpose: str) -> str:
    _assert_dir(STATE_ROOT, 0o700)
    expected = _marker(purpose)
    try:
        descriptor = os.open(
            MAINTENANCE_GATE,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o400,
        )
    except FileExistsError:
        _read_marker(purpose)
        return "CARRIER_CERTIFICATE_MAINTENANCE_ALREADY_GATED"
    except OSError as exc:
        raise GuardError("certificate maintenance gate could not be created") from exc
    try:
        os.fchown(descriptor, ROOT_UID, ROOT_GID)
        os.fchmod(descriptor, 0o400)
        offset = 0
        while offset < len(expected):
            offset += os.write(descriptor, expected[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_dir(STATE_ROOT)
    return "CARRIER_CERTIFICATE_MAINTENANCE_GATED"


def assert_available() -> str:
    try:
        MAINTENANCE_GATE.lstat()
    except FileNotFoundError:
        return "CARRIER_CERTIFICATE_OPERATION_AVAILABLE"
    except OSError as exc:
        raise MaintenanceBlocked("certificate maintenance gate cannot be inspected") from exc
    raise MaintenanceBlocked("certificate maintenance blocks renewal or activation")


def _open_locked(path: Path) -> int:
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except OSError as exc:
        raise GuardError(f"certificate lock cannot be opened safely: {path}") from exc
    try:
        record = os.fstat(descriptor)
        if (
            not stat.S_ISREG(record.st_mode)
            or record.st_nlink != 1
            or record.st_uid != ROOT_UID
            or record.st_gid != ROOT_GID
        ):
            raise GuardError(f"certificate lock metadata is unsafe: {path}")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise GuardError(f"certificate operation remains active: {path.name}") from exc
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _locked_operation_descriptors(purpose: str) -> list[int]:
    _assert_dir(STATE_ROOT, 0o700)
    _assert_dir(ACME_ROOT, 0o700)
    _assert_dir(ROTATION_ROOT, 0o700)
    _read_marker(purpose)
    descriptors: list[int] = []
    try:
        for path in (RENEW_LOCK, ROTATION_LOCK):
            descriptors.append(_open_locked(path))
        return descriptors
    except Exception:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def assert_locks_quiescent(purpose: str) -> str:
    descriptors = _locked_operation_descriptors(purpose)
    for descriptor in reversed(descriptors):
        os.close(descriptor)
    return "CARRIER_CERTIFICATE_LOCKS_QUIESCENT"


def assert_quiescent(purpose: str) -> str:
    descriptors = _locked_operation_descriptors(purpose)
    try:
        try:
            ROTATION_JOURNAL.lstat()
        except FileNotFoundError:
            pass
        else:
            raise GuardError("certificate activation journal remains during maintenance")
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
    return "CARRIER_CERTIFICATE_OPERATIONS_QUIESCENT"


def snapshot_pki(purpose: str) -> dict[str, str]:
    assert_quiescent(purpose)
    _assert_dir(PKI_ROOT, 0o750, RUNTIME_GID)
    _assert_dir(EGRESS_PKI_ROOT, 0o750, EGRESS_RUNTIME_GID)
    certificate = _secure_read(
        LIVE_CERT,
        mode=0o440,
        uid=ROOT_UID,
        gid=RUNTIME_GID,
        maximum=MAX_PEM_BYTES,
    )
    private_key = _secure_read(
        LIVE_KEY,
        mode=0o440,
        uid=ROOT_UID,
        gid=RUNTIME_GID,
        maximum=MAX_PEM_BYTES,
    )
    egress_certificate = _secure_read(
        EGRESS_LIVE_CERT,
        mode=0o440,
        uid=ROOT_UID,
        gid=EGRESS_RUNTIME_GID,
        maximum=MAX_PEM_BYTES,
    )
    egress_private_key = _secure_read(
        EGRESS_LIVE_KEY,
        mode=0o440,
        uid=ROOT_UID,
        gid=EGRESS_RUNTIME_GID,
        maximum=MAX_PEM_BYTES,
    )
    if certificate != egress_certificate or private_key != egress_private_key:
        raise GuardError("common and provider-egress certificate copies differ")
    return {
        "certificateSha256": hashlib.sha256(certificate).hexdigest(),
        "egressCertificateSha256": hashlib.sha256(egress_certificate).hexdigest(),
        "egressPrivateKeySha256": hashlib.sha256(egress_private_key).hexdigest(),
        "privateKeySha256": hashlib.sha256(private_key).hexdigest(),
        "status": "CARRIER_PKI_SNAPSHOT_BOUND",
    }


def end_maintenance(purpose: str) -> str:
    assert_quiescent(purpose)
    try:
        MAINTENANCE_GATE.unlink()
    except OSError as exc:
        raise GuardError("certificate maintenance gate could not be removed") from exc
    _fsync_dir(STATE_ROOT)
    return "CARRIER_CERTIFICATE_MAINTENANCE_RELEASED"


def release_for_recovery(purpose: str) -> str:
    """Release only after both workers stopped, while allowing a recovery journal."""

    assert_locks_quiescent(purpose)
    try:
        MAINTENANCE_GATE.unlink()
    except OSError as exc:
        raise GuardError("certificate recovery gate could not be removed") from exc
    _fsync_dir(STATE_ROOT)
    return "CARRIER_CERTIFICATE_MAINTENANCE_RELEASED_FOR_RECOVERY"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("assert-available")
    for command in (
        "begin",
        "assert-locks-quiescent",
        "assert-quiescent",
        "snapshot-pki",
        "end",
        "release-for-recovery",
    ):
        selected = subparsers.add_parser(command)
        selected.add_argument("--purpose", choices=sorted(PURPOSES), required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if os.geteuid() != ROOT_UID:
        print("carrier certificate operation guard requires root", file=sys.stderr)
        return 1
    try:
        if args.command == "assert-available":
            evidence: str | dict[str, str] = assert_available()
        elif args.command == "begin":
            evidence = begin_maintenance(args.purpose)
        elif args.command == "assert-locks-quiescent":
            evidence = assert_locks_quiescent(args.purpose)
        elif args.command == "assert-quiescent":
            evidence = assert_quiescent(args.purpose)
        elif args.command == "snapshot-pki":
            evidence = snapshot_pki(args.purpose)
        elif args.command == "release-for-recovery":
            evidence = release_for_recovery(args.purpose)
        else:
            evidence = end_maintenance(args.purpose)
    except MaintenanceBlocked as exc:
        print(f"CARRIER_CERTIFICATE_OPERATION_BLOCKED: {exc}", file=sys.stderr)
        return 75
    except (GuardError, OSError, ValueError) as exc:
        print(f"CARRIER_CERTIFICATE_GUARD_REJECTED: {exc}", file=sys.stderr)
        return 1
    if isinstance(evidence, dict):
        print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    else:
        print(evidence)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
