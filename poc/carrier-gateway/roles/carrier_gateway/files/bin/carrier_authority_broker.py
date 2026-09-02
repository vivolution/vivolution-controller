#!/usr/bin/env python3
"""Root-owned, fail-closed ledger for one isolated carrier-egress call.

The Common Teams Leg UID never receives the SIP-provider credential and cannot
reach the provider. Only the separately root-managed carrier-egress UID can
reach this broker and the carrier network. The egress Asterisk process remains a
small, pinned POC trust component, but compromise of the much broader
Edge-facing UID cannot bypass the one-call ledger.

A hard link is published in the root-only claims ledger before ``pending`` is
unlinked.  The root-only ``reconcile`` operation converts every interrupted
link/unlink state into an auditable burn, so a crash is safe and recoverable.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
import re
import socket
import stat
import struct
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

AUTHORITY_SCHEMA = "poc.vivolution.ae/carrier-call-authority/v2"
RECEIPT_SCHEMA = "poc.vivolution.ae/carrier-call-claim/v1"
SAFE_REQUEST_ID = re.compile(r"^[a-z0-9][a-z0-9-]{7,63}$")
SAFE_DESTINATION = re.compile(r"^\+[1-9][0-9]{7,14}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_RECORD_BYTES = 4096
MAX_REQUEST_BYTES = 96
BROKER_VERSION = "v4"
DEFAULT_REQUEST_TIMEOUT_SECONDS = 1.0
DEFAULT_MAX_CONNECTIONS = 4
SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)

CONFIG_ARTIFACTS = (
    "etc/vivolution/carrier-gateway/asterisk/asterisk.conf",
    "etc/vivolution/carrier-gateway/asterisk/cdr.conf",
    "etc/vivolution/carrier-gateway/asterisk/cdr_custom.conf",
    "etc/vivolution/carrier-gateway/asterisk/extensions.conf",
    "etc/vivolution/carrier-gateway/asterisk/http.conf",
    "etc/vivolution/carrier-gateway/asterisk/logger.conf",
    "etc/vivolution/carrier-gateway/asterisk/manager.conf",
    "etc/vivolution/carrier-gateway/asterisk/modules.conf",
    "etc/vivolution/carrier-gateway/asterisk/pjsip.conf",
    "etc/vivolution/carrier-gateway/asterisk/rtp.conf",
    "etc/vivolution/carrier-gateway/egress/asterisk/asterisk.conf",
    "etc/vivolution/carrier-gateway/egress/asterisk/cdr.conf",
    "etc/vivolution/carrier-gateway/egress/asterisk/cdr_custom.conf",
    "etc/vivolution/carrier-gateway/egress/asterisk/extensions.conf",
    "etc/vivolution/carrier-gateway/egress/asterisk/http.conf",
    "etc/vivolution/carrier-gateway/egress/asterisk/logger.conf",
    "etc/vivolution/carrier-gateway/egress/asterisk/manager.conf",
    "etc/vivolution/carrier-gateway/egress/asterisk/modules.conf",
    "etc/vivolution/carrier-gateway/egress/asterisk/pjsip.conf",
    "etc/vivolution/carrier-gateway/egress/asterisk/rtp.conf",
    "etc/vivolution/carrier-gateway/secrets/provider-auth.conf",
    "etc/vivolution/carrier-gateway/agi/vivolution-provider-authorize.agi",
    "etc/vivolution/carrier-gateway/authority-broker-version",
    "etc/vivolution/carrier-gateway/asterisk-image-id",
    "etc/vivolution/carrier-gateway/provider-enabled",
    "etc/vivolution/carrier-gateway/provider-profile",
    "etc/vivolution/carrier-gateway/pki/carrier.fullchain.pem",
    "etc/vivolution/carrier-gateway/pki/carrier.key",
    "etc/systemd/system/user-10003.slice.d/10-vivolution-carrier-gateway-policy.conf",
    "etc/systemd/system/vivolution-carrier-authority-broker.service",
    "etc/systemd/system/vivolution-carrier-authority-broker.socket",
    "etc/containers/systemd/vivolution-carrier-egress.container",
    "etc/tmpfiles.d/vivolution-carrier-gateway.conf",
    "usr/local/libexec/vivolution-carrier-authority-broker",
    "usr/local/libexec/vivolution-carrier-cdr-evidence",
    "usr/local/libexec/vivolution-carrier-rollback-bundle",
    "usr/local/libexec/vivolution-carrier-gateway-readiness",
    "usr/local/libexec/vivolution-carrier-verify-edge-hosts",
    "usr/local/sbin/vivolution-carrier-gateway-test",
    "var/lib/vivolution/carrier-gateway/rootless-home/.config/containers/systemd/vivolution-carrier-gateway.container",
)


class AuthorityError(RuntimeError):
    """An authority operation could not be proven safe."""


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _exact_json(
    data: bytes, required_keys: set[str], *, require_canonical: bool = True
) -> dict[str, Any]:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AuthorityError("duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(data, object_pairs_hook=reject_duplicate)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthorityError("invalid authority JSON") from exc
    if not isinstance(value, dict) or set(value) != required_keys:
        raise AuthorityError("authority has an inexact field set")
    if require_canonical and canonical(value) != data:
        raise AuthorityError("authority is not canonical JSON")
    return value


def _read_fd(
    fd: int, limit: int, *, allowed_links: frozenset[int] = frozenset({1})
) -> tuple[bytes, os.stat_result]:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink not in allowed_links:
        raise AuthorityError("authority has an unsafe regular-file link count")
    if before.st_size > limit:
        raise AuthorityError("authority exceeds its size bound")
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        chunk = os.read(fd, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks)
    after = os.fstat(fd)
    stable = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_nlink,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_nlink,
    )
    if not stable or len(data) != before.st_size:
        raise AuthorityError("authority changed while it was read")
    return data, after


def config_digest(
    system_root: Path = Path("/"), artifacts: Iterable[str] = CONFIG_ARTIFACTS
) -> str:
    """Bind call authority to the exact deployed configuration and policy."""
    digest = hashlib.sha256()
    root = system_root.resolve()
    for relative in sorted(artifacts):
        if relative.startswith("/") or ".." in Path(relative).parts:
            raise AuthorityError("unsafe configuration artifact path")
        path = root / relative
        try:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as exc:
            raise AuthorityError(f"configuration artifact unavailable: {relative}") from exc
        try:
            data, status = _read_fd(fd, 8 * 1024 * 1024)
        finally:
            os.close(fd)
        descriptor = {
            "gid": status.st_gid,
            "mode": stat.S_IMODE(status.st_mode),
            "path": relative,
            "sha256": sha256(data),
            "size": len(data),
            "uid": status.st_uid,
        }
        digest.update(canonical(descriptor))
    return "sha256:" + digest.hexdigest()


class AuthorityStore:
    def __init__(
        self,
        root: Path,
        *,
        system_root: Path = Path("/"),
        config_artifacts: Iterable[str] = CONFIG_ARTIFACTS,
        trusted_uid: int = 0,
        trusted_gid: int = 0,
        expected_peer_uid: int = 10004,
        max_seconds: int = 120,
        max_spend_microusd: int = 2_000_000,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.root = root
        self.system_root = system_root
        self.config_artifacts = tuple(config_artifacts)
        self.trusted_uid = trusted_uid
        self.trusted_gid = trusted_gid
        self.expected_peer_uid = expected_peer_uid
        self.max_seconds = max_seconds
        self.max_spend_microusd = max_spend_microusd
        self.fault_hook = fault_hook

    def _fault(self, boundary: str) -> None:
        if self.fault_hook is not None:
            self.fault_hook(boundary)

    @contextmanager
    def _exclusive_lock(self, root_fd: int) -> Iterator[None]:
        """Serialize the service and root CLI across all ledger transitions."""
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
        lock_fd = os.open(".broker.lock", flags, 0o600, dir_fd=root_fd)
        try:
            status = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(status.st_mode)
                or status.st_uid != self.trusted_uid
                or status.st_gid != self.trusted_gid
                or stat.S_IMODE(status.st_mode) != 0o600
                or status.st_nlink != 1
            ):
                raise AuthorityError("broker lock metadata mismatch")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(lock_fd)

    def _open_dir(self, path: Path, mode: int = 0o700) -> int:
        try:
            fd = os.open(
                path,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
            )
        except OSError as exc:
            raise AuthorityError(f"protected directory unavailable: {path.name}") from exc
        status = os.fstat(fd)
        if (
            status.st_uid != self.trusted_uid
            or status.st_gid != self.trusted_gid
            or stat.S_IMODE(status.st_mode) != mode
        ):
            os.close(fd)
            raise AuthorityError(f"protected directory metadata mismatch: {path.name}")
        return fd

    def _open_layout(self) -> tuple[int, int, int, int]:
        root_fd = self._open_dir(self.root)
        try:
            claims_fd = self._open_dir(self.root / "claims")
            invalidated_fd = self._open_dir(self.root / "invalidated")
            ids_fd = self._open_dir(self.root / "ids")
        except Exception:
            os.close(root_fd)
            raise
        return root_fd, claims_fd, invalidated_fd, ids_fd

    def _read_pending(
        self, root_fd: int, *, allowed_links: frozenset[int] = frozenset({1})
    ) -> tuple[bytes, dict[str, Any], os.stat_result]:
        try:
            fd = os.open(
                "pending",
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=root_fd,
            )
        except OSError as exc:
            raise AuthorityError("no usable pending authority") from exc
        try:
            data, status = _read_fd(fd, MAX_RECORD_BYTES, allowed_links=allowed_links)
        finally:
            os.close(fd)
        if (
            status.st_uid != self.trusted_uid
            or status.st_gid != self.trusted_gid
            or stat.S_IMODE(status.st_mode) != 0o600
        ):
            raise AuthorityError("pending authority metadata mismatch")
        keys = {
            "configDigest",
            "destination",
            "expiresEpoch",
            "issuedEpoch",
            "maxCallSeconds",
            "maxSpendMicroUsd",
            "maximumCalls",
            "requestId",
            "schema",
        }
        return data, _exact_json(data, keys), status

    def _validate_record(self, record: dict[str, Any], destination: str, now: int) -> None:
        integer_fields = (
            "issuedEpoch",
            "expiresEpoch",
            "maxCallSeconds",
            "maxSpendMicroUsd",
            "maximumCalls",
        )
        if any(type(record[field]) is not int for field in integer_fields):
            raise AuthorityError("authority integer field has the wrong type")
        if record["schema"] != AUTHORITY_SCHEMA:
            raise AuthorityError("authority schema mismatch")
        if not SAFE_REQUEST_ID.fullmatch(record["requestId"]):
            raise AuthorityError("unsafe request ID")
        if not SAFE_DESTINATION.fullmatch(record["destination"]):
            raise AuthorityError("unsafe destination")
        if record["destination"] != destination:
            raise AuthorityError("destination does not match authority")
        if record["maximumCalls"] != 1:
            raise AuthorityError("authority is not one-shot")
        if not 1 <= record["maxCallSeconds"] <= self.max_seconds:
            raise AuthorityError("call duration exceeds broker policy")
        if not 1 <= record["maxSpendMicroUsd"] <= self.max_spend_microusd:
            raise AuthorityError("spend exceeds broker policy")
        if not record["issuedEpoch"] <= now < record["expiresEpoch"]:
            raise AuthorityError("authority is not currently valid")
        if record["expiresEpoch"] > record["issuedEpoch"] + 600:
            raise AuthorityError("authority validity window is too broad")
        if not DIGEST.fullmatch(record["configDigest"]):
            raise AuthorityError("unsafe configuration digest")
        current = config_digest(self.system_root, self.config_artifacts)
        if record["configDigest"] != current:
            raise AuthorityError("deployed configuration changed after authorization")

    @staticmethod
    def _write_new_at(directory_fd: int, name: str, data: bytes, mode: int = 0o600) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        fd = os.open(name, flags, mode, dir_fd=directory_fd)
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise AuthorityError("short authority write")
                view = view[written:]
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)

    def _read_authority_at(
        self,
        directory_fd: int,
        name: str,
        *,
        allowed_links: frozenset[int] = frozenset({1}),
    ) -> tuple[bytes, dict[str, Any], os.stat_result]:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        try:
            data, status = _read_fd(
                fd, MAX_RECORD_BYTES, allowed_links=allowed_links
            )
        finally:
            os.close(fd)
        if (
            status.st_uid != self.trusted_uid
            or status.st_gid != self.trusted_gid
            or stat.S_IMODE(status.st_mode) != 0o600
        ):
            raise AuthorityError("authority ledger metadata mismatch")
        keys = {
            "configDigest",
            "destination",
            "expiresEpoch",
            "issuedEpoch",
            "maxCallSeconds",
            "maxSpendMicroUsd",
            "maximumCalls",
            "requestId",
            "schema",
        }
        return data, _exact_json(data, keys), status

    def _claim_receipt_is_valid(
        self, claims_fd: int, record: dict[str, Any], authority_data: bytes
    ) -> bool:
        name = f"{record['requestId']}.receipt.json"
        try:
            fd = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=claims_fd,
            )
        except FileNotFoundError:
            return False
        try:
            data, status = _read_fd(fd, MAX_RECORD_BYTES)
        except AuthorityError:
            return False
        finally:
            os.close(fd)
        if (
            status.st_uid != self.trusted_uid
            or status.st_gid != self.trusted_gid
            or stat.S_IMODE(status.st_mode) != 0o600
        ):
            return False
        keys = {
            "authorityDigest",
            "claimedEpoch",
            "configDigest",
            "destinationDigest",
            "maxCallSeconds",
            "maxSpendMicroUsd",
            "peerUid",
            "requestId",
            "schema",
        }
        try:
            receipt = _exact_json(data, keys)
        except AuthorityError:
            return False
        return (
            receipt["schema"] == RECEIPT_SCHEMA
            and receipt["requestId"] == record["requestId"]
            and receipt["authorityDigest"] == sha256(authority_data)
            and receipt["configDigest"] == record["configDigest"]
            and receipt["destinationDigest"]
            == sha256(record["destination"].encode())
            and receipt["maxCallSeconds"] == record["maxCallSeconds"]
            and receipt["maxSpendMicroUsd"] == record["maxSpendMicroUsd"]
            and receipt["peerUid"] == self.expected_peer_uid
            and type(receipt["claimedEpoch"]) is int
        )

    def _write_reconciliation_receipt(
        self,
        invalidated_fd: int,
        record: dict[str, Any],
        authority_data: bytes,
        reason: str,
    ) -> bool:
        name = f"{record['requestId']}.reconciled.json"
        receipt = {
            "authorityDigest": sha256(authority_data),
            "reason": reason,
            "reconciledEpoch": int(time.time()),
            "requestId": record["requestId"],
            "schema": "poc.vivolution.ae/carrier-call-reconciliation/v1",
            "status": "AMBIGUOUS_AUTHORITY_BURNED",
        }
        try:
            self._write_new_at(invalidated_fd, name, canonical(receipt))
            os.fsync(invalidated_fd)
            return True
        except FileExistsError:
            fd = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=invalidated_fd,
            )
            try:
                data, status = _read_fd(fd, MAX_RECORD_BYTES)
            finally:
                os.close(fd)
            existing = _exact_json(
                data,
                {
                    "authorityDigest",
                    "reason",
                    "reconciledEpoch",
                    "requestId",
                    "schema",
                    "status",
                },
            )
            if (
                status.st_uid != self.trusted_uid
                or status.st_gid != self.trusted_gid
                or stat.S_IMODE(status.st_mode) != 0o600
                or existing["authorityDigest"] != sha256(authority_data)
                or existing["requestId"] != record["requestId"]
                or existing["schema"]
                != "poc.vivolution.ae/carrier-call-reconciliation/v1"
                or existing["status"] != "AMBIGUOUS_AUTHORITY_BURNED"
            ):
                raise AuthorityError("reconciliation receipt collision")
            return False

    def _write_invalidation_receipt(
        self,
        invalidated_fd: int,
        invalidated_name: str,
        record: dict[str, Any],
        authority_data: bytes,
        reason: str,
    ) -> bool:
        receipt_name = invalidated_name + ".json"
        receipt = {
            "authorityDigest": sha256(authority_data),
            "invalidatedEpoch": int(time.time()),
            "reason": reason,
            "requestId": record["requestId"],
            "schema": "poc.vivolution.ae/carrier-call-invalidation/v2",
        }
        try:
            self._write_new_at(invalidated_fd, receipt_name, canonical(receipt))
            os.fsync(invalidated_fd)
            return True
        except FileExistsError:
            fd = os.open(
                receipt_name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=invalidated_fd,
            )
            try:
                data, status = _read_fd(fd, MAX_RECORD_BYTES)
            finally:
                os.close(fd)
            existing = _exact_json(
                data,
                {
                    "authorityDigest",
                    "invalidatedEpoch",
                    "reason",
                    "requestId",
                    "schema",
                },
            )
            if (
                status.st_uid != self.trusted_uid
                or status.st_gid != self.trusted_gid
                or stat.S_IMODE(status.st_mode) != 0o600
                or existing["authorityDigest"] != sha256(authority_data)
                or existing["requestId"] != record["requestId"]
                or existing["schema"]
                != "poc.vivolution.ae/carrier-call-invalidation/v2"
            ):
                raise AuthorityError("invalidation receipt collision")
            return False

    def arm(self, request: dict[str, Any], now: int | None = None) -> dict[str, Any]:
        now = int(time.time()) if now is None else now
        exact = {
            "destination",
            "expiresEpoch",
            "maxCallSeconds",
            "maxSpendMicroUsd",
            "requestId",
        }
        if set(request) != exact:
            raise AuthorityError("arm request has an inexact field set")
        if not SAFE_REQUEST_ID.fullmatch(request.get("requestId", "")):
            raise AuthorityError("unsafe request ID")
        if not SAFE_DESTINATION.fullmatch(request.get("destination", "")):
            raise AuthorityError("unsafe destination")
        for key in ("expiresEpoch", "maxCallSeconds", "maxSpendMicroUsd"):
            if type(request.get(key)) is not int:
                raise AuthorityError("arm request integer field has the wrong type")
        record = {
            **request,
            "configDigest": config_digest(self.system_root, self.config_artifacts),
            "issuedEpoch": now,
            "maximumCalls": 1,
            "schema": AUTHORITY_SCHEMA,
        }
        self._validate_record(record, record["destination"], now)
        root_fd, claims_fd, invalidated_fd, ids_fd = self._open_layout()
        try:
            with self._exclusive_lock(root_fd):
                # Burning the request ID first makes a crash fail closed.  No ID is
                # ever reusable, even if pending publication is interrupted.
                self._write_new_at(
                    ids_fd,
                    record["requestId"],
                    sha256(canonical(record)).encode() + b"\n",
                )
                os.fsync(ids_fd)
                self._write_new_at(root_fd, "pending", canonical(record))
                os.fsync(root_fd)
        except FileExistsError as exc:
            raise AuthorityError("pending authority or request ID already exists") from exc
        finally:
            for fd in (ids_fd, invalidated_fd, claims_fd, root_fd):
                os.close(fd)
        return record

    def claim(self, destination: str, peer_uid: int, now: int | None = None) -> dict[str, Any]:
        if peer_uid != self.expected_peer_uid:
            raise AuthorityError("peer UID is not the carrier runtime UID")
        if not SAFE_DESTINATION.fullmatch(destination):
            raise AuthorityError("unsafe destination")
        now = int(time.time()) if now is None else now
        root_fd, claims_fd, invalidated_fd, ids_fd = self._open_layout()
        try:
            with self._exclusive_lock(root_fd):
                data, record, _status = self._read_pending(root_fd)
                self._validate_record(record, destination, now)
                request_id = record["requestId"]
                claimed_name = f"{request_id}.claimed"
                receipt_name = f"{request_id}.receipt.json"
                os.link(
                    "pending",
                    claimed_name,
                    src_dir_fd=root_fd,
                    dst_dir_fd=claims_fd,
                    follow_symlinks=False,
                )
                self._fault("claim-after-link")
                os.fsync(claims_fd)
                self._fault("claim-after-claims-fsync")
                os.unlink("pending", dir_fd=root_fd)
                self._fault("claim-after-pending-unlink")
                os.fsync(root_fd)
                self._fault("claim-after-root-fsync")
                receipt = {
                    "authorityDigest": sha256(data),
                    "claimedEpoch": now,
                    "configDigest": record["configDigest"],
                    "destinationDigest": sha256(destination.encode()),
                    "maxCallSeconds": record["maxCallSeconds"],
                    "maxSpendMicroUsd": record["maxSpendMicroUsd"],
                    "peerUid": peer_uid,
                    "requestId": request_id,
                    "schema": RECEIPT_SCHEMA,
                }
                self._write_new_at(claims_fd, receipt_name, canonical(receipt))
                os.fsync(claims_fd)
                return {"record": record, "receipt": receipt}
        except FileExistsError as exc:
            raise AuthorityError("claim ledger collision burned the authority") from exc
        finally:
            for fd in (ids_fd, invalidated_fd, claims_fd, root_fd):
                os.close(fd)

    def reconcile(self, reason: str, peer_uid: int | None = None) -> bool:
        if peer_uid is not None and peer_uid != self.expected_peer_uid:
            raise AuthorityError("peer UID cannot reconcile authority")
        if not re.fullmatch(r"[a-z][a-z0-9-]{2,31}", reason):
            raise AuthorityError("unsafe reconciliation reason")
        root_fd, claims_fd, invalidated_fd, ids_fd = self._open_layout()
        try:
            with self._exclusive_lock(root_fd):
                changed = False
                try:
                    data, record, pending_status = self._read_pending(
                        root_fd, allowed_links=frozenset({1, 2})
                    )
                except AuthorityError as exc:
                    try:
                        os.stat("pending", dir_fd=root_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        record = None
                    else:
                        raise exc

                if record is not None:
                    request_id = record["requestId"]
                    invalidated_name = f"{request_id}.invalidated"
                    if pending_status.st_nlink == 1:
                        os.link(
                            "pending",
                            invalidated_name,
                            src_dir_fd=root_fd,
                            dst_dir_fd=invalidated_fd,
                            follow_symlinks=False,
                        )
                        self._fault("invalidate-after-link")
                        os.fsync(invalidated_fd)
                        self._fault("invalidate-after-invalidated-fsync")
                    else:
                        siblings: list[tuple[str, str]] = []
                        for name in os.listdir(claims_fd):
                            if not name.endswith(".claimed"):
                                continue
                            status = os.stat(name, dir_fd=claims_fd, follow_symlinks=False)
                            if (
                                status.st_dev,
                                status.st_ino,
                            ) == (pending_status.st_dev, pending_status.st_ino):
                                siblings.append(("claim", name))
                        for name in os.listdir(invalidated_fd):
                            if not name.endswith(".invalidated"):
                                continue
                            status = os.stat(
                                name, dir_fd=invalidated_fd, follow_symlinks=False
                            )
                            if (
                                status.st_dev,
                                status.st_ino,
                            ) == (pending_status.st_dev, pending_status.st_ino):
                                siblings.append(("invalidation", name))
                        if len(siblings) != 1:
                            raise AuthorityError(
                                "ambiguous pending authority lacks one exact ledger sibling"
                            )
                        sibling_kind, sibling_name = siblings[0]
                        if sibling_kind == "invalidation":
                            invalidated_name = sibling_name
                    os.unlink("pending", dir_fd=root_fd)
                    self._fault("invalidate-after-pending-unlink")
                    os.fsync(root_fd)
                    self._fault("invalidate-after-root-fsync")
                    if pending_status.st_nlink == 2 and sibling_kind == "claim":
                        self._write_reconciliation_receipt(
                            invalidated_fd, record, data, reason
                        )
                    else:
                        self._write_invalidation_receipt(
                            invalidated_fd,
                            invalidated_name,
                            record,
                            data,
                            reason,
                        )
                    changed = True

                # A crash after pending unlink but before receipt publication
                # leaves an orphan claim/invalidation.  Reconcile it without
                # ever reconstructing authority.
                for name in sorted(os.listdir(claims_fd)):
                    if not name.endswith(".claimed"):
                        continue
                    authority_data, claim_record, _ = self._read_authority_at(
                        claims_fd, name
                    )
                    if not self._claim_receipt_is_valid(
                        claims_fd, claim_record, authority_data
                    ):
                        changed = self._write_reconciliation_receipt(
                            invalidated_fd, claim_record, authority_data, reason
                        ) or changed
                for name in sorted(os.listdir(invalidated_fd)):
                    if not name.endswith(".invalidated"):
                        continue
                    authority_data, invalidated_record, _ = self._read_authority_at(
                        invalidated_fd, name
                    )
                    changed = self._write_invalidation_receipt(
                        invalidated_fd,
                        name,
                        invalidated_record,
                        authority_data,
                        reason,
                    ) or changed
                return changed
        finally:
            for fd in (ids_fd, invalidated_fd, claims_fd, root_fd):
                os.close(fd)

    def invalidate(self, reason: str, peer_uid: int | None = None) -> bool:
        """Compatibility name: invalidation now includes crash reconciliation."""
        return self.reconcile(reason, peer_uid)


def _read_request(connection: socket.socket) -> str:
    data = bytearray()
    while len(data) <= MAX_REQUEST_BYTES:
        chunk = connection.recv(MAX_REQUEST_BYTES + 1 - len(data))
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in data:
            break
    if len(data) > MAX_REQUEST_BYTES or data.count(b"\n") != 1 or not data.endswith(b"\n"):
        raise AuthorityError("inexact broker request framing")
    try:
        return bytes(data[:-1]).decode("ascii")
    except UnicodeDecodeError as exc:
        raise AuthorityError("broker request is not ASCII") from exc


def _peer_uid(connection: socket.socket) -> int:
    credentials = connection.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", credentials)
    return uid


def handle_connection(
    connection: socket.socket,
    store: AuthorityStore,
    *,
    request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
) -> None:
    response = b"DENIED\n"
    try:
        connection.settimeout(request_timeout_seconds)
        uid = _peer_uid(connection)
        request = _read_request(connection)
        if request.startswith("CLAIM "):
            claimed = store.claim(request[6:], uid)
            record = claimed["record"]
            response = (
                f"AUTHORIZED {record['maxCallSeconds']} {record['requestId']}\n".encode()
            )
        elif request == "INVALIDATE_START":
            store.invalidate("container-start", uid)
            response = b"INVALIDATED\n"
    except (AuthorityError, OSError, ValueError):
        # Never disclose which normal-path authority check failed to the peer.
        response = b"DENIED\n"
    try:
        connection.sendall(response)
    except OSError:
        # A dropped response never restores authority; claim ambiguity is deny.
        pass


def serve(
    store: AuthorityStore,
    listen_fd: int = 3,
    *,
    request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
    max_connections: int = DEFAULT_MAX_CONNECTIONS,
) -> None:
    if not 0.05 <= request_timeout_seconds <= 5.0:
        raise AuthorityError("broker request timeout is outside its strict bound")
    if not 1 <= max_connections <= 16:
        raise AuthorityError("broker concurrency is outside its strict bound")
    # A process crash can occur between publishing the root-owned claim link,
    # removing ``pending``, and publishing its receipt.  Never begin serving a
    # new socket activation with that ambiguous state still present: burn it
    # deterministically first so a fresh operator authorization can be armed.
    store.reconcile("broker-start")
    listener = socket.socket(fileno=listen_fd)
    slots = threading.BoundedSemaphore(max_connections)

    def worker(connection: socket.socket) -> None:
        try:
            with connection:
                handle_connection(
                    connection,
                    store,
                    request_timeout_seconds=request_timeout_seconds,
                )
        finally:
            slots.release()

    while True:
        connection, _address = listener.accept()
        if not slots.acquire(blocking=False):
            try:
                connection.settimeout(request_timeout_seconds)
                connection.sendall(b"DENIED\n")
            except OSError:
                pass
            finally:
                connection.close()
            continue
        threading.Thread(target=worker, args=(connection,), daemon=True).start()


def _store_from_args(args: argparse.Namespace) -> AuthorityStore:
    return AuthorityStore(
        Path(args.authorization_root),
        system_root=Path(args.system_root),
        expected_peer_uid=args.expected_uid,
        max_seconds=args.max_seconds,
        max_spend_microusd=args.max_spend_microusd,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authorization-root", default="/var/lib/vivolution/carrier-gateway/authorization")
    parser.add_argument("--system-root", default="/")
    parser.add_argument("--expected-uid", type=int, default=10004)
    parser.add_argument("--max-seconds", type=int, default=120)
    parser.add_argument("--max-spend-microusd", type=int, default=2_000_000)
    parser.add_argument("--request-timeout-ms", type=int, default=1000)
    parser.add_argument("--max-connections", type=int, default=4)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("serve")
    subparsers.add_parser("config-digest")
    subparsers.add_parser("version")
    arm_parser = subparsers.add_parser("arm")
    arm_parser.add_argument("--stdin", action="store_true", required=True)
    invalidate_parser = subparsers.add_parser("invalidate")
    invalidate_parser.add_argument("--reason", required=True)
    reconcile_parser = subparsers.add_parser("reconcile")
    reconcile_parser.add_argument("--reason", required=True)
    args = parser.parse_args()
    store = _store_from_args(args)
    try:
        if args.command == "serve":
            serve(
                store,
                request_timeout_seconds=args.request_timeout_ms / 1000,
                max_connections=args.max_connections,
            )
        elif args.command == "config-digest":
            print(config_digest(Path(args.system_root)))
        elif args.command == "version":
            print(BROKER_VERSION)
        elif args.command == "arm":
            if os.geteuid() != 0:
                raise AuthorityError("only root may arm call authority")
            raw = sys.stdin.buffer.read(MAX_RECORD_BYTES + 1)
            request = _exact_json(
                raw,
                {"destination", "expiresEpoch", "maxCallSeconds", "maxSpendMicroUsd", "requestId"},
                require_canonical=False,
            )
            record = store.arm(request)
            print(f"ARMED {record['requestId']} {record['expiresEpoch']}")
        elif args.command == "invalidate":
            if os.geteuid() != 0:
                raise AuthorityError("only root may invalidate call authority")
            changed = store.invalidate(args.reason)
            print("INVALIDATED" if changed else "NO_PENDING_AUTHORITY")
        elif args.command == "reconcile":
            if os.geteuid() != 0:
                raise AuthorityError("only root may reconcile call authority")
            changed = store.reconcile(args.reason)
            print("RECONCILED_AND_BURNED" if changed else "LEDGER_ALREADY_CONSISTENT")
    except (AuthorityError, OSError, ValueError) as exc:
        print(f"authority broker refused operation: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
