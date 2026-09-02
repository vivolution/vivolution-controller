#!/usr/bin/env python3
"""Create, validate, and restore exact carrier-gateway rollback bundles.

Bundles deliberately exclude call authority, CDRs, checkpoints, and result
evidence.  Rollback can restore executable/configuration state but can never
resurrect a billable-call permission.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import tarfile
from pathlib import Path
from typing import Any, Callable

SCHEMA = "poc.vivolution.ae/carrier-rollback-bundle/v4"
TRANSACTION_SCHEMA = "poc.vivolution.ae/carrier-rollback-transaction/v3"
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
MAX_BUNDLE_BYTES = 32 * 1024 * 1024
ARTIFACTS = (
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
    "etc/vivolution/carrier-gateway/agi/vivolution-provider-authorize.agi",
    "etc/vivolution/carrier-gateway/authority-broker-version",
    "etc/vivolution/carrier-gateway/asterisk-image-id",
    "etc/vivolution/carrier-gateway/provider-enabled",
    "etc/vivolution/carrier-gateway/provider-profile",
    "etc/systemd/system/user-10003.slice.d/10-vivolution-carrier-gateway-policy.conf",
    "etc/systemd/system/vivolution-carrier-authority-broker.service",
    "etc/systemd/system/vivolution-carrier-authority-broker.socket",
    "etc/tmpfiles.d/vivolution-carrier-gateway.conf",
    "usr/local/libexec/vivolution-carrier-authority-broker",
    "usr/local/libexec/vivolution-carrier-cdr-evidence",
    "usr/local/libexec/vivolution-carrier-gateway-readiness",
    "usr/local/libexec/vivolution-carrier-verify-edge-hosts",
    "usr/local/sbin/vivolution-carrier-gateway-test",
    "var/lib/vivolution/carrier-gateway/rootless-home/.config/containers/systemd/vivolution-carrier-gateway.container",
)
OPTIONAL_ARTIFACTS = (
    "etc/containers/systemd/vivolution-carrier-egress.container",
    "etc/vivolution/carrier-gateway/secrets/provider-auth.conf",
)
EXCLUDED_STATE = (
    "etc/vivolution/carrier-gateway/pki",
    "etc/vivolution/carrier-gateway/egress-pki",
    "var/lib/vivolution-carrier-certificate",
    "var/lib/vivolution/carrier-gateway/authorization",
    "var/lib/vivolution/carrier-gateway/authorization-legacy-untrusted",
    "var/lib/vivolution/carrier-gateway/asterisk-log",
    "var/lib/vivolution/carrier-gateway/egress-log",
    "var/lib/vivolution/carrier-gateway/results",
)
PROVIDER_CREDENTIAL = "etc/vivolution/carrier-gateway/secrets/provider-auth.conf"
PROVIDER_ENABLED = "etc/vivolution/carrier-gateway/provider-enabled"
PROVIDER_PROFILE = "etc/vivolution/carrier-gateway/provider-profile"
PROVIDER_ADAPTER_ROOT = "usr/local/libexec/carrier_cdr_provider_adapters"
PROVIDER_PROFILE_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{1,31}")
PROVIDER_CREDENTIAL_UID = 0
PROVIDER_CREDENTIAL_GID = 10004
PROVIDER_CREDENTIAL_MODE = 0o440
PROVIDER_ADAPTER_UID = 0
PROVIDER_ADAPTER_GID = 0
PROVIDER_ADAPTER_MODE = 0o550


class BundleError(RuntimeError):
    pass


def provider_adapter_relative(enabled: bytes, profile: bytes) -> str | None:
    if enabled == b"false\n" and profile == b"disabled\n":
        return None
    if enabled != b"true\n":
        raise BundleError("provider-enabled marker is not exact")
    try:
        selected = profile.decode("ascii").removesuffix("\n")
    except UnicodeDecodeError as exc:
        raise BundleError("provider profile marker is not ASCII") from exc
    if profile != (selected + "\n").encode() or not PROVIDER_PROFILE_PATTERN.fullmatch(
        selected
    ):
        raise BundleError("provider profile marker is not exact")
    return f"{PROVIDER_ADAPTER_ROOT}/{selected}.py"


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def secure_read(path: Path, maximum: int) -> tuple[bytes, os.stat_result]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise BundleError(f"cannot securely read {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise BundleError(f"artifact is not one single-link regular file: {path}")
        if before.st_size > maximum:
            raise BundleError(f"artifact exceeds its bound: {path}")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
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
    if fingerprint(before) != fingerprint(after) or len(data) != before.st_size:
        raise BundleError(f"artifact changed during read: {path}")
    return data, after


def _write_new(path: Path, data: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode,
    )
    try:
        view = memoryview(data)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise BundleError("short bundle write")
            view = view[count:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_new(path: Path, data: bytes) -> None:
    parent = path.parent
    token = f".{path.name}.building-{os.getpid()}"
    temporary = parent / token
    _write_new(temporary, data)
    try:
        os.link(temporary, path, follow_symlinks=False)
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def build_bundle(system_root: Path = Path("/")) -> tuple[bytes, dict[str, Any]]:
    root = system_root.resolve()
    dynamic_artifacts: tuple[str, ...] = ()
    if PROVIDER_ENABLED in ARTIFACTS and PROVIDER_PROFILE in ARTIFACTS:
        provider_enabled, _enabled_status = secure_read(
            root / PROVIDER_ENABLED, MAX_ARTIFACT_BYTES
        )
        provider_profile, _profile_status = secure_read(
            root / PROVIDER_PROFILE, MAX_ARTIFACT_BYTES
        )
        adapter = provider_adapter_relative(provider_enabled, provider_profile)
        dynamic_artifacts = (adapter,) if adapter is not None else ()
    payloads: dict[str, bytes] = {}
    entries: list[dict[str, Any]] = []
    total = 0
    absent_artifacts: list[str] = []
    all_artifacts = ARTIFACTS + dynamic_artifacts + OPTIONAL_ARTIFACTS
    if len(all_artifacts) != len(set(all_artifacts)):
        raise BundleError("rollback artifact contract contains a duplicate")
    for relative in sorted(all_artifacts):
        candidate = root / relative
        if relative in OPTIONAL_ARTIFACTS and not candidate.exists():
            if candidate.is_symlink():
                raise BundleError(f"optional artifact is an unsafe symlink: {candidate}")
            absent_artifacts.append(relative)
            continue
        data, status = secure_read(candidate, MAX_ARTIFACT_BYTES)
        if relative == PROVIDER_CREDENTIAL and (
            status.st_uid != PROVIDER_CREDENTIAL_UID
            or status.st_gid != PROVIDER_CREDENTIAL_GID
            or stat.S_IMODE(status.st_mode) != PROVIDER_CREDENTIAL_MODE
        ):
            raise BundleError("provider credential is not exact root:10004 0440")
        if relative in dynamic_artifacts and (
            status.st_uid != PROVIDER_ADAPTER_UID
            or status.st_gid != PROVIDER_ADAPTER_GID
            or stat.S_IMODE(status.st_mode) != PROVIDER_ADAPTER_MODE
        ):
            raise BundleError("provider adapter is not exact root:root 0550")
        total += len(data)
        if total > MAX_BUNDLE_BYTES:
            raise BundleError("rollback payload exceeds its aggregate bound")
        payloads[relative] = data
        entries.append(
            {
                "gid": status.st_gid,
                "mode": stat.S_IMODE(status.st_mode),
                "path": relative,
                "sha256": digest(data),
                "size": len(data),
                "uid": status.st_uid,
            }
        )
    manifest = {
        "absentArtifacts": absent_artifacts,
        "artifacts": entries,
        "excludedMutableState": list(EXCLUDED_STATE),
        "schema": SCHEMA,
    }
    if PROVIDER_ENABLED in ARTIFACTS and PROVIDER_PROFILE in ARTIFACTS:
        provider_enabled = payloads.get(PROVIDER_ENABLED)
        provider_profile = payloads.get(PROVIDER_PROFILE)
        adapter = provider_adapter_relative(provider_enabled, provider_profile)
        if adapter is not None and adapter not in payloads:
            raise BundleError("provider adapter is absent from its profile binding")
        credential_present = PROVIDER_CREDENTIAL in payloads
        if credential_present != (provider_enabled == b"true\n"):
            raise BundleError(
                "provider credential presence does not match the bound provider profile"
            )
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as bundle:
        for entry in entries:
            data = payloads[entry["path"]]
            info = tarfile.TarInfo("payload/" + entry["path"])
            info.size = len(data)
            info.mode = entry["mode"]
            info.uid = entry["uid"]
            info.gid = entry["gid"]
            info.mtime = 0
            info.uname = ""
            info.gname = ""
            bundle.addfile(info, io.BytesIO(data))
        manifest_data = canonical(manifest)
        info = tarfile.TarInfo("MANIFEST.json")
        info.size = len(manifest_data)
        info.mode = 0o400
        info.uid = 0
        info.gid = 0
        info.mtime = 0
        info.uname = ""
        info.gname = ""
        bundle.addfile(info, io.BytesIO(manifest_data))
    data = stream.getvalue()
    if len(data) > MAX_BUNDLE_BYTES:
        raise BundleError("rollback bundle exceeds its aggregate bound")
    return data, manifest


def create_bundle(output: Path, digest_output: Path, system_root: Path = Path("/")) -> str:
    if output.exists() or output.is_symlink() or digest_output.exists() or digest_output.is_symlink():
        raise BundleError("rollback output already exists")
    data, _manifest = build_bundle(system_root)
    package_digest = hashlib.sha256(data).hexdigest()
    _publish_new(output, data)
    try:
        _publish_new(digest_output, f"sha256:{package_digest}\n".encode())
    except Exception:
        # An archive without its detached digest is never accepted.  Leave it
        # crash-visible rather than silently replacing any prior authority.
        raise
    return "sha256:" + package_digest


def _parse_exact_json(data: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise BundleError("duplicate manifest key")
            result[key] = value
        return result

    try:
        value = json.loads(data, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundleError("invalid bundle manifest") from exc
    if not isinstance(value, dict) or canonical(value) != data:
        raise BundleError("manifest is not canonical")
    return value


def load_bundle(archive: Path, digest_path: Path) -> tuple[dict[str, bytes], dict[str, Any]]:
    data, _status = secure_read(archive, MAX_BUNDLE_BYTES)
    detached, _digest_status = secure_read(digest_path, 256)
    expected_detached = f"sha256:{hashlib.sha256(data).hexdigest()}\n".encode()
    if detached != expected_detached:
        raise BundleError("detached rollback digest does not match the archive")
    try:
        bundle = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    except tarfile.TarError as exc:
        raise BundleError("rollback archive is not an uncompressed tar") from exc
    with bundle:
        members = bundle.getmembers()
        names = [member.name for member in members]
        if (
            len(names) != len(set(names))
            or not names
            or names[-1] != "MANIFEST.json"
            or names[:-1] != sorted(names[:-1])
            or any(not name.startswith("payload/") for name in names[:-1])
        ):
            raise BundleError("rollback archive members are duplicate, missing, extra, or unordered")
        if any(not member.isfile() or member.issym() or member.islnk() for member in members):
            raise BundleError("rollback archive contains a non-regular member")
        extracted: dict[str, bytes] = {}
        for member in members:
            handle = bundle.extractfile(member)
            if handle is None or member.size > MAX_ARTIFACT_BYTES:
                raise BundleError("rollback member cannot be read safely")
            content = handle.read(MAX_ARTIFACT_BYTES + 1)
            if len(content) != member.size:
                raise BundleError("rollback member size is inconsistent")
            extracted[member.name] = content
    manifest = _parse_exact_json(extracted.pop("MANIFEST.json"))
    if set(manifest) != {
        "absentArtifacts",
        "artifacts",
        "excludedMutableState",
        "schema",
    }:
        raise BundleError("rollback manifest has an inexact field set")
    if manifest["schema"] != SCHEMA or manifest["excludedMutableState"] != list(EXCLUDED_STATE):
        raise BundleError("rollback manifest schema or exclusions drifted")
    entries = manifest["artifacts"]
    absent = manifest["absentArtifacts"]
    if (
        not isinstance(absent, list)
        or absent != sorted(absent)
        or any(value not in OPTIONAL_ARTIFACTS for value in absent)
        or len(absent) != len(set(absent))
    ):
        raise BundleError("rollback optional-artifact absence list is not exact")
    dynamic_artifacts: tuple[str, ...] = ()
    if PROVIDER_ENABLED in ARTIFACTS and PROVIDER_PROFILE in ARTIFACTS:
        adapter = provider_adapter_relative(
            extracted.get("payload/" + PROVIDER_ENABLED, b""),
            extracted.get("payload/" + PROVIDER_PROFILE, b""),
        )
        dynamic_artifacts = (adapter,) if adapter is not None else ()
    expected_present = sorted(
        set(ARTIFACTS + dynamic_artifacts + OPTIONAL_ARTIFACTS) - set(absent)
    )
    if (
        not isinstance(entries, list)
        or [entry.get("path") for entry in entries] != expected_present
        or names != ["payload/" + value for value in expected_present] + ["MANIFEST.json"]
    ):
        raise BundleError("rollback manifest artifact list is not exact")
    for entry in entries:
        if set(entry) != {"gid", "mode", "path", "sha256", "size", "uid"}:
            raise BundleError("rollback artifact metadata is inexact")
        for key in ("gid", "mode", "size", "uid"):
            if type(entry[key]) is not int or entry[key] < 0:
                raise BundleError("rollback artifact metadata type is invalid")
        content = extracted.get("payload/" + entry["path"])
        if content is None or len(content) != entry["size"] or digest(content) != entry["sha256"]:
            raise BundleError("rollback artifact content is not digest-bound")
        if entry["path"] == PROVIDER_CREDENTIAL and (
            entry["uid"] != PROVIDER_CREDENTIAL_UID
            or entry["gid"] != PROVIDER_CREDENTIAL_GID
            or entry["mode"] != PROVIDER_CREDENTIAL_MODE
        ):
            raise BundleError("provider credential metadata is not exact")
        if entry["path"] in dynamic_artifacts and (
            entry["uid"] != PROVIDER_ADAPTER_UID
            or entry["gid"] != PROVIDER_ADAPTER_GID
            or entry["mode"] != PROVIDER_ADAPTER_MODE
        ):
            raise BundleError("provider adapter metadata is not exact")
    if PROVIDER_ENABLED in ARTIFACTS and PROVIDER_PROFILE in ARTIFACTS:
        provider_enabled = extracted.get("payload/" + PROVIDER_ENABLED)
        credential_present = "payload/" + PROVIDER_CREDENTIAL in extracted
        if provider_enabled not in (b"true\n", b"false\n") or credential_present != (
            provider_enabled == b"true\n"
        ):
            raise BundleError("provider credential/profile binding is not exact")
    return extracted, manifest


def _open_parent(root_fd: int, relative: str) -> tuple[int, str]:
    parts = Path(relative).parts
    if not parts or relative.startswith("/") or ".." in parts:
        raise BundleError("unsafe restore path")
    descriptor = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_fd
        return descriptor, parts[-1]
    except Exception:
        os.close(descriptor)
        raise


def restore_bundle(
    archive: Path, digest_path: Path, system_root: Path = Path("/")
) -> None:
    extracted, manifest = load_bundle(archive, digest_path)
    root_fd = os.open(system_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for entry in manifest["artifacts"]:
            parent_fd, name = _open_parent(root_fd, entry["path"])
            temporary = f".{name}.rollback-{os.getpid()}"
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=parent_fd,
                )
                try:
                    content = extracted["payload/" + entry["path"]]
                    view = memoryview(content)
                    while view:
                        count = os.write(descriptor, view)
                        if count <= 0:
                            raise BundleError("short rollback restore write")
                        view = view[count:]
                    os.fchown(descriptor, entry["uid"], entry["gid"])
                    os.fchmod(descriptor, entry["mode"])
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                os.fsync(parent_fd)
            finally:
                try:
                    os.unlink(temporary, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
                os.close(parent_fd)
        for relative in manifest["absentArtifacts"]:
            try:
                parent_fd, name = _open_parent(root_fd, relative)
            except FileNotFoundError:
                continue
            try:
                try:
                    status = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                    raise BundleError(
                        f"optional rollback removal target is unsafe: {relative}"
                    )
                os.unlink(name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
    finally:
        os.close(root_fd)


TRANSACTION_TRANSITIONS = {
    "PREPARING_PRE_ROLLBACK_LKG": {"PRE_ROLLBACK_LKG_PROTECTED"},
    "PRE_ROLLBACK_LKG_PROTECTED": {"RESTORE_STARTED", "RECOVERY_STARTED"},
    "RESTORE_STARTED": {"TARGET_RESTORED", "RECOVERY_STARTED"},
    "TARGET_RESTORED": {"TARGET_ACCEPTED", "RECOVERY_STARTED"},
    "RECOVERY_STARTED": {"RECOVERY_ACCEPTED"},
    "TARGET_ACCEPTED": {"RECOVERY_STARTED"},
    "RECOVERY_ACCEPTED": {"RECOVERY_STARTED"},
}
COMMIT_PHASES = {
    "TARGET_ACCEPTED": "TARGET_COMMITTED",
    "RECOVERY_ACCEPTED": "RECOVERY_COMMITTED",
}
COMMITTED_PHASES = set(COMMIT_PHASES.values())
TARGET_KINDS = {"pending-config", "previous-config"}


def _transaction_parent(
    journal: Path, trusted_uid: int, trusted_gid: int
) -> tuple[int, str]:
    parent_fd = os.open(
        journal.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    status = os.fstat(parent_fd)
    if (
        status.st_uid != trusted_uid
        or status.st_gid != trusted_gid
        or stat.S_IMODE(status.st_mode) != 0o700
    ):
        os.close(parent_fd)
        raise BundleError("rollback transaction parent metadata mismatch")
    return parent_fd, journal.name


def _write_at(directory_fd: int, name: str, data: bytes, mode: int) -> None:
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        mode,
        dir_fd=directory_fd,
    )
    try:
        view = memoryview(data)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise BundleError("short rollback transaction write")
            view = view[count:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_transaction_at(
    parent_fd: int, name: str, trusted_uid: int, trusted_gid: int
) -> dict[str, str]:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=parent_fd,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != trusted_uid
            or before.st_gid != trusted_gid
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_size > 1024
        ):
            raise BundleError("rollback transaction journal metadata mismatch")
        data = os.read(descriptor, 1025)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(data) != before.st_size
        or (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns)
        != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns)
    ):
        raise BundleError("rollback transaction journal changed during read")
    value = _parse_exact_json(data)
    if (
        set(value) != {"phase", "schema", "targetKind"}
        or value["schema"] != TRANSACTION_SCHEMA
        or value["targetKind"] not in TARGET_KINDS
        or value["phase"]
        not in set(TRANSACTION_TRANSITIONS)
        | set(COMMIT_PHASES)
        | COMMITTED_PHASES
        | {"PRE_ROLLBACK_LKG_PROTECTED"}
    ):
        raise BundleError("rollback transaction phase is invalid")
    return value


def read_transaction(
    journal: Path, *, trusted_uid: int | None = None, trusted_gid: int | None = None
) -> dict[str, str]:
    uid = os.geteuid() if trusted_uid is None else trusted_uid
    gid = os.getegid() if trusted_gid is None else trusted_gid
    parent_fd, name = _transaction_parent(journal, uid, gid)
    try:
        return _read_transaction_at(parent_fd, name, uid, gid)
    finally:
        os.close(parent_fd)


def begin_transaction(
    journal: Path,
    target_kind: str,
    *,
    trusted_uid: int | None = None,
    trusted_gid: int | None = None,
    fault_hook: Callable[[str], None] | None = None,
) -> None:
    if target_kind not in TARGET_KINDS:
        raise BundleError("rollback target kind is invalid")
    uid = os.geteuid() if trusted_uid is None else trusted_uid
    gid = os.getegid() if trusted_gid is None else trusted_gid
    parent_fd, name = _transaction_parent(journal, uid, gid)
    try:
        _write_at(
            parent_fd,
            name,
            canonical(
                {
                    "phase": "PREPARING_PRE_ROLLBACK_LKG",
                    "schema": TRANSACTION_SCHEMA,
                    "targetKind": target_kind,
                }
            ),
            0o400,
        )
        if fault_hook:
            fault_hook("transaction-begin-after-file-fsync")
        os.fsync(parent_fd)
        if fault_hook:
            fault_hook("transaction-begin-after-parent-fsync")
    finally:
        os.close(parent_fd)


def transition_transaction(
    journal: Path,
    expected_phase: str,
    next_phase: str,
    *,
    trusted_uid: int | None = None,
    trusted_gid: int | None = None,
    fault_hook: Callable[[str], None] | None = None,
) -> None:
    if next_phase not in TRANSACTION_TRANSITIONS.get(expected_phase, set()):
        raise BundleError("rollback transaction transition is not permitted")
    uid = os.geteuid() if trusted_uid is None else trusted_uid
    gid = os.getegid() if trusted_gid is None else trusted_gid
    parent_fd, name = _transaction_parent(journal, uid, gid)
    temporary = f".{name}.next-{os.getpid()}"
    try:
        current = _read_transaction_at(parent_fd, name, uid, gid)
        if current["phase"] != expected_phase:
            raise BundleError("rollback transaction phase changed unexpectedly")
        _write_at(
            parent_fd,
            temporary,
            canonical({**current, "phase": next_phase}),
            0o400,
        )
        if fault_hook:
            fault_hook("transaction-transition-after-next-fsync")
        os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        if fault_hook:
            fault_hook("transaction-transition-after-replace")
        os.fsync(parent_fd)
        if fault_hook:
            fault_hook("transaction-transition-after-parent-fsync")
    finally:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def commit_transaction(
    journal: Path,
    expected_phase: str,
    *,
    trusted_uid: int | None = None,
    trusted_gid: int | None = None,
    fault_hook: Callable[[str], None] | None = None,
) -> None:
    if expected_phase not in COMMIT_PHASES:
        raise BundleError("rollback transaction is not in a committable phase")
    uid = os.geteuid() if trusted_uid is None else trusted_uid
    gid = os.getegid() if trusted_gid is None else trusted_gid
    parent_fd, name = _transaction_parent(journal, uid, gid)
    temporary = f".{name}.committed-{os.getpid()}"
    try:
        current = _read_transaction_at(parent_fd, name, uid, gid)
        if current["phase"] != expected_phase:
            raise BundleError("rollback transaction commit phase changed unexpectedly")
        _write_at(
            parent_fd,
            temporary,
            canonical({**current, "phase": COMMIT_PHASES[expected_phase]}),
            0o400,
        )
        if fault_hook:
            fault_hook("transaction-commit-after-next-fsync")
        os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        if fault_hook:
            fault_hook("transaction-commit-after-replace")
        os.fsync(parent_fd)
        if fault_hook:
            fault_hook("transaction-commit-after-parent-fsync")
    finally:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def finalize_transaction(
    journal: Path,
    expected_phase: str,
    *,
    trusted_uid: int | None = None,
    trusted_gid: int | None = None,
    fault_hook: Callable[[str], None] | None = None,
) -> None:
    if expected_phase not in COMMITTED_PHASES:
        raise BundleError("rollback transaction is not durably committed")
    uid = os.geteuid() if trusted_uid is None else trusted_uid
    gid = os.getegid() if trusted_gid is None else trusted_gid
    parent_fd, name = _transaction_parent(journal, uid, gid)
    try:
        current = _read_transaction_at(parent_fd, name, uid, gid)
        if current["phase"] != expected_phase:
            raise BundleError("rollback transaction finalize phase changed unexpectedly")
        os.unlink(name, dir_fd=parent_fd)
        if fault_hook:
            fault_hook("transaction-finalize-after-journal-unlink")
        os.fsync(parent_fd)
        if fault_hook:
            fault_hook("transaction-finalize-after-parent-fsync")
    finally:
        os.close(parent_fd)


def abort_transaction(
    journal: Path,
    expected_phase: str,
    *,
    trusted_uid: int | None = None,
    trusted_gid: int | None = None,
) -> None:
    if expected_phase != "PREPARING_PRE_ROLLBACK_LKG":
        raise BundleError("only a pre-mutation preparing transaction may be aborted")
    uid = os.geteuid() if trusted_uid is None else trusted_uid
    gid = os.getegid() if trusted_gid is None else trusted_gid
    parent_fd, name = _transaction_parent(journal, uid, gid)
    try:
        current = _read_transaction_at(parent_fd, name, uid, gid)
        if current["phase"] != expected_phase:
            raise BundleError("rollback transaction abort phase changed unexpectedly")
        os.unlink(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--system-root", type=Path, default=Path("/"))
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--digest-output", type=Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--archive", type=Path, required=True)
    validate.add_argument("--digest", type=Path, required=True)
    restore = subparsers.add_parser("restore")
    restore.add_argument("--archive", type=Path, required=True)
    restore.add_argument("--digest", type=Path, required=True)
    transaction_begin = subparsers.add_parser("transaction-begin")
    transaction_begin.add_argument("--journal", type=Path, required=True)
    transaction_begin.add_argument("--target-kind", choices=sorted(TARGET_KINDS), required=True)
    transaction_show = subparsers.add_parser("transaction-show")
    transaction_show.add_argument("--journal", type=Path, required=True)
    transaction_target = subparsers.add_parser("transaction-target")
    transaction_target.add_argument("--journal", type=Path, required=True)
    transaction_transition = subparsers.add_parser("transaction-transition")
    transaction_transition.add_argument("--journal", type=Path, required=True)
    transaction_transition.add_argument("--from-phase", required=True)
    transaction_transition.add_argument("--to-phase", required=True)
    transaction_commit = subparsers.add_parser("transaction-commit")
    transaction_commit.add_argument("--journal", type=Path, required=True)
    transaction_commit.add_argument("--expected-phase", required=True)
    transaction_finalize = subparsers.add_parser("transaction-finalize")
    transaction_finalize.add_argument("--journal", type=Path, required=True)
    transaction_finalize.add_argument("--expected-phase", required=True)
    transaction_abort = subparsers.add_parser("transaction-abort")
    transaction_abort.add_argument("--journal", type=Path, required=True)
    transaction_abort.add_argument("--expected-phase", required=True)
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise BundleError("rollback bundle operations require root")
        if args.command == "create":
            print(create_bundle(args.output, args.digest_output, args.system_root))
        elif args.command == "validate":
            load_bundle(args.archive, args.digest)
            print("VALID_ROLLBACK_BUNDLE")
        elif args.command == "restore":
            restore_bundle(args.archive, args.digest, args.system_root)
            print("RESTORED_EXACT_ROLLBACK_BUNDLE")
        elif args.command == "transaction-begin":
            begin_transaction(args.journal, args.target_kind)
            print("ROLLBACK_TRANSACTION_PREPARING")
        elif args.command == "transaction-show":
            print(read_transaction(args.journal)["phase"])
        elif args.command == "transaction-target":
            print(read_transaction(args.journal)["targetKind"])
        elif args.command == "transaction-transition":
            transition_transaction(
                args.journal, args.from_phase, args.to_phase
            )
            print(f"ROLLBACK_TRANSACTION_{args.to_phase}")
        elif args.command == "transaction-commit":
            commit_transaction(args.journal, args.expected_phase)
            print("ROLLBACK_TRANSACTION_COMMITTED")
        elif args.command == "transaction-finalize":
            finalize_transaction(args.journal, args.expected_phase)
            print("ROLLBACK_TRANSACTION_FINALIZED")
        elif args.command == "transaction-abort":
            abort_transaction(args.journal, args.expected_phase)
            print("ROLLBACK_TRANSACTION_ABORTED_BEFORE_MUTATION")
    except (BundleError, OSError, ValueError, tarfile.TarError) as exc:
        print(f"rollback bundle refused operation: {exc}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
