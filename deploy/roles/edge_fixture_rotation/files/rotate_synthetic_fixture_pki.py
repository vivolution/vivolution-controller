#!/usr/bin/python3
"""Crash-recoverable re-pin of synthetic fixture credentials on one Edge."""

from __future__ import annotations

import fcntl
import grp
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple


ROOT = Path("/var/lib/vivolution-edge/fixture-pki-rotation")
INCOMING_ROOT = ROOT / "incoming"
BACKUP_ROOT = ROOT / "backup"
EVIDENCE_ROOT = ROOT / "evidence"
JOURNAL = ROOT / "transaction.json"
RUNTIME_ROOT = Path("/var/lib/vivolution-edge/runtime")
RUNTIME_LOCK = RUNTIME_ROOT / "runtime.lock"
RUNTIME_STATE = RUNTIME_ROOT / "state.json"
RUNTIME_TRANSACTION = RUNTIME_ROOT / "transaction.json"
AUTHORITY = Path("/var/lib/vivolution-edge/runtime/runtime-authority.json")
NODE_FACTS = Path("/etc/vivolution-edge/node-facts.json")
TLS_ROOT = Path("/etc/vivolution-edge/tls")
PYTHON_ROOT = "/usr/lib/vivolution-edge/python"
MAX_PEM_BYTES = 1024 * 1024
MAX_JSON_BYTES = 256 * 1024
ROTATING_NAMES = frozenset(
    {"fixtureCaCrt", "fixtureClientCrt", "fixtureClientKey"}
)
LIVE_PATHS = {
    "fixtureCaCrt": TLS_ROOT / "fixture-ca.crt",
    "fixtureClientCrt": TLS_ROOT / "fixture-client.crt",
    "fixtureClientKey": TLS_ROOT / "fixture-client.key",
}
INCOMING_PATHS = {
    name: INCOMING_ROOT / path.name for name, path in LIVE_PATHS.items()
}
BACKUP_PATHS = {
    name: BACKUP_ROOT / path.name for name, path in LIVE_PATHS.items()
}
BACKUP_AUTHORITY = BACKUP_ROOT / "runtime-authority.json"
JOURNAL_FIELDS = frozenset({"phase", "wasActive"})
JOURNAL_PHASES = frozenset(
    {
        "PREPARED",
        "SERVICE_STOPPED",
        "SECRETS_INSTALLED",
        "AUTHORITY_RECONCILED",
        "HEALTHY",
    }
)


class FixtureRotationError(RuntimeError):
    pass


def recovery_action_for_phase(phase: str) -> str:
    if phase not in JOURNAL_PHASES:
        raise FixtureRotationError("fixture rotation journal phase is unsupported")
    return "FINALIZE_NEW" if phase == "HEALTHY" else "RESTORE_PRIOR"


def _canonical(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        .encode("ascii")
        + b"\n"
    )


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _fsync_dir(path: Path) -> None:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _assert_directory(path: Path, mode: int) -> None:
    record = path.lstat()
    if (
        not stat.S_ISDIR(record.st_mode)
        or stat.S_ISLNK(record.st_mode)
        or record.st_uid != 0
        or record.st_gid != 0
        or stat.S_IMODE(record.st_mode) != mode
    ):
        raise FixtureRotationError("unsafe fixture rotation directory: {}".format(path))


def _secure_read(
    path: Path,
    *,
    modes: Tuple[int, ...],
    maximum: int,
    gid: Optional[int] = None,
) -> bytes:
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
    except OSError as exc:
        raise FixtureRotationError("secure read rejected {}: {}".format(path, exc)) from exc
    try:
        record = os.fstat(descriptor)
        if (
            not stat.S_ISREG(record.st_mode)
            or record.st_nlink != 1
            or record.st_uid != 0
            or stat.S_IMODE(record.st_mode) not in modes
            or (gid is not None and record.st_gid != gid)
            or not 0 < record.st_size <= maximum
        ):
            raise FixtureRotationError(
                "unsafe owner, mode, group, type, link count, or size: {}".format(path)
            )
        chunks = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) != record.st_size or len(content) > maximum:
            raise FixtureRotationError("file changed during secure read: {}".format(path))
        return content
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, content: bytes, *, mode: int, gid: int) -> None:
    temporary = path.parent / ".{}.{}.fixture-rotation".format(path.name, os.getpid())
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode,
    )
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, 0, gid)
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    _fsync_dir(path.parent)


def _unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    _fsync_dir(path.parent)


def _exists_regular(path: Path) -> bool:
    try:
        record = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(record.st_mode) or not stat.S_ISREG(record.st_mode):
        raise FixtureRotationError("unexpected non-regular path: {}".format(path))
    return True


def _run(
    argv: Tuple[str, ...], name: str, *, allow_failure: bool = False
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=45,
            check=False,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise FixtureRotationError("{} could not execute: {}".format(name, exc)) from exc
    if result.returncode != 0 and not allow_failure:
        detail = (result.stderr or result.stdout).strip().replace("\n", " ")[:400]
        raise FixtureRotationError(
            "{} failed: {}".format(name, detail or "non-zero exit")
        )
    return result


def _service_active() -> bool:
    result = _run(
        ("/usr/bin/systemctl", "is-active", "--quiet", "opensips.service"),
        "OpenSIPS active-state probe",
        allow_failure=True,
    )
    if result.returncode == 0:
        return True
    if result.returncode in (3, 4):
        return False
    raise FixtureRotationError("OpenSIPS active-state probe returned an unexpected status")


def _stop_service() -> None:
    _run(("/usr/bin/systemctl", "stop", "opensips.service"), "stop OpenSIPS")


def _start_and_check_service(private_ipv4: str) -> None:
    _run(("/usr/bin/systemctl", "start", "opensips.service"), "start OpenSIPS")
    _run(
        ("/usr/bin/systemctl", "is-active", "--quiet", "opensips.service"),
        "OpenSIPS health",
    )
    _run(
        ("/usr/sbin/opensips", "-C", "-f", "/etc/opensips/opensips.cfg"),
        "OpenSIPS active parse",
    )
    listeners = _run(("/usr/bin/ss", "-H", "-lnt"), "OpenSIPS listeners").stdout
    for port in (5061, 15061):
        pattern = r"(?<![0-9A-Fa-f:.]){}:{}(?:\s|$)".format(
            re.escape(private_ipv4), port
        )
        if re.search(pattern, listeners) is None:
            raise FixtureRotationError(
                "OpenSIPS did not restore private TLS listener {}:{}".format(
                    private_ipv4, port
                )
            )


def _runtime_modules():
    if PYTHON_ROOT not in sys.path:
        sys.path.insert(0, PYTHON_ROOT)
    try:
        from edge.compiler.core import NodeFacts
        from edge.runtime.contracts import (
            RuntimeAuthority,
            SecretPaths,
            sha256_digest,
            validate_secret_material,
        )
        from edge.schema import manifest_tool
    except ImportError as exc:
        raise FixtureRotationError(
            "installed fixed runtime modules are unavailable: {}".format(exc)
        ) from exc
    return (
        NodeFacts,
        RuntimeAuthority,
        SecretPaths,
        sha256_digest,
        validate_secret_material,
        manifest_tool,
    )


def _load_context(opensips_gid: int, *, require_digest_match: bool = True):
    (
        NodeFacts,
        RuntimeAuthority,
        SecretPaths,
        sha256_digest,
        validate_secret_material,
        manifest_tool,
    ) = _runtime_modules()
    try:
        facts = NodeFacts.from_mapping(
            manifest_tool.parse_json_text(
                _secure_read(
                    NODE_FACTS, modes=(0o600,), maximum=MAX_JSON_BYTES
                ).decode("utf-8")
            )
        )
        authority = RuntimeAuthority.from_mapping(
            manifest_tool.parse_json_text(
                _secure_read(
                    AUTHORITY, modes=(0o600,), maximum=MAX_JSON_BYTES
                ).decode("utf-8")
            )
        )
    except Exception as exc:
        raise FixtureRotationError(
            "installed runtime facts or authority are invalid: {}".format(exc)
        ) from exc
    if authority.profile != "SYNTHETIC_PRIVATE":
        raise FixtureRotationError("fixture credentials cannot be installed on Direct Routing")
    paths = SecretPaths(
        TLS_ROOT / "teams-fullchain.pem",
        TLS_ROOT / "teams-key.pem",
        TLS_ROOT / "fixture-ca.crt",
        TLS_ROOT / "fixture-client.crt",
        TLS_ROOT / "fixture-client.key",
        TLS_ROOT / "microsoft-ca-bundle.pem",
        TLS_ROOT / "pbx-ca-bundle.pem",
        TLS_ROOT / "public-ca-bundle.pem",
    )
    secret_bytes = {
        name: _secure_read(
            path, modes=(0o440,), maximum=MAX_PEM_BYTES, gid=opensips_gid
        )
        for name, path in paths.as_mapping(authority.profile).items()
    }
    actual = {
        name: sha256_digest(content) for name, content in secret_bytes.items()
    }
    if require_digest_match and dict(authority.secret_digests) != actual:
        raise FixtureRotationError(
            "current TLS bytes already differ from protected runtime authority"
        )
    return (
        facts,
        authority,
        secret_bytes,
        RuntimeAuthority,
        sha256_digest,
        validate_secret_material,
        manifest_tool,
    )


def _build_reconciled_authority(
    opensips_gid: int, incoming: Mapping[str, bytes]
) -> tuple[Any, bytes, str]:
    (
        facts,
        authority,
        secret_bytes,
        RuntimeAuthority,
        sha256_digest,
        validate_secret_material,
        manifest_tool,
    ) = _load_context(opensips_gid)
    rotated = dict(secret_bytes)
    rotated.update(incoming)
    record = authority.canonical_record()
    record["secretDigests"] = {
        name: sha256_digest(content) for name, content in sorted(rotated.items())
    }
    reconciled = RuntimeAuthority.from_mapping(record)
    try:
        validate_secret_material(facts, reconciled, rotated)
    except Exception as exc:
        raise FixtureRotationError(
            "incoming fixture credentials failed full runtime validation: {}".format(exc)
        ) from exc
    encoded = manifest_tool.canonical_json_bytes(reconciled.canonical_record()) + b"\n"
    return facts, encoded, _digest(encoded)


def _write_journal(phase: str, was_active: bool) -> None:
    if phase not in JOURNAL_PHASES:
        raise FixtureRotationError("internal fixture rotation phase is invalid")
    _atomic_write(
        JOURNAL,
        _canonical({"phase": phase, "wasActive": was_active}),
        mode=0o600,
        gid=0,
    )


def _read_journal() -> Optional[Dict[str, Any]]:
    if not _exists_regular(JOURNAL):
        return None
    try:
        value = json.loads(
            _secure_read(JOURNAL, modes=(0o600,), maximum=MAX_JSON_BYTES).decode(
                "utf-8"
            )
        )
    except (UnicodeError, ValueError) as exc:
        raise FixtureRotationError("fixture rotation journal is invalid") from exc
    if (
        not isinstance(value, dict)
        or set(value) != JOURNAL_FIELDS
        or value.get("phase") not in JOURNAL_PHASES
        or not isinstance(value.get("wasActive"), bool)
    ):
        raise FixtureRotationError("fixture rotation journal differs from its contract")
    return value


def _cleanup_transaction_files(*, remove_incoming: bool) -> None:
    paths = list(BACKUP_PATHS.values())
    if remove_incoming:
        paths.extend(INCOMING_PATHS.values())
    for path in paths:
        _unlink(path)
    _unlink(BACKUP_AUTHORITY)
    _unlink(JOURNAL)


def _restore_previous(journal: Mapping[str, Any], opensips_gid: int) -> None:
    if recovery_action_for_phase(journal["phase"]) == "FINALIZE_NEW":
        _load_context(opensips_gid)
        _cleanup_transaction_files(remove_incoming=False)
        return
    if _service_active():
        _stop_service()
    for name, live_path in LIVE_PATHS.items():
        previous = _secure_read(
            BACKUP_PATHS[name], modes=(0o400,), maximum=MAX_PEM_BYTES
        )
        _atomic_write(live_path, previous, mode=0o440, gid=opensips_gid)
    previous_authority = _secure_read(
        BACKUP_AUTHORITY, modes=(0o400,), maximum=MAX_JSON_BYTES
    )
    _atomic_write(AUTHORITY, previous_authority, mode=0o600, gid=0)
    context = _load_context(opensips_gid)
    if journal["wasActive"]:
        _start_and_check_service(context[0].private_ipv4)
    _cleanup_transaction_files(remove_incoming=False)


def _write_evidence(record: Mapping[str, Any]) -> Dict[str, Any]:
    unsigned = dict(record)
    unsigned["apiVersion"] = "edge.vivolution.ae/fixture-pki-rotation/v0.1"
    unsigned["kind"] = "SyntheticFixturePkiRotationEvidence"
    value = dict(unsigned)
    value["evidenceDigest"] = _digest(_canonical(unsigned).rstrip(b"\n"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = "{}-{}.json".format(
        stamp, value["evidenceDigest"].split(":", 1)[1]
    )
    _atomic_write(EVIDENCE_ROOT / filename, _canonical(value), mode=0o600, gid=0)
    return value


def _prepare_directories() -> None:
    for path, mode in (
        (ROOT, 0o700),
        (INCOMING_ROOT, 0o700),
        (BACKUP_ROOT, 0o700),
        (EVIDENCE_ROOT, 0o700),
        (RUNTIME_ROOT, 0o755),
    ):
        if not path.exists():
            path.mkdir(mode=mode, parents=False)
            os.chown(path, 0, 0)
            os.chmod(path, mode)
        _assert_directory(path, mode)


def main() -> int:
    if os.geteuid() != 0:
        raise FixtureRotationError("fixture PKI rotation must execute as root")
    if _exists_regular(RUNTIME_TRANSACTION):
        raise FixtureRotationError(
            "runtime activation transaction is pending; recover it before fixture rotation"
        )
    opensips_gid = grp.getgrnam("opensips").gr_gid
    _prepare_directories()
    lock_descriptor = os.open(
        RUNTIME_LOCK,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        lock_record = os.fstat(lock_descriptor)
        if not stat.S_ISREG(lock_record.st_mode) or lock_record.st_nlink != 1:
            raise FixtureRotationError("runtime lock is not a single-link regular file")
        os.fchmod(lock_descriptor, 0o600)
        os.fchown(lock_descriptor, 0, 0)
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        if _exists_regular(RUNTIME_TRANSACTION):
            raise FixtureRotationError(
                "runtime activation transaction is pending; recover it before fixture rotation"
            )
        if not _exists_regular(RUNTIME_STATE):
            raise FixtureRotationError("protected runtime state is absent")
        stale = _read_journal()
        if stale is not None:
            _restore_previous(stale, opensips_gid)

        incoming = {
            name: _secure_read(path, modes=(0o400,), maximum=MAX_PEM_BYTES)
            for name, path in INCOMING_PATHS.items()
        }
        facts, new_authority, new_authority_digest = _build_reconciled_authority(
            opensips_gid, incoming
        )
        current_context = _load_context(opensips_gid)
        current_secrets = current_context[2]
        if all(current_secrets[name] == incoming[name] for name in ROTATING_NAMES):
            evidence = _write_evidence(
                {
                    "authorityDigest": _digest(
                        _secure_read(AUTHORITY, modes=(0o600,), maximum=MAX_JSON_BYTES)
                    ),
                    "nodeId": current_context[1].node_id,
                    "opensipsRestarted": False,
                    "status": "FIXTURE_PKI_UNCHANGED",
                    "timestamp": datetime.now(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                }
            )
            for path in INCOMING_PATHS.values():
                _unlink(path)
            sys.stdout.buffer.write(_canonical(evidence))
            return 0

        for name in ROTATING_NAMES:
            _atomic_write(
                BACKUP_PATHS[name],
                current_secrets[name],
                mode=0o400,
                gid=0,
            )
        old_authority = _secure_read(
            AUTHORITY, modes=(0o600,), maximum=MAX_JSON_BYTES
        )
        _atomic_write(BACKUP_AUTHORITY, old_authority, mode=0o400, gid=0)
        was_active = _service_active()
        if not was_active:
            raise FixtureRotationError(
                "OpenSIPS must be healthy and active before serialized fixture rotation"
            )
        _write_journal("PREPARED", was_active)
        try:
            if was_active:
                _stop_service()
            _write_journal("SERVICE_STOPPED", was_active)
            for name, live_path in LIVE_PATHS.items():
                _atomic_write(live_path, incoming[name], mode=0o440, gid=opensips_gid)
            _write_journal("SECRETS_INSTALLED", was_active)
            _atomic_write(AUTHORITY, new_authority, mode=0o600, gid=0)
            _write_journal("AUTHORITY_RECONCILED", was_active)
            _load_context(opensips_gid)
            if was_active:
                _start_and_check_service(facts.private_ipv4)
            _write_journal("HEALTHY", was_active)
        except Exception as exc:
            try:
                _restore_previous(_read_journal() or {}, opensips_gid)
            except Exception as recovery_exc:
                raise FixtureRotationError(
                    "fixture rotation failed and rollback also failed: {}; {}".format(
                        exc, recovery_exc
                    )
                ) from recovery_exc
            raise FixtureRotationError(
                "fixture rotation failed and prior credentials were restored: {}".format(
                    exc
                )
            ) from exc

        evidence = _write_evidence(
            {
                "authorityDigest": new_authority_digest,
                "fixtureCaDigest": _digest(incoming["fixtureCaCrt"]),
                "fixtureClientCertificateDigest": _digest(
                    incoming["fixtureClientCrt"]
                ),
                "nodeId": current_context[1].node_id,
                "opensipsRestarted": was_active,
                "status": "FIXTURE_PKI_ROTATED",
                "timestamp": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            }
        )
        _cleanup_transaction_files(remove_incoming=True)
        sys.stdout.buffer.write(_canonical(evidence))
        return 0
    finally:
        os.close(lock_descriptor)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FixtureRotationError, KeyError, OSError, ValueError) as exc:
        print("fixture PKI rotation rejected: {}".format(exc), file=sys.stderr)
        raise SystemExit(2)
