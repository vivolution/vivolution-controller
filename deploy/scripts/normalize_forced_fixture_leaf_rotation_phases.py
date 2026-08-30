#!/usr/bin/env python3
"""Migrate only the exact legacy no-newline forced-rotation phase files.

The migration validates a canonical copy of the complete evidence set before
changing any historical phase.  It then revalidates the exact source bytes and
metadata immediately before atomic replacement.  Normal evidence compilation
remains strictly newline-terminated and is run separately afterward.
"""

from __future__ import annotations

import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
from typing import Any


SCRIPT_ROOT = Path(__file__).resolve().parent


def _load_contract():
    path = SCRIPT_ROOT / "forced_fixture_leaf_rotation_evidence.py"
    specification = importlib.util.spec_from_file_location(
        "vivolution_forced_fixture_phase_migration_contract", path
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("forced fixture evidence contract is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


contract = _load_contract()
PHASES = contract.PHASES
MAX_PHASE_BYTES = 4 * 1024 * 1024
canonical_bytes = contract.canonical_bytes


class PhaseNormalizationError(ValueError):
    """The evidence cannot be migrated without changing its meaning."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, member in pairs:
        if key in value:
            raise PhaseNormalizationError("phase JSON contains duplicate members")
        value[key] = member
    return value


def _phase_boundary(raw: bytes, name: str) -> bytes:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PhaseNormalizationError(f"{name} is not one UTF-8 JSON value") from exc
    if not isinstance(value, dict):
        raise PhaseNormalizationError(f"{name} is not one JSON object")
    canonical = canonical_bytes(value)
    if raw not in (canonical, canonical[:-1]):
        raise PhaseNormalizationError(
            f"{name} differs from the exact legacy no-newline representation"
        )
    return canonical


def _stat_signature(record: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        record.st_dev,
        record.st_ino,
        record.st_size,
        record.st_mtime_ns,
        record.st_ctime_ns,
    )


def _read_phase(directory: Path, phase: str) -> tuple[bytes, os.stat_result]:
    name = f"{phase}.json"
    path = directory / name
    before = path.lstat()
    raw = contract._read_file(directory, name, MAX_PHASE_BYTES)
    after = path.lstat()
    if _stat_signature(before) != _stat_signature(after):
        raise PhaseNormalizationError(f"{name} changed across its secure read")
    return raw, before


def _write_file(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PhaseNormalizationError(f"failed to write {path.name}")
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(
        directory,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _cleanup_workspace(workspace: Path, allowed_names: set[str]) -> None:
    try:
        record = workspace.lstat()
    except FileNotFoundError:
        return
    if (
        not stat.S_ISDIR(record.st_mode)
        or stat.S_ISLNK(record.st_mode)
        or record.st_uid != os.getuid()
        or stat.S_IMODE(record.st_mode) != 0o700
    ):
        raise PhaseNormalizationError("stale migration workspace is unsafe")
    with os.scandir(workspace) as iterator:
        entries = list(iterator)
    for entry in entries:
        item = entry.stat(follow_symlinks=False)
        if (
            entry.name not in allowed_names
            or not stat.S_ISREG(item.st_mode)
            or stat.S_ISLNK(item.st_mode)
            or item.st_uid != os.getuid()
            or stat.S_IMODE(item.st_mode) != 0o600
            or item.st_nlink != 1
        ):
            raise PhaseNormalizationError("stale migration workspace content is unsafe")
    for entry in entries:
        os.unlink(entry.path)
    os.rmdir(workspace)
    _fsync_directory(workspace.parent)


def _cleanup_stale_workspaces(parent: Path, request_id: str, names: set[str]) -> None:
    prefix = f".{request_id}.phase-migration-workspace."
    with os.scandir(parent) as iterator:
        workspaces = [Path(entry.path) for entry in iterator if entry.name.startswith(prefix)]
    for workspace in workspaces:
        _cleanup_workspace(workspace, names)


def _cleanup_stale_write_files(parent: Path, request_id: str) -> None:
    prefix = f".{request_id}.phase-migration-write."
    phase_pattern = "|".join(re.escape(phase) for phase in PHASES)
    pattern = re.compile(
        rf"\A{re.escape(prefix)}(?:{phase_pattern})\.json\.[0-9a-f]{{24}}\Z"
    )
    with os.scandir(parent) as iterator:
        entries = [entry for entry in iterator if entry.name.startswith(prefix)]
    for entry in entries:
        item = entry.stat(follow_symlinks=False)
        if (
            pattern.fullmatch(entry.name) is None
            or not stat.S_ISREG(item.st_mode)
            or stat.S_ISLNK(item.st_mode)
            or item.st_uid != os.getuid()
            or stat.S_IMODE(item.st_mode) != 0o600
            or item.st_nlink != 1
        ):
            raise PhaseNormalizationError("stale phase migration write is unsafe")
    for entry in entries:
        os.unlink(entry.path)
    if entries:
        _fsync_directory(parent)


def _acquire_lock(parent: Path, request_id: str) -> int:
    path = parent / f".{request_id}.phase-migration.lock"
    descriptor = os.open(
        path,
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    record = os.fstat(descriptor)
    if (
        not stat.S_ISREG(record.st_mode)
        or record.st_uid != os.getuid()
        or stat.S_IMODE(record.st_mode) != 0o600
        or record.st_nlink != 1
    ):
        os.close(descriptor)
        raise PhaseNormalizationError("phase migration lock is unsafe")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(descriptor)
        raise PhaseNormalizationError("another phase migration is active") from exc
    return descriptor


def _atomic_replace(
    path: Path,
    canonical: bytes,
    expected_raw: bytes,
    expected_stat: os.stat_result,
    request_id: str,
) -> None:
    current_raw, current_stat = _read_phase(path.parent, path.stem)
    if (
        current_raw != expected_raw
        or _stat_signature(current_stat) != _stat_signature(expected_stat)
    ):
        raise PhaseNormalizationError(f"{path.name} changed before replacement")

    temporary = path.parent.parent / (
        f".{request_id}.phase-migration-write.{path.name}.{secrets.token_hex(12)}"
    )
    try:
        _write_file(temporary, canonical)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
        _fsync_directory(path.parent.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def normalize_directory(directory: Path, request_id: str) -> int:
    if contract.REQUEST_ID_RE.fullmatch(request_id) is None:
        raise PhaseNormalizationError("request ID is invalid")
    root = contract._validate_directory(directory)
    lock = _acquire_lock(root.parent, request_id)
    try:
        contract._validate_layout(root)
        try:
            (root / "acceptance.json").lstat()
        except FileNotFoundError:
            pass
        else:
            raise PhaseNormalizationError("accepted evidence must never be migrated")

        with os.scandir(root) as iterator:
            names = {entry.name for entry in iterator}
        _cleanup_stale_write_files(root.parent, request_id)
        _cleanup_stale_workspaces(root.parent, request_id, names)

        source: dict[str, bytes] = {}
        phase_source: dict[str, tuple[bytes, bytes, os.stat_result]] = {}
        for name in sorted(names):
            phase = name.removesuffix(".json")
            if phase in PHASES and name == f"{phase}.json":
                raw, record = _read_phase(root, phase)
                canonical = _phase_boundary(raw, name)
                source[name] = canonical
                phase_source[phase] = (raw, canonical, record)
            else:
                source[name] = contract._read_file(root, name)

        state = contract._parse_json(source["state.json"], "state.json")
        if state.get("requestId") != request_id:
            raise PhaseNormalizationError("state does not name the exact migration request")

        workspace = Path(
            tempfile.mkdtemp(
                prefix=f".{request_id}.phase-migration-workspace.", dir=root.parent
            )
        )
        os.chmod(workspace, 0o700)
        try:
            for name, raw in source.items():
                _write_file(workspace / name, raw)
            _fsync_directory(workspace)
            compiled = contract.compile_evidence(workspace)
            if compiled.get("requestId") != request_id:
                raise PhaseNormalizationError(
                    "canonical migration snapshot names a different request"
                )
        except contract.ForcedFixtureRotationEvidenceError as exc:
            raise PhaseNormalizationError(
                f"complete canonical migration snapshot is invalid: {exc}"
            ) from exc
        finally:
            _cleanup_workspace(workspace, names)

        changed = 0
        for phase in PHASES:
            raw, canonical, record = phase_source[phase]
            if raw == canonical:
                continue
            _atomic_replace(
                root / f"{phase}.json",
                canonical,
                raw,
                record,
                request_id,
            )
            changed += 1
        return changed
    finally:
        os.close(lock)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--request-id", required=True)
    arguments = parser.parse_args()
    try:
        changed = normalize_directory(arguments.evidence_dir, arguments.request_id)
    except (
        FileNotFoundError,
        OSError,
        PhaseNormalizationError,
        contract.ForcedFixtureRotationEvidenceError,
    ) as exc:
        print(f"forced fixture phase normalization rejected: {exc}", file=sys.stderr)
        return 2
    print(f"FORCED_FIXTURE_PHASES_CANONICAL changed={changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
