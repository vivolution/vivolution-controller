#!/usr/bin/env python3
"""Maintain one crash-resumable serialized active-Edge reboot request.

The journal lives beside, never inside, the canonical evidence leaf.  Every
transition is locked, self-digested, atomically replaced, and fsynced.  A
rerun therefore resumes the same exact request instead of allocating a new
run or scheduling an already-observed reboot a second time.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from datetime import datetime, timezone
from typing import Any, Mapping


API_VERSION = "edge.vivolution.ae/active-edge-reboot-journal/v0.1"
KIND = "ActiveEdgeRebootQualificationJournal"
ACKNOWLEDGEMENT = "REBOOT_ACTIVE_SYNTHETIC_EDGES_SBC1_THEN_SBC2_ONCE"
ROLLOVER_ACKNOWLEDGEMENT = (
    "ARCHIVE_RECONCILED_ACTIVE_EDGE_REBOOT_AND_ALLOCATE_FRESH_RUN"
)
SCOPE = "BOUNDED_PRIVATE_SYNTHETIC_POC"
ORDER = ("sbc1", "sbc2")
STATE_DIRECTORY_NAME = ".active-run"
STATE_FILE_NAME = "state.json"
LOCK_FILE_NAME = ".active-edge-reboot.lock"
ROLLOVER_TRANSACTION_FILE_NAME = ".active-edge-reboot-rollover.json"
ARCHIVED_JOURNAL_DIRECTORY_NAME = "journal"
ROLLOVER_MANIFEST_FILE_NAME = "rollover-archive-manifest.json"
ROLLOVER_RECEIPT_FILE_NAME = "rollover-receipt.json"
RUN_ID_RE = re.compile(r"\A[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}\Z")
UUID_RE = re.compile(
    r"\A[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")

ROLLOVER_TRANSACTION_KEYS = {
    "acknowledgement",
    "apiVersion",
    "fromRunId",
    "fromStateDigest",
    "kind",
    "newEvidenceDirectory",
    "newRunId",
    "newStateDigest",
    "scope",
    "transactionDigest",
}
ROLLOVER_MANIFEST_KEYS = {
    "apiVersion",
    "files",
    "fromRunId",
    "fromStateDigest",
    "kind",
    "manifestDigest",
    "scope",
}
ROLLOVER_MANIFEST_ENTRY_KEYS = {"path", "sha256", "size"}
ROLLOVER_RECEIPT_KEYS = {
    "acknowledgement",
    "apiVersion",
    "archiveManifestDigest",
    "archivedJournalPath",
    "fromRunId",
    "fromStateDigest",
    "kind",
    "newEvidenceDirectory",
    "newRunId",
    "newStateDigest",
    "receiptDigest",
    "scope",
    "status",
    "transactionDigest",
}

STATE_KEYS = {
    "abortReason",
    "acceptanceDigest",
    "acknowledgement",
    "apiVersion",
    "currentNode",
    "evidenceDirectory",
    "kind",
    "nodes",
    "rebootOrder",
    "runId",
    "scope",
    "stateDigest",
    "status",
}
NODE_KEYS = {
    "bootIdBefore",
    "lossPeerObservationDigest",
    "lossPeerObservationFile",
    "lossTiming",
    "observationDigest",
    "phase",
    "preflightDigest",
    "preflightFile",
    "reconnectTiming",
    "scheduleTiming",
}
TIMING_KEYS = {"epochMs", "monotonicNs"}
PREFLIGHT_KEYS = {
    "apiVersion",
    "nodeId",
    "peer",
    "peerIdentitySources",
    "peerNodeId",
    "target",
    "targetIdentitySources",
}
PHASES = {
    "PENDING",
    "ARMED",
    "SCHEDULED",
    "SSH_LOST",
    "RECONNECTED",
    "QUALIFIED",
    "ABORTED_RECONCILED",
}
ABORT_REASONS = {
    "FAILED_TRANSIENT_UNIT_RECONCILED",
    "REBOOT_DID_NOT_OCCUR_RECONCILED",
    "REBOOT_OCCURRED_WITHOUT_OBSERVED_SSH_LOSS",
    "READY_BOUND_EXPIRED_RECONCILED",
    "SSH_RECONNECT_BOUND_OR_CLOCK_ORIGIN_EXPIRED_RECONCILED",
}


class JournalError(ValueError):
    """The durable reboot request or requested transition is invalid."""


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def sha256_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JournalError("JSON contains a duplicate member")
        result[key] = value
    return result


def _parse_json(raw: bytes, label: str, *, canonical: bool = True) -> Mapping[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JournalError(f"{label} is not one UTF-8 JSON document") from exc
    if not isinstance(value, dict):
        raise JournalError(f"{label} must be a JSON object")
    if canonical and canonical_bytes(value) != raw:
        raise JournalError(f"{label} is not canonical newline-terminated JSON")
    return value


def _exact(value: object, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise JournalError(f"{label} must have exact keys {sorted(keys)}")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise JournalError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise JournalError(f"{label} is outside its fixed bounds")
    return value


def _timing(value: object, label: str) -> Mapping[str, int]:
    timing = _exact(value, TIMING_KEYS, label)
    return {
        "epochMs": _integer(timing["epochMs"], f"{label} epoch", 1, 2**63 - 1),
        "monotonicNs": _integer(
            timing["monotonicNs"], f"{label} monotonic", 1, 2**63 - 1
        ),
    }


def _bounded_interval(
    earlier: Mapping[str, int],
    later: Mapping[str, int],
    bound_ns: int,
    label: str,
) -> None:
    """Require one bounded interval from the same controller clock origin.

    Monotonic time is authoritative for duration, while the independently
    sampled epoch delta detects a controller reboot/clock-origin change.  A
    two-second tolerance permits bounded wall-clock slew and millisecond
    sampling granularity but fails closed across a restarted controller.
    """

    monotonic_delta = later["monotonicNs"] - earlier["monotonicNs"]
    epoch_delta_ns = (later["epochMs"] - earlier["epochMs"]) * 1_000_000
    if (
        monotonic_delta <= 0
        or monotonic_delta > bound_ns
        or epoch_delta_ns <= 0
        or epoch_delta_ns > bound_ns
        or abs(epoch_delta_ns - monotonic_delta) > 2_000_000_000
    ):
        raise JournalError(f"{label} exceeded its bound or changed controller clock origin")


def _secure_directory(path: Path, mode: int, label: str) -> Path:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise JournalError(f"{label} is absent") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise JournalError(f"{label} must be a runner-owned real mode-{mode:04o} directory")
    return path.resolve(strict=True)


def _secure_read(path: Path, maximum: int = 2 * 1024 * 1024) -> bytes:
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise JournalError(f"{path.name} is absent") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or not 1 <= before.st_size <= maximum
    ):
        raise JournalError(
            f"{path.name} must be a bounded runner-owned single-link mode-0600 file"
        )
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise JournalError(f"{path.name} changed before read")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(256 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(raw) != before.st_size or (
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) != (before.st_size, before.st_mtime_ns, before.st_ctime_ns):
        raise JournalError(f"{path.name} changed while read")
    return raw


def _write_all(descriptor: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("journal write made no progress")
        remaining = remaining[written:]


def _exclusive_staging_path(path: Path) -> Path:
    return path.with_name(f".{path.name}.exclusive-staging")


def _exclusive_write_checkpoint(_path: Path, _phase: str) -> None:
    """No-op fault-injection boundary used by crash-recovery tests."""


def _exclusive_candidate(
    path: Path,
    *,
    maximum: int,
    allowed_links: set[int],
    allow_empty: bool,
) -> tuple[os.stat_result, bytes]:
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise JournalError(f"exclusive file {path.name} is absent") from exc
    minimum = 0 if allow_empty else 1
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink not in allowed_links
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or not minimum <= before.st_size <= maximum
    ):
        raise JournalError(
            f"exclusive file {path.name} is linked, unprotected, or outside bounds"
        )
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_nlink,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_nlink,
        ):
            raise JournalError(f"exclusive file {path.name} changed before read")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(256 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if len(raw) != before.st_size or (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_nlink,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_nlink,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ):
        raise JournalError(f"exclusive file {path.name} changed while read")
    return before, raw


def _normalize_exclusive_target(path: Path, *, maximum: int = 16 * 1024 * 1024) -> None:
    """Finish the only safe hard-link crash state for an exclusive write."""

    if not (path.exists() or path.is_symlink()):
        return
    staging = _exclusive_staging_path(path)
    target_metadata, target_raw = _exclusive_candidate(
        path,
        maximum=maximum,
        allowed_links={1, 2},
        allow_empty=False,
    )
    if target_metadata.st_nlink == 1:
        if staging.exists() or staging.is_symlink():
            raise JournalError(
                f"exclusive target {path.name} has an unrelated staging file"
            )
        _fsync_directory(path.parent)
        return
    if not (staging.exists() or staging.is_symlink()):
        raise JournalError(
            f"exclusive target {path.name} has an unaccounted hard link"
        )
    staging_metadata, staging_raw = _exclusive_candidate(
        staging,
        maximum=maximum,
        allowed_links={2},
        allow_empty=False,
    )
    if (
        (target_metadata.st_dev, target_metadata.st_ino)
        != (staging_metadata.st_dev, staging_metadata.st_ino)
        or staging_raw != target_raw
    ):
        raise JournalError(
            f"exclusive target {path.name} does not match its staging link"
        )
    staging.unlink()
    _fsync_directory(path.parent)
    final_metadata, final_raw = _exclusive_candidate(
        path,
        maximum=maximum,
        allowed_links={1},
        allow_empty=False,
    )
    if final_metadata.st_ino != target_metadata.st_ino or final_raw != target_raw:
        raise JournalError(f"exclusive target {path.name} changed during recovery")


def _exclusive_atomic_write(path: Path, content: bytes) -> None:
    if not content:
        raise JournalError("exclusive writes must not be empty")
    staging = _exclusive_staging_path(path)
    if path.exists() or path.is_symlink():
        _normalize_exclusive_target(path, maximum=len(content))
        _metadata, existing = _exclusive_candidate(
            path,
            maximum=len(content),
            allowed_links={1},
            allow_empty=False,
        )
        if existing != content:
            raise JournalError(f"refusing to replace existing {path.name}")
        return

    if staging.exists() or staging.is_symlink():
        _metadata, staged = _exclusive_candidate(
            staging,
            maximum=len(content),
            allowed_links={1},
            allow_empty=True,
        )
        if staged != content:
            staging.unlink()
            _fsync_directory(path.parent)
        else:
            descriptor = os.open(
                staging,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    if not (staging.exists() or staging.is_symlink()):
        descriptor = os.open(
            staging,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            _exclusive_write_checkpoint(path, "after-create")
            _write_all(descriptor, content)
            _exclusive_write_checkpoint(path, "after-write")
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            _exclusive_write_checkpoint(path, "after-file-fsync")
        finally:
            os.close(descriptor)

    try:
        os.link(staging, path, follow_symlinks=False)
    except FileExistsError:
        _normalize_exclusive_target(path, maximum=len(content))
        _metadata, existing = _exclusive_candidate(
            path,
            maximum=len(content),
            allowed_links={1},
            allow_empty=False,
        )
        if existing != content:
            raise JournalError(f"refusing to replace existing {path.name}")
        return
    _exclusive_write_checkpoint(path, "after-link")
    _fsync_directory(path.parent)
    _exclusive_write_checkpoint(path, "after-link-fsync")
    staging.unlink()
    _exclusive_write_checkpoint(path, "after-unlink")
    _fsync_directory(path.parent)
    _exclusive_write_checkpoint(path, "after-unlink-fsync")


def _atomic_write(path: Path, content: bytes, *, replace: bool) -> None:
    if not replace:
        _exclusive_atomic_write(path, content)
        return
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        _write_all(descriptor, content)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _digest_state(state: Mapping[str, Any]) -> str:
    unsigned = dict(state)
    unsigned.pop("stateDigest", None)
    return sha256_digest(canonical_bytes(unsigned))


def _self_digest(value: Mapping[str, Any], digest_key: str) -> str:
    unsigned = dict(value)
    unsigned.pop(digest_key, None)
    return sha256_digest(canonical_bytes(unsigned))


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_preflight(raw: bytes, node: str) -> Mapping[str, Any]:
    value = _exact(_parse_json(raw, f"{node} preflight"), PREFLIGHT_KEYS, f"{node} preflight")
    peer = "sbc2" if node == "sbc1" else "sbc1"
    if (
        value["apiVersion"]
        != "edge.vivolution.ae/active-edge-reboot-preflight/v0.1"
        or value["nodeId"] != node
        or value["peerNodeId"] != peer
    ):
        raise JournalError(f"{node} preflight identity is invalid")
    target = value["target"]
    if not isinstance(target, dict) or set(target) != {
        "agentState",
        "agentStatus",
        "bootId",
        "health",
        "recoveryUnitEnabled",
        "status",
        "transactionJournalPresent",
        "unitStates",
    }:
        raise JournalError(f"{node} preflight target shape is invalid")
    if not isinstance(target["bootId"], str) or UUID_RE.fullmatch(target["bootId"]) is None:
        raise JournalError(f"{node} preflight boot ID is invalid")
    return value


def _validate_state(
    value: object, evidence_root: Path, state_directory: Path
) -> Mapping[str, Any]:
    state = _exact(value, STATE_KEYS, "reboot journal")
    if (
        state["apiVersion"] != API_VERSION
        or state["kind"] != KIND
        or state["acknowledgement"] != ACKNOWLEDGEMENT
        or state["scope"] != SCOPE
        or state["rebootOrder"] != list(ORDER)
        or not isinstance(state["runId"], str)
        or RUN_ID_RE.fullmatch(state["runId"]) is None
        or state["stateDigest"] != _digest_state(state)
    ):
        raise JournalError("reboot journal authority or self-digest is invalid")
    expected_evidence = str(evidence_root / state["runId"])
    if state["evidenceDirectory"] != expected_evidence:
        raise JournalError("journal evidence directory is not derived from its run ID")
    _secure_directory(Path(expected_evidence), 0o700, "evidence leaf")
    if state["status"] not in {"IN_PROGRESS", "COMPLETE", "ABORTED_RECONCILED"}:
        raise JournalError("journal status is invalid")
    nodes = state["nodes"]
    if not isinstance(nodes, dict) or list(nodes) != list(ORDER):
        raise JournalError("journal node order is invalid")
    first_unqualified: str | None = None
    for node in ORDER:
        item = _exact(nodes[node], NODE_KEYS, f"{node} journal state")
        if item["phase"] not in PHASES:
            raise JournalError(f"{node} journal phase is invalid")
        if item["phase"] == "PENDING":
            if any(item[key] is not None for key in NODE_KEYS - {"phase"}):
                raise JournalError(f"{node} pending journal contains progress")
        else:
            if (
                not isinstance(item["preflightFile"], str)
                or item["preflightFile"] != f"{node}-preflight.json"
                or not isinstance(item["preflightDigest"], str)
                or DIGEST_RE.fullmatch(item["preflightDigest"]) is None
                or not isinstance(item["bootIdBefore"], str)
                or UUID_RE.fullmatch(item["bootIdBefore"]) is None
            ):
                raise JournalError(f"{node} armed journal is incomplete")
            raw = _secure_read(state_directory / item["preflightFile"])
            preflight = _validate_preflight(raw, node)
            if (
                sha256_digest(raw) != item["preflightDigest"]
                or preflight["target"]["bootId"] != item["bootIdBefore"]
            ):
                raise JournalError(f"{node} durable preflight differs from its journal")
            if item["phase"] == "ARMED":
                if item["scheduleTiming"] is not None:
                    raise JournalError(f"{node} armed journal has stale schedule timing")
            elif item["phase"] == "ABORTED_RECONCILED" and item["scheduleTiming"] is None:
                pass
            elif item["scheduleTiming"] is None:
                raise JournalError(f"{node} progressed journal lacks schedule timing")
            else:
                _timing(item["scheduleTiming"], f"{node} schedule timing")
        if item["phase"] in {"SSH_LOST", "RECONNECTED", "QUALIFIED"}:
            _timing(item["lossTiming"], f"{node} SSH-loss timing")
        elif item["phase"] == "ABORTED_RECONCILED" and item["lossTiming"] is not None:
            _timing(item["lossTiming"], f"{node} SSH-loss timing")
        elif item["lossTiming"] is not None:
            raise JournalError(f"{node} journal has an unexpected SSH-loss timing")
        if item["lossTiming"] is not None:
            expected_peer_file = f"{node}-peer-during-ssh-loss.json"
            if (
                item["lossPeerObservationFile"] != expected_peer_file
                or not isinstance(item["lossPeerObservationDigest"], str)
                or DIGEST_RE.fullmatch(item["lossPeerObservationDigest"]) is None
                or sha256_digest(_secure_read(state_directory / expected_peer_file))
                != item["lossPeerObservationDigest"]
            ):
                raise JournalError(f"{node} durable peer-loss observation is invalid")
        elif (
            item["lossPeerObservationFile"] is not None
            or item["lossPeerObservationDigest"] is not None
        ):
            raise JournalError(f"{node} has peer-loss evidence before observed SSH loss")
        if item["phase"] in {"RECONNECTED", "QUALIFIED"}:
            _timing(item["reconnectTiming"], f"{node} reconnect timing")
        elif item["phase"] == "ABORTED_RECONCILED" and item["reconnectTiming"] is not None:
            if item["lossTiming"] is None:
                raise JournalError(f"{node} aborted reconnect lacks SSH-loss timing")
            _timing(item["reconnectTiming"], f"{node} reconnect timing")
        elif item["reconnectTiming"] is not None:
            raise JournalError(f"{node} journal has an unexpected reconnect timing")
        if item["phase"] == "QUALIFIED":
            if not isinstance(item["observationDigest"], str) or DIGEST_RE.fullmatch(
                item["observationDigest"]
            ) is None:
                raise JournalError(f"{node} qualified observation digest is invalid")
            if sha256_digest(_secure_read(Path(expected_evidence) / f"{node}-observation.json")) != item[
                "observationDigest"
            ]:
                raise JournalError(f"{node} qualified observation differs from its journal")
        elif item["observationDigest"] is not None:
            raise JournalError(f"{node} journal has an unexpected observation digest")
        if first_unqualified is None and item["phase"] != "QUALIFIED":
            first_unqualified = node

    if state["status"] == "IN_PROGRESS":
        if state["currentNode"] != first_unqualified or state["abortReason"] is not None or state[
            "acceptanceDigest"
        ] is not None:
            raise JournalError("in-progress journal current-node state is inconsistent")
    elif state["status"] == "COMPLETE":
        if (
            first_unqualified is not None
            or state["currentNode"] is not None
            or state["abortReason"] is not None
            or not isinstance(state["acceptanceDigest"], str)
            or DIGEST_RE.fullmatch(state["acceptanceDigest"]) is None
            or sha256_digest(_secure_read(Path(expected_evidence) / "acceptance.json"))
            != state["acceptanceDigest"]
        ):
            raise JournalError("complete journal evidence binding is inconsistent")
    else:
        if (
            state["currentNode"] not in ORDER
            or state["abortReason"] not in ABORT_REASONS
            or state["acceptanceDigest"] is not None
            or nodes[state["currentNode"]]["phase"] != "ABORTED_RECONCILED"
        ):
            raise JournalError("aborted journal reconciliation is inconsistent")
    return state


def _paths(raw_root: str) -> tuple[Path, Path, Path, Path]:
    root_input = Path(raw_root)
    if not root_input.is_absolute():
        raise JournalError("evidence root must be absolute")
    root = _secure_directory(root_input, 0o700, "evidence root")
    state_directory = root / STATE_DIRECTORY_NAME
    state_path = state_directory / STATE_FILE_NAME
    lock_path = root / LOCK_FILE_NAME
    return root, state_directory, state_path, lock_path


def _lock(path: Path) -> int:
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise JournalError("journal lock is not a protected runner-owned file")
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    return descriptor


def _load(
    root: Path,
    state_directory: Path,
    state_path: Path,
    *,
    allow_rollover: bool = False,
) -> dict[str, Any]:
    rollover_path = root / ROLLOVER_TRANSACTION_FILE_NAME
    if not allow_rollover and (rollover_path.exists() or rollover_path.is_symlink()):
        raise JournalError(
            "a rollover transaction is pending; exact rollover acknowledgement is required"
        )
    _secure_directory(state_directory, 0o700, "active journal directory")
    return dict(_validate_state(_parse_json(_secure_read(state_path), "state.json"), root, state_directory))


def _save(path: Path, state: dict[str, Any]) -> None:
    state["stateDigest"] = _digest_state(state)
    _atomic_write(path, canonical_bytes(state), replace=True)


def _empty_node() -> dict[str, Any]:
    return {
        "bootIdBefore": None,
        "lossPeerObservationDigest": None,
        "lossPeerObservationFile": None,
        "lossTiming": None,
        "observationDigest": None,
        "phase": "PENDING",
        "preflightDigest": None,
        "preflightFile": None,
        "reconnectTiming": None,
        "scheduleTiming": None,
    }


def _new_state(root: Path, run_id: str) -> dict[str, Any]:
    state: dict[str, Any] = {
        "abortReason": None,
        "acceptanceDigest": None,
        "acknowledgement": ACKNOWLEDGEMENT,
        "apiVersion": API_VERSION,
        "currentNode": "sbc1",
        "evidenceDirectory": str(root / run_id),
        "kind": KIND,
        "nodes": {node: _empty_node() for node in ORDER},
        "rebootOrder": list(ORDER),
        "runId": run_id,
        "scope": SCOPE,
        "stateDigest": "",
        "status": "IN_PROGRESS",
    }
    state["stateDigest"] = _digest_state(state)
    return state


def _new_run_id(root: Path) -> str:
    for _attempt in range(32):
        run_id = (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + "-"
            + secrets.token_hex(6)
        )
        if not (root / run_id).exists() and not (root / run_id).is_symlink():
            return run_id
    raise JournalError("could not allocate a unique reboot run ID")


def _begin(args: argparse.Namespace) -> Mapping[str, Any]:
    if args.acknowledgement != ACKNOWLEDGEMENT:
        raise JournalError("one-run acknowledgement is not exact")
    root, state_directory, state_path, lock_path = _paths(args.evidence_root)
    lock_fd = _lock(lock_path)
    try:
        rollover_path = root / ROLLOVER_TRANSACTION_FILE_NAME
        if rollover_path.exists() or rollover_path.is_symlink():
            raise JournalError(
                "a rollover transaction is pending; exact rollover acknowledgement is required"
            )
        if state_directory.exists() or state_directory.is_symlink():
            if state_path.exists() or state_path.is_symlink():
                return _load(root, state_directory, state_path)
            orphan = _secure_directory(
                state_directory, 0o700, "orphan active journal directory"
            )
            if any(orphan.iterdir()):
                raise JournalError(
                    "orphan active journal directory is not empty; refusing recovery"
                )
            orphan.rmdir()
        for candidate in root.glob(f".{STATE_DIRECTORY_NAME.lstrip('.')}.init-*"):
            orphan = _secure_directory(candidate, 0o700, "orphan journal initializer")
            for entry in orphan.iterdir():
                if entry.name != STATE_FILE_NAME:
                    raise JournalError("orphan journal initializer has unexpected content")
                _secure_read(entry)
                entry.unlink()
            orphan.rmdir()
        run_id = _new_run_id(root)
        evidence = root / run_id
        os.mkdir(evidence, 0o700)
        initializer = root / f".{STATE_DIRECTORY_NAME.lstrip('.')}.init-{secrets.token_hex(8)}"
        os.mkdir(initializer, 0o700)
        state = _new_state(root, run_id)
        _save(initializer / STATE_FILE_NAME, state)
        os.replace(initializer, state_directory)
        root_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(root_fd)
        finally:
            os.close(root_fd)
        return _load(root, state_directory, state_path)
    finally:
        os.close(lock_fd)


def _rollover_transaction(
    root: Path,
    terminal: Mapping[str, Any],
    new_state: Mapping[str, Any],
) -> dict[str, Any]:
    transaction: dict[str, Any] = {
        "acknowledgement": ROLLOVER_ACKNOWLEDGEMENT,
        "apiVersion": "edge.vivolution.ae/active-edge-reboot-rollover/v0.1",
        "fromRunId": terminal["runId"],
        "fromStateDigest": terminal["stateDigest"],
        "kind": "ActiveEdgeRebootQualificationRollover",
        "newEvidenceDirectory": new_state["evidenceDirectory"],
        "newRunId": new_state["runId"],
        "newStateDigest": new_state["stateDigest"],
        "scope": SCOPE,
        "transactionDigest": "",
    }
    transaction["transactionDigest"] = _self_digest(
        transaction, "transactionDigest"
    )
    return transaction


def _validate_rollover_transaction(
    value: object,
    root: Path,
    terminal_run_id: str,
    terminal_state_digest: str,
) -> Mapping[str, Any]:
    transaction = _exact(
        value, ROLLOVER_TRANSACTION_KEYS, "reboot rollover transaction"
    )
    if (
        transaction["acknowledgement"] != ROLLOVER_ACKNOWLEDGEMENT
        or transaction["apiVersion"]
        != "edge.vivolution.ae/active-edge-reboot-rollover/v0.1"
        or transaction["kind"] != "ActiveEdgeRebootQualificationRollover"
        or transaction["scope"] != SCOPE
        or transaction["fromRunId"] != terminal_run_id
        or transaction["fromStateDigest"] != terminal_state_digest
        or not isinstance(transaction["newRunId"], str)
        or RUN_ID_RE.fullmatch(transaction["newRunId"]) is None
        or transaction["newRunId"] == terminal_run_id
        or transaction["newEvidenceDirectory"]
        != str(root / transaction["newRunId"])
        or not isinstance(transaction["newStateDigest"], str)
        or DIGEST_RE.fullmatch(transaction["newStateDigest"]) is None
        or transaction["transactionDigest"]
        != _self_digest(transaction, "transactionDigest")
    ):
        raise JournalError("reboot rollover transaction authority is invalid")
    return transaction


def _load_rollover_transaction(
    path: Path,
    root: Path,
    terminal_run_id: str,
    terminal_state_digest: str,
) -> Mapping[str, Any]:
    return _validate_rollover_transaction(
        _parse_json(_secure_read(path), "reboot rollover transaction"),
        root,
        terminal_run_id,
        terminal_state_digest,
    )


def _rollover_initializer(root: Path, run_id: str) -> Path:
    return root / f".active-run.rollover-{run_id}"


def _ensure_rollover_resources(
    root: Path,
    state_directory: Path,
    transaction: Mapping[str, Any],
) -> Mapping[str, Any]:
    new_run_id = transaction["newRunId"]
    evidence = root / new_run_id
    if evidence.exists() or evidence.is_symlink():
        _secure_directory(evidence, 0o700, "new rollover evidence leaf")
    else:
        os.mkdir(evidence, 0o700)
        _fsync_directory(root)
    if any(evidence.iterdir()):
        raise JournalError("new rollover evidence leaf is not empty")

    expected = _new_state(root, new_run_id)
    if expected["stateDigest"] != transaction["newStateDigest"]:
        raise JournalError("new rollover state differs from its transaction")

    initializer = _rollover_initializer(root, new_run_id)
    active_is_new = False
    if state_directory.exists() or state_directory.is_symlink():
        active = _load(
            root,
            state_directory,
            state_directory / STATE_FILE_NAME,
            allow_rollover=True,
        )
        active_is_new = active["runId"] == new_run_id
    if active_is_new:
        if initializer.exists() or initializer.is_symlink():
            raise JournalError("new active journal has a duplicate rollover initializer")
        if active != expected:
            raise JournalError("new active journal differs from its allocated state")
        return expected

    if initializer.exists() or initializer.is_symlink():
        _secure_directory(initializer, 0o700, "rollover initializer")
    else:
        os.mkdir(initializer, 0o700)
        _fsync_directory(root)
    initializer_state = initializer / STATE_FILE_NAME
    allowed_initializer_entries = {
        STATE_FILE_NAME,
        _exclusive_staging_path(initializer_state).name,
    }
    if any(
        entry.name not in allowed_initializer_entries
        for entry in os.scandir(initializer)
    ):
        raise JournalError("rollover initializer has unexpected content")
    _atomic_write(
        initializer_state,
        canonical_bytes(expected),
        replace=False,
    )
    if {entry.name for entry in os.scandir(initializer)} != {STATE_FILE_NAME}:
        raise JournalError("rollover initializer did not reconcile exactly")
    existing = _load(
        root,
        initializer,
        initializer_state,
        allow_rollover=True,
    )
    if existing != expected:
        raise JournalError("rollover initializer differs from its transaction")
    _fsync_directory(root)
    return expected


def _archive_terminal_journal(
    root: Path,
    state_directory: Path,
    terminal_run_id: str,
    terminal_state_digest: str,
    new_run_id: str,
) -> Mapping[str, Any]:
    evidence = _secure_directory(
        root / terminal_run_id, 0o700, "terminal evidence leaf"
    )
    archive = evidence / ARCHIVED_JOURNAL_DIRECTORY_NAME

    if state_directory.exists() or state_directory.is_symlink():
        active = _load(
            root,
            state_directory,
            state_directory / STATE_FILE_NAME,
            allow_rollover=True,
        )
        if active["runId"] == terminal_run_id:
            if archive.exists() or archive.is_symlink():
                raise JournalError(
                    "terminal journal exists both active and archived; refusing overwrite"
                )
            os.rename(state_directory, archive)
            _fsync_directory(evidence)
            _fsync_directory(root)
        elif active["runId"] != new_run_id:
            raise JournalError("active journal is unrelated to the rollover transaction")
    if not (archive.exists() or archive.is_symlink()):
        raise JournalError("terminal journal was not durably archived")

    archived = _load(
        root,
        archive,
        archive / STATE_FILE_NAME,
        allow_rollover=True,
    )
    if (
        archived["runId"] != terminal_run_id
        or archived["stateDigest"] != terminal_state_digest
        or archived["status"] != "ABORTED_RECONCILED"
    ):
        raise JournalError("archived terminal journal identity is invalid")
    return archived


def _archive_file_inventory(evidence: Path) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    total_size = 0
    reserved_metadata = {
        ROLLOVER_MANIFEST_FILE_NAME,
        ROLLOVER_RECEIPT_FILE_NAME,
        f".{ROLLOVER_MANIFEST_FILE_NAME}.exclusive-staging",
        f".{ROLLOVER_RECEIPT_FILE_NAME}.exclusive-staging",
    }

    def visit(directory: Path, relative_directory: Path) -> None:
        nonlocal total_size
        _secure_directory(directory, 0o700, "rollover archive directory")
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            relative = relative_directory / entry.name
            if (
                relative_directory == Path(".")
                and entry.name in reserved_metadata
            ):
                continue
            path = Path(entry.path)
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                visit(path, relative)
                continue
            raw = _secure_read(path, maximum=16 * 1024 * 1024)
            total_size += len(raw)
            if len(files) >= 128 or total_size > 64 * 1024 * 1024:
                raise JournalError("rollover archive inventory exceeds fixed bounds")
            files.append(
                {
                    "path": relative.as_posix(),
                    "sha256": sha256_digest(raw),
                    "size": len(raw),
                }
            )

    visit(evidence, Path("."))
    if not any(item["path"] == "journal/state.json" for item in files):
        raise JournalError("rollover archive does not contain its terminal journal")
    return files


def _archive_manifest(
    evidence: Path,
    terminal_run_id: str,
    terminal_state_digest: str,
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "apiVersion": "edge.vivolution.ae/active-edge-reboot-archive/v0.1",
        "files": _archive_file_inventory(evidence),
        "fromRunId": terminal_run_id,
        "fromStateDigest": terminal_state_digest,
        "kind": "ActiveEdgeRebootQualificationArchive",
        "manifestDigest": "",
        "scope": SCOPE,
    }
    manifest["manifestDigest"] = _self_digest(manifest, "manifestDigest")
    return manifest


def _validate_archive_manifest(
    value: object,
    evidence: Path,
    terminal_run_id: str,
    terminal_state_digest: str,
) -> Mapping[str, Any]:
    manifest = _exact(value, ROLLOVER_MANIFEST_KEYS, "rollover archive manifest")
    raw_files = manifest["files"]
    if not isinstance(raw_files, list):
        raise JournalError("rollover archive manifest file inventory is invalid")
    normalized_files: list[Mapping[str, Any]] = []
    for index, item in enumerate(raw_files):
        entry = _exact(
            item,
            ROLLOVER_MANIFEST_ENTRY_KEYS,
            f"rollover archive manifest file {index}",
        )
        if (
            not isinstance(entry["path"], str)
            or entry["path"].startswith("/")
            or ".." in Path(entry["path"]).parts
            or not isinstance(entry["sha256"], str)
            or DIGEST_RE.fullmatch(entry["sha256"]) is None
        ):
            raise JournalError("rollover archive manifest entry is invalid")
        _integer(entry["size"], "rollover archive file size", 1, 16 * 1024 * 1024)
        normalized_files.append(entry)
    if (
        manifest["apiVersion"]
        != "edge.vivolution.ae/active-edge-reboot-archive/v0.1"
        or manifest["kind"] != "ActiveEdgeRebootQualificationArchive"
        or manifest["scope"] != SCOPE
        or manifest["fromRunId"] != terminal_run_id
        or manifest["fromStateDigest"] != terminal_state_digest
        or manifest["manifestDigest"] != _self_digest(manifest, "manifestDigest")
        or normalized_files != _archive_file_inventory(evidence)
    ):
        raise JournalError("rollover archive manifest does not match retained evidence")
    return manifest


def _ensure_archive_manifest(
    evidence: Path,
    terminal_run_id: str,
    terminal_state_digest: str,
) -> Mapping[str, Any]:
    path = evidence / ROLLOVER_MANIFEST_FILE_NAME
    if path.exists() or path.is_symlink():
        _normalize_exclusive_target(path)
        return _validate_archive_manifest(
            _parse_json(_secure_read(path), "rollover archive manifest"),
            evidence,
            terminal_run_id,
            terminal_state_digest,
        )
    manifest = _archive_manifest(evidence, terminal_run_id, terminal_state_digest)
    _atomic_write(path, canonical_bytes(manifest), replace=False)
    return _validate_archive_manifest(
        _parse_json(_secure_read(path), "rollover archive manifest"),
        evidence,
        terminal_run_id,
        terminal_state_digest,
    )


def _activate_rollover_journal(
    root: Path,
    state_directory: Path,
    transaction: Mapping[str, Any],
) -> Mapping[str, Any]:
    initializer = _rollover_initializer(root, transaction["newRunId"])
    if state_directory.exists() or state_directory.is_symlink():
        active = _load(
            root,
            state_directory,
            state_directory / STATE_FILE_NAME,
            allow_rollover=True,
        )
    else:
        _secure_directory(initializer, 0o700, "rollover initializer")
        os.rename(initializer, state_directory)
        _fsync_directory(root)
        active = _load(
            root,
            state_directory,
            state_directory / STATE_FILE_NAME,
            allow_rollover=True,
        )
    if (
        active["runId"] != transaction["newRunId"]
        or active["stateDigest"] != transaction["newStateDigest"]
        or active["status"] != "IN_PROGRESS"
        or active["currentNode"] != "sbc1"
    ):
        raise JournalError("fresh rollover journal identity is invalid")
    return active


def _rollover_receipt(
    transaction: Mapping[str, Any], manifest: Mapping[str, Any]
) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "acknowledgement": ROLLOVER_ACKNOWLEDGEMENT,
        "apiVersion": "edge.vivolution.ae/active-edge-reboot-rollover-receipt/v0.1",
        "archiveManifestDigest": manifest["manifestDigest"],
        "archivedJournalPath": "journal/state.json",
        "fromRunId": transaction["fromRunId"],
        "fromStateDigest": transaction["fromStateDigest"],
        "kind": "ActiveEdgeRebootQualificationRolloverReceipt",
        "newEvidenceDirectory": transaction["newEvidenceDirectory"],
        "newRunId": transaction["newRunId"],
        "newStateDigest": transaction["newStateDigest"],
        "receiptDigest": "",
        "scope": SCOPE,
        "status": "ARCHIVED_RECONCILED_RUN_AND_ALLOCATED_FRESH_RUN",
        "transactionDigest": transaction["transactionDigest"],
    }
    receipt["receiptDigest"] = _self_digest(receipt, "receiptDigest")
    return receipt


def _validate_rollover_receipt(
    value: object,
    root: Path,
    terminal_run_id: str,
    terminal_state_digest: str,
) -> Mapping[str, Any]:
    receipt = _exact(value, ROLLOVER_RECEIPT_KEYS, "reboot rollover receipt")
    evidence = _secure_directory(
        root / terminal_run_id, 0o700, "terminal evidence leaf"
    )
    for final_name in (
        ROLLOVER_MANIFEST_FILE_NAME,
        ROLLOVER_RECEIPT_FILE_NAME,
    ):
        staging = _exclusive_staging_path(evidence / final_name)
        if staging.exists() or staging.is_symlink():
            raise JournalError("completed rollover retains unfinished metadata staging")
    manifest = _validate_archive_manifest(
        _parse_json(
            _secure_read(evidence / ROLLOVER_MANIFEST_FILE_NAME),
            "rollover archive manifest",
        ),
        evidence,
        terminal_run_id,
        terminal_state_digest,
    )
    archived = _load(
        root,
        evidence / ARCHIVED_JOURNAL_DIRECTORY_NAME,
        evidence / ARCHIVED_JOURNAL_DIRECTORY_NAME / STATE_FILE_NAME,
        allow_rollover=True,
    )
    reconstructed_transaction = {
        "acknowledgement": receipt["acknowledgement"],
        "apiVersion": "edge.vivolution.ae/active-edge-reboot-rollover/v0.1",
        "fromRunId": receipt["fromRunId"],
        "fromStateDigest": receipt["fromStateDigest"],
        "kind": "ActiveEdgeRebootQualificationRollover",
        "newEvidenceDirectory": receipt["newEvidenceDirectory"],
        "newRunId": receipt["newRunId"],
        "newStateDigest": receipt["newStateDigest"],
        "scope": receipt["scope"],
        "transactionDigest": receipt["transactionDigest"],
    }
    if (
        archived["status"] != "ABORTED_RECONCILED"
        or archived["runId"] != terminal_run_id
        or archived["stateDigest"] != terminal_state_digest
        or receipt["acknowledgement"] != ROLLOVER_ACKNOWLEDGEMENT
        or receipt["apiVersion"]
        != "edge.vivolution.ae/active-edge-reboot-rollover-receipt/v0.1"
        or receipt["kind"] != "ActiveEdgeRebootQualificationRolloverReceipt"
        or receipt["scope"] != SCOPE
        or receipt["status"]
        != "ARCHIVED_RECONCILED_RUN_AND_ALLOCATED_FRESH_RUN"
        or receipt["fromRunId"] != terminal_run_id
        or receipt["fromStateDigest"] != terminal_state_digest
        or receipt["archivedJournalPath"] != "journal/state.json"
        or receipt["archiveManifestDigest"] != manifest["manifestDigest"]
        or not isinstance(receipt["newRunId"], str)
        or RUN_ID_RE.fullmatch(receipt["newRunId"]) is None
        or receipt["newRunId"] == terminal_run_id
        or receipt["newEvidenceDirectory"] != str(root / receipt["newRunId"])
        or not isinstance(receipt["newStateDigest"], str)
        or DIGEST_RE.fullmatch(receipt["newStateDigest"]) is None
        or not isinstance(receipt["transactionDigest"], str)
        or DIGEST_RE.fullmatch(receipt["transactionDigest"]) is None
        or receipt["transactionDigest"]
        != _self_digest(reconstructed_transaction, "transactionDigest")
        or receipt["receiptDigest"] != _self_digest(receipt, "receiptDigest")
    ):
        raise JournalError("reboot rollover receipt authority is invalid")
    return receipt


def _rollover_result(receipt: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        "apiVersion": "edge.vivolution.ae/active-edge-reboot-rollover-result/v0.1",
        "archiveManifestDigest": receipt["archiveManifestDigest"],
        "archivedRunId": receipt["fromRunId"],
        "archivedStateDigest": receipt["fromStateDigest"],
        "newEvidenceDirectory": receipt["newEvidenceDirectory"],
        "newRunId": receipt["newRunId"],
        "newStateDigest": receipt["newStateDigest"],
        "status": receipt["status"],
    }


def _rollover(args: argparse.Namespace) -> Mapping[str, Any]:
    if args.acknowledgement != ROLLOVER_ACKNOWLEDGEMENT:
        raise JournalError("rollover acknowledgement is not exact")
    if (
        RUN_ID_RE.fullmatch(args.terminal_run_id) is None
        or DIGEST_RE.fullmatch(args.terminal_state_digest) is None
    ):
        raise JournalError("terminal rollover identity is invalid")

    root, state_directory, state_path, lock_path = _paths(args.evidence_root)
    lock_fd = _lock(lock_path)
    try:
        transaction_path = root / ROLLOVER_TRANSACTION_FILE_NAME
        terminal_evidence = root / args.terminal_run_id
        receipt_path = terminal_evidence / ROLLOVER_RECEIPT_FILE_NAME

        if transaction_path.exists() or transaction_path.is_symlink():
            _normalize_exclusive_target(transaction_path)
        if receipt_path.exists() or receipt_path.is_symlink():
            _normalize_exclusive_target(receipt_path)

        if not (transaction_path.exists() or transaction_path.is_symlink()):
            if receipt_path.exists() or receipt_path.is_symlink():
                receipt = _validate_rollover_receipt(
                    _parse_json(_secure_read(receipt_path), "reboot rollover receipt"),
                    root,
                    args.terminal_run_id,
                    args.terminal_state_digest,
                )
                active = _load(root, state_directory, state_path)
                if (
                    active["runId"] != receipt["newRunId"]
                    or active["stateDigest"] != receipt["newStateDigest"]
                ):
                    raise JournalError(
                        "fresh active journal differs from its rollover receipt"
                    )
                return _rollover_result(receipt)

            terminal = _load(root, state_directory, state_path)
            if (
                terminal["status"] != "ABORTED_RECONCILED"
                or terminal["runId"] != args.terminal_run_id
                or terminal["stateDigest"] != args.terminal_state_digest
            ):
                raise JournalError(
                    "only the exact terminal reconciled journal can roll over"
                )
            for reserved in (
                terminal_evidence / ARCHIVED_JOURNAL_DIRECTORY_NAME,
                terminal_evidence / ROLLOVER_MANIFEST_FILE_NAME,
                terminal_evidence / ROLLOVER_RECEIPT_FILE_NAME,
                _exclusive_staging_path(
                    terminal_evidence / ROLLOVER_MANIFEST_FILE_NAME
                ),
                _exclusive_staging_path(
                    terminal_evidence / ROLLOVER_RECEIPT_FILE_NAME
                ),
            ):
                if reserved.exists() or reserved.is_symlink():
                    raise JournalError(
                        f"terminal evidence already contains reserved {reserved.name}"
                    )
            new_state = _new_state(root, _new_run_id(root))
            transaction = _rollover_transaction(root, terminal, new_state)
            _atomic_write(
                transaction_path, canonical_bytes(transaction), replace=False
            )

        transaction = _load_rollover_transaction(
            transaction_path,
            root,
            args.terminal_run_id,
            args.terminal_state_digest,
        )
        _ensure_rollover_resources(root, state_directory, transaction)
        _archive_terminal_journal(
            root,
            state_directory,
            args.terminal_run_id,
            args.terminal_state_digest,
            transaction["newRunId"],
        )
        manifest = _ensure_archive_manifest(
            _secure_directory(
                terminal_evidence, 0o700, "terminal evidence leaf"
            ),
            args.terminal_run_id,
            args.terminal_state_digest,
        )
        active = _activate_rollover_journal(root, state_directory, transaction)
        if active["stateDigest"] != transaction["newStateDigest"]:
            raise JournalError("activated rollover journal differs from its transaction")

        expected_receipt = _rollover_receipt(transaction, manifest)
        if receipt_path.exists() or receipt_path.is_symlink():
            _normalize_exclusive_target(receipt_path)
            receipt = _validate_rollover_receipt(
                _parse_json(_secure_read(receipt_path), "reboot rollover receipt"),
                root,
                args.terminal_run_id,
                args.terminal_state_digest,
            )
            if receipt != expected_receipt:
                raise JournalError("existing rollover receipt differs from transaction")
        else:
            _atomic_write(
                receipt_path, canonical_bytes(expected_receipt), replace=False
            )
            receipt = _validate_rollover_receipt(
                _parse_json(_secure_read(receipt_path), "reboot rollover receipt"),
                root,
                args.terminal_run_id,
                args.terminal_state_digest,
            )

        _secure_read(transaction_path)
        transaction_path.unlink()
        _fsync_directory(root)
        return _rollover_result(receipt)
    finally:
        os.close(lock_fd)


def _mutate(args: argparse.Namespace, operation: str) -> Mapping[str, Any]:
    root, state_directory, state_path, lock_path = _paths(args.evidence_root)
    lock_fd = _lock(lock_path)
    try:
        state = _load(root, state_directory, state_path)
        if state["status"] != "IN_PROGRESS" or state["currentNode"] != args.node:
            raise JournalError("transition does not target the current in-progress node")
        item = state["nodes"][args.node]
        if operation == "arm":
            if item["phase"] != "PENDING":
                raise JournalError("only a pending node can be armed")
            source = Path(args.preflight_file)
            destination = state_directory / f"{args.node}-preflight.json"
            if source.absolute() == destination.absolute():
                raise JournalError("preflight staging cannot be its journal destination")
            source_exists = source.exists() or source.is_symlink()
            if source_exists:
                raw = _secure_read(source)
            elif destination.exists() or destination.is_symlink():
                _normalize_exclusive_target(destination)
                raw = _secure_read(destination)
            else:
                raise JournalError(f"{args.node} preflight staging and journal are absent")
            preflight = _validate_preflight(raw, args.node)
            if destination.exists() or destination.is_symlink():
                _normalize_exclusive_target(destination)
                if _secure_read(destination) != raw:
                    raise JournalError(
                        f"{args.node} orphan preflight differs from current staging"
                    )
            else:
                _atomic_write(destination, raw, replace=False)
            if source_exists:
                source.unlink()
            item.update(
                {
                    "bootIdBefore": preflight["target"]["bootId"],
                    "phase": "ARMED",
                    "preflightDigest": sha256_digest(raw),
                    "preflightFile": destination.name,
                }
            )
        elif operation == "scheduled":
            if item["phase"] == "ARMED":
                item["scheduleTiming"] = _timing(
                    json.loads(args.timing, object_pairs_hook=_pairs),
                    "schedule timing",
                )
                item["phase"] = "SCHEDULED"
            elif item["phase"] != "SCHEDULED":
                raise JournalError("scheduled transition requires an armed node")
        elif operation == "loss":
            if item["phase"] not in {"ARMED", "SCHEDULED"}:
                raise JournalError("SSH-loss transition is out of order")
            timing = _timing(json.loads(args.timing, object_pairs_hook=_pairs), "SSH-loss timing")
            schedule = _timing(item["scheduleTiming"], "schedule timing")
            _bounded_interval(
                schedule,
                timing,
                60_000_000_000,
                "observed SSH loss",
            )
            preflight = _validate_preflight(
                _secure_read(state_directory / item["preflightFile"]),
                args.node,
            )
            peer_source = Path(args.peer_observation_file)
            peer_raw = _secure_read(peer_source)
            peer_observation = _parse_json(
                peer_raw,
                f"{args.node} peer during SSH loss",
            )
            if peer_observation != preflight["peer"]:
                raise JournalError(
                    "peer observation during SSH loss differs from durable preflight"
                )
            peer_destination = (
                state_directory / f"{args.node}-peer-during-ssh-loss.json"
            )
            if peer_destination.exists() or peer_destination.is_symlink():
                _normalize_exclusive_target(peer_destination)
                existing = _secure_read(peer_destination)
                if existing != peer_raw:
                    raise JournalError(
                        "orphan peer-loss evidence differs from the current observation"
                    )
            else:
                _atomic_write(peer_destination, peer_raw, replace=False)
            peer_source.unlink()
            item["lossTiming"] = timing
            item["lossPeerObservationDigest"] = sha256_digest(peer_raw)
            item["lossPeerObservationFile"] = peer_destination.name
            item["phase"] = "SSH_LOST"
        elif operation == "reconnected":
            if item["phase"] != "SSH_LOST":
                raise JournalError("reconnect transition requires observed SSH loss")
            timing = _timing(json.loads(args.timing, object_pairs_hook=_pairs), "reconnect timing")
            schedule = _timing(item["scheduleTiming"], "schedule timing")
            loss = _timing(item["lossTiming"], "SSH-loss timing")
            _bounded_interval(loss, timing, 300_000_000_000, "SSH reconnect from loss")
            _bounded_interval(
                schedule,
                timing,
                360_000_000_000,
                "SSH reconnect from scheduling",
            )
            item["reconnectTiming"] = timing
            item["phase"] = "RECONNECTED"
        elif operation == "qualified":
            if item["phase"] != "RECONNECTED":
                raise JournalError("qualification requires a reconnected node")
            observation = Path(args.observation_file)
            raw = _secure_read(observation)
            parsed = _parse_json(raw, f"{args.node} observation")
            preflight = _validate_preflight(
                _secure_read(state_directory / item["preflightFile"]),
                args.node,
            )
            peer_during = _parse_json(
                _secure_read(state_directory / item["lossPeerObservationFile"]),
                f"{args.node} durable peer during SSH loss",
            )
            target = parsed.get("target")
            peer = parsed.get("peer")
            reboot = parsed.get("reboot")
            if (
                parsed.get("nodeId") != args.node
                or parsed.get("peerNodeId") != preflight["peerNodeId"]
                or not isinstance(target, dict)
                or not isinstance(peer, dict)
                or not isinstance(reboot, dict)
                or target.get("pre") != preflight["target"]
                or peer.get("before") != preflight["peer"]
                or peer.get("duringTargetSshLoss") != peer_during
                or parsed.get("targetIdentitySources")
                != preflight["targetIdentitySources"]
                or peer.get("identitySources") != preflight["peerIdentitySources"]
            ):
                raise JournalError(
                    "qualified observation is not bound to its durable preflight"
                )
            timing_pairs = (
                (
                    "rebootScheduledAtEpochMs",
                    "rebootScheduledAtMonotonicNs",
                    item["scheduleTiming"],
                    "schedule timing",
                ),
                (
                    "sshLossObservedAtEpochMs",
                    "sshLossObservedAtMonotonicNs",
                    item["lossTiming"],
                    "SSH-loss timing",
                ),
                (
                    "sshReconnectObservedAtEpochMs",
                    "sshReconnectObservedAtMonotonicNs",
                    item["reconnectTiming"],
                    "reconnect timing",
                ),
            )
            for epoch_key, monotonic_key, durable, label in timing_pairs:
                observed = _timing(
                    {
                        "epochMs": reboot.get(epoch_key),
                        "monotonicNs": reboot.get(monotonic_key),
                    },
                    f"observation {label}",
                )
                if observed != _timing(durable, f"durable {label}"):
                    raise JournalError(
                        "qualified observation timing differs from its durable journal"
                    )
            item["observationDigest"] = sha256_digest(raw)
            item["phase"] = "QUALIFIED"
            state["currentNode"] = "sbc2" if args.node == "sbc1" else None
        elif operation == "abort":
            if args.reason not in ABORT_REASONS or item["phase"] == "PENDING":
                raise JournalError("abort reconciliation reason or phase is invalid")
            item["phase"] = "ABORTED_RECONCILED"
            state["abortReason"] = args.reason
            state["status"] = "ABORTED_RECONCILED"
        else:
            raise JournalError("unsupported journal transition")
        _save(state_path, state)
        return _load(root, state_directory, state_path)
    finally:
        os.close(lock_fd)


def _complete(args: argparse.Namespace) -> Mapping[str, Any]:
    root, state_directory, state_path, lock_path = _paths(args.evidence_root)
    lock_fd = _lock(lock_path)
    try:
        state = _load(root, state_directory, state_path)
        if state["status"] == "COMPLETE":
            return state
        if state["status"] != "IN_PROGRESS" or any(
            state["nodes"][node]["phase"] != "QUALIFIED" for node in ORDER
        ):
            raise JournalError("run cannot complete before both nodes qualify")
        acceptance = Path(args.acceptance_file)
        raw = _secure_read(acceptance)
        parsed = _parse_json(raw, "acceptance evidence")
        if parsed.get("status") != "ACTIVE_SYNTHETIC_EDGE_REBOOTS_QUALIFIED":
            raise JournalError("acceptance evidence conclusion is invalid")
        state["acceptanceDigest"] = sha256_digest(raw)
        state["currentNode"] = None
        state["status"] = "COMPLETE"
        _save(state_path, state)
        return _load(root, state_directory, state_path)
    finally:
        os.close(lock_fd)


def _status(args: argparse.Namespace) -> Mapping[str, Any]:
    root, state_directory, state_path, lock_path = _paths(args.evidence_root)
    lock_fd = _lock(lock_path)
    try:
        return _load(root, state_directory, state_path)
    finally:
        os.close(lock_fd)


def _preflight(args: argparse.Namespace) -> Mapping[str, Any]:
    root, state_directory, state_path, lock_path = _paths(args.evidence_root)
    lock_fd = _lock(lock_path)
    try:
        state = _load(root, state_directory, state_path)
        item = state["nodes"][args.node]
        if item["phase"] == "PENDING":
            raise JournalError("pending node has no durable preflight")
        return _validate_preflight(_secure_read(state_directory / item["preflightFile"]), args.node)
    finally:
        os.close(lock_fd)


def _peer_during_loss(args: argparse.Namespace) -> Mapping[str, Any]:
    root, state_directory, state_path, lock_path = _paths(args.evidence_root)
    lock_fd = _lock(lock_path)
    try:
        state = _load(root, state_directory, state_path)
        item = state["nodes"][args.node]
        if item["lossPeerObservationFile"] is None:
            raise JournalError("node has no durable peer observation during SSH loss")
        return _parse_json(
            _secure_read(state_directory / item["lossPeerObservationFile"]),
            f"{args.node} durable peer during SSH loss",
        )
    finally:
        os.close(lock_fd)


def _assess_reconnect(args: argparse.Namespace) -> Mapping[str, Any]:
    """Classify a fresh reconnect observation without mutating the journal."""

    root, state_directory, state_path, lock_path = _paths(args.evidence_root)
    lock_fd = _lock(lock_path)
    try:
        state = _load(root, state_directory, state_path)
        if state["status"] != "IN_PROGRESS" or state["currentNode"] != args.node:
            raise JournalError("reconnect assessment does not target the current node")
        item = state["nodes"][args.node]
        if item["phase"] != "SSH_LOST":
            raise JournalError("reconnect assessment requires durable SSH loss")
        timing = _timing(
            json.loads(args.timing, object_pairs_hook=_pairs),
            "reconnect timing",
        )
        schedule = _timing(item["scheduleTiming"], "schedule timing")
        loss = _timing(item["lossTiming"], "SSH-loss timing")
        try:
            _bounded_interval(loss, timing, 300_000_000_000, "SSH reconnect from loss")
            _bounded_interval(
                schedule,
                timing,
                360_000_000_000,
                "SSH reconnect from scheduling",
            )
        except JournalError:
            assessment = "EXPIRED_OR_CLOCK_ORIGIN_CHANGED"
        else:
            assessment = "IN_BOUND"
        return {
            "apiVersion": "edge.vivolution.ae/active-edge-reconnect-assessment/v0.1",
            "assessment": assessment,
            "nodeId": args.node,
        }
    finally:
        os.close(lock_fd)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--evidence-root", required=True)
    commands = result.add_subparsers(dest="command", required=True)
    begin = commands.add_parser("begin")
    begin.add_argument("--acknowledgement", required=True)
    begin.set_defaults(handler=_begin)
    rollover = commands.add_parser("rollover")
    rollover.add_argument("--acknowledgement", required=True)
    rollover.add_argument("--terminal-run-id", required=True)
    rollover.add_argument("--terminal-state-digest", required=True)
    rollover.set_defaults(handler=_rollover)
    status = commands.add_parser("status")
    status.set_defaults(handler=_status)
    preflight = commands.add_parser("preflight")
    preflight.add_argument("--node", choices=ORDER, required=True)
    preflight.set_defaults(handler=_preflight)
    peer_during = commands.add_parser("peer-during-loss")
    peer_during.add_argument("--node", choices=ORDER, required=True)
    peer_during.set_defaults(handler=_peer_during_loss)
    arm = commands.add_parser("arm")
    arm.add_argument("--node", choices=ORDER, required=True)
    arm.add_argument("--preflight-file", required=True)
    arm.set_defaults(handler=lambda args: _mutate(args, "arm"))
    scheduled = commands.add_parser("mark-scheduled")
    scheduled.add_argument("--node", choices=ORDER, required=True)
    scheduled.add_argument("--timing", required=True)
    scheduled.set_defaults(handler=lambda args: _mutate(args, "scheduled"))
    loss = commands.add_parser("mark-loss")
    loss.add_argument("--node", choices=ORDER, required=True)
    loss.add_argument("--timing", required=True)
    loss.add_argument("--peer-observation-file", required=True)
    loss.set_defaults(handler=lambda args: _mutate(args, "loss"))
    reconnected = commands.add_parser("mark-reconnected")
    reconnected.add_argument("--node", choices=ORDER, required=True)
    reconnected.add_argument("--timing", required=True)
    reconnected.set_defaults(handler=lambda args: _mutate(args, "reconnected"))
    reconnect_assessment = commands.add_parser("assess-reconnect")
    reconnect_assessment.add_argument("--node", choices=ORDER, required=True)
    reconnect_assessment.add_argument("--timing", required=True)
    reconnect_assessment.set_defaults(handler=_assess_reconnect)
    qualified = commands.add_parser("mark-qualified")
    qualified.add_argument("--node", choices=ORDER, required=True)
    qualified.add_argument("--observation-file", required=True)
    qualified.set_defaults(handler=lambda args: _mutate(args, "qualified"))
    abort = commands.add_parser("abort")
    abort.add_argument("--node", choices=ORDER, required=True)
    abort.add_argument("--reason", choices=sorted(ABORT_REASONS), required=True)
    abort.set_defaults(handler=lambda args: _mutate(args, "abort"))
    complete = commands.add_parser("complete")
    complete.add_argument("--acceptance-file", required=True)
    complete.set_defaults(handler=_complete)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        value = args.handler(args)
    except (JournalError, OSError, json.JSONDecodeError) as exc:
        print(f"active Edge reboot journal rejected: {exc}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_bytes(value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
