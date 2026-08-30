#!/usr/bin/env python3
"""Journal one explicitly forced synthetic fixture leaf rotation.

The fixture role selects complete PKI generations with one atomic symlink
replacement.  This helper binds that replacement to a unique operator request
and makes the surrounding qualification safe to resume: if execution stops
after selection but before finalization, the next run observes the exact
public-certificate transition and finalizes the existing request instead of
forcing another rotation.

Only public certificate identity is recorded.  Private keys are never read.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import Any, Mapping, Optional


API_VERSION = "edge.vivolution.ae/forced-fixture-leaf-rotation-state/v0.1"
ACKNOWLEDGEMENT = "FORCE_SYNTHETIC_FIXTURE_LEAVES_ONCE_AND_REPIN_BOTH_EDGES"
SCOPE = "BOUNDED_PRIVATE_SYNTHETIC_POC"
PKI_CURRENT = Path("/etc/vivolution/voice-fixture/pki-current")
PKI_GENERATIONS = Path("/etc/vivolution/voice-fixture/pki-generations")
GENERATION_REQUEST_NAME = "generation-request.json"
STATE_ROOT = Path("/var/lib/vivolution/voice-fixture/forced-leaf-rotation")
LOCK = STATE_ROOT / "qualification.lock"
LEAF_NAMES = ("asterisk", "sipp", "sbc1", "sbc2")
PHASES = frozenset({"PREPARED", "SELECTED"})
STATE_KEYS = {
    "acknowledgement",
    "after",
    "apiVersion",
    "before",
    "phase",
    "requestId",
    "scope",
    "selectedAtEpochMs",
}
SNAPSHOT_KEYS = {"ca", "generation", "leaves", "rotationRequest"}
CERTIFICATE_KEYS = {"pemSha256", "serial", "sha256Fingerprint"}
GENERATION_REQUEST_KEYS = {"acknowledgement", "apiVersion", "requestId", "scope"}
GENERATION_REQUEST_API_VERSION = (
    "edge.vivolution.ae/synthetic-fixture-generation-request/v0.1"
)
OPERATIONAL_SCOPE = "EXPIRY_AWARE_OPERATIONAL"
REQUEST_ID_RE = re.compile(r"\A[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}\Z")
GENERATION_RE = re.compile(r"\Ageneration-[0-9a-f]{32}\Z")
SERIAL_RE = re.compile(r"\A[0-9A-F]{1,40}\Z")
FINGERPRINT_RE = re.compile(r"\A[0-9a-f]{64}\Z")
MAX_STATE_BYTES = 128 * 1024
MAX_CERTIFICATE_BYTES = 1024 * 1024


class ForcedFixtureRotationStateError(ValueError):
    """The forced-rotation journal or public PKI state is unsafe."""


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _exact_mapping(value: object, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ForcedFixtureRotationStateError(
            f"{label} must have exact keys {sorted(keys)}"
        )
    return value


def _assert_root_directory(path: Path, mode: int) -> None:
    record = path.lstat()
    if (
        not stat.S_ISDIR(record.st_mode)
        or stat.S_ISLNK(record.st_mode)
        or record.st_uid != 0
        or record.st_gid != 0
        or stat.S_IMODE(record.st_mode) != mode
    ):
        raise ForcedFixtureRotationStateError(f"unsafe directory {path}")


def _prepare_state_root() -> None:
    if not STATE_ROOT.exists():
        STATE_ROOT.mkdir(mode=0o700, parents=False)
        os.chown(STATE_ROOT, 0, 0)
        os.chmod(STATE_ROOT, 0o700)
    _assert_root_directory(STATE_ROOT, 0o700)


def _safe_read(
    path: Path,
    *,
    mode: int,
    maximum: int,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> bytes:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != expected_uid
            or before.st_gid != expected_gid
            or stat.S_IMODE(before.st_mode) != mode
            or not 0 < before.st_size <= maximum
        ):
            raise ForcedFixtureRotationStateError(f"unsafe file {path}")
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
    if (
        len(content) != before.st_size
        or after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_size != before.st_size
        or after.st_mtime_ns != before.st_mtime_ns
        or after.st_ctime_ns != before.st_ctime_ns
    ):
        raise ForcedFixtureRotationStateError(f"file changed while read: {path}")
    return content


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, content: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
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
        os.fchown(descriptor, 0, 0)
        view = memoryview(content)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _parse_certificate(content: bytes, label: str) -> Mapping[str, str]:
    try:
        result = subprocess.run(
            [
                "/usr/bin/openssl",
                "x509",
                "-inform",
                "PEM",
                "-noout",
                "-serial",
                "-fingerprint",
                "-sha256",
            ],
            input=content,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ForcedFixtureRotationStateError(
            f"could not inspect {label}: {exc}"
        ) from exc
    if result.returncode != 0:
        raise ForcedFixtureRotationStateError(f"{label} is not a valid PEM certificate")
    try:
        lines = result.stdout.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ForcedFixtureRotationStateError(
            f"{label} certificate identity is not ASCII"
        ) from exc
    if len(lines) != 2 or not lines[0].startswith("serial=") or "=" not in lines[1]:
        raise ForcedFixtureRotationStateError(
            f"{label} certificate identity has an unexpected shape"
        )
    serial = lines[0].removeprefix("serial=").upper()
    fingerprint = lines[1].split("=", 1)[1].replace(":", "").lower()
    if SERIAL_RE.fullmatch(serial) is None or FINGERPRINT_RE.fullmatch(fingerprint) is None:
        raise ForcedFixtureRotationStateError(
            f"{label} certificate serial or fingerprint is invalid"
        )
    return {
        "pemSha256": hashlib.sha256(content).hexdigest(),
        "serial": serial,
        "sha256Fingerprint": fingerprint,
    }


def validate_generation_request(
    value: object, label: str
) -> Optional[Mapping[str, Any]]:
    if value is None:
        # Existing generations created before request binding remain valid as
        # the PREPARED baseline, but can never satisfy forced finalization.
        return None
    record = _exact_mapping(value, GENERATION_REQUEST_KEYS, label)
    if record["apiVersion"] != GENERATION_REQUEST_API_VERSION:
        raise ForcedFixtureRotationStateError(
            f"{label} API version is invalid"
        )
    request_id = record["requestId"]
    if request_id is None:
        if (
            record["acknowledgement"] is not None
            or record["scope"] != OPERATIONAL_SCOPE
        ):
            raise ForcedFixtureRotationStateError(
                f"{label} operational identity is invalid"
            )
    elif (
        not isinstance(request_id, str)
        or REQUEST_ID_RE.fullmatch(request_id) is None
        or record["acknowledgement"] != ACKNOWLEDGEMENT
        or record["scope"] != SCOPE
    ):
        raise ForcedFixtureRotationStateError(
            f"{label} forced-request identity is invalid"
        )
    return record


def _read_generation_request(generation: Path) -> Optional[Mapping[str, Any]]:
    path = generation / GENERATION_REQUEST_NAME
    try:
        content = _safe_read(path, mode=0o644, maximum=MAX_STATE_BYTES)
    except FileNotFoundError:
        return None
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ForcedFixtureRotationStateError(
            "generation request metadata is not one UTF-8 JSON object"
        ) from exc
    if canonical_bytes(value) != content:
        raise ForcedFixtureRotationStateError(
            "generation request metadata is not canonical JSON"
        )
    return validate_generation_request(value, "generation request metadata")


def snapshot() -> Mapping[str, Any]:
    pointer = PKI_CURRENT.lstat()
    if (
        not stat.S_ISLNK(pointer.st_mode)
        or pointer.st_uid != 0
        or pointer.st_gid != 0
    ):
        raise ForcedFixtureRotationStateError(
            "current fixture PKI pointer is not a root-owned symlink"
        )
    generation = PKI_CURRENT.resolve(strict=True)
    generations_root = PKI_GENERATIONS.resolve(strict=True)
    if generation.parent != generations_root or GENERATION_RE.fullmatch(generation.name) is None:
        raise ForcedFixtureRotationStateError(
            "current fixture PKI pointer escapes its immutable generation root"
        )
    _assert_root_directory(generations_root, 0o755)
    _assert_root_directory(generation, 0o755)

    def certificate(name: str) -> Mapping[str, str]:
        content = _safe_read(
            generation / f"{name}.crt", mode=0o644, maximum=MAX_CERTIFICATE_BYTES
        )
        return _parse_certificate(content, name)

    return {
        "ca": certificate("ca"),
        "generation": str(generation),
        "leaves": {name: certificate(name) for name in LEAF_NAMES},
        "rotationRequest": _read_generation_request(generation),
    }


def validate_snapshot(value: object, label: str) -> Mapping[str, Any]:
    record = _exact_mapping(value, SNAPSHOT_KEYS, label)
    generation = record["generation"]
    if (
        not isinstance(generation, str)
        or not generation.startswith(str(PKI_GENERATIONS) + "/")
        or GENERATION_RE.fullmatch(Path(generation).name) is None
    ):
        raise ForcedFixtureRotationStateError(f"{label} generation is invalid")

    def validate_certificate(value: object, certificate_label: str) -> None:
        certificate = _exact_mapping(value, CERTIFICATE_KEYS, certificate_label)
        if (
            not isinstance(certificate["pemSha256"], str)
            or FINGERPRINT_RE.fullmatch(certificate["pemSha256"]) is None
            or not isinstance(certificate["sha256Fingerprint"], str)
            or FINGERPRINT_RE.fullmatch(certificate["sha256Fingerprint"]) is None
            or not isinstance(certificate["serial"], str)
            or SERIAL_RE.fullmatch(certificate["serial"]) is None
        ):
            raise ForcedFixtureRotationStateError(
                f"{certificate_label} public identity is invalid"
            )

    validate_certificate(record["ca"], f"{label} CA")
    leaves = record["leaves"]
    if not isinstance(leaves, dict) or set(leaves) != set(LEAF_NAMES):
        raise ForcedFixtureRotationStateError(
            f"{label} leaves must contain exactly {LEAF_NAMES}"
        )
    for name in LEAF_NAMES:
        validate_certificate(leaves[name], f"{label} {name}")
    validate_generation_request(record["rotationRequest"], f"{label} rotation request")
    return record


def _require_request_marker(value: object, request_id: str) -> None:
    snapshot_record = validate_snapshot(value, "selected snapshot")
    request = snapshot_record["rotationRequest"]
    if request is None or request["requestId"] != request_id:
        raise ForcedFixtureRotationStateError(
            "selected generation is not bound to this forced-rotation request"
        )


def validate_transition(before: object, after: object) -> None:
    old = validate_snapshot(before, "before snapshot")
    new = validate_snapshot(after, "after snapshot")
    if old["generation"] == new["generation"]:
        raise ForcedFixtureRotationStateError(
            "forced rotation did not select a new immutable generation"
        )
    if old["ca"] != new["ca"]:
        raise ForcedFixtureRotationStateError(
            "forced leaf rotation changed the fixture CA"
        )
    for name in LEAF_NAMES:
        for field in CERTIFICATE_KEYS:
            if old["leaves"][name][field] == new["leaves"][name][field]:
                raise ForcedFixtureRotationStateError(
                    f"forced rotation did not change {name} {field}"
                )


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ForcedFixtureRotationStateError("state JSON contains duplicate members")
        result[key] = value
    return result


def validate_state(value: object, request_id: str) -> Mapping[str, Any]:
    record = _exact_mapping(value, STATE_KEYS, "forced rotation state")
    if (
        record["apiVersion"] != API_VERSION
        or record["acknowledgement"] != ACKNOWLEDGEMENT
        or record["scope"] != SCOPE
        or record["requestId"] != request_id
        or record["phase"] not in PHASES
    ):
        raise ForcedFixtureRotationStateError("forced rotation state identity is invalid")
    validate_snapshot(record["before"], "state before snapshot")
    if record["phase"] == "PREPARED":
        if record["after"] is not None or record["selectedAtEpochMs"] is not None:
            raise ForcedFixtureRotationStateError("PREPARED state contains completion data")
    else:
        validate_transition(record["before"], record["after"])
        _require_request_marker(record["after"], request_id)
        selected = record["selectedAtEpochMs"]
        if isinstance(selected, bool) or not isinstance(selected, int) or selected < 1:
            raise ForcedFixtureRotationStateError("selection time is invalid")
    return record


def _read_state(path: Path, request_id: str) -> Mapping[str, Any]:
    content = _safe_read(path, mode=0o600, maximum=MAX_STATE_BYTES)
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ForcedFixtureRotationStateError("state is not one UTF-8 JSON object") from exc
    if canonical_bytes(value) != content:
        raise ForcedFixtureRotationStateError("state is not canonical JSON")
    return validate_state(value, request_id)


def _state_path(request_id: str) -> Path:
    if REQUEST_ID_RE.fullmatch(request_id) is None:
        raise ForcedFixtureRotationStateError("request ID is invalid")
    return STATE_ROOT / f"{request_id}.json"


def _prepared_state(request_id: str, before: Mapping[str, Any]) -> Mapping[str, Any]:
    return {
        "acknowledgement": ACKNOWLEDGEMENT,
        "after": None,
        "apiVersion": API_VERSION,
        "before": before,
        "phase": "PREPARED",
        "requestId": request_id,
        "scope": SCOPE,
        "selectedAtEpochMs": None,
    }


def _selected_state(
    state: Mapping[str, Any], after: Mapping[str, Any]
) -> Mapping[str, Any]:
    validate_transition(state["before"], after)
    _require_request_marker(after, str(state["requestId"]))
    result = dict(state)
    result["after"] = after
    result["phase"] = "SELECTED"
    result["selectedAtEpochMs"] = time.time_ns() // 1_000_000
    validate_state(result, str(state["requestId"]))
    return result


def _find_other_prepared(request_id: str) -> None:
    for entry in os.scandir(STATE_ROOT):
        if entry.name == LOCK.name:
            continue
        match = re.fullmatch(
            r"([0-9]{8}T[0-9]{6}Z-[0-9a-f]{12})\.json", entry.name
        )
        if match is None:
            raise ForcedFixtureRotationStateError(
                "forced rotation state root contains an unexpected entry"
            )
        candidate_id = match.group(1)
        if candidate_id == request_id:
            continue
        candidate = STATE_ROOT / entry.name
        state = _read_state(candidate, candidate_id)
        if state["phase"] == "PREPARED":
            raise ForcedFixtureRotationStateError(
                f"another forced rotation request is pending: {candidate_id}"
            )


def reconcile(command: str, request_id: str) -> Mapping[str, Any]:
    path = _state_path(request_id)
    current = snapshot()
    _find_other_prepared(request_id)
    if path.exists() or path.is_symlink():
        state = _read_state(path, request_id)
    else:
        if command == "finalize":
            raise ForcedFixtureRotationStateError("forced rotation was not prepared")
        state = _prepared_state(request_id, current)
        _atomic_write(path, canonical_bytes(state))

    if state["phase"] == "SELECTED":
        if current != state["after"]:
            raise ForcedFixtureRotationStateError(
                "current PKI differs from the completed forced-rotation request"
            )
        return {
            "action": "ROTATION_ALREADY_SELECTED",
            "requestId": request_id,
            "state": state,
        }

    if current == state["before"]:
        if command == "finalize":
            raise ForcedFixtureRotationStateError(
                "forced rotation did not change the selected generation"
            )
        return {
            "action": "ROTATE_REQUIRED",
            "requestId": request_id,
            "state": state,
        }

    selected = _selected_state(state, current)
    _atomic_write(path, canonical_bytes(selected))
    return {
        "action": "ROTATION_SELECTED",
        "requestId": request_id,
        "state": selected,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("command", choices=("prepare", "finalize", "status"))
    result.add_argument("--request-id", required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if os.geteuid() != 0:
            raise ForcedFixtureRotationStateError("state helper must run as root")
        _prepare_state_root()
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
                raise ForcedFixtureRotationStateError("state lock is unsafe")
            os.fchmod(lock_descriptor, 0o600)
            os.fchown(lock_descriptor, 0, 0)
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            if args.command == "status":
                path = _state_path(args.request_id)
                _find_other_prepared(args.request_id)
                state = _read_state(path, args.request_id)
                current = snapshot()
                if state["phase"] != "SELECTED" or current != state["after"]:
                    raise ForcedFixtureRotationStateError(
                        "forced rotation is not selected as the current PKI generation"
                    )
                output = {
                    "action": "ROTATION_STATUS",
                    "requestId": args.request_id,
                    "state": state,
                }
            else:
                output = reconcile(args.command, args.request_id)
        finally:
            os.close(lock_descriptor)
    except (ForcedFixtureRotationStateError, OSError) as exc:
        print(f"forced fixture leaf rotation state rejected: {exc}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_bytes(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
