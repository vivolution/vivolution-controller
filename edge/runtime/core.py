#!/usr/bin/env python3
"""Privileged, transactional Edge runtime activation and rollback core.

The production CLI fixes every path and command.  This module accepts a layout
and command runner only so tests can exercise the full transaction in a
temporary directory without root or host mutation.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import socket
import stat
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterator, Mapping, Optional, Sequence, Tuple

from edge.runtime import contracts
from edge.runtime.contracts import (
    HANDOFF_FILENAMES,
    RUNTIME_API_VERSION,
    RuntimeContractError,
    SecretPaths,
    ValidatedCandidate,
    canonical_bytes,
    parse_json_bytes,
    sha256_digest,
    validate_candidate,
)


STATE_FORMAT_VERSION = 1
MAX_STATE_BYTES = 256 * 1024
MAX_COMMAND_OUTPUT = 2 * 1024 * 1024

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_NAME_RE = re.compile(r"[^a-z0-9-]+")

_COMMON_SUCCESS_RUNTIME_CHECKS = (
    "package-opensips-3.6.8",
    "package-rtpengine-26.0.1.22",
    "opensips-offline-parse",
    "nftables-offline-parse",
    "rtpengine-typed-config",
    "systemd-nftables",
    "systemd-rtpengine-daemon",
    "systemd-opensips",
    "opensips-active-parse",
    "nft-owned-default-deny",
    "rtpengine-ng-ping",
    "listeners-exact",
    "rtpengine-control-loopback",
)
_PROFILE_SUCCESS_RUNTIME_CHECKS = {
    "SYNTHETIC_PRIVATE": (
        "synthetic-private-fixture-routing",
        "rtpengine-synthetic-private-advertisement",
        "nft-bounded-ingress",
        "nft-bounded-egress",
    ),
    "DIRECT_ROUTING": (
        "teams-three-hub-failover",
        "rtpengine-direct-public-advertisement",
        "nft-bounded-ingress",
        "nft-bounded-egress",
    ),
}


class RuntimeErrorBase(RuntimeError):
    """Base class for root-helper failures."""


class RuntimeSecurityError(RuntimeErrorBase):
    """A path, owner, mode, link or immutable release invariant failed."""


class RuntimeApplyError(RuntimeErrorBase):
    """An offline or live activation gate failed."""


class ApplyFailed(RuntimeApplyError):
    """Candidate activation failed and carries canonical failure evidence."""

    def __init__(self, message: str, evidence: Mapping[str, Any]):
        super().__init__(message)
        self.evidence = dict(evidence)


class RollbackFailed(ApplyFailed):
    """Activation failed and the prior LKG could not be restored."""


@dataclass(frozen=True)
class RuntimeIdentity:
    root_uid: int
    root_gid: int
    opensips_gid: int
    rtpengine_gid: int
    agent_gid: int


@dataclass(frozen=True)
class RuntimeLayout:
    runtime_root: Path
    inbox_root: Path
    node_facts: Path
    runtime_authority: Path
    signing_public_key: Path
    secrets: SecretPaths
    live_opensips: Path
    live_rtpengine: Path
    live_nftables: Path

    @classmethod
    def production(cls) -> "RuntimeLayout":
        tls = Path("/etc/vivolution-edge/tls")
        return cls(
            Path("/var/lib/vivolution-edge/runtime"),
            Path("/var/lib/vivolution-edge/runtime-inbox"),
            Path("/etc/vivolution-edge/node-facts.json"),
            Path("/etc/vivolution-edge/runtime-authority.json"),
            Path("/usr/lib/vivolution-edge/config/signing-public-key.json"),
            SecretPaths(
                tls / "teams-fullchain.pem",
                tls / "teams-key.pem",
                tls / "fixture-ca.crt",
                tls / "fixture-client.crt",
                tls / "fixture-client.key",
                tls / "microsoft-ca-bundle.pem",
                tls / "pbx-ca-bundle.pem",
                tls / "public-ca-bundle.pem",
            ),
            Path("/etc/opensips/opensips.cfg"),
            Path("/etc/rtpengine/rtpengine.conf"),
            Path("/etc/nftables.conf"),
        )

    @property
    def active_link(self) -> Path:
        return self.runtime_root / "active"

    @property
    def state_file(self) -> Path:
        return self.runtime_root / "state.json"

    @property
    def journal_file(self) -> Path:
        return self.runtime_root / "transaction.json"

    @property
    def lock_file(self) -> Path:
        return self.runtime_root / "runtime.lock"

    @property
    def evidence_dir(self) -> Path:
        return self.runtime_root / "evidence"

    def candidate_dir(self, sequence: int, manifest_digest: str) -> Path:
        return self.inbox_root / candidate_slug(sequence, manifest_digest)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandRunner:
    """Fixed argv executor and RTPengine NG health probe."""

    def run(self, argv: Sequence[str], *, timeout: float = 30) -> CommandResult:
        try:
            completed = subprocess.run(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeApplyError("fixed command failed to execute: {}".format(exc)) from exc
        stdout = completed.stdout[-MAX_COMMAND_OUTPUT:]
        stderr = completed.stderr[-MAX_COMMAND_OUTPUT:]
        return CommandResult(completed.returncode, stdout, stderr)

    def rtpengine_ping(self, *, timeout: float = 2.0) -> bool:
        cookie = b"vivo-runtime-ping"
        request = cookie + b" d7:command4:pinge"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(timeout)
                client.sendto(request, ("127.0.0.1", 2223))
                response, peer = client.recvfrom(4096)
        except OSError:
            return False
        return peer == ("127.0.0.1", 2223) and response.startswith(cookie + b" ") and b"6:result2:ok" in response

    def checkpoint(self, name: str) -> None:
        """Crash-injection seam. Production intentionally does nothing."""


def candidate_slug(sequence: int, manifest_digest: str) -> str:
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or not 1 <= sequence <= 2**53 - 1
        or not isinstance(manifest_digest, str)
        or _DIGEST_RE.fullmatch(manifest_digest) is None
    ):
        raise RuntimeContractError("candidate sequence or manifest digest is invalid")
    return "{:016d}-{}".format(sequence, manifest_digest.split(":", 1)[1])


def _mode(record: os.stat_result) -> int:
    return stat.S_IMODE(record.st_mode)


def _assert_directory(
    path: Path,
    identity: RuntimeIdentity,
    *,
    modes: Tuple[int, ...],
    owner_gid: int | None = None,
) -> os.stat_result:
    try:
        record = path.lstat()
    except OSError as exc:
        raise RuntimeSecurityError("required directory {} is unavailable: {}".format(path, exc)) from exc
    if stat.S_ISLNK(record.st_mode) or not stat.S_ISDIR(record.st_mode):
        raise RuntimeSecurityError("{} must be a non-symlink directory".format(path))
    if (
        record.st_uid != identity.root_uid
        or _mode(record) not in modes
        or (owner_gid is not None and record.st_gid != owner_gid)
    ):
        raise RuntimeSecurityError("{} has an unauthorized owner or mode".format(path))
    return record


def _secure_read(
    path: Path,
    identity: RuntimeIdentity,
    *,
    modes: Tuple[int, ...],
    owner_gid: int | None = None,
    maximum: int,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeSecurityError("secure open rejected {}: {}".format(path, exc)) from exc
    try:
        record = os.fstat(descriptor)
        if not stat.S_ISREG(record.st_mode) or record.st_nlink != 1:
            raise RuntimeSecurityError("{} must be a single-link regular file".format(path))
        if record.st_uid != identity.root_uid or _mode(record) not in modes:
            raise RuntimeSecurityError("{} has an unauthorized owner or mode".format(path))
        if owner_gid is not None and record.st_gid != owner_gid:
            raise RuntimeSecurityError("{} has an unauthorized group".format(path))
        if record.st_size <= 0 or record.st_size > maximum:
            raise RuntimeSecurityError("{} is empty or oversized".format(path))
        chunks = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != record.st_size or len(raw) > maximum:
            raise RuntimeSecurityError("{} changed while being read or is oversized".format(path))
        return raw
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(
    path: Path,
    content: bytes,
    identity: RuntimeIdentity,
    *,
    mode: int,
    gid: int,
    replace_existing: bool = True,
) -> None:
    temporary = path.parent / (".{}.{}.tmp".format(path.name, os.getpid()))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, identity.root_uid, gid)
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if not replace_existing and (path.exists() or path.is_symlink()):
        temporary.unlink()
        raise RuntimeSecurityError("immutable path already exists: {}".format(path))
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _atomic_symlink(path: Path, target: str) -> None:
    temporary = path.parent / (".{}.{}.link".format(path.name, os.getpid()))
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    os.symlink(target, temporary)
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _unlink_atomic_marker(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    _fsync_directory(path.parent)


@dataclass(frozen=True)
class ReleaseRef:
    kind: str
    slot: str
    relative_path: str
    sequence: int
    manifest_digest: Optional[str]
    release_digest: str

    @classmethod
    def from_mapping(cls, value: Any) -> "ReleaseRef":
        if not isinstance(value, Mapping):
            raise RuntimeSecurityError("release reference must be an object")
        fields = {"kind", "manifestDigest", "relativePath", "releaseDigest", "sequence", "slot"}
        if set(value) != fields:
            raise RuntimeSecurityError("release reference members differ from the fixed format")
        kind = value["kind"]
        slot = value["slot"]
        sequence = value["sequence"]
        digest = value["manifestDigest"]
        release_digest = value["releaseDigest"]
        relative = value["relativePath"]
        if kind not in {"BOOTSTRAP", "CANDIDATE"}:
            raise RuntimeSecurityError("release kind is invalid")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or not 0 <= sequence <= 2**53 - 1:
            raise RuntimeSecurityError("release sequence is invalid")
        if not isinstance(release_digest, str) or _DIGEST_RE.fullmatch(release_digest) is None:
            raise RuntimeSecurityError("release digest is invalid")
        if not isinstance(relative, str):
            raise RuntimeSecurityError("release relative path is invalid")
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or str(pure) != relative:
            raise RuntimeSecurityError("release relative path escapes the runtime root")
        if kind == "BOOTSTRAP":
            if slot != "NONE" or sequence != 0 or digest is not None or relative != "bootstrap":
                raise RuntimeSecurityError("bootstrap release reference is invalid")
        else:
            if slot not in {"A", "B"} or not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None:
                raise RuntimeSecurityError("candidate release identity is invalid")
            if relative != "slots/{}/{}".format(slot, candidate_slug(sequence, digest)):
                raise RuntimeSecurityError("candidate release relative path is not canonical")
        return cls(kind, slot, relative, sequence, digest, release_digest)

    def record(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "manifestDigest": self.manifest_digest,
            "relativePath": self.relative_path,
            "releaseDigest": self.release_digest,
            "sequence": self.sequence,
            "slot": self.slot,
        }


@dataclass(frozen=True)
class RuntimeState:
    highest_seen_sequence: int
    active: ReleaseRef
    previous: Optional[ReleaseRef]
    last_evidence_digest: Optional[str]

    @classmethod
    def from_mapping(cls, value: Any) -> "RuntimeState":
        if not isinstance(value, Mapping) or set(value) != {
            "active",
            "formatVersion",
            "highestSeenSequence",
            "lastEvidenceDigest",
            "previous",
        }:
            raise RuntimeSecurityError("runtime state differs from protected format v1")
        if value["formatVersion"] != STATE_FORMAT_VERSION:
            raise RuntimeSecurityError("runtime state format requires explicit migration")
        highest = value["highestSeenSequence"]
        if not isinstance(highest, int) or isinstance(highest, bool) or not 0 <= highest <= 2**53 - 1:
            raise RuntimeSecurityError("runtime replay floor is invalid")
        active = ReleaseRef.from_mapping(value["active"])
        previous = None if value["previous"] is None else ReleaseRef.from_mapping(value["previous"])
        last = value["lastEvidenceDigest"]
        if last is not None and (not isinstance(last, str) or _DIGEST_RE.fullmatch(last) is None):
            raise RuntimeSecurityError("runtime last evidence digest is invalid")
        if active.kind == "CANDIDATE" and active.sequence > highest:
            raise RuntimeSecurityError("active runtime release exceeds its replay floor")
        return cls(highest, active, previous, last)

    def record(self) -> Dict[str, Any]:
        return {
            "active": self.active.record(),
            "formatVersion": STATE_FORMAT_VERSION,
            "highestSeenSequence": self.highest_seen_sequence,
            "lastEvidenceDigest": self.last_evidence_digest,
            "previous": None if self.previous is None else self.previous.record(),
        }


@dataclass(frozen=True)
class Transaction:
    operation: str
    phase: str
    prior: ReleaseRef
    target: ReleaseRef

    @classmethod
    def from_mapping(cls, value: Any) -> "Transaction":
        if not isinstance(value, Mapping) or set(value) != {
            "apiVersion",
            "operation",
            "phase",
            "prior",
            "target",
        }:
            raise RuntimeSecurityError("transaction journal differs from its fixed format")
        if value["apiVersion"] != RUNTIME_API_VERSION:
            raise RuntimeSecurityError("transaction journal apiVersion is unsupported")
        operation = value["operation"]
        phase = value["phase"]
        if operation not in {"APPLY", "MANUAL_ROLLBACK"}:
            raise RuntimeSecurityError("transaction operation is invalid")
        if phase not in {"STAGED", "STOPPED", "POINTER_ACTIVATED", "NFT_APPLIED", "SERVICES_STARTED"}:
            raise RuntimeSecurityError("transaction phase is invalid")
        return cls(operation, phase, ReleaseRef.from_mapping(value["prior"]), ReleaseRef.from_mapping(value["target"]))

    def record(self) -> Dict[str, Any]:
        return {
            "apiVersion": RUNTIME_API_VERSION,
            "operation": self.operation,
            "phase": self.phase,
            "prior": self.prior.record(),
            "target": self.target.record(),
        }


class RuntimeManager:
    """One serialized A/B activation transaction and its recovery path."""

    def __init__(
        self,
        layout: RuntimeLayout,
        identity: RuntimeIdentity,
        runner: CommandRunner,
        *,
        clock=lambda: datetime.now(timezone.utc),
        monotonic_clock=time.monotonic,
    ) -> None:
        self.layout = layout
        self.identity = identity
        self.runner = runner
        self.clock = clock
        self.monotonic_clock = monotonic_clock

    def _ensure_directories(self) -> None:
        root = self.layout.runtime_root
        if not root.exists():
            root.mkdir(mode=0o755, parents=False)
            os.chmod(root, 0o755)
            os.chown(root, self.identity.root_uid, self.identity.root_gid)
        _assert_directory(root, self.identity, modes=(0o755,))
        for path, mode, gid in (
            (root / "slots", 0o755, self.identity.root_gid),
            (root / "slots" / "A", 0o755, self.identity.root_gid),
            (root / "slots" / "B", 0o755, self.identity.root_gid),
            (self.layout.evidence_dir, 0o750, self.identity.agent_gid),
        ):
            if not path.exists():
                path.mkdir(mode=mode)
                os.chmod(path, mode)
                os.chown(path, self.identity.root_uid, gid)
            _assert_directory(
                path, self.identity, modes=(mode,), owner_gid=gid
            )

    @contextmanager
    def _lock(self) -> Iterator[None]:
        self._ensure_directories()
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.layout.lock_file, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            os.fchown(descriptor, self.identity.root_uid, self.identity.root_gid)
            record = os.fstat(descriptor)
            if not stat.S_ISREG(record.st_mode) or record.st_nlink != 1:
                raise RuntimeSecurityError("runtime lock must be a single-link regular file")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    def _read_state(self) -> Optional[RuntimeState]:
        if not self.layout.state_file.exists() and not self.layout.state_file.is_symlink():
            return None
        raw = _secure_read(
            self.layout.state_file,
            self.identity,
            modes=(0o600,),
            maximum=MAX_STATE_BYTES,
        )
        return RuntimeState.from_mapping(parse_json_bytes(raw, "runtime state", maximum=MAX_STATE_BYTES))

    def _write_state(self, state: RuntimeState) -> None:
        _atomic_write(
            self.layout.state_file,
            canonical_bytes(state.record()),
            self.identity,
            mode=0o600,
            gid=self.identity.root_gid,
        )

    def _read_journal(self) -> Optional[Transaction]:
        if not self.layout.journal_file.exists() and not self.layout.journal_file.is_symlink():
            return None
        raw = _secure_read(
            self.layout.journal_file,
            self.identity,
            modes=(0o600,),
            maximum=MAX_STATE_BYTES,
        )
        return Transaction.from_mapping(parse_json_bytes(raw, "transaction journal", maximum=MAX_STATE_BYTES))

    def _write_journal(self, transaction: Transaction) -> None:
        _atomic_write(
            self.layout.journal_file,
            canonical_bytes(transaction.record()),
            self.identity,
            mode=0o600,
            gid=self.identity.root_gid,
        )

    def _release_path(self, release: ReleaseRef) -> Path:
        path = self.layout.runtime_root / release.relative_path
        try:
            path.relative_to(self.layout.runtime_root)
        except ValueError as exc:
            raise RuntimeSecurityError("release path escapes runtime root") from exc
        return path

    def _active_relative(self) -> str:
        try:
            target = os.readlink(self.layout.active_link)
        except OSError as exc:
            raise RuntimeSecurityError("active release link is missing or invalid: {}".format(exc)) from exc
        pure = PurePosixPath(target)
        if pure.is_absolute() or ".." in pure.parts or str(pure) != target:
            raise RuntimeSecurityError("active release link escapes runtime root")
        return target

    def _point_active(self, release: ReleaseRef) -> None:
        self._validate_release(release)
        _atomic_symlink(self.layout.active_link, release.relative_path)

    def _read_live_regular(self, path: Path, maximum: int) -> bytes:
        return _secure_read(
            path,
            self.identity,
            modes=(0o600, 0o640, 0o644),
            maximum=maximum,
        )

    def _build_bootstrap(self) -> ReleaseRef:
        path = self.layout.runtime_root / "bootstrap"
        files = {
            "opensips.cfg": self._read_live_regular(self.layout.live_opensips, 512 * 1024),
            "rtpengine.conf": self._read_live_regular(self.layout.live_rtpengine, 128 * 1024),
            "nftables.conf": self._read_live_regular(self.layout.live_nftables, 512 * 1024),
        }
        path.mkdir(mode=0o755)
        os.chown(path, self.identity.root_uid, self.identity.root_gid)
        self._write_release_files(path, files)
        meta_without_digest = {
            "apiVersion": RUNTIME_API_VERSION,
            "kind": "BootstrapRelease",
            "runtimeFileDigests": {name: sha256_digest(content) for name, content in sorted(files.items())},
        }
        release_digest = sha256_digest(contracts.manifest_tool.canonical_json_bytes(meta_without_digest))
        meta = dict(meta_without_digest)
        meta["releaseDigest"] = release_digest
        _atomic_write(
            path / "release-meta.json",
            canonical_bytes(meta),
            self.identity,
            mode=0o400,
            gid=self.identity.root_gid,
            replace_existing=False,
        )
        os.chmod(path, 0o555)
        _fsync_directory(path.parent)
        return ReleaseRef("BOOTSTRAP", "NONE", "bootstrap", 0, None, release_digest)

    def _write_release_files(self, path: Path, files: Mapping[str, bytes]) -> None:
        expected = {"opensips.cfg", "rtpengine.conf", "nftables.conf"}
        if set(files) != expected:
            raise RuntimeSecurityError("runtime release file set is invalid")
        properties = {
            "opensips.cfg": (0o440, self.identity.opensips_gid),
            "rtpengine.conf": (0o440, self.identity.rtpengine_gid),
            "nftables.conf": (0o400, self.identity.root_gid),
        }
        for name in sorted(files):
            mode, gid = properties[name]
            _atomic_write(
                path / name,
                files[name],
                self.identity,
                mode=mode,
                gid=gid,
                replace_existing=False,
            )

    def _install_live_links(self) -> None:
        mappings = {
            self.layout.live_opensips: self.layout.runtime_root / "active" / "opensips.cfg",
            self.layout.live_rtpengine: self.layout.runtime_root / "active" / "rtpengine.conf",
            self.layout.live_nftables: self.layout.runtime_root / "active" / "nftables.conf",
        }
        for live, target in mappings.items():
            if live.is_symlink():
                if os.readlink(live) != str(target):
                    raise RuntimeSecurityError("live config {} points outside the fixed active release".format(live))
                continue
            _atomic_symlink(live, str(target))

    def _initialize(self) -> RuntimeState:
        state = self._read_state()
        if state is not None:
            self._validate_release(state.active)
            if state.previous is not None:
                self._validate_release(state.previous)
            active_relative = self._active_relative()
            if active_relative != state.active.relative_path:
                journal = self._read_journal()
                if (
                    journal is None
                    or journal.prior != state.active
                    or active_relative != journal.target.relative_path
                ):
                    raise RuntimeSecurityError("protected state and active release pointer differ")
            self._install_live_links()
            return state

        bootstrap_path = self.layout.runtime_root / "bootstrap"
        if bootstrap_path.exists():
            bootstrap = self._load_release_ref_from_meta(bootstrap_path, "bootstrap")
            if bootstrap.kind != "BOOTSTRAP":
                raise RuntimeSecurityError("existing bootstrap path has wrong release type")
        else:
            bootstrap = self._build_bootstrap()
        if self.layout.active_link.exists() or self.layout.active_link.is_symlink():
            if self._active_relative() != bootstrap.relative_path:
                raise RuntimeSecurityError("uninitialized active release pointer is unexpected")
        else:
            _atomic_symlink(self.layout.active_link, bootstrap.relative_path)
        self._install_live_links()
        state = RuntimeState(0, bootstrap, None, None)
        self._write_state(state)
        return state

    def _load_release_ref_from_meta(self, path: Path, relative: str) -> ReleaseRef:
        _assert_directory(path, self.identity, modes=(0o555,))
        raw = _secure_read(
            path / "release-meta.json",
            self.identity,
            modes=(0o400,),
            maximum=MAX_STATE_BYTES,
        )
        meta = parse_json_bytes(raw, "release metadata", maximum=MAX_STATE_BYTES)
        release = self._release_ref_from_metadata(meta, relative)
        self._validate_release(release, metadata=meta)
        return release

    def _release_ref_from_metadata(self, meta: Any, relative: str) -> ReleaseRef:
        """Parse the identity committed by one immutable release metadata file."""

        if not isinstance(meta, Mapping):
            raise RuntimeSecurityError("release metadata must be an object")
        if meta.get("apiVersion") != RUNTIME_API_VERSION:
            raise RuntimeSecurityError("release metadata apiVersion is invalid")
        if meta.get("kind") == "BootstrapRelease":
            expected = {"apiVersion", "kind", "releaseDigest", "runtimeFileDigests"}
            if set(meta) != expected:
                raise RuntimeSecurityError("bootstrap metadata fields are invalid")
            reference = {
                "kind": "BOOTSTRAP",
                "manifestDigest": None,
                "relativePath": relative,
                "releaseDigest": meta["releaseDigest"],
                "sequence": 0,
                "slot": "NONE",
            }
        elif meta.get("kind") == "CandidateRelease":
            expected = {
                "apiVersion",
                "compileEvidenceDigest",
                "kind",
                "localHealthGatePlan",
                "localHealthGatePlanDigest",
                "manifestDigest",
                "manifestId",
                "releaseDigest",
                "runtimeFileDigests",
                "sequence",
                "signedEnvelopeDigest",
                "slot",
                "sourceArtifactDigests",
                "verifiedKeyIds",
            }
            if set(meta) != expected:
                raise RuntimeSecurityError("candidate metadata fields are invalid")
            manifest_id = meta["manifestId"]
            if (
                not isinstance(manifest_id, str)
                or contracts.manifest_tool.ID_RE.fullmatch(manifest_id) is None
            ):
                raise RuntimeSecurityError("candidate metadata manifestId is invalid")
            source_digests = meta["sourceArtifactDigests"]
            if (
                not isinstance(source_digests, Mapping)
                or set(source_digests) != set(contracts.ARTIFACT_FILENAMES)
                or any(
                    not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None
                    for value in source_digests.values()
                )
            ):
                raise RuntimeSecurityError("candidate source artifact digest inventory is invalid")
            for field in (
                "compileEvidenceDigest",
                "localHealthGatePlanDigest",
                "signedEnvelopeDigest",
            ):
                if (
                    not isinstance(meta[field], str)
                    or _DIGEST_RE.fullmatch(meta[field]) is None
                ):
                    raise RuntimeSecurityError(
                        "candidate metadata {} is invalid".format(field)
                    )
            verified_key_ids = meta["verifiedKeyIds"]
            if (
                not isinstance(verified_key_ids, list)
                or not verified_key_ids
                or any(
                    not isinstance(value, str)
                    or contracts.manifest_tool.ID_RE.fullmatch(value) is None
                    for value in verified_key_ids
                )
                or sorted(set(verified_key_ids)) != verified_key_ids
            ):
                raise RuntimeSecurityError(
                    "candidate metadata verified signing-key inventory is invalid"
                )
            plan = meta["localHealthGatePlan"]
            if (
                not isinstance(plan, Mapping)
                or set(plan)
                != {"apiVersion", "healthGates", "kind", "manifestDigest"}
                or plan["apiVersion"] != contracts.LOCAL_HEALTH_PLAN_API_VERSION
                or plan["kind"] != contracts.LOCAL_HEALTH_PLAN_KIND
                or plan["manifestDigest"] != meta["manifestDigest"]
                or sha256_digest(
                    contracts.manifest_tool.canonical_json_bytes(plan)
                )
                != meta["localHealthGatePlanDigest"]
            ):
                raise RuntimeSecurityError(
                    "candidate metadata local health gate plan is invalid"
                )
            reference = {
                "kind": "CANDIDATE",
                "manifestDigest": meta["manifestDigest"],
                "relativePath": relative,
                "releaseDigest": meta["releaseDigest"],
                "sequence": meta["sequence"],
                "slot": meta["slot"],
            }
        else:
            raise RuntimeSecurityError("release metadata kind is invalid")
        return ReleaseRef.from_mapping(reference)

    def _validate_release(self, release: ReleaseRef, *, metadata: Mapping[str, Any] | None = None) -> None:
        path = self._release_path(release)
        _assert_directory(path, self.identity, modes=(0o555,))
        expected_names = {
            "nftables.conf",
            "opensips.cfg",
            "release-meta.json",
            "rtpengine.conf",
        }
        if {entry.name for entry in path.iterdir()} != expected_names:
            raise RuntimeSecurityError("immutable release file set is invalid")
        files = {
            "opensips.cfg": _secure_read(
                path / "opensips.cfg", self.identity, modes=(0o440,), owner_gid=self.identity.opensips_gid, maximum=512 * 1024
            ),
            "rtpengine.conf": _secure_read(
                path / "rtpengine.conf", self.identity, modes=(0o440,), owner_gid=self.identity.rtpengine_gid, maximum=128 * 1024
            ),
            "nftables.conf": _secure_read(
                path / "nftables.conf", self.identity, modes=(0o400,), owner_gid=self.identity.root_gid, maximum=512 * 1024
            ),
        }
        if metadata is None:
            raw = _secure_read(
                path / "release-meta.json", self.identity, modes=(0o400,), maximum=MAX_STATE_BYTES
            )
            metadata = parse_json_bytes(raw, "release metadata", maximum=MAX_STATE_BYTES)
        metadata_release = self._release_ref_from_metadata(metadata, release.relative_path)
        if metadata_release != release:
            raise RuntimeSecurityError("release reference differs from immutable metadata")
        digests = metadata.get("runtimeFileDigests")
        if (
            not isinstance(digests, Mapping)
            or set(digests) != set(files)
            or any(
                not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None
                for value in digests.values()
            )
        ):
            raise RuntimeSecurityError("release runtime file digest inventory is invalid")
        actual = {name: sha256_digest(content) for name, content in sorted(files.items())}
        if dict(digests) != actual:
            raise RuntimeSecurityError("immutable release file digest mismatch")
        unsigned = dict(metadata)
        claimed = unsigned.pop("releaseDigest", None)
        actual_release = sha256_digest(contracts.manifest_tool.canonical_json_bytes(unsigned))
        if claimed != release.release_digest or actual_release != release.release_digest:
            raise RuntimeSecurityError("immutable release metadata digest mismatch")

    def _build_candidate_release(self, candidate: ValidatedCandidate, state: RuntimeState) -> ReleaseRef:
        slot = "B" if state.active.slot == "A" else "A"
        relative = "slots/{}/{}".format(slot, candidate_slug(candidate.sequence, candidate.manifest_digest))
        path = self.layout.runtime_root / relative
        files = candidate.runtime_files()
        meta_without_digest = {
            "apiVersion": RUNTIME_API_VERSION,
            "compileEvidenceDigest": candidate.compile_evidence_digest,
            "kind": "CandidateRelease",
            "localHealthGatePlan": candidate.local_health_gate_plan.record(),
            "localHealthGatePlanDigest": candidate.local_health_gate_plan_digest,
            "manifestDigest": candidate.manifest_digest,
            "manifestId": candidate.manifest_id,
            "runtimeFileDigests": {name: sha256_digest(content) for name, content in sorted(files.items())},
            "sequence": candidate.sequence,
            "signedEnvelopeDigest": candidate.signed_envelope_digest,
            "slot": slot,
            "sourceArtifactDigests": dict(candidate.source_artifact_digests),
            "verifiedKeyIds": list(candidate.verified_key_ids),
        }
        release_digest = sha256_digest(contracts.manifest_tool.canonical_json_bytes(meta_without_digest))
        metadata = dict(meta_without_digest)
        metadata["releaseDigest"] = release_digest
        release = ReleaseRef(
            "CANDIDATE",
            slot,
            relative,
            candidate.sequence,
            candidate.manifest_digest,
            release_digest,
        )
        if path.exists() or path.is_symlink():
            existing = self._load_release_ref_from_meta(path, relative)
            existing_metadata = parse_json_bytes(
                _secure_read(
                    path / "release-meta.json",
                    self.identity,
                    modes=(0o400,),
                    maximum=MAX_STATE_BYTES,
                ),
                "existing release metadata",
                maximum=MAX_STATE_BYTES,
            )
            if existing != release or existing_metadata != metadata:
                raise RuntimeSecurityError(
                    "existing candidate release does not exactly match the validated candidate"
                )
            return existing
        path.mkdir(mode=0o755)
        os.chown(path, self.identity.root_uid, self.identity.root_gid)
        self._write_release_files(path, files)
        _atomic_write(
            path / "release-meta.json",
            canonical_bytes(metadata),
            self.identity,
            mode=0o400,
            gid=self.identity.root_gid,
            replace_existing=False,
        )
        os.chmod(path, 0o555)
        _fsync_directory(path.parent)
        self._validate_release(release)
        return release

    def _load_handoff(self, sequence: int, manifest_digest: str) -> Mapping[str, bytes]:
        _assert_directory(self.layout.inbox_root, self.identity, modes=(0o700,))
        candidate_dir = self.layout.candidate_dir(sequence, manifest_digest)
        _assert_directory(candidate_dir, self.identity, modes=(0o700,))
        names = {entry.name for entry in candidate_dir.iterdir()}
        if names != HANDOFF_FILENAMES:
            raise RuntimeSecurityError("root-owned candidate inbox has an unexpected file set")
        return {
            name: _secure_read(
                candidate_dir / name,
                self.identity,
                modes=(0o600,),
                maximum=(
                    contracts.MAX_SIGNED_ENVELOPE_BYTES
                    if name == "signed-envelope.json"
                    else 512 * 1024
                ),
            )
            for name in sorted(HANDOFF_FILENAMES)
        }

    def _load_local_authority(
        self,
    ) -> Tuple[bytes, bytes, bytes, Mapping[str, bytes]]:
        node_facts = _secure_read(
            self.layout.node_facts,
            self.identity,
            modes=(0o600,),
            maximum=MAX_STATE_BYTES,
        )
        authority = _secure_read(
            self.layout.runtime_authority,
            self.identity,
            modes=(0o600,),
            maximum=MAX_STATE_BYTES,
        )
        signing_public_key = _secure_read(
            self.layout.signing_public_key,
            self.identity,
            modes=(0o444,),
            owner_gid=self.identity.root_gid,
            maximum=4096,
        )
        try:
            authority_profile = contracts.RuntimeAuthority.from_mapping(
                contracts.parse_json_bytes(authority, "runtime authority")
            ).profile
        except Exception as exc:
            raise RuntimeSecurityError(
                "root-provisioned runtime authority is invalid"
            ) from exc
        secrets = {
            name: _secure_read(
                path,
                self.identity,
                modes=(0o440,),
                owner_gid=self.identity.opensips_gid,
                maximum=1024 * 1024,
            )
            for name, path in self.layout.secrets.as_mapping(authority_profile).items()
        }
        return node_facts, authority, signing_public_key, secrets

    def _accepted_runtime_state(
        self, state: RuntimeState
    ) -> contracts.AcceptedRuntimeState:
        if state.active.kind == "BOOTSTRAP":
            return contracts.AcceptedRuntimeState(
                state.highest_seen_sequence, 0, None, ()
            )
        metadata = self._read_release_metadata(state.active)
        source_digests = metadata.get("sourceArtifactDigests")
        if not isinstance(source_digests, Mapping):
            raise RuntimeSecurityError(
                "active release lacks root-protected artifact lineage"
            )
        return contracts.AcceptedRuntimeState(
            state.highest_seen_sequence,
            state.active.sequence,
            state.active.manifest_digest,
            tuple(sorted(set(source_digests.values()))),
        )

    def _run(
        self, argv: Sequence[str], gate: str, *, timeout: float = 30
    ) -> str:
        if timeout <= 0:
            raise RuntimeApplyError("{} exhausted its signed timeout".format(gate))
        result = self.runner.run(argv, timeout=timeout)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip().replace("\n", " ")[:400]
            raise RuntimeApplyError("{} failed: {}".format(gate, detail or "non-zero exit"))
        return result.stdout

    def _remaining_gate_timeout(self, deadline: float, gate_id: str) -> float:
        remaining = deadline - self.monotonic_clock()
        if remaining <= 0:
            raise RuntimeApplyError(
                "signed local health gate {} exhausted its timeout".format(gate_id)
            )
        return remaining

    def _read_release_metadata(self, release: ReleaseRef) -> Mapping[str, Any]:
        raw = _secure_read(
            self._release_path(release) / "release-meta.json",
            self.identity,
            modes=(0o400,),
            owner_gid=self.identity.root_gid,
            maximum=MAX_STATE_BYTES,
        )
        value = parse_json_bytes(
            raw, "immutable release metadata", maximum=MAX_STATE_BYTES
        )
        if not isinstance(value, Mapping):
            raise RuntimeSecurityError("immutable release metadata is not an object")
        return value

    def _read_candidate_release_file(
        self, release: ReleaseRef, name: str
    ) -> bytes:
        properties = {
            "opensips.cfg": (0o440, self.identity.opensips_gid, 512 * 1024),
            "rtpengine.conf": (0o440, self.identity.rtpengine_gid, 128 * 1024),
            "nftables.conf": (0o400, self.identity.root_gid, 512 * 1024),
        }
        if name not in properties:
            raise RuntimeSecurityError("immutable release file name is invalid")
        mode, gid, maximum = properties[name]
        return _secure_read(
            self._release_path(release) / name,
            self.identity,
            modes=(mode,),
            owner_gid=gid,
            maximum=maximum,
        )

    def _assert_opensips_profile_identity(
        self, candidate: ValidatedCandidate, content: bytes
    ) -> None:
        if candidate.authority.profile == "SYNTHETIC_PRIVATE":
            for token in (
                b"10.20.1.4:16061",
                b"10.20.1.4:25061",
                b"fixture-client.crt",
                b"fixture-client.key",
                b"[teams-inbound]",
                self.layout.secrets.edge_certificate_chain_pem.name.encode("ascii"),
                b"[pbx-inbound]",
            ):
                if token not in content:
                    raise RuntimeApplyError(
                        "active OpenSIPS config lacks fixed private fixture routing/identity"
                    )
            for domain in (b"teams-inbound", b"pbx-inbound"):
                forbidden = (
                    b"["
                    + domain
                    + b"]"
                    + str(self.layout.secrets.fixture_client_crt).encode("ascii")
                )
                if forbidden in content:
                    raise RuntimeApplyError(
                        "fixture client leaf was assigned to a public Edge server listener"
                    )
            return
        for hub in contracts.TEAMS_HUBS:
            if hub.encode("ascii") not in content:
                raise RuntimeApplyError(
                    "active OpenSIPS config lacks fixed Teams hub identity"
                )
        for token in (
            b"TEAMS_FAILOVER",
            candidate.route.pbx_host.encode("ascii"),
            'force_send_socket("tls:{}:5061")'.format(
                candidate.facts.private_ipv4
            ).encode("ascii"),
            'force_send_socket("tls:{}:15061")'.format(
                candidate.facts.private_ipv4
            ).encode("ascii"),
        ):
            if token not in content:
                raise RuntimeApplyError(
                    "active OpenSIPS config lacks Direct Routing identity boundary"
                )
        if b"fixture-client.crt" in content or b"fixture-client.key" in content:
            raise RuntimeApplyError(
                "Direct Routing OpenSIPS config retained synthetic fixture identity"
            )

    def _assert_rtpengine_profile_advertisement(
        self, candidate: ValidatedCandidate, content: bytes
    ) -> None:
        advertised_ipv4 = (
            candidate.facts.private_ipv4
            if candidate.authority.profile == "SYNTHETIC_PRIVATE"
            else candidate.facts.public_ipv4
        )
        expected = "interface = {}!{}\n".format(
            candidate.facts.private_ipv4, advertised_ipv4
        ).encode("ascii")
        if content.count(expected) != 1:
            raise RuntimeApplyError(
                "active RTPengine interface differs from the trusted runtime profile"
            )

    def _execute_signed_gate_attempt(
        self,
        gate: Mapping[str, Any],
        candidate: ValidatedCandidate,
        release: ReleaseRef,
        deadline: float,
    ) -> None:
        gate_id = gate["gateId"]
        gate_type = gate["type"]
        if gate_type == "ARTIFACT_DIGESTS":
            self._validate_release(release)
            metadata = self._read_release_metadata(release)
            if (
                metadata.get("compileEvidenceDigest")
                != candidate.compile_evidence_digest
                or metadata.get("signedEnvelopeDigest")
                != candidate.signed_envelope_digest
                or metadata.get("verifiedKeyIds")
                != list(candidate.verified_key_ids)
                or metadata.get("sourceArtifactDigests")
                != dict(candidate.source_artifact_digests)
                or metadata.get("localHealthGatePlanDigest")
                != candidate.local_health_gate_plan_digest
                or metadata.get("localHealthGatePlan")
                != candidate.local_health_gate_plan.record()
            ):
                raise RuntimeApplyError(
                    "immutable release does not bind the validated compiler handoff"
                )
            self._remaining_gate_timeout(deadline, gate_id)
            return

        if gate_type == "OPENSIPS_CONFIG":
            release_config = self._release_path(release) / "opensips.cfg"
            self._run(
                ["/usr/sbin/opensips", "-C", "-f", str(release_config)],
                "signed OpenSIPS offline parse",
                timeout=self._remaining_gate_timeout(deadline, gate_id),
            )
            self._run(
                ["/usr/sbin/opensips", "-C", "-f", str(self.layout.live_opensips)],
                "signed active OpenSIPS parse",
                timeout=self._remaining_gate_timeout(deadline, gate_id),
            )
            content = self._read_candidate_release_file(release, "opensips.cfg")
            if (
                self._active_relative() != release.relative_path
                or content != candidate.opensips_config
            ):
                raise RuntimeApplyError(
                    "active OpenSIPS release differs from the validated candidate"
                )
            self._assert_opensips_profile_identity(candidate, content)
            self._remaining_gate_timeout(deadline, gate_id)
            return

        if gate_type == "RTPENGINE_READY":
            expected_typed = contracts.render_runtime_rtpengine(
                candidate.facts, candidate.authority, candidate.rtpengine
            )
            if expected_typed != candidate.rtpengine_config:
                raise RuntimeApplyError(
                    "validated RTPengine config differs from the typed runtime renderer"
                )
            if self._run(
                [
                    "/usr/bin/systemctl",
                    "is-active",
                    "rtpengine-daemon.service",
                ],
                "signed RTPengine service health",
                timeout=self._remaining_gate_timeout(deadline, gate_id),
            ).strip() != "active":
                raise RuntimeApplyError("RTPengine service is not active")
            ping_timeout = min(
                2.0, self._remaining_gate_timeout(deadline, gate_id)
            )
            if not self.runner.rtpengine_ping(timeout=ping_timeout):
                raise RuntimeApplyError(
                    "RTPengine NG loopback control did not answer signed health ping"
                )
            sockets = self._run(
                ["/usr/bin/ss", "-H", "-lntup"],
                "signed RTPengine control listener inventory",
                timeout=self._remaining_gate_timeout(deadline, gate_id),
            )
            for port in (2223, 2224):
                if re.search(r"(?<![0-9A-Fa-f:.])127\.0\.0\.1:{}(?:\s|$)".format(port), sockets) is None:
                    raise RuntimeApplyError(
                        "RTPengine loopback control listener {} is absent".format(port)
                    )
            if re.search(r"(?:0\.0\.0\.0|\[::\]):222[34]\b", sockets):
                raise RuntimeApplyError("RTPengine control listener escaped loopback")
            content = self._read_candidate_release_file(release, "rtpengine.conf")
            if (
                self._active_relative() != release.relative_path
                or content != candidate.rtpengine_config
            ):
                raise RuntimeApplyError(
                    "active RTPengine config differs from the validated candidate"
                )
            self._assert_rtpengine_profile_advertisement(candidate, content)
            self._remaining_gate_timeout(deadline, gate_id)
            return

        raise RuntimeSecurityError("unsupported signed local health gate type")

    def _execute_signed_health_plan(
        self, candidate: ValidatedCandidate, release: ReleaseRef
    ) -> Tuple[Mapping[str, Any], ...]:
        results = []
        for gate in candidate.local_health_gate_plan.health_gates:
            attempts_used = 0
            while attempts_used < gate["maxAttempts"]:
                attempts_used += 1
                deadline = self.monotonic_clock() + gate["timeoutSeconds"]
                try:
                    self._execute_signed_gate_attempt(
                        gate, candidate, release, deadline
                    )
                except RuntimeApplyError as exc:
                    if attempts_used < gate["maxAttempts"]:
                        continue
                    raise RuntimeApplyError(
                        "signed local health gate {} failed after {} attempt(s): {}".format(
                            gate["gateId"], attempts_used, exc
                        )
                    ) from exc
                break
            results.append(
                {
                    "attemptsUsed": attempts_used,
                    "gateId": gate["gateId"],
                    "proofs": [
                        {"name": name, "status": "PASSED"}
                        for name in contracts.LOCAL_HEALTH_GATE_PROOFS[gate["type"]]
                    ],
                    "status": "PASSED",
                    "type": gate["type"],
                }
            )
        return contracts.validate_local_health_gate_results(
            results, candidate.local_health_gate_plan
        )

    def _offline_validate(self, release: ReleaseRef) -> Tuple[str, ...]:
        self._validate_release(release)
        path = self._release_path(release)
        opensips_version = self._run(
            ["/usr/bin/dpkg-query", "-W", "-f=${Version}", "opensips"], "OpenSIPS package version"
        ).strip()
        if opensips_version != contracts.OPENSIPS_VERSION:
            raise RuntimeApplyError("OpenSIPS package version is not the fixed 3.6.8 build")
        rtpengine_version = self._run(
            ["/usr/bin/dpkg-query", "-W", "-f=${Version}", "rtpengine-daemon"], "RTPengine package version"
        ).strip()
        if rtpengine_version != contracts.RTPENGINE_VERSION:
            raise RuntimeApplyError("RTPengine package version is not the fixed userspace build")
        self._run(["/usr/sbin/opensips", "-C", "-f", str(path / "opensips.cfg")], "OpenSIPS offline parse")
        self._run(["/usr/sbin/nft", "--check", "--file", str(path / "nftables.conf")], "nftables offline parse")
        return (
            "package-opensips-3.6.8",
            "package-rtpengine-26.0.1.22",
            "opensips-offline-parse",
            "nftables-offline-parse",
            "rtpengine-typed-config",
        )

    def _stop_services(self) -> None:
        self._run(["/usr/bin/systemctl", "stop", "opensips.service"], "stop OpenSIPS")
        self._run(["/usr/bin/systemctl", "stop", "rtpengine-daemon.service"], "stop RTPengine")

    def _start_services(self) -> None:
        self._run(["/usr/bin/systemctl", "start", "rtpengine-daemon.service"], "start RTPengine")
        self._run(["/usr/bin/systemctl", "start", "opensips.service"], "start OpenSIPS")

    def _apply_active_firewall(self) -> None:
        self._run(["/usr/sbin/nft", "--file", str(self.layout.live_nftables)], "apply owned nftables table")

    def _baseline_health(self) -> Tuple[str, ...]:
        gates = []
        for service in ("nftables.service", "rtpengine-daemon.service", "opensips.service"):
            if self._run(["/usr/bin/systemctl", "is-active", service], "{} health".format(service)).strip() != "active":
                raise RuntimeApplyError("{} is not active".format(service))
            gates.append("systemd-{}".format(service.removesuffix(".service")))
        self._run(["/usr/sbin/opensips", "-C", "-f", str(self.layout.live_opensips)], "active OpenSIPS parse")
        nft = self._run(
            ["/usr/sbin/nft", "list", "table", "inet", "vivolution_edge_filter"], "active owned nftables table"
        )
        if (
            "table inet vivolution_edge_filter" not in nft
            or "hook input priority filter; policy drop;" not in nft
            or "hook output priority filter; policy drop;" not in nft
            or "flush ruleset" in nft
        ):
            raise RuntimeApplyError("active nftables table is not owned default-deny policy")
        if not self.runner.rtpengine_ping():
            raise RuntimeApplyError("RTPengine NG loopback control did not answer ping")
        try:
            node_facts_raw = _secure_read(
                self.layout.node_facts,
                self.identity,
                modes=(0o600,),
                maximum=MAX_STATE_BYTES,
            )
            facts = contracts.NodeFacts.from_mapping(
                contracts.parse_json_bytes(node_facts_raw, "immutable node facts")
            )
        except Exception as exc:
            raise RuntimeSecurityError(
                "immutable node facts are unavailable to active health"
            ) from exc
        sockets = self._run(["/usr/bin/ss", "-H", "-lntup"], "listener inventory")
        expectations = (
            (facts.private_ipv4, 5061),
            (facts.private_ipv4, 15061),
            ("127.0.0.1", 2223),
            ("127.0.0.1", 2224),
        )
        for address, port in expectations:
            pattern = re.compile(
                r"(?<![0-9A-Fa-f:.]){}:{}(?:\s|$)".format(
                    re.escape(address), port
                )
            )
            if pattern.search(sockets) is None:
                raise RuntimeApplyError(
                    "required listener {}:{} is absent".format(address, port)
                )
        if re.search(r"(?:0\.0\.0\.0|\[::\]):222[34]\b", sockets):
            raise RuntimeApplyError("RTPengine control listener escaped loopback")
        return tuple(
            gates
            + [
                "opensips-active-parse",
                "nft-owned-default-deny",
                "rtpengine-ng-ping",
                "listeners-exact",
                "rtpengine-control-loopback",
            ]
        )

    def _candidate_health(
        self, candidate: ValidatedCandidate, release: ReleaseRef
    ) -> Tuple[Tuple[str, ...], Tuple[Mapping[str, Any], ...]]:
        gates = list(self._baseline_health())
        nft = self._run(
            ["/usr/sbin/nft", "list", "table", "inet", "vivolution_edge_filter"], "candidate nftables inventory"
        )
        required_nft = (
            "tcp dport 5061",
            "tcp dport 15061",
            "udp dport {}-{}".format(candidate.facts.tenant_media_port_start, candidate.facts.tenant_media_port_end),
        )
        if any(token not in nft for token in required_nft):
            raise RuntimeApplyError("active nftables table lacks a required bounded ingress rule")
        required_output_nft = (
            "hook output priority filter; policy drop;",
            "ip daddr 168.63.129.16 udp sport 68 udp dport 67 accept",
            "ip daddr @ntp_server_ipv4 udp dport 123 accept",
        )
        if any(token not in nft for token in required_output_nft):
            raise RuntimeApplyError("active nftables table lacks required fail-closed platform egress")
        if candidate.authority.profile == "SYNTHETIC_PRIVATE":
            voice_egress = (
                "ip daddr @control_plane_ipv4 tcp dport { 16061, 25061 }",
                "ip daddr @control_plane_ipv4 udp sport {}-{} udp dport {{ 21000-21127, 22000-22063 }}".format(
                    candidate.facts.tenant_media_port_start,
                    candidate.facts.tenant_media_port_end,
                ),
            )
        else:
            voice_egress = (
                "ip daddr @microsoft_signaling_source_ipv4 tcp dport 5061",
                "ip daddr @microsoft_media_source_ipv4 udp sport {}-{} udp dport {{ 3478-3481, 49152-53247 }}".format(
                    candidate.facts.tenant_media_port_start,
                    candidate.facts.tenant_media_port_end,
                ),
                "ip daddr @pbx_source_ipv4 tcp dport {}".format(candidate.route.pbx_port),
                "ip daddr @pbx_source_ipv4 udp sport {}-{} udp dport {}-{}".format(
                    candidate.facts.tenant_media_port_start,
                    candidate.facts.tenant_media_port_end,
                    candidate.facts.pbx_media_destination_port_start,
                    candidate.facts.pbx_media_destination_port_end,
                ),
            )
        if any(token not in nft for token in voice_egress):
            raise RuntimeApplyError("active nftables table lacks profile-specific bounded voice egress")
        opensips_config = self._read_candidate_release_file(release, "opensips.cfg")
        rtpengine_config = self._read_candidate_release_file(
            release, "rtpengine.conf"
        )
        if self._active_relative() != release.relative_path:
            raise RuntimeApplyError(
                "active release pointer differs from the validated candidate"
            )
        if opensips_config != candidate.opensips_config:
            raise RuntimeApplyError(
                "active OpenSIPS config differs from the validated candidate"
            )
        if rtpengine_config != candidate.rtpengine_config:
            raise RuntimeApplyError("active RTPengine config differs from the validated candidate")
        if candidate.authority.profile == "SYNTHETIC_PRIVATE":
            gates.append("synthetic-private-fixture-routing")
            media_gate = "rtpengine-synthetic-private-advertisement"
        else:
            gates.append("teams-three-hub-failover")
            media_gate = "rtpengine-direct-public-advertisement"
        self._assert_opensips_profile_identity(candidate, opensips_config)
        self._assert_rtpengine_profile_advertisement(candidate, rtpengine_config)
        gates.extend(
            (
                media_gate,
                "nft-bounded-ingress",
                "nft-bounded-egress",
            )
        )
        signed_results = self._execute_signed_health_plan(candidate, release)
        return tuple(gates), signed_results

    def _evidence_path(
        self,
        *,
        sequence: int,
        manifest_digest: Optional[str],
        status: str,
        evidence_digest: str,
    ) -> Path:
        status = status.lower()
        status = _EVIDENCE_NAME_RE.sub("-", status).strip("-")[:64]
        short = (
            manifest_digest.split(":", 1)[1][:16]
            if isinstance(manifest_digest, str)
            and _DIGEST_RE.fullmatch(manifest_digest)
            else "none"
        )
        evidence_short = evidence_digest.split(":", 1)[1]
        name = "{:016d}-{}-{}-{}.json".format(sequence, short, status, evidence_short)
        return self.layout.evidence_dir / name

    def _write_evidence(self, record: Mapping[str, Any]) -> Mapping[str, Any]:
        unsigned = dict(record)
        unsigned["apiVersion"] = RUNTIME_API_VERSION
        unsigned["kind"] = "EdgeRuntimeApplyEvidence"
        evidence_digest = sha256_digest(contracts.manifest_tool.canonical_json_bytes(unsigned))
        complete = dict(unsigned)
        complete["evidenceDigest"] = evidence_digest
        path = self._evidence_path(
            sequence=complete.get("sequence", 0),
            manifest_digest=complete.get("manifestDigest"),
            status=str(complete.get("status", "unknown")),
            evidence_digest=evidence_digest,
        )
        encoded = canonical_bytes(complete)
        if path.exists() or path.is_symlink():
            existing = _secure_read(
                path,
                self.identity,
                modes=(0o440,),
                owner_gid=self.identity.agent_gid,
                maximum=MAX_STATE_BYTES,
            )
            if existing != encoded:
                raise RuntimeSecurityError("runtime evidence digest filename collision")
            return complete
        _atomic_write(
            path,
            encoded,
            self.identity,
            mode=0o440,
            gid=self.identity.agent_gid,
            replace_existing=False,
        )
        return complete

    def _load_original_success_evidence(
        self, state: RuntimeState
    ) -> Mapping[str, Any]:
        release = state.active
        evidence_digest = state.last_evidence_digest
        if (
            release.kind != "CANDIDATE"
            or release.manifest_digest is None
            or evidence_digest is None
        ):
            raise RuntimeSecurityError(
                "committed candidate lacks original success evidence identity"
            )
        path = self._evidence_path(
            sequence=release.sequence,
            manifest_digest=release.manifest_digest,
            status="RUNTIME_APPLIED_HEALTHY",
            evidence_digest=evidence_digest,
        )
        raw = _secure_read(
            path,
            self.identity,
            modes=(0o440,),
            owner_gid=self.identity.agent_gid,
            maximum=MAX_STATE_BYTES,
        )
        evidence = parse_json_bytes(
            raw, "original runtime success evidence", maximum=MAX_STATE_BYTES
        )
        expected_fields = {
            "agentAction",
            "apiVersion",
            "evidenceDigest",
            "healthGates",
            "kind",
            "liveTeamsInteroperability",
            "localHealthGatePlan",
            "localHealthGatePlanDigest",
            "manifestDigest",
            "nodeId",
            "rollback",
            "rtpAdvertisedIpv4",
            "runtimeApplied",
            "runtimeChecks",
            "runtimeProfile",
            "runtimeReleaseDigest",
            "sequence",
            "status",
            "timestamp",
        }
        if not isinstance(evidence, Mapping) or set(evidence) != expected_fields:
            raise RuntimeSecurityError(
                "original runtime success evidence fields are invalid"
            )
        if raw != canonical_bytes(evidence):
            raise RuntimeSecurityError(
                "original runtime success evidence is not canonical"
            )
        unsigned = dict(evidence)
        claimed_digest = unsigned.pop("evidenceDigest")
        if (
            claimed_digest != evidence_digest
            or sha256_digest(
                contracts.manifest_tool.canonical_json_bytes(unsigned)
            )
            != evidence_digest
        ):
            raise RuntimeSecurityError(
                "original runtime success evidence self-digest is invalid"
            )
        if (
            evidence["apiVersion"] != RUNTIME_API_VERSION
            or evidence["kind"] != "EdgeRuntimeApplyEvidence"
            or evidence["status"] != "RUNTIME_APPLIED_HEALTHY"
            or evidence["agentAction"] != "COMMIT_PENDING"
            or evidence["runtimeApplied"] is not True
            or evidence["liveTeamsInteroperability"] != "NOT_ASSERTED"
            or evidence["sequence"] != release.sequence
            or evidence["manifestDigest"] != release.manifest_digest
            or evidence["runtimeReleaseDigest"] != release.release_digest
        ):
            raise RuntimeSecurityError(
                "original runtime success evidence identity is invalid"
            )
        timestamp_errors = []
        if contracts.manifest_tool.parse_utc_timestamp(
            evidence["timestamp"],
            "original runtime success evidence timestamp",
            timestamp_errors,
        ) is None:
            raise RuntimeSecurityError(
                "original runtime success evidence timestamp is invalid"
            )
        if state.previous is None or evidence["rollback"] != {
            "performed": False,
            "status": "NOT_REQUIRED",
            "targetReleaseDigest": state.previous.release_digest,
        }:
            raise RuntimeSecurityError(
                "original runtime success evidence rollback identity is invalid"
            )
        node_raw = _secure_read(
            self.layout.node_facts,
            self.identity,
            modes=(0o600,),
            maximum=MAX_STATE_BYTES,
        )
        facts = contracts.NodeFacts.from_mapping(
            contracts.parse_json_bytes(node_raw, "immutable node facts")
        )
        if evidence["nodeId"] != facts.node_id:
            raise RuntimeSecurityError(
                "original runtime success evidence node identity is invalid"
            )
        profile = evidence["runtimeProfile"]
        if profile not in _PROFILE_SUCCESS_RUNTIME_CHECKS:
            raise RuntimeSecurityError(
                "original runtime success evidence profile is invalid"
            )
        expected_advertised = (
            facts.private_ipv4
            if profile == "SYNTHETIC_PRIVATE"
            else facts.public_ipv4
            if profile == "DIRECT_ROUTING"
            else None
        )
        if evidence["rtpAdvertisedIpv4"] != expected_advertised:
            raise RuntimeSecurityError(
                "original runtime success evidence profile identity is invalid"
            )
        expected_checks = _COMMON_SUCCESS_RUNTIME_CHECKS + (
            _PROFILE_SUCCESS_RUNTIME_CHECKS[profile]
        )
        if evidence["runtimeChecks"] != [
            {"name": name, "status": "PASSED"} for name in expected_checks
        ]:
            raise RuntimeSecurityError(
                "original runtime success evidence checks are invalid"
            )
        metadata = self._read_release_metadata(release)
        plan = contracts.validate_local_health_gate_plan(
            evidence["localHealthGatePlan"],
            facts=facts,
            expected_manifest_digest=release.manifest_digest,
        )
        if (
            evidence["localHealthGatePlanDigest"] != plan.digest
            or metadata.get("localHealthGatePlanDigest") != plan.digest
            or metadata.get("localHealthGatePlan") != plan.record()
        ):
            raise RuntimeSecurityError(
                "original runtime success evidence plan binding is invalid"
            )
        results = contracts.validate_local_health_gate_results(
            evidence["healthGates"], plan
        )
        normalized = dict(evidence)
        normalized["healthGates"] = [dict(result) for result in results]
        return normalized

    def _base_evidence(
        self,
        *,
        status: str,
        sequence: int,
        manifest_digest: Optional[str],
        node_id: str,
        release: Optional[ReleaseRef],
        runtime_checks: Sequence[str],
        rollback: Mapping[str, Any],
        agent_action: str,
        health_gates: Sequence[Mapping[str, Any]] = (),
        local_health_gate_plan: Optional[contracts.LocalHealthGatePlan] = None,
        local_health_gate_plan_digest: Optional[str] = None,
        failure: Optional[str] = None,
        runtime_profile: Optional[str] = None,
        rtp_advertised_ipv4: Optional[str] = None,
    ) -> Mapping[str, Any]:
        if (
            len(set(runtime_checks)) != len(runtime_checks)
            or any(
                not isinstance(name, str)
                or contracts.manifest_tool.ID_RE.fullmatch(name) is None
                for name in runtime_checks
            )
        ):
            raise RuntimeSecurityError("runtime check inventory is invalid")
        if status == "RUNTIME_APPLIED_HEALTHY":
            if runtime_profile not in _PROFILE_SUCCESS_RUNTIME_CHECKS:
                raise RuntimeSecurityError(
                    "successful runtime evidence requires an exact profile"
                )
            expected_checks = _COMMON_SUCCESS_RUNTIME_CHECKS + (
                _PROFILE_SUCCESS_RUNTIME_CHECKS[runtime_profile]
            )
            if tuple(runtime_checks) != expected_checks:
                raise RuntimeSecurityError(
                    "successful runtime evidence checks differ from the exact profile contract"
                )
            if local_health_gate_plan is None:
                raise RuntimeSecurityError(
                    "successful runtime evidence requires the signed local health plan"
                )
            contracts.validate_local_health_gate_results(
                list(health_gates), local_health_gate_plan
            )
        elif health_gates:
            raise RuntimeSecurityError(
                "non-success runtime evidence cannot assert signed health gate success"
            )
        record: Dict[str, Any] = {
            "agentAction": agent_action,
            "healthGates": [dict(result) for result in health_gates],
            "liveTeamsInteroperability": "NOT_ASSERTED",
            "manifestDigest": manifest_digest,
            "nodeId": node_id,
            "rollback": dict(rollback),
            "runtimeApplied": status == "RUNTIME_APPLIED_HEALTHY",
            "runtimeChecks": [
                {"name": name, "status": "PASSED"} for name in runtime_checks
            ],
            "runtimeReleaseDigest": None if release is None else release.release_digest,
            "sequence": sequence,
            "status": status,
            "timestamp": self.clock().astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        if (local_health_gate_plan is None) != (
            local_health_gate_plan_digest is None
        ):
            raise RuntimeSecurityError(
                "runtime evidence local health plan and digest must be recorded together"
            )
        if local_health_gate_plan is not None:
            if (
                local_health_gate_plan.digest != local_health_gate_plan_digest
                or local_health_gate_plan.manifest_digest != manifest_digest
            ):
                raise RuntimeSecurityError(
                    "runtime evidence local health plan identity is invalid"
                )
            record["localHealthGatePlan"] = local_health_gate_plan.record()
            record["localHealthGatePlanDigest"] = local_health_gate_plan_digest
        if (runtime_profile is None) != (rtp_advertised_ipv4 is None):
            raise RuntimeSecurityError("runtime evidence profile and RTP address must be recorded together")
        if runtime_profile is not None and rtp_advertised_ipv4 is not None:
            if runtime_profile not in {"SYNTHETIC_PRIVATE", "DIRECT_ROUTING"}:
                raise RuntimeSecurityError("runtime evidence profile is invalid")
            try:
                packed_address = socket.inet_pton(socket.AF_INET, rtp_advertised_ipv4)
            except OSError as exc:
                raise RuntimeSecurityError("runtime evidence RTP address is invalid") from exc
            if socket.inet_ntop(socket.AF_INET, packed_address) != rtp_advertised_ipv4:
                raise RuntimeSecurityError("runtime evidence RTP address is not canonical")
            record["rtpAdvertisedIpv4"] = rtp_advertised_ipv4
            record["runtimeProfile"] = runtime_profile
        if failure is not None:
            record["failure"] = failure[:500]
        return record

    def _rollback_live(self, prior: ReleaseRef) -> Tuple[str, ...]:
        self._stop_services()
        self._point_active(prior)
        self.runner.checkpoint("rollback-pointer-activated")
        self._apply_active_firewall()
        self._start_services()
        return self._baseline_health()

    def _execute_switch(
        self,
        transaction: Transaction,
        *,
        candidate: ValidatedCandidate | None,
    ) -> Tuple[Tuple[str, ...], Tuple[Mapping[str, Any], ...]]:
        self._write_journal(transaction)
        self._stop_services()
        transaction = replace(transaction, phase="STOPPED")
        self._write_journal(transaction)
        self.runner.checkpoint("services-stopped")
        self._point_active(transaction.target)
        transaction = replace(transaction, phase="POINTER_ACTIVATED")
        self._write_journal(transaction)
        self.runner.checkpoint("pointer-activated")
        self._apply_active_firewall()
        transaction = replace(transaction, phase="NFT_APPLIED")
        self._write_journal(transaction)
        self.runner.checkpoint("nft-applied")
        self._start_services()
        transaction = replace(transaction, phase="SERVICES_STARTED")
        self._write_journal(transaction)
        self.runner.checkpoint("services-started")
        if candidate is None:
            return self._baseline_health(), ()
        return self._candidate_health(candidate, transaction.target)

    def activate(self, sequence: int, manifest_digest: str) -> Mapping[str, Any]:
        candidate_slug(sequence, manifest_digest)
        with self._lock():
            state = self._initialize()
            if self._read_journal() is not None:
                self._recover_locked(state)
                state = self._read_state()
                assert state is not None
            if sequence <= state.highest_seen_sequence:
                raise RuntimeSecurityError("candidate sequence is at or below the runtime replay floor")
            handoff = self._load_handoff(sequence, manifest_digest)
            (
                node_facts,
                authority,
                signing_public_key,
                secrets,
            ) = self._load_local_authority()
            candidate = validate_candidate(
                handoff,
                node_facts,
                authority,
                signing_public_key,
                secrets,
                self.layout.secrets,
                expected_sequence=sequence,
                expected_manifest_digest=manifest_digest,
                accepted_runtime=self._accepted_runtime_state(state),
                now=self.clock(),
            )
            runtime_profile = candidate.authority.profile
            rtp_advertised_ipv4 = (
                candidate.facts.private_ipv4
                if runtime_profile == "SYNTHETIC_PRIVATE"
                else candidate.facts.public_ipv4
            )

            # Burn the local replay floor before preflight or any live change.
            # A failed candidate can never be replayed under the same sequence,
            # and even a no-live-change preflight failure gives the Agent an
            # exact ABORT_PENDING reconciliation result.
            state_with_floor = replace(state, highest_seen_sequence=sequence)
            self._write_state(state_with_floor)
            release: Optional[ReleaseRef] = None
            try:
                release = self._build_candidate_release(candidate, state)
                offline_checks = self._offline_validate(release)
            except Exception as preflight_error:
                evidence = self._write_evidence(
                    self._base_evidence(
                        status="RUNTIME_PREFLIGHT_FAILED_NO_LIVE_CHANGE",
                        sequence=sequence,
                        manifest_digest=manifest_digest,
                        node_id=candidate.facts.node_id,
                        release=release,
                        runtime_checks=(),
                        rollback={
                            "performed": False,
                            "status": "NOT_REQUIRED",
                            "targetReleaseDigest": state.active.release_digest,
                        },
                        agent_action="ABORT_PENDING",
                        failure=str(preflight_error),
                        runtime_profile=runtime_profile,
                        rtp_advertised_ipv4=rtp_advertised_ipv4,
                    )
                )
                self._write_state(
                    replace(
                        state_with_floor,
                        last_evidence_digest=evidence["evidenceDigest"],
                    )
                )
                raise ApplyFailed(
                    "candidate preflight failed before live mutation", evidence
                ) from preflight_error
            assert release is not None
            transaction = Transaction("APPLY", "STAGED", state.active, release)
            try:
                live_checks, signed_health_results = self._execute_switch(
                    transaction, candidate=candidate
                )
            except Exception as primary:
                try:
                    rollback_gates = self._rollback_live(state.active)
                except Exception as rollback_error:
                    evidence = self._write_evidence(
                        self._base_evidence(
                            status="RUNTIME_APPLY_FAILED_ROLLBACK_FAILED",
                            sequence=sequence,
                            manifest_digest=manifest_digest,
                            node_id=candidate.facts.node_id,
                            release=release,
                            runtime_checks=offline_checks,
                            rollback={"performed": True, "status": "FAILED", "targetReleaseDigest": state.active.release_digest},
                            agent_action="DO_NOT_COMMIT_OPERATOR_RECOVERY_REQUIRED",
                            failure="{}; rollback: {}".format(primary, rollback_error),
                            runtime_profile=runtime_profile,
                            rtp_advertised_ipv4=rtp_advertised_ipv4,
                        )
                    )
                    raise RollbackFailed("candidate failed and prior LKG rollback failed", evidence) from rollback_error
                _unlink_atomic_marker(self.layout.journal_file)
                evidence = self._write_evidence(
                    self._base_evidence(
                        status="RUNTIME_APPLY_FAILED_ROLLED_BACK",
                        sequence=sequence,
                        manifest_digest=manifest_digest,
                        node_id=candidate.facts.node_id,
                        release=release,
                        runtime_checks=tuple(offline_checks) + tuple(rollback_gates),
                        rollback={"performed": True, "status": "HEALTHY", "targetReleaseDigest": state.active.release_digest},
                        agent_action="ABORT_PENDING",
                        failure=str(primary),
                        runtime_profile=runtime_profile,
                        rtp_advertised_ipv4=rtp_advertised_ipv4,
                    )
                )
                self._write_state(replace(state_with_floor, last_evidence_digest=evidence["evidenceDigest"]))
                raise ApplyFailed("candidate activation failed; prior LKG restored", evidence) from primary

            success = self._write_evidence(
                self._base_evidence(
                    status="RUNTIME_APPLIED_HEALTHY",
                    sequence=sequence,
                    manifest_digest=manifest_digest,
                    node_id=candidate.facts.node_id,
                    release=release,
                    runtime_checks=tuple(offline_checks) + tuple(live_checks),
                    rollback={"performed": False, "status": "NOT_REQUIRED", "targetReleaseDigest": state.active.release_digest},
                    agent_action="COMMIT_PENDING",
                    health_gates=signed_health_results,
                    local_health_gate_plan=candidate.local_health_gate_plan,
                    local_health_gate_plan_digest=candidate.local_health_gate_plan_digest,
                    runtime_profile=runtime_profile,
                    rtp_advertised_ipv4=rtp_advertised_ipv4,
                )
            )
            committed = RuntimeState(sequence, release, state.active, success["evidenceDigest"])
            self._write_state(committed)
            self.runner.checkpoint("state-committed")
            _unlink_atomic_marker(self.layout.journal_file)
            return success

    def _recover_locked(self, state: RuntimeState) -> Mapping[str, Any]:
        transaction = self._read_journal()
        if transaction is None:
            return {
                "apiVersion": RUNTIME_API_VERSION,
                "kind": "EdgeRuntimeApplyEvidence",
                "status": "NO_RECOVERY_REQUIRED",
            }
        current = self._active_relative()
        # A crash may occur after the healthy result and new protected state
        # are durable but before the journal unlink is durable.  In that case
        # the state, pointer and final journal phase jointly prove the switch
        # was committed.  Preserve it, recheck baseline health, and expose the
        # original evidence digest so the agent can finish its pending action.
        if current == transaction.target.relative_path and state.active == transaction.target:
            if (
                transaction.phase != "SERVICES_STARTED"
                or state.previous != transaction.prior
                or state.last_evidence_digest is None
            ):
                raise RuntimeSecurityError(
                    "transaction journal and protected committed state are inconsistent"
                )
            original_success = (
                self._load_original_success_evidence(state)
                if transaction.operation == "APPLY"
                else None
            )
            gates = self._baseline_health()
            _unlink_atomic_marker(self.layout.journal_file)
            result: Dict[str, Any] = {
                "active": state.active.record(),
                "agentAction": (
                    "COMMIT_PENDING"
                    if transaction.operation == "APPLY"
                    else "RECONCILE_PROTECTED_STATE"
                ),
                "apiVersion": RUNTIME_API_VERSION,
                "healthGates": (
                    []
                    if original_success is None
                    else original_success["healthGates"]
                ),
                "kind": "EdgeRuntimeRecoveryResult",
                "lastEvidenceDigest": state.last_evidence_digest,
                "operation": transaction.operation,
                "runtimeChecks": [
                    {"name": name, "status": "PASSED"} for name in gates
                ],
                "status": "COMMITTED_TRANSACTION_RECOVERY_FINALIZED",
            }
            if original_success is not None:
                result["localHealthGatePlan"] = original_success[
                    "localHealthGatePlan"
                ]
                result["localHealthGatePlanDigest"] = original_success[
                    "localHealthGatePlanDigest"
                ]
            return result
        # Always converge to the protected prior LKG. This also handles a crash
        # between the atomic pointer swap and the following journal fsync.
        if current == transaction.target.relative_path or transaction.phase != "STAGED":
            gates = self._rollback_live(transaction.prior)
        else:
            self._start_services()
            gates = self._baseline_health()
        _unlink_atomic_marker(self.layout.journal_file)
        node_id = "unknown"
        try:
            node_raw = _secure_read(
                self.layout.node_facts, self.identity, modes=(0o600,), maximum=MAX_STATE_BYTES
            )
            node_id = parse_json_bytes(node_raw, "immutable node facts").get("nodeId", "unknown")
        except Exception:
            pass
        evidence = self._write_evidence(
            self._base_evidence(
                status="CRASH_RECOVERED_TO_PRIOR_LKG",
                sequence=transaction.target.sequence,
                manifest_digest=transaction.target.manifest_digest,
                node_id=node_id,
                release=transaction.target,
                runtime_checks=gates,
                rollback={"performed": True, "status": "HEALTHY", "targetReleaseDigest": transaction.prior.release_digest},
                agent_action="ABORT_PENDING" if transaction.operation == "APPLY" else "RECONCILE_PROTECTED_STATE",
            )
        )
        self._write_state(replace(state, last_evidence_digest=evidence["evidenceDigest"]))
        return evidence

    def recover(self) -> Mapping[str, Any]:
        with self._lock():
            state = self._initialize()
            return self._recover_locked(state)

    def health(self) -> Mapping[str, Any]:
        """Prove the protected active release is healthy without changing state."""

        with self._lock():
            if self._read_journal() is not None:
                raise RuntimeSecurityError(
                    "runtime health is unavailable while a transaction journal exists"
                )
            state = self._initialize()
            gates = self._baseline_health()
            return {
                "active": state.active.record(),
                "apiVersion": RUNTIME_API_VERSION,
                "runtimeChecks": [
                    {"name": name, "status": "PASSED"} for name in gates
                ],
                "highestSeenSequence": state.highest_seen_sequence,
                "kind": "EdgeRuntimeHealth",
            }

    def rollback(self, sequence: int, manifest_digest: str) -> Mapping[str, Any]:
        candidate_slug(sequence, manifest_digest)
        with self._lock():
            state = self._initialize()
            if self._read_journal() is not None:
                self._recover_locked(state)
                state = self._read_state()
                assert state is not None
            target = state.previous
            if (
                target is None
                or target.kind != "CANDIDATE"
                or target.sequence != sequence
                or target.manifest_digest != manifest_digest
            ):
                raise RuntimeSecurityError("manual rollback target must exactly equal the protected previous candidate")
            offline = self._offline_validate(target)
            transaction = Transaction("MANUAL_ROLLBACK", "STAGED", state.active, target)
            try:
                live, _ = self._execute_switch(transaction, candidate=None)
            except Exception as primary:
                try:
                    rollback_gates = self._rollback_live(state.active)
                except Exception as rollback_error:
                    evidence = self._write_evidence(
                        self._base_evidence(
                            status="MANUAL_ROLLBACK_FAILED_ORIGINAL_RESTORE_FAILED",
                            sequence=sequence,
                            manifest_digest=manifest_digest,
                            node_id="unknown",
                            release=target,
                            runtime_checks=offline,
                            rollback={"performed": True, "status": "FAILED", "targetReleaseDigest": state.active.release_digest},
                            agent_action="OPERATOR_RECOVERY_REQUIRED",
                            failure="{}; original restore: {}".format(primary, rollback_error),
                        )
                    )
                    raise RollbackFailed("manual rollback and original restore failed", evidence) from rollback_error
                _unlink_atomic_marker(self.layout.journal_file)
                evidence = self._write_evidence(
                    self._base_evidence(
                        status="MANUAL_ROLLBACK_FAILED_ORIGINAL_RESTORED",
                        sequence=sequence,
                        manifest_digest=manifest_digest,
                        node_id="unknown",
                        release=target,
                        runtime_checks=tuple(offline) + tuple(rollback_gates),
                        rollback={"performed": True, "status": "HEALTHY", "targetReleaseDigest": state.active.release_digest},
                        agent_action="NO_STATE_CHANGE",
                        failure=str(primary),
                    )
                )
                self._write_state(replace(state, last_evidence_digest=evidence["evidenceDigest"]))
                raise ApplyFailed("manual rollback failed; original active release restored", evidence) from primary
            success = self._write_evidence(
                self._base_evidence(
                    status="RUNTIME_ROLLED_BACK_HEALTHY_REQUIRES_AGENT_RECONCILIATION",
                    sequence=sequence,
                    manifest_digest=manifest_digest,
                    node_id="unknown",
                    release=target,
                    runtime_checks=tuple(offline) + tuple(live),
                    rollback={"performed": True, "status": "HEALTHY", "targetReleaseDigest": target.release_digest},
                    agent_action="RECONCILE_PROTECTED_STATE",
                )
            )
            self._write_state(RuntimeState(state.highest_seen_sequence, target, state.active, success["evidenceDigest"]))
            self.runner.checkpoint("rollback-state-committed")
            _unlink_atomic_marker(self.layout.journal_file)
            return success

    def status(self) -> Mapping[str, Any]:
        with self._lock():
            state = self._initialize()
            journal = self._read_journal()
            return {
                "active": state.active.record(),
                "apiVersion": RUNTIME_API_VERSION,
                "highestSeenSequence": state.highest_seen_sequence,
                "journalPresent": journal is not None,
                "kind": "EdgeRuntimeStatus",
                "lastEvidenceDigest": state.last_evidence_digest,
                "previous": None if state.previous is None else state.previous.record(),
            }
