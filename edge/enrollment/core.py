#!/usr/bin/env python3
"""Security-sensitive local primitives for Edge enrollment.

This module deliberately contains no controller-specific persistence and opens
no listener.  It owns the one-time-grant input boundary, node-local identity,
strict enrollment metadata, and protected local state used by the outbound
client.
"""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import ipaddress
import json
import os
import platform
import re
import socket
import stat
import tempfile
import termios
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Mapping
from urllib.parse import urlsplit, urlunsplit

AGENT_VERSION = "0.1.0"
STATE_API_VERSION = "edge.vivolution.ae/enrollment-state/v1"
SIGNED_REQUEST_PREFIX = b"edge.vivolution.ae/SignedNodeRequest/v1\0"
MAX_TOKEN_BYTES = 4096
MAX_STATE_BYTES = 64 * 1024
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_HOSTNAME_BYTES = 253
BASE64URL_32_RE = re.compile(rb"\A[A-Za-z0-9_-]{43}\Z")
GRANT_RE = re.compile(
    rb"\Av1\.([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    rb"[89ab][0-9a-f]{3}-[0-9a-f]{12})\.([A-Za-z0-9_-]{43})\Z"
)
GRANT_SEARCH_RE = re.compile(
    rb"v1\.[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    rb"[89ab][0-9a-f]{3}-[0-9a-f]{12}\.[A-Za-z0-9_-]{43}"
)
HOSTNAME_RE = re.compile(
    r"\A(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\Z"
)
DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")


class EnrollmentError(RuntimeError):
    """A bounded enrollment operation failed closed."""


class StateSecurityError(EnrollmentError):
    """A protected state path violates its ownership/type/mode contract."""


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EnrollmentError("protected state contains a duplicate JSON member")
        result[key] = value
    return result


def _check_canonical_domain(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str):
            value.encode("utf-8")
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise EnrollmentError("{} exceeds the interoperable integer range".format(path))
        return
    if isinstance(value, float):
        raise EnrollmentError("{} contains a forbidden floating-point value".format(path))
    if isinstance(value, list):
        for index, item in enumerate(value):
            _check_canonical_domain(item, "{}[{}]".format(path, index))
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise EnrollmentError("{} contains a non-string member name".format(path))
            try:
                key.encode("ascii")
            except UnicodeEncodeError as exc:
                raise EnrollmentError(
                    "{} contains a non-ASCII member name".format(path)
                ) from exc
            _check_canonical_domain(item, "{}.{}".format(path, key))
        return
    raise EnrollmentError(
        "{} contains unsupported JSON type {}".format(path, type(value).__name__)
    )


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the shared constrained RFC 8785-compatible byte form."""

    _check_canonical_domain(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def normalize_controller_url(raw: str) -> str:
    """Return one HTTPS origin/base path without credentials or ambiguity."""

    candidate = raw.strip()
    if not candidate:
        raise EnrollmentError("controller shared URL is required")
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise EnrollmentError("controller shared URL is invalid") from exc
    if parsed.scheme.lower() != "https":
        raise EnrollmentError("controller shared URL must use HTTPS")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise EnrollmentError("controller shared URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise EnrollmentError("controller shared URL must not contain a query or fragment")
    hostname = parsed.hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        is_ip_address = False
    else:
        is_ip_address = True
    if not HOSTNAME_RE.fullmatch(hostname) or "." not in hostname or is_ip_address:
        raise EnrollmentError("controller shared URL must use a valid DNS hostname")
    if port not in (None, 443):
        raise EnrollmentError("controller shared URL v1 supports HTTPS port 443 only")
    netloc = hostname
    if parsed.path not in ("", "/"):
        raise EnrollmentError("controller shared URL must be an HTTPS origin")
    return urlunsplit(("https", netloc, "", "", ""))


def _validate_uuid(value: str, field: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError) as exc:
        raise EnrollmentError("{} must be a canonical UUID".format(field)) from exc
    canonical = str(parsed)
    if value != canonical:
        raise EnrollmentError("{} must be a canonical lowercase UUID".format(field))
    return canonical


def _validate_hostname(value: str) -> str:
    canonical = value.rstrip(".").lower()
    if len(canonical.encode("ascii", "ignore")) > MAX_HOSTNAME_BYTES:
        raise EnrollmentError("hostname is too long")
    if canonical != value or not HOSTNAME_RE.fullmatch(canonical):
        raise EnrollmentError("hostname must be a canonical lowercase DNS name")
    return canonical


@dataclass(frozen=True)
class EnrollmentMetadata:
    """Immutable cluster placement asserted by the enrolling node."""

    node_id: str
    cluster_id: str
    slot: str
    generation: int
    release_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_id", _validate_uuid(self.node_id, "node_id"))
        object.__setattr__(
            self, "cluster_id", _validate_uuid(self.cluster_id, "cluster_id")
        )
        if self.slot not in ("A", "B"):
            raise EnrollmentError("slot must be A or B")
        if isinstance(self.generation, bool) or not 1 <= self.generation <= 2_147_483_647:
            raise EnrollmentError("generation must be a positive 32-bit integer")
        if not isinstance(self.release_digest, str) or not DIGEST_RE.fullmatch(
            self.release_digest
        ):
            raise EnrollmentError("release_digest must be one canonical SHA-256 digest")

    def as_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "generation": self.generation,
            "node_id": self.node_id,
            "release_digest": self.release_digest,
            "slot": self.slot,
        }


@dataclass(frozen=True)
class Identity:
    """An Ed25519 node identity whose private key never leaves this host."""

    private_seed: bytes
    public_key_base64url: str
    fingerprint: str

    @classmethod
    def generate(cls) -> "Identity":
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
        except ImportError as exc:
            raise EnrollmentError("python3-cryptography is required") from exc
        private_key = Ed25519PrivateKey.generate()
        private_seed = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return cls(
            private_seed=private_seed,
            public_key_base64url=base64.urlsafe_b64encode(public_raw)
            .rstrip(b"=")
            .decode("ascii"),
            fingerprint="sha256:" + hashlib.sha256(public_raw).hexdigest(),
        )

    @classmethod
    def from_seed(cls, private_seed: bytes) -> "Identity":
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
            private_key = Ed25519PrivateKey.from_private_bytes(private_seed)
        except (ImportError, ValueError) as exc:
            raise EnrollmentError("protected node identity is invalid") from exc
        public_raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return cls(
            private_seed=private_seed,
            public_key_base64url=base64.urlsafe_b64encode(public_raw)
            .rstrip(b"=")
            .decode("ascii"),
            fingerprint="sha256:" + hashlib.sha256(public_raw).hexdigest(),
        )

    def sign_bytes(self, value: bytes) -> str:
        """Sign exact controller-contract bytes with the node-local key."""

        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            key = Ed25519PrivateKey.from_private_bytes(self.private_seed)
        except (ImportError, ValueError) as exc:
            raise EnrollmentError("protected node identity is invalid") from exc
        return base64.urlsafe_b64encode(key.sign(value)).rstrip(b"=").decode("ascii")


def _validate_token(raw: bytes) -> str:
    value = raw
    if value.endswith(b"\r\n"):
        value = value[:-2]
    elif value.endswith(b"\n"):
        value = value[:-1]
    match = GRANT_RE.fullmatch(value)
    if match is None:
        raise EnrollmentError(
            "one-time enrollment grant must use the exact v1 selector/secret format"
        )
    try:
        decoded = base64.urlsafe_b64decode(match.group(2) + b"=")
    except (binascii.Error, ValueError) as exc:
        raise EnrollmentError("one-time enrollment grant is invalid") from exc
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).rstrip(b"=") != match.group(2):
        raise EnrollmentError("one-time enrollment grant is not canonical")
    return value.decode("ascii")


def validate_enrollment_grant(value: str) -> str:
    """Validate one v1 display-once grant already obtained from a safe source."""

    if not isinstance(value, str):
        raise EnrollmentError("one-time enrollment grant must be text")
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise EnrollmentError("one-time enrollment grant must be ASCII") from exc
    return _validate_token(raw)


def read_token_stream(stream: BinaryIO) -> str:
    """Read one bounded token from stdin without accepting it in argv or env."""

    raw = stream.read(MAX_TOKEN_BYTES + 2)
    if len(raw) > MAX_TOKEN_BYTES + 1:
        raise EnrollmentError("one-time enrollment token exceeds the size limit")
    return _validate_token(raw)


def read_token_tty(prompt: str = "One-time enrollment grant: ") -> str:
    """Read the display-once grant only from /dev/tty with echo disabled."""

    flags = os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOCTTY"):
        flags |= os.O_NOCTTY
    try:
        descriptor = os.open("/dev/tty", flags)
    except OSError as exc:
        raise EnrollmentError(
            "no controlling terminal; use --token-stdin or a root-only tmpfs token file"
        ) from exc
    original = None
    try:
        original = termios.tcgetattr(descriptor)
        hidden = list(original)
        hidden[3] &= ~termios.ECHO
        termios.tcsetattr(descriptor, termios.TCSAFLUSH, hidden)
        os.write(descriptor, prompt.encode("utf-8"))
        value = bytearray()
        while len(value) <= MAX_TOKEN_BYTES + 1:
            character = os.read(descriptor, 1)
            if not character or character in (b"\n", b"\r"):
                break
            value.extend(character)
        if len(value) > MAX_TOKEN_BYTES:
            raise EnrollmentError("one-time enrollment grant exceeds the size limit")
        return _validate_token(bytes(value))
    except termios.error as exc:
        raise EnrollmentError("cannot securely disable terminal echo") from exc
    finally:
        if original is not None:
            termios.tcsetattr(descriptor, termios.TCSAFLUSH, original)
            try:
                os.write(descriptor, b"\n")
            except OSError:
                pass
        os.close(descriptor)


def read_text_tty(prompt: str, *, maximum_bytes: int = 1024) -> str:
    """Read one non-secret line from the controlling terminal."""

    flags = os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOCTTY"):
        flags |= os.O_NOCTTY
    try:
        descriptor = os.open("/dev/tty", flags)
    except OSError as exc:
        raise EnrollmentError("no controlling terminal; supply --controller") from exc
    try:
        os.write(descriptor, prompt.encode("utf-8"))
        value = bytearray()
        while len(value) <= maximum_bytes:
            character = os.read(descriptor, 1)
            if not character or character in (b"\n", b"\r"):
                break
            value.extend(character)
        if len(value) > maximum_bytes:
            raise EnrollmentError("terminal input exceeds the size limit")
        try:
            return bytes(value).decode("utf-8")
        except UnicodeError as exc:
            raise EnrollmentError("terminal input is not valid UTF-8") from exc
    finally:
        os.close(descriptor)


def consume_root_token_file(path: Path) -> str:
    """Read and erase one root-owned 0600 regular token file without links."""

    if not path.is_absolute():
        raise StateSecurityError("token file path must be absolute")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise StateSecurityError("cannot resolve the one-time token file") from exc
    if resolved != path:
        raise StateSecurityError("token file and parent path must not use links")
    if not _path_is_tmpfs(path):
        raise StateSecurityError("token file must be on a tmpfs filesystem")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise StateSecurityError("cannot securely open the one-time token file") from exc
    accepted = False
    inode: tuple[int, int] | None = None
    try:
        record = os.fstat(descriptor)
        if (
            not stat.S_ISREG(record.st_mode)
            or record.st_nlink != 1
            or record.st_uid != 0
            or stat.S_IMODE(record.st_mode) != 0o600
            or not 16 <= record.st_size <= MAX_TOKEN_BYTES + 1
        ):
            raise StateSecurityError(
                "token file must be one root-owned 0600 single-link regular file"
            )
        inode = (record.st_dev, record.st_ino)
        chunks: list[bytes] = []
        remaining = MAX_TOKEN_BYTES + 2
        while remaining:
            chunk = os.read(descriptor, min(4096, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != record.st_size:
            raise StateSecurityError("token file changed while it was read")
        value = _validate_token(raw)
        accepted = True
        return value
    finally:
        os.close(descriptor)
        if accepted and inode is not None:
            try:
                current = path.lstat()
                if (current.st_dev, current.st_ino) != inode:
                    raise StateSecurityError("token file changed before erasure")
                path.unlink()
            except FileNotFoundError as exc:
                raise StateSecurityError("token file disappeared before erasure") from exc


def _path_is_tmpfs(path: Path) -> bool:
    """Use Linux mountinfo to require a real tmpfs grant handoff."""

    try:
        target = str(path.resolve(strict=True))
        records = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return False
    best_length = -1
    best_type = None
    for line in records:
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError:
            continue
        if separator < 6 or separator + 1 >= len(fields):
            continue
        mount_point = (
            fields[4]
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\")
        )
        if target == mount_point or target.startswith(mount_point.rstrip("/") + "/"):
            if len(mount_point) > best_length:
                best_length = len(mount_point)
                best_type = fields[separator + 1]
    return best_type == "tmpfs"


class ProtectedState:
    """Atomic 0700 directory / 0600 file persistence with owner pinning."""

    IDENTITY_NAME = "identity.key"
    STATE_NAME = "state.json"
    LOCK_NAME = ".identity.lock"

    def __init__(self, directory: Path, *, expected_uid: int) -> None:
        self.directory = directory
        self.owner_uid = expected_uid
        if isinstance(expected_uid, bool) or expected_uid < 0:
            raise StateSecurityError("expected enrollment state UID is invalid")
        self._ensure_directory()

    def _ensure_directory(self) -> None:
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise StateSecurityError("cannot create protected enrollment state") from exc
        record = self.directory.lstat()
        if os.geteuid() == 0 and record.st_uid == 0 and self.owner_uid != 0:
            os.chown(self.directory, self.owner_uid, -1)
            record = self.directory.lstat()
        current_uid = os.geteuid()
        if (
            not stat.S_ISDIR(record.st_mode)
            or stat.S_ISLNK(record.st_mode)
            or record.st_nlink < 1
            or stat.S_IMODE(record.st_mode) != 0o700
            or record.st_uid != self.owner_uid
            or current_uid not in (0, self.owner_uid)
        ):
            raise StateSecurityError(
                "enrollment state must be one owner-controlled 0700 directory"
            )

    def _secure_read(self, name: str, maximum: int) -> bytes:
        path = self.directory / name
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise StateSecurityError("cannot securely open protected state") from exc
        try:
            record = os.fstat(descriptor)
            if (
                not stat.S_ISREG(record.st_mode)
                or record.st_nlink != 1
                or record.st_uid != self.owner_uid
                or stat.S_IMODE(record.st_mode) != 0o600
                or not 1 <= record.st_size <= maximum
            ):
                raise StateSecurityError("protected state file violates its file contract")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            if len(content) != record.st_size or len(content) > maximum:
                raise StateSecurityError("protected state changed while it was read")
            return content
        finally:
            os.close(descriptor)

    def _atomic_write(self, name: str, content: bytes) -> None:
        if not content or len(content) > MAX_STATE_BYTES:
            raise StateSecurityError("protected state content has an invalid size")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".{}-".format(name), dir=str(self.directory)
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            if os.geteuid() == 0 and self.owner_uid != 0:
                os.fchown(descriptor, self.owner_uid, -1)
            offset = 0
            while offset < len(content):
                offset += os.write(descriptor, content[offset:])
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, self.directory / name)
            directory_descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def load_or_create_identity(self) -> tuple[Identity, bool]:
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        lock_path = self.directory / self.LOCK_NAME
        descriptor = os.open(lock_path, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            if os.geteuid() == 0 and self.owner_uid != 0:
                os.fchown(descriptor, self.owner_uid, -1)
            record = os.fstat(descriptor)
            if (
                not stat.S_ISREG(record.st_mode)
                or record.st_nlink != 1
                or record.st_uid != self.owner_uid
                or stat.S_IMODE(record.st_mode) != 0o600
            ):
                raise StateSecurityError("identity lock violates its file contract")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                content = self._secure_read(self.IDENTITY_NAME, 32)
            except FileNotFoundError:
                identity = Identity.generate()
                self._atomic_write(self.IDENTITY_NAME, identity.private_seed)
                return identity, True
            return Identity.from_seed(content), False
        finally:
            os.close(descriptor)

    def read_state(self) -> dict[str, Any] | None:
        try:
            content = self._secure_read(self.STATE_NAME, MAX_STATE_BYTES)
        except FileNotFoundError:
            return None
        try:
            value = json.loads(
                content.decode("utf-8"), object_pairs_hook=_strict_object_pairs
            )
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise EnrollmentError("protected enrollment state is invalid JSON") from exc
        if not isinstance(value, dict) or value.get("api_version") != STATE_API_VERSION:
            raise EnrollmentError("protected enrollment state version is unsupported")
        return value

    def write_state(self, value: Mapping[str, Any]) -> None:
        if value.get("api_version") != STATE_API_VERSION:
            raise EnrollmentError("protected enrollment state version is unsupported")
        forbidden = {
            key
            for key in value
            if "enrollment_token" in key.lower() or key.lower() == "token"
        }
        if forbidden:
            raise EnrollmentError("one-time enrollment tokens must never be persisted")
        content = canonical_json_bytes(value)
        if GRANT_SEARCH_RE.search(content):
            raise EnrollmentError("one-time enrollment grants must never be persisted")
        self._atomic_write(self.STATE_NAME, content)


def fixed_inventory() -> dict[str, Any]:
    """Return a bounded, provider-neutral, self-reported inventory snapshot."""

    os_release: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key in ("ID", "VERSION_ID"):
                os_release[key] = value.strip().strip('"')[:64]
    except (OSError, UnicodeError):
        pass
    return {
        "architecture": platform.machine().lower()[:32],
        "capabilities": [
            "enrollment_v1",
            "heartbeat_v1",
            "provider_neutral_metadata_v1",
            "signed_node_request_v1",
        ],
        "os_id": os_release.get("ID", "unknown"),
        "os_version": os_release.get("VERSION_ID", "unknown"),
        "python_version": "{}.{}.{}".format(*platform.python_version_tuple()),
    }


def default_hostname() -> str:
    return _validate_hostname(socket.getfqdn().rstrip(".").lower())
