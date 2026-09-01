#!/usr/bin/env python3
"""Provider-neutral Vivolution Controller installer orchestration core.

This module intentionally uses only the Python standard library.  Host
configuration is delegated to a configurable Ansible playbook; this layer owns
question/answer validation, durable state, logging, locking, resume semantics,
and the secret-safe Ansible handoff.
"""

import argparse
import contextlib
import datetime
import email.utils
import fcntl
import hashlib
import io
import ipaddress
import json
import os
import platform
import pwd
import re
import secrets
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
import zoneinfo
from pathlib import Path


INSTALLER_VERSION = "0.3.0-rc6"
LEDGER_SCHEMA_VERSION = 5
SUPPORTED_OS_ID = "ubuntu"
SUPPORTED_OS_VERSION = "24.04"
DEFAULT_STATE_DIR = "/var/lib/vivolution/installer"
DEFAULT_LOG_DIR = "/var/log/vivolution/installer"
DEFAULT_DRY_RUN_STATE_DIR = "/var/lib/vivolution/installer-dry-run"
DEFAULT_DRY_RUN_LOG_DIR = "/var/log/vivolution/installer-dry-run"
LEGACY_STATE_DIR = "/var/lib/vivolution-installer"
LEGACY_LOG_DIR = "/var/log/vivolution-installer"
DEFAULT_PLAYBOOK = "installer/ansible/install-controller.yml"
DEFAULT_ANSIBLE_CONFIG = "installer/ansible/ansible.cfg"
LETS_ENCRYPT_PRODUCTION_DIRECTORY = (
    "https://acme-v02.api.letsencrypt.org/directory"
)

PHASES = (
    "preflight",
    "answers",
    "confirmation",
    "release",
    "bootstrap",
    "secrets",
    "ansible",
    "summary",
)
CONFIRMATION_TOKEN = "INSTALL"
DISCARD_CONFIRMATION_TOKEN = "DISCARD-INCOMPLETE"
BASE_BOOTSTRAP_PACKAGES = ("ansible-core", "ca-certificates", "python3-apt")
INSTALLER_FIREWALL_PACKAGES = ("ufw",)
BOOTSTRAP_PACKAGES = BASE_BOOTSTRAP_PACKAGES + INSTALLER_FIREWALL_PACKAGES
PUBLIC_IPV4_SOURCES = (
    "https://ifconfig.me/ip",
    "https://api.ipify.org",
    "https://checkip.amazonaws.com",
)
LOG_LEVELS = ("TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL")
LOG_ROTATE_BYTES = 10 * 1024 * 1024
LOG_ROTATE_COUNT = 5
COMMAND_OUTPUT_MAX_LINES = 10000
COMMAND_OUTPUT_MAX_BYTES = 4 * 1024 * 1024
MENU_OPTIONS = (
    ("create-controller", "Create a new Controller Plane", True),
    ("join-controller", "Join an existing Controller Plane", False),
    ("deploy-edge", "Deploy an Edge Appliance (SBC)", False),
    ("manage", "Manage an existing installation", True),
    ("diagnostics", "Diagnostics / network readiness test", True),
)
ANSWER_KEYS = {
    "deployment_mode",
    "node_fqdn",
    "shared_fqdn",
    "public_ipv4",
    "ssh_source_cidrs",
    "admin_username",
    "admin_email",
    "acme_email",
    "ssh_allowed_user",
    "firewall_mode",
    "timezone",
    "ntp_mode",
    "ntp_servers",
}
REQUIRED_ANSWER_KEYS = ANSWER_KEYS - {
    "ssh_allowed_user",
    "acme_email",
    "firewall_mode",
    "timezone",
    "ntp_mode",
    "ntp_servers",
    "ssh_source_cidrs",
}
SECRET_KEYS = {
    "cp_controller_admin_password",
    "cp_db_owner_password",
    "cp_db_runtime_password",
    "cp_django_secret_key",
    "cp_edge_enrollment_token_pepper",
    "cp_rls_context_key",
}
SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "authorization",
)
RESERVED_ADMIN_USERS = {
    "root",
    "postgres",
    "caddy",
    "nobody",
    "systemd-network",
    "vivolution",
}
CONTROLLER_REQUIRED_FILES = (
    ".dockerignore",
    "Containerfile",
    "RELEASE_NOTES.md",
    "constraints.txt",
    "entrypoint.sh",
    "manage.py",
    "requirements.lock",
)


class InstallerError(RuntimeError):
    """A safe, user-facing installer failure."""


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def effective_process_identity():
    """Return the kernel effective UID and its account name, never env/login state."""
    effective_uid = os.geteuid()
    try:
        effective_user = pwd.getpwuid(effective_uid).pw_name
    except KeyError:
        effective_user = str(effective_uid)
    return effective_uid, effective_user


def _fsync_directory(path):
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd = os.open(str(path), flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _directory_metadata(path):
    """Return lstat metadata for a real directory without following links."""
    path = Path(path)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise InstallerError("Could not inspect secure directory %s: %s" % (path, exc))
    if stat.S_ISLNK(metadata.st_mode):
        raise InstallerError("Secure directory ancestry must not contain a symbolic link: %s" % path)
    if not stat.S_ISDIR(metadata.st_mode):
        raise InstallerError("Secure directory ancestry contains a non-directory: %s" % path)
    return metadata


def _validate_secure_directory_metadata(metadata, component, boundary, expected_uid):
    if not stat.S_ISDIR(metadata.st_mode):
        raise InstallerError("Secure directory ancestry contains a non-directory: %s" % component)
    if metadata.st_uid != expected_uid:
        raise InstallerError(
            "Secure directory must be owned by UID %d: %s"
            % (expected_uid, component)
        )
    unsafe_write_bits = stat.S_IMODE(metadata.st_mode) & 0o022
    # Ubuntu Noble with rsyslog may package /var/log as root:syslog 0775.
    # This is the sole fixed OS-anchor exception: it remains a real,
    # root-owned directory and is never chmodded by us.  The Vivolution child
    # and every other component remain non-group/world-writable.
    if component == boundary / "var/log":
        unsafe_write_bits &= ~0o020
    if unsafe_write_bits:
        raise InstallerError(
            "Secure directory must not be group/world writable: %s" % component
        )


def _validate_secure_directory_chain(path, boundary, expected_uid):
    """Validate every existing directory from ``boundary`` through ``path``.

    The live installer passes ``/`` and UID 0.  Unit tests pass their explicit
    fake root and the test process UID, so security failures can be exercised
    without weakening or special-casing the individual installer paths.
    """
    path = Path(path)
    boundary = Path(boundary)
    if not path.is_absolute() or not boundary.is_absolute():
        raise InstallerError("Secure directory paths must be absolute")
    try:
        relative = path.relative_to(boundary)
    except ValueError:
        raise InstallerError("Secure path %s escapes trusted root %s" % (path, boundary))

    components = [boundary]
    current = boundary
    for part in relative.parts:
        current = current / part
        components.append(current)

    missing_parent = False
    for component in components:
        metadata = _directory_metadata(component)
        if metadata is None:
            missing_parent = True
            continue
        if missing_parent:
            raise InstallerError(
                "Secure directory ancestry is inconsistent at %s" % component
            )
        _validate_secure_directory_metadata(
            metadata, component, boundary, expected_uid
        )
    return True


def _secure_ensure_private_directory(path, boundary, expected_uid):
    """Create a private directory chain only after validating its ancestry."""
    path = Path(path)
    boundary = Path(boundary)
    _validate_secure_directory_chain(path, boundary, expected_uid)
    try:
        relative = path.relative_to(boundary)
    except ValueError:
        raise InstallerError("Secure path %s escapes trusted root %s" % (path, boundary))

    if _directory_metadata(boundary) is None:
        raise InstallerError("Trusted filesystem root does not exist: %s" % boundary)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(boundary), flags)
    except OSError as exc:
        raise InstallerError("Could not securely open trusted root %s: %s" % (boundary, exc))
    current = boundary
    try:
        _validate_secure_directory_metadata(
            os.fstat(descriptor), current, boundary, expected_uid
        )
        for part in relative.parts:
            current = current / part
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise InstallerError(
                        "Could not create secure directory %s: %s" % (current, exc)
                    )
                try:
                    child = os.open(part, flags, dir_fd=descriptor)
                except OSError as exc:
                    raise InstallerError(
                        "Could not securely open new directory %s: %s" % (current, exc)
                    )
            except OSError as exc:
                raise InstallerError(
                    "Could not securely open directory %s: %s" % (current, exc)
                )
            try:
                _validate_secure_directory_metadata(
                    os.fstat(child), current, boundary, expected_uid
                )
            except Exception:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child

        # Existing safe private roots may be 0750/0755. Narrow only the opened
        # installer-owned leaf; never chmod a re-resolved absolute path.
        os.fchmod(descriptor, 0o700)
        _validate_secure_directory_metadata(
            os.fstat(descriptor), path, boundary, expected_uid
        )
    finally:
        os.close(descriptor)
    _validate_secure_directory_chain(path, boundary, expected_uid)
    return path


def ensure_private_directory(path):
    path = Path(path)
    metadata = _directory_metadata(path)
    if metadata is not None:
        if metadata.st_uid != os.geteuid():
            raise InstallerError("Private directory has an unexpected owner: %s" % path)
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise InstallerError(
                "Private directory must not be group/world writable: %s" % path
            )
    else:
        path.mkdir(mode=0o700, parents=True)
    os.chmod(str(path), 0o700)
    return path


def atomic_write_bytes(path, payload, mode=0o600):
    path = Path(path)
    ensure_private_directory(path.parent)
    fd, temporary = tempfile.mkstemp(prefix=".%s." % path.name, dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            fd = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, str(path))
        os.chmod(str(path), mode)
        _fsync_directory(path.parent)
    except Exception:
        if fd >= 0:
            os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def atomic_write_json(path, value, mode=0o600):
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    atomic_write_bytes(path, payload, mode=mode)


def read_json_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise InstallerError("Required JSON file is unsafe or missing: %s" % path)
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError) as exc:
        raise InstallerError("Could not read JSON file %s: %s" % (path, exc))
    return value


def append_private_line(path, line):
    path = Path(path)
    ensure_private_directory(path.parent)
    encoded = (line.rstrip("\n") + "\n").encode("utf-8", errors="replace")
    if path.exists() and not path.is_symlink():
        try:
            needs_rotation = path.stat().st_size + len(encoded) > LOG_ROTATE_BYTES
        except OSError as exc:
            raise InstallerError("Could not inspect installer log %s: %s" % (path, exc))
        if needs_rotation:
            for index in range(LOG_ROTATE_COUNT - 1, 0, -1):
                source = path.with_name("%s.%d" % (path.name, index))
                destination = path.with_name("%s.%d" % (path.name, index + 1))
                if source.exists() and not source.is_symlink():
                    os.replace(str(source), str(destination))
            os.replace(str(path), str(path.with_name("%s.1" % path.name)))
            _fsync_directory(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)


class Redactor:
    _authorization_pattern = re.compile(
        r"(?im)\b((?:proxy-)?authorization)\s*:\s*[^\r\n]+"
    )
    _assignment_pattern = re.compile(
        r"(?i)([\"']?(?:password|passwd|token|access[_-]?token|refresh[_-]?token|"
        r"secret|api[_-]?key|apikey|client[_-]?secret)[\"']?\s*[:=]\s*)"
        r"(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;}\]\r\n]+)"
    )
    _credential_url_pattern = re.compile(
        r"(?i)\b([a-z][a-z0-9+.-]*://)([^/@\s]+)@"
    )
    _private_key_pattern = re.compile(
        r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?"
        r"(?:-----END \1-----|\Z)",
        re.DOTALL,
    )
    _private_key_begin_pattern = re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"
    )
    _private_key_end_pattern = re.compile(
        r"-----END [A-Z0-9 ]*PRIVATE KEY-----"
    )

    def __init__(self, secret_values=None):
        self._values = set()
        self.add_values(secret_values or [])

    def add_values(self, values):
        for value in values:
            if isinstance(value, str) and value:
                self._values.add(value)

    @staticmethod
    def _sensitive_key(key):
        lowered = str(key).lower()
        return any(part in lowered for part in SENSITIVE_KEY_PARTS)

    @staticmethod
    def _quoted_redaction(match):
        prefix = match.group(1)
        original = match.group(2)
        if len(original) >= 2 and original[0] in ("\"", "'") and original[-1] == original[0]:
            replacement = "%s[REDACTED]%s" % (original[0], original[0])
        else:
            replacement = "[REDACTED]"
        return prefix + replacement

    @staticmethod
    def _private_key_redaction(match):
        # Keep the same physical line count so surrounding diagnostics retain
        # useful record boundaries without retaining any key material.
        rendered = match.group(0)
        line_count = max(1, len(rendered.splitlines()))
        ending = "\n" if rendered.endswith("\n") else ""
        return "\n".join("[REDACTED PRIVATE KEY]" for _unused in range(line_count)) + ending

    def _patterns(self, value):
        rendered = str(value)
        for secret_value in sorted(self._values, key=len, reverse=True):
            rendered = rendered.replace(secret_value, "[REDACTED]")
        rendered = self._private_key_pattern.sub(
            self._private_key_redaction, rendered
        )
        rendered = self._authorization_pattern.sub(
            lambda match: "%s: [REDACTED]" % match.group(1), rendered
        )
        rendered = self._assignment_pattern.sub(
            self._quoted_redaction, rendered
        )
        rendered = self._credential_url_pattern.sub(
            lambda match: "%s[REDACTED]@" % match.group(1), rendered
        )
        return rendered

    @staticmethod
    def _escape_controls(rendered, preserve_newlines=False):
        safe = []
        for character in rendered:
            codepoint = ord(character)
            if character == "\n" and preserve_newlines:
                safe.append("\n")
            elif character == "\n":
                safe.append("\\n")
            elif character == "\r":
                safe.append("\\r")
            elif character == "\t":
                safe.append("\\t")
            elif codepoint < 32 or 127 <= codepoint <= 159:
                safe.append("\\x%02x" % codepoint)
            else:
                safe.append(character)
        return "".join(safe)

    def text(self, value):
        return self._escape_controls(self._patterns(value))

    def multiline_text(self, value):
        return self._escape_controls(
            self._patterns(value), preserve_newlines=True
        )

    def stream_line(self, value, private_key_active=False):
        """Redact one subprocess line while carrying PEM-block state."""
        rendered = str(value)
        begins = bool(self._private_key_begin_pattern.search(rendered))
        ends = bool(self._private_key_end_pattern.search(rendered))
        if private_key_active or begins:
            return "[REDACTED PRIVATE KEY]", bool((private_key_active or begins) and not ends)
        return self.text(rendered), False

    def argv(self, command):
        """Redact an argv vector, including secrets in a following argument."""
        sensitive_options = {
            "--password",
            "--passwd",
            "--token",
            "--access-token",
            "--refresh-token",
            "--secret",
            "--api-key",
            "--apikey",
            "--client-secret",
            "--client_secret",
            "--authorization",
            "--proxy-authorization",
            "--user",
            "--userpwd",
        }
        safe = []
        next_mode = None
        for raw_argument in command:
            argument = str(raw_argument)
            if next_mode == "secret":
                safe.append("[REDACTED]")
                next_mode = None
                continue
            if next_mode == "header":
                safe.append(self.text(argument))
                next_mode = None
                continue

            safe.append(self.text(argument))
            lowered = argument.lower()
            if lowered in sensitive_options:
                next_mode = "secret"
            elif argument == "-H" or lowered == "--header":
                # Preserve harmless headers, while text() removes Authorization
                # and Proxy-Authorization values from the following argument.
                next_mode = "header"
        return safe

    def value(self, value, key=None):
        if key is not None and self._sensitive_key(key):
            return "[REDACTED]"
        if isinstance(value, dict):
            result = {}
            for item_key, item_value in value.items():
                rendered_key = str(item_key)
                normalized_key = rendered_key.lower().replace("-", "_")
                if normalized_key in ("argv", "command") and isinstance(
                    item_value, (list, tuple)
                ):
                    result[rendered_key] = self.argv(item_value)
                else:
                    result[rendered_key] = self.value(item_value, key=item_key)
            return result
        if isinstance(value, list):
            return [self.value(item) for item in value]
        if isinstance(value, tuple):
            return [self.value(item) for item in value]
        if isinstance(value, str):
            return self.text(value)
        return value


class InstallerLog:
    def __init__(self, human_path, event_path, redactor=None):
        self.human_path = Path(human_path)
        self.event_path = Path(event_path)
        self.redactor = redactor or Redactor()
        self.context = {}

    def bind(self, **fields):
        for key, value in fields.items():
            if value is None:
                self.context.pop(key, None)
            else:
                self.context[key] = value

    def write(self, level, message, category="installer"):
        normalized_level = str(level).upper()
        if normalized_level not in LOG_LEVELS:
            raise InstallerError("Unknown installer log level: %s" % level)
        safe_message = self.redactor.text(message)
        append_private_line(
            self.human_path,
            "%s %-5s [%s] %s"
            % (utc_now(), normalized_level, str(category), safe_message),
        )
        self.event(
            "log",
            level=normalized_level,
            category=str(category),
            message=safe_message,
        )

    def trace(self, message, category="installer"):
        self.write("TRACE", message, category)

    def debug(self, message, category="installer"):
        self.write("DEBUG", message, category)

    def info(self, message, category="installer"):
        self.write("INFO", message, category)

    def warn(self, message, category="installer"):
        self.write("WARN", message, category)

    def error(self, message, category="installer"):
        self.write("ERROR", message, category)

    def fatal(self, message, category="installer"):
        self.write("FATAL", message, category)

    def audit(self, event_name, **fields):
        audit_category = str(fields.pop("category", "lifecycle"))
        self.event(
            event_name,
            level="INFO",
            category="AUDIT",
            audit_category=audit_category,
            **fields,
        )
        rendered = self.redactor.text(event_name)
        append_private_line(
            self.human_path,
            "%s AUDIT [%s] %s"
            % (utc_now(), audit_category, rendered),
        )

    def event(self, event_name, **fields):
        record = {
            "timestamp": utc_now(),
            "event": event_name,
            "fields": self.redactor.value({**self.context, **fields}),
        }
        if "level" in fields:
            record["level"] = str(fields["level"]).upper()
        if "category" in fields:
            record["category"] = str(fields["category"])
        append_private_line(self.event_path, json.dumps(record, sort_keys=True))


def run_streamed_command(
    command,
    log,
    prefix,
    runner=subprocess.Popen,
    console_stream=None,
    show_output=True,
    max_output_lines=COMMAND_OUTPUT_MAX_LINES,
    max_output_bytes=COMMAND_OUTPUT_MAX_BYTES,
    **kwargs,
):
    """Run a command while durably logging and displaying each redacted line.

    The production runner is ``subprocess.Popen`` so output is consumed while
    the child is running.  Tests may inject a lightweight runner returning a
    ``CompletedProcess``; that compatibility path is intentionally buffered
    and is not used by the installer CLI.
    """
    console_stream = sys.stdout if console_stream is None else console_stream
    safe_command = log.redactor.argv(command)
    safe_cwd = log.redactor.text(kwargs.get("cwd", os.getcwd()))
    effective_uid, effective_user = effective_process_identity()
    started_at = utc_now()
    started_monotonic = time.monotonic()
    log.info(
        "Command started: %s" % " ".join(shlex.quote(item) for item in safe_command),
        category="command",
    )
    log.event(
        "command_started",
        level="INFO",
        category="command",
        command=safe_command,
        step=prefix,
        cwd=safe_cwd,
        effective_uid=effective_uid,
        effective_user=effective_user,
        started_at=started_at,
    )
    process = runner(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        bufsize=1,
        **kwargs,
    )

    output_lines = 0
    output_bytes = 0
    output_truncated = False
    private_key_active = False

    def emit(raw_line):
        nonlocal output_lines, output_bytes, output_truncated, private_key_active
        line = str(raw_line).rstrip("\r\n")
        safe_line, private_key_active = log.redactor.stream_line(
            line, private_key_active=private_key_active
        )
        encoded_size = len(safe_line.encode("utf-8", errors="replace")) + 1
        if output_lines >= max_output_lines or output_bytes + encoded_size > max_output_bytes:
            output_truncated = True
            return
        output_lines += 1
        output_bytes += encoded_size
        # append_private_line fsyncs every line before it is shown, so a power
        # loss cannot leave console progress that never reached the log.
        log.debug("%s: %s" % (prefix, safe_line), category="command-output")
        if show_output:
            console_stream.write("%s: %s\n" % (prefix, safe_line))
            console_stream.flush()

    output = getattr(process, "stdout", None)
    if isinstance(output, str):
        for line in output.splitlines():
            emit(line)
    elif output is not None:
        for line in output:
            emit(line)
        with contextlib.suppress(Exception):
            output.close()

    if hasattr(process, "wait"):
        return_code = process.wait()
    else:
        return_code = getattr(process, "returncode", None)
    if not isinstance(return_code, int):
        raise InstallerError("Command runner did not provide an exit code")
    if output_truncated:
        log.warn(
            "Command output was truncated after %d lines / %d bytes"
            % (output_lines, output_bytes),
            category="command-output",
        )
        log.event(
            "command_output_truncated",
            level="WARN",
            category="command-output",
            captured_lines=output_lines,
            captured_bytes=output_bytes,
            line_limit=max_output_lines,
            byte_limit=max_output_bytes,
            step=prefix,
        )
    duration_ms = max(0, round((time.monotonic() - started_monotonic) * 1000))
    signal_number = -return_code if return_code < 0 else None
    log.event(
        "command_completed",
        level="INFO" if return_code == 0 else "ERROR",
        category="command",
        command=safe_command,
        step=prefix,
        cwd=safe_cwd,
        effective_uid=effective_uid,
        effective_user=effective_user,
        started_at=started_at,
        completed_at=utc_now(),
        duration_ms=duration_ms,
        exit_code=return_code if return_code >= 0 else None,
        signal=signal_number,
    )
    log.info(
        "Command completed in %d ms with %s"
        % (
            duration_ms,
            "signal %d" % signal_number
            if signal_number is not None
            else "exit code %d" % return_code,
        ),
        category="command",
    )
    return return_code


class ExclusiveInstallerLock:
    def __init__(self, path, security_root=None, expected_uid=None):
        self.path = Path(path)
        self.security_root = Path(security_root) if security_root is not None else None
        self.expected_uid = os.geteuid() if expected_uid is None else int(expected_uid)
        self._handle = None

    def __enter__(self):
        if self.security_root is None:
            ensure_private_directory(self.path.parent)
        else:
            _secure_ensure_private_directory(
                self.path.parent, self.security_root, self.expected_uid
            )
        try:
            existing = self.path.lstat()
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise InstallerError("Could not inspect installer lock %s: %s" % (self.path, exc))
        if existing is not None:
            if (
                not stat.S_ISREG(existing.st_mode)
                or existing.st_uid != self.expected_uid
                or stat.S_IMODE(existing.st_mode) & 0o022
            ):
                raise InstallerError("Installer lock file is unsafe: %s" % self.path)
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(self.path), flags, 0o600)
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_uid != self.expected_uid:
            os.close(fd)
            raise InstallerError("Installer lock file is unsafe: %s" % self.path)
        os.fchmod(fd, 0o600)
        self._handle = os.fdopen(fd, "a+", encoding="ascii")
        try:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._handle.close()
            self._handle = None
            raise InstallerError("Another Vivolution installer process holds %s" % self.path)
        self._handle.seek(0)
        self._handle.truncate()
        self._handle.write("%d\n" % os.getpid())
        self._handle.flush()
        os.fsync(self._handle.fileno())
        return self

    def __exit__(self, exc_type, exc, traceback):
        if self._handle is not None:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
            self._handle.close()
        self._handle = None


class InstallerPaths:
    def __init__(self, root="/", state_dir=None, log_dir=None, dry_run=False):
        root_path = Path(root)
        if not root_path.is_absolute():
            raise InstallerError("--root must be an absolute path")
        if ".." in root_path.parts:
            raise InstallerError("--root must not contain '..'")
        # Do not resolve here: resolution would silently traverse an attacker-
        # controlled fake-root symlink before the secure ancestry check runs.
        self.root = root_path
        self.dry_run = bool(dry_run)
        if state_dir is None:
            state_dir = DEFAULT_DRY_RUN_STATE_DIR if self.dry_run else DEFAULT_STATE_DIR
        if log_dir is None:
            log_dir = DEFAULT_DRY_RUN_LOG_DIR if self.dry_run else DEFAULT_LOG_DIR
        if self.root == Path("/"):
            approved_state = (
                DEFAULT_DRY_RUN_STATE_DIR if self.dry_run else DEFAULT_STATE_DIR
            )
            approved_log = DEFAULT_DRY_RUN_LOG_DIR if self.dry_run else DEFAULT_LOG_DIR
            if str(Path(state_dir)) != approved_state:
                raise InstallerError(
                    "--state-dir overrides are refused on the live host; approved path is %s"
                    % approved_state
                )
            if str(Path(log_dir)) != approved_log:
                raise InstallerError(
                    "--log-dir overrides are refused on the live host; approved path is %s"
                    % approved_log
                )
        self.state_dir = self._rooted(state_dir)
        self.log_dir = self._rooted(log_dir)
        self.ledger = self.state_dir / "ledger.json"
        self.answers = self.state_dir / "answers.json"
        self.secrets = self.state_dir / "secrets.json"
        self.credentials = self.state_dir / "credentials.txt"
        self.summary = self.state_dir / "summary.json"
        self.inventory = self.state_dir / "inventory.json"
        self.ownership = self.state_dir / "ownership.json"
        self.tombstone = self.state_dir / "tombstone.json"
        lock_name = "installer-dry-run.lock" if self.dry_run else "installer.lock"
        self.lock = self.host_path("/run/vivolution/%s" % lock_name)
        self.human_log = self.log_dir / "install.log"
        self.event_log = self.log_dir / "events.jsonl"
        self.legacy_state_dir = self._rooted(LEGACY_STATE_DIR)
        self.legacy_log_dir = self._rooted(LEGACY_LOG_DIR)
        self.legacy_ledger = self.legacy_state_dir / "ledger.json"
        self.legacy_lock = self.legacy_state_dir / "installer.lock"

    def _rooted(self, logical_path):
        path = Path(logical_path)
        if not path.is_absolute():
            raise InstallerError("Installer state paths must be absolute: %s" % path)
        if ".." in path.parts:
            raise InstallerError("Installer state paths must not contain '..': %s" % path)
        if self.root == Path("/"):
            return path
        return self.root / str(path).lstrip("/")

    def host_path(self, logical_path):
        return self._rooted(logical_path)

    @property
    def security_uid(self):
        return 0 if self.root == Path("/") else os.geteuid()

    def validate_critical_paths(self):
        """Validate state, log, and runtime-lock ancestry without writing."""
        for directory in (self.state_dir, self.log_dir, self.lock.parent):
            _validate_secure_directory_chain(
                directory, self.root, self.security_uid
            )
        return True

    def ensure_lock_directory(self):
        self.validate_critical_paths()
        return _secure_ensure_private_directory(
            self.lock.parent, self.root, self.security_uid
        )

    def ensure_state_log_directories(self):
        self.validate_critical_paths()
        for directory in (self.state_dir, self.log_dir):
            _secure_ensure_private_directory(
                directory, self.root, self.security_uid
            )
        self.validate_critical_paths()

    def exclusive_lock(self):
        # Validate all three namespaces before the first lock-directory mkdir
        # or lock-file write, then have the lock validate again at open time.
        self.ensure_lock_directory()
        return ExclusiveInstallerLock(
            self.lock,
            security_root=self.root,
            expected_uid=self.security_uid,
        )


def parse_os_release(path):
    values = {}
    path = Path(path)
    try:
        path_metadata = path.lstat()
    except OSError:
        raise InstallerError("OS metadata is missing or unsafe: %s" % path)

    read_path = path
    if stat.S_ISLNK(path_metadata.st_mode):
        try:
            link_target = os.readlink(path)
        except OSError:
            raise InstallerError("OS metadata is missing or unsafe: %s" % path)
        if link_target == "../usr/lib/os-release":
            read_path = path.parent.parent / "usr/lib/os-release"
        else:
            raise InstallerError("OS metadata is missing or unsafe: %s" % path)
    elif not stat.S_ISREG(path_metadata.st_mode):
        raise InstallerError("OS metadata is missing or unsafe: %s" % path)

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = None
    try:
        descriptor = os.open(read_path, flags)
        opened_metadata = os.fstat(descriptor)
        if not stat.S_ISREG(opened_metadata.st_mode) or opened_metadata.st_size > 65536:
            raise InstallerError("OS metadata is missing or unsafe: %s" % path)
        if path == Path("/etc/os-release") and (
            opened_metadata.st_uid != 0 or opened_metadata.st_mode & 0o022
        ):
            raise InstallerError("OS metadata is missing or unsafe: %s" % path)
        chunks = []
        remaining = 65537
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > 65536 or b"\x00" in content:
            raise InstallerError("OS metadata is missing or unsafe: %s" % path)
        lines = content.decode("utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise InstallerError("Could not read %s: %s" % (read_path, exc))
    finally:
        if descriptor is not None:
            os.close(descriptor)
    for line in lines:
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if key in values:
            raise InstallerError("OS metadata contains a duplicate key: %s" % key)
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def validate_fqdn(value, field_name="FQDN"):
    if not isinstance(value, str):
        raise InstallerError("%s must be a string" % field_name)
    candidate = value.strip().rstrip(".")
    if not candidate or "*" in candidate or any(ch.isspace() for ch in candidate):
        raise InstallerError("%s must be a concrete DNS name" % field_name)
    try:
        ascii_name = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise InstallerError("%s is not a valid DNS name" % field_name)
    if len(ascii_name) > 253 or "." not in ascii_name:
        raise InstallerError("%s must be a fully qualified DNS name" % field_name)
    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    if any(not label_pattern.fullmatch(label) for label in ascii_name.split(".")):
        raise InstallerError("%s contains an invalid DNS label" % field_name)
    return ascii_name


def validate_public_ipv4(value, field_name="public_ipv4"):
    if not isinstance(value, str):
        raise InstallerError("%s must be a string" % field_name)
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        raise InstallerError("%s must be a valid IPv4 address" % field_name)
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
        raise InstallerError("%s must be a globally routable IPv4 address" % field_name)
    return str(address)


def validate_ssh_cidrs(value):
    if value is None:
        values = []
    elif isinstance(value, str):
        values = [item.strip() for item in value.split(",") if item.strip()]
    elif isinstance(value, list):
        values = value
    else:
        raise InstallerError("ssh_source_cidrs must be a JSON list or comma-separated string")
    if not values:
        raise InstallerError("At least one SSH source /32 CIDR is required")
    if len(values) > 16:
        raise InstallerError("At most sixteen SSH source /32 CIDRs are supported")
    normalized = []
    for raw_value in values:
        if not isinstance(raw_value, str):
            raise InstallerError("Every SSH source CIDR must be a string")
        try:
            network = ipaddress.ip_network(raw_value.strip(), strict=True)
        except ValueError:
            raise InstallerError("Invalid SSH source CIDR: %s" % raw_value)
        if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen != 32:
            raise InstallerError("SSH source must be an exact IPv4 /32: %s" % raw_value)
        address = network.network_address
        if address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local:
            raise InstallerError("SSH source is not a usable management address: %s" % raw_value)
        normalized.append(str(network))
    return sorted(set(normalized), key=lambda cidr: int(ipaddress.ip_network(cidr).network_address))


def current_ssh_client_cidr(environment=None):
    environment = os.environ if environment is None else environment
    connection = environment.get("SSH_CONNECTION", "").strip()
    if not connection:
        return None
    fields = connection.split()
    if len(fields) != 4:
        raise InstallerError("SSH_CONNECTION is present but malformed")
    try:
        address = ipaddress.ip_address(fields[0])
    except ValueError:
        raise InstallerError("SSH_CONNECTION contains an invalid client address")
    if not isinstance(address, ipaddress.IPv4Address):
        return None
    if address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local:
        raise InstallerError("SSH_CONNECTION contains an unsafe client IPv4 address")
    return "%s/32" % address


def validate_admin_username(value):
    if not isinstance(value, str):
        raise InstallerError("admin_username must be a string")
    username = value.strip().lower()
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username):
        raise InstallerError("admin_username is not a safe Linux/application username")
    if username in RESERVED_ADMIN_USERS:
        raise InstallerError("admin_username is reserved: %s" % username)
    return username


def validate_ssh_username(value):
    if not isinstance(value, str):
        raise InstallerError("ssh_allowed_user must be a string")
    username = value.strip()
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username):
        raise InstallerError("ssh_allowed_user is not a safe Linux username")
    if username in RESERVED_ADMIN_USERS:
        raise InstallerError("ssh_allowed_user must be an existing non-root administrator")
    return username


def validate_contact_email(value, field_name):
    if not isinstance(value, str):
        raise InstallerError("%s must be a string" % field_name)
    candidate = value.strip()
    if len(candidate) > 254 or "\n" in candidate or "\r" in candidate:
        raise InstallerError("%s is invalid" % field_name)
    display_name, address = email.utils.parseaddr(candidate)
    if display_name or address != candidate or address.count("@") != 1:
        raise InstallerError("%s must be one plain email address" % field_name)
    local_part, domain = address.rsplit("@", 1)
    if not local_part or len(local_part) > 64:
        raise InstallerError("%s has an invalid local part" % field_name)
    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local_part):
        raise InstallerError("%s has an invalid local part" % field_name)
    normalized_domain = validate_fqdn(domain, "%s domain" % field_name)
    return "%s@%s" % (local_part, normalized_domain)


def validate_admin_email(value):
    return validate_contact_email(value, "admin_email")


def validate_acme_email(value):
    return validate_contact_email(value, "acme_email")


def validate_firewall_mode(value):
    candidate = str(value or "infrastructure").strip().lower()
    if candidate not in ("infrastructure", "installer"):
        raise InstallerError("firewall_mode must be infrastructure or installer")
    return candidate


def available_timezones():
    """Return canonical IANA timezone choices without accepting free-form paths."""
    try:
        names = zoneinfo.available_timezones()
    except (OSError, RuntimeError) as exc:
        raise InstallerError("Could not load the host IANA timezone database: %s" % exc)
    safe = sorted(
        name
        for name in names
        if name
        and not name.startswith(("posix/", "right/"))
        and ".." not in name
        and not name.startswith("/")
    )
    if "Etc/UTC" not in safe:
        raise InstallerError("The host timezone database does not contain Etc/UTC")
    return tuple(safe)


def validate_timezone(value, choices=None):
    candidate = str(value or "Etc/UTC").strip()
    allowed = set(available_timezones() if choices is None else choices)
    if candidate not in allowed:
        raise InstallerError("timezone must be selected from the host IANA timezone list")
    return candidate


def validate_ntp_server(value):
    if not isinstance(value, str):
        raise InstallerError("Every NTP server must be a string")
    candidate = value.strip().rstrip(".").lower()
    if not candidate or len(candidate) > 253 or any(ch.isspace() for ch in candidate):
        raise InstallerError("NTP server is invalid")
    with contextlib.suppress(ValueError):
        address = ipaddress.ip_address(candidate)
        if address.is_unspecified or address.is_multicast:
            raise InstallerError("NTP server address is unusable: %s" % candidate)
        return str(address)
    return validate_fqdn(candidate, "NTP server")


def validate_ntp_settings(mode, servers):
    normalized_mode = str(mode or "automatic").strip().lower()
    if normalized_mode not in ("automatic", "custom"):
        raise InstallerError("ntp_mode must be automatic or custom")
    if servers is None:
        values = []
    elif isinstance(servers, str):
        values = [item.strip() for item in servers.split(",") if item.strip()]
    elif isinstance(servers, list):
        values = servers
    else:
        raise InstallerError("ntp_servers must be a JSON list or comma-separated string")
    normalized = []
    for value in values:
        server = validate_ntp_server(value)
        if server not in normalized:
            normalized.append(server)
    if len(normalized) > 4:
        raise InstallerError("At most four NTP servers are supported")
    if normalized_mode == "automatic" and normalized:
        raise InstallerError("ntp_servers must be empty when ntp_mode is automatic")
    if normalized_mode == "custom" and not normalized:
        raise InstallerError("Custom NTP mode requires at least one NTP server")
    return normalized_mode, normalized


def _https_ipv4_fetch(url, timeout=8):
    if not str(url).startswith("https://"):
        raise InstallerError("Public IPv4 discovery sources must use HTTPS")
    curl = shutil.which("curl")
    if curl is None:
        raise InstallerError("curl is unavailable for forced-IPv4 HTTPS discovery")
    try:
        completed = subprocess.run(
            [
                curl,
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--tlsv1.2",
                "--ipv4",
                "--connect-timeout",
                "5",
                "--max-time",
                str(timeout),
                "--user-agent",
                "Vivolution-Installer/%s" % INSTALLER_VERSION,
                url,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout + 2,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        raise InstallerError("HTTPS request failed: %s" % exc)
    if completed.returncode != 0:
        raise InstallerError("HTTPS IPv4 discovery request failed")
    payload = completed.stdout
    if len(payload) > 64:
        raise InstallerError("Public IPv4 discovery returned an oversized response")
    try:
        rendered = payload.decode("ascii").strip()
    except UnicodeDecodeError:
        raise InstallerError("Public IPv4 discovery returned non-ASCII data")
    return validate_public_ipv4(rendered, "discovered public IPv4")


def discover_public_ipv4(fetcher=_https_ipv4_fetch, sources=PUBLIC_IPV4_SOURCES):
    """Best-effort multi-source discovery; never treats one echo service as truth."""
    observations = []
    errors = []
    for source in sources:
        try:
            address = validate_public_ipv4(fetcher(source), "discovered public IPv4")
            observations.append({"source": source, "address": address})
        except (InstallerError, OSError, ValueError) as exc:
            errors.append({"source": source, "error": str(exc)})
    counts = {}
    for observation in observations:
        counts[observation["address"]] = counts.get(observation["address"], 0) + 1
    address = None
    if counts:
        ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        if len(ranked) == 1 or ranked[0][1] > ranked[1][1]:
            address = ranked[0][0]
    return {
        "address": address,
        "confirmed_by": counts.get(address, 0) if address else 0,
        "observations": observations,
        "errors": errors,
        "disagreement": len(counts) > 1,
    }


def validate_answers(raw_answers, environment=None):
    if not isinstance(raw_answers, dict):
        raise InstallerError("Answers must be a JSON object")
    unknown = sorted(set(raw_answers) - ANSWER_KEYS)
    if unknown:
        raise InstallerError("Unknown answer keys: %s" % ", ".join(unknown))
    missing = sorted(REQUIRED_ANSWER_KEYS - set(raw_answers))
    if missing:
        raise InstallerError("Missing answer keys: %s" % ", ".join(missing))
    mode = str(raw_answers.get("deployment_mode", "")).strip().lower()
    if mode != "standalone":
        raise InstallerError(
            "Only Create a new Controller Plane is implemented; mode '%s' is unavailable"
            % (mode or "missing")
        )
    ssh_user_value = raw_answers.get("ssh_allowed_user")
    if not ssh_user_value:
        environment = os.environ if environment is None else environment
        ssh_user_value = environment.get("SUDO_USER")
    if not ssh_user_value:
        raise InstallerError(
            "ssh_allowed_user is required when a non-root SUDO_USER cannot be detected"
        )
    raw_firewall_mode = raw_answers.get("firewall_mode")
    if raw_firewall_mode is None:
        # Compatibility for validated answer files created before schema 5.
        raw_firewall_mode = (
            "installer" if raw_answers.get("ssh_source_cidrs") else "infrastructure"
        )
    firewall_mode = validate_firewall_mode(raw_firewall_mode)
    if firewall_mode == "installer":
        ssh_cidrs = validate_ssh_cidrs(raw_answers.get("ssh_source_cidrs"))
    else:
        raw_cidrs = raw_answers.get("ssh_source_cidrs")
        if raw_cidrs not in (None, "", []):
            raise InstallerError(
                "ssh_source_cidrs must be empty when firewall_mode is infrastructure"
            )
        ssh_cidrs = []
    active_client = current_ssh_client_cidr(environment=environment)
    if (
        firewall_mode == "installer"
        and active_client is not None
        and active_client not in ssh_cidrs
    ):
        ssh_cidrs = validate_ssh_cidrs(ssh_cidrs + [active_client])
    node_fqdn = validate_fqdn(raw_answers["node_fqdn"], "node_fqdn")
    shared_fqdn = validate_fqdn(raw_answers["shared_fqdn"], "shared_fqdn")
    if node_fqdn == shared_fqdn:
        raise InstallerError("node_fqdn and shared_fqdn must be different DNS names")
    admin_email = validate_admin_email(raw_answers["admin_email"])
    acme_email = validate_acme_email(raw_answers.get("acme_email") or admin_email)
    ntp_mode, ntp_servers = validate_ntp_settings(
        raw_answers.get("ntp_mode"), raw_answers.get("ntp_servers")
    )
    return {
        "deployment_mode": "standalone",
        "node_fqdn": node_fqdn,
        "shared_fqdn": shared_fqdn,
        "public_ipv4": validate_public_ipv4(raw_answers["public_ipv4"]),
        "ssh_source_cidrs": ssh_cidrs,
        "firewall_mode": firewall_mode,
        "timezone": validate_timezone(raw_answers.get("timezone") or "Etc/UTC"),
        "ntp_mode": ntp_mode,
        "ntp_servers": ntp_servers,
        "admin_username": validate_admin_username(raw_answers["admin_username"]),
        "admin_email": admin_email,
        "acme_email": acme_email,
        "ssh_allowed_user": validate_ssh_username(ssh_user_value),
    }


def _numbered_select(title, options, input_function=input, output_function=print):
    output_function(title)
    for index, option in enumerate(options, start=1):
        enabled = option[2] if len(option) == 3 else True
        suffix = "" if enabled else " (not yet available)"
        output_function("  %d. %s%s" % (index, option[1], suffix))
    while True:
        response = input_function("Select an option by number: ").strip()
        try:
            index = int(response) - 1
        except ValueError:
            output_function("Enter one of the displayed option numbers.")
            continue
        if index < 0 or index >= len(options):
            output_function("Enter one of the displayed option numbers.")
            continue
        option = options[index]
        enabled = option[2] if len(option) == 3 else True
        if not enabled:
            output_function(
                "%s is reserved for a future reviewed release; no action was taken."
                % option[1]
            )
            continue
        return option[0]


def _next_enabled_index(options, selected, direction):
    if direction not in (-1, 1):
        raise InstallerError("Menu movement direction must be -1 or 1")
    candidate = selected
    for _unused in range(len(options)):
        candidate = (candidate + direction) % len(options)
        option = options[candidate]
        if len(option) < 3 or option[2]:
            return candidate
    raise InstallerError("Menu does not contain an enabled option")


def _tty_arrow_select(title, options, input_stream, output_stream):
    """Dependency-free Up/Down selector used only with a controlling TTY."""
    import termios
    import tty

    selected = next(
        (index for index, option in enumerate(options) if len(option) < 3 or option[2]),
        0,
    )
    descriptor = input_stream.fileno()
    old_settings = termios.tcgetattr(descriptor)
    drawn = False
    output_stream.write("%s\n" % title)
    try:
        tty.setraw(descriptor)
        while True:
            if drawn:
                output_stream.write("\x1b[%dA" % len(options))
            drawn = True
            for index, option in enumerate(options):
                enabled = option[2] if len(option) == 3 else True
                marker = "\u203a" if index == selected else " "
                suffix = "" if enabled else " (not yet available)"
                output_stream.write("\x1b[2K%s %s%s\r\n" % (marker, option[1], suffix))
            output_stream.flush()
            key = input_stream.read(1)
            if key in ("\r", "\n"):
                option = options[selected]
                if len(option) < 3 or option[2]:
                    output_stream.write("\r\n")
                    output_stream.flush()
                    return option[0]
            elif key == "\x03":
                raise KeyboardInterrupt
            elif key == "\x1b":
                sequence = input_stream.read(2)
                if sequence == "[A":
                    selected = _next_enabled_index(options, selected, -1)
                elif sequence == "[B":
                    selected = _next_enabled_index(options, selected, 1)
    finally:
        termios.tcsetattr(descriptor, termios.TCSADRAIN, old_settings)


def select_option(
    title,
    options,
    input_function=input,
    output_function=print,
    input_stream=None,
    output_stream=None,
):
    input_stream = sys.stdin if input_stream is None else input_stream
    output_stream = sys.stdout if output_stream is None else output_stream
    can_use_arrow = (
        input_function is input
        and output_function is print
        and hasattr(input_stream, "isatty")
        and hasattr(output_stream, "isatty")
        and input_stream.isatty()
        and output_stream.isatty()
    )
    if can_use_arrow:
        try:
            return _tty_arrow_select(title, options, input_stream, output_stream)
        except (ImportError, OSError, RuntimeError):
            pass
    return _numbered_select(title, options, input_function, output_function)


def select_installer_action(input_function=input, output_function=print):
    return select_option(
        "Vivolution Turnkey Installer",
        MENU_OPTIONS,
        input_function=input_function,
        output_function=output_function,
    )


def select_manage_action(paths, input_function=input, output_function=print):
    status = installer_status(paths)
    current = status.get("status")
    has_schema5 = paths.ledger.exists()
    incomplete = current in ("pending", "running", "failed")
    complete = current == "complete"
    legacy = current == "legacy-state-detected"
    return select_option(
        "Manage an existing Vivolution installation",
        (
            ("status", "Show installer status", True),
            ("support-bundle", "Create a redacted support bundle", has_schema5),
            ("resume", "Resume an incomplete installation", has_schema5 and incomplete),
            ("reconcile", "Reconcile a completed installation", has_schema5 and complete),
            (
                "discard-incomplete",
                "Discard proven pre-mutation incomplete installer state",
                has_schema5 and incomplete,
            ),
            (
                "preview-legacy-cleanup",
                "Preview recognized legacy rc3-rc5 cleanup (deletion unavailable)",
                legacy,
            ),
        ),
        input_function=input_function,
        output_function=output_function,
    )


def select_timezone(input_function=input, output_function=print, choices=None):
    zones = tuple(available_timezones() if choices is None else choices)
    regions = {}
    for zone in zones:
        region = zone.split("/", 1)[0] if "/" in zone else "Other"
        regions.setdefault(region, []).append(zone)
    region_options = []
    if "Etc/UTC" in zones:
        region_options.append(("__utc__", "Etc/UTC (recommended)", True))
    for region in sorted(regions):
        region_options.append((region, region, True))
    selected_region = select_option(
        "Select the host timezone region (application timestamps remain UTC):",
        region_options,
        input_function=input_function,
        output_function=output_function,
    )
    if selected_region == "__utc__":
        return "Etc/UTC"
    region_zones = sorted(regions[selected_region])
    return select_option(
        "Select a canonical IANA timezone from %s:" % selected_region,
        [(zone, zone, True) for zone in region_zones],
        input_function=input_function,
        output_function=output_function,
    )


def prompt_answers(
    input_function=input,
    output_function=print,
    environment=None,
    public_ip_discoverer=discover_public_ipv4,
    timezone_selector=select_timezone,
):
    environment = os.environ if environment is None else environment
    output_function("Vivolution Controller Plane installer")
    output_function(
        "This release creates a new standalone Controller Plane. "
        "Controller joining and Edge voice deployment are not implemented.\n"
    )
    detected_ssh_user = environment.get("SUDO_USER", "").strip() or None
    detected_ssh_cidr = current_ssh_client_cidr(environment=environment)
    collected = {"deployment_mode": "standalone"}
    for key, label in (
        ("node_fqdn", "This controller's public FQDN"),
        ("shared_fqdn", "Shared controller web FQDN"),
    ):
        collected[key] = input_function("%s: " % label).strip()

    discovery = public_ip_discoverer()
    discovered = discovery.get("address") if isinstance(discovery, dict) else None
    if discovered:
        output_function(
            "Detected outbound public IPv4 %s (%d agreeing HTTPS source%s)."
            % (
                discovered,
                discovery.get("confirmed_by", 0),
                "" if discovery.get("confirmed_by", 0) == 1 else "s",
            )
        )
        if discovery.get("disagreement"):
            output_function(
                "Warning: public-IP services disagreed; the displayed address is only "
                "the majority observation. Confirm the actual inbound NAT/load-balancer "
                "IPv4 before continuing."
            )
        use_detected = input_function(
            "Use %s as this controller's inbound public IPv4? [Y/n]: " % discovered
        ).strip().lower()
        if use_detected in ("", "y", "yes"):
            collected["public_ipv4"] = discovered
    if "public_ipv4" not in collected:
        if isinstance(discovery, dict) and discovery.get("disagreement"):
            output_function(
                "Public-IP services disagreed. Enter the inbound/NAT/load-balancer IPv4 manually."
            )
        elif not discovered:
            output_function(
                "Public IPv4 could not be discovered. Outbound HTTPS is required for "
                "installation; enter the inbound address manually."
            )
            output_function(
                "Required outbound network access: TCP 80/443, UDP/TCP 53 (DNS), "
                "and UDP 123 (NTP). No inbound NTP port is required."
            )
        while True:
            candidate = input_function("This controller's public IPv4: ").strip()
            try:
                collected["public_ipv4"] = validate_public_ipv4(candidate)
                break
            except InstallerError as exc:
                output_function("Invalid public IPv4: %s" % exc)

    collected["firewall_mode"] = select_option(
        "Select firewall ownership:",
        (
            (
                "infrastructure",
                "Infrastructure-managed (installer does not modify UFW)",
                True,
            ),
            (
                "installer",
                "Installer-managed (UFW deny-by-default; SSH restricted to /32s)",
                True,
            ),
        ),
        input_function=input_function,
        output_function=output_function,
    )
    collected["ssh_source_cidrs"] = []
    if collected["firewall_mode"] == "installer":
        while True:
            suffix = " [%s]" % detected_ssh_cidr if detected_ssh_cidr else ""
            candidate = input_function(
                "Allowed administrator SSH /32 CIDRs (comma separated)%s: " % suffix
            ).strip() or detected_ssh_cidr
            try:
                ssh_cidrs = validate_ssh_cidrs(candidate)
                if detected_ssh_cidr and detected_ssh_cidr not in ssh_cidrs:
                    ssh_cidrs = validate_ssh_cidrs(ssh_cidrs + [detected_ssh_cidr])
                collected["ssh_source_cidrs"] = ssh_cidrs
                break
            except InstallerError as exc:
                output_function("Invalid SSH source restriction: %s" % exc)
                if not detected_ssh_cidr:
                    output_function(
                        "Enter exact administrator IPv4 /32 addresses; "
                        "0.0.0.0/0 is intentionally refused."
                    )

    admin_response = input_function("Initial web administrator username [cpadmin]: ").strip()
    collected["admin_username"] = admin_response or "cpadmin"
    collected["admin_email"] = input_function("Initial web administrator email: ").strip()
    acme_response = input_function(
        "Let's Encrypt ACME contact email [%s]: " % collected["admin_email"]
    ).strip()
    collected["acme_email"] = acme_response or collected["admin_email"]
    ssh_suffix = " [%s]" % detected_ssh_user if detected_ssh_user else ""
    ssh_response = input_function(
        "Existing non-root Linux SSH administrator%s: " % ssh_suffix
    ).strip()
    collected["ssh_allowed_user"] = ssh_response or detected_ssh_user

    collected["timezone"] = timezone_selector(
        input_function=input_function, output_function=output_function
    )
    collected["ntp_mode"] = select_option(
        "Select time synchronization source mode:",
        (
            ("automatic", "Automatic / Ubuntu or provider defaults", True),
            ("custom", "Custom NTP servers", True),
        ),
        input_function=input_function,
        output_function=output_function,
    )
    collected["ntp_servers"] = []
    if collected["ntp_mode"] == "custom":
        while True:
            primary = input_function("NTP server 1: ").strip()
            secondary = input_function("NTP server 2 (optional): ").strip()
            try:
                _mode, servers = validate_ntp_settings(
                    "custom", [item for item in (primary, secondary) if item]
                )
                collected["ntp_servers"] = servers
                break
            except InstallerError as exc:
                output_function("Invalid NTP configuration: %s" % exc)
    return validate_answers(collected, environment=environment)


def load_answers(answer_file=None, input_function=input):
    if answer_file is None:
        return prompt_answers(input_function=input_function)
    return validate_answers(read_json_file(Path(answer_file)))


def configuration_summary_lines(answers):
    """Return the fixed, non-secret fields shown before host mutation."""
    answers = validate_answers(answers)
    return (
        "Action: Create a new Controller Plane",
        "Node FQDN: %s" % answers["node_fqdn"],
        "Shared FQDN: %s" % answers["shared_fqdn"],
        "Public IPv4: %s" % answers["public_ipv4"],
        "SSH administrator: %s" % answers["ssh_allowed_user"],
        "Firewall ownership: %s" % answers["firewall_mode"],
        "SSH source /32s: %s"
        % (", ".join(answers["ssh_source_cidrs"]) or "infrastructure-managed"),
        "Timezone: %s" % answers["timezone"],
        "NTP mode: %s" % answers["ntp_mode"],
        "NTP servers: %s"
        % (", ".join(answers["ntp_servers"]) or "Ubuntu/provider defaults"),
        "Web administrator: %s" % answers["admin_username"],
        "Web administrator email: %s" % answers["admin_email"],
        "Let's Encrypt ACME email: %s" % answers["acme_email"],
        "ACME directory: %s" % LETS_ENCRYPT_PRODUCTION_DIRECTORY,
        "Inbound: TCP 22 (firewall-owner policy), TCP 80/443 (public)",
        "Outbound: TCP 80/443, UDP/TCP 53, UDP 123",
        "Never expose publicly: TCP 5432, 6432, 8000",
    )


def validate_answer_dns(answers, resolver=socket.getaddrinfo):
    """Require both public names to resolve only to the declared IPv4."""
    answers = validate_answers(answers)
    expected = answers["public_ipv4"]
    resolved_by_name = {}
    for key in ("node_fqdn", "shared_fqdn"):
        name = answers[key]
        try:
            results = resolver(name, 443, socket.AF_INET, socket.SOCK_STREAM)
        except (OSError, socket.gaierror) as exc:
            raise InstallerError("IPv4 DNS lookup failed for %s: %s" % (name, exc))
        addresses = sorted(
            {
                item[4][0]
                for item in results
                if len(item) >= 5 and item[4] and item[4][0]
            }
        )
        if addresses != [expected]:
            rendered = ", ".join(addresses) if addresses else "no IPv4 addresses"
            raise InstallerError(
                "%s must resolve exclusively to declared public IPv4 %s; got %s"
                % (name, expected, rendered)
            )
        try:
            ipv6_results = resolver(name, 443, socket.AF_INET6, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            no_ipv6_errors = {
                code
                for code in (
                    getattr(socket, "EAI_NONAME", None),
                    getattr(socket, "EAI_NODATA", None),
                    getattr(socket, "EAI_ADDRFAMILY", None),
                )
                if code is not None
            }
            if exc.errno not in no_ipv6_errors:
                raise InstallerError("IPv6 DNS lookup failed for %s: %s" % (name, exc))
            ipv6_results = []
        except OSError as exc:
            raise InstallerError("IPv6 DNS lookup failed for %s: %s" % (name, exc))
        ipv6_addresses = sorted(
            {
                item[4][0].split("%", 1)[0]
                for item in ipv6_results
                if len(item) >= 5 and item[4] and item[4][0]
            }
        )
        if ipv6_addresses:
            raise InstallerError(
                "%s must not publish IPv6 AAAA records because this standalone "
                "installer exposes no IPv6 ingress; got %s"
                % (name, ", ".join(ipv6_addresses))
            )
        resolved_by_name[name] = addresses
    return resolved_by_name


def _edit_dns_answers(answers, input_function=input, output_function=print):
    updated = dict(validate_answers(answers))
    output_function("Enter only DNS hostnames, without http:// or https://.")
    for key, label in (
        ("node_fqdn", "This controller's public FQDN"),
        ("shared_fqdn", "Shared controller web FQDN"),
        ("public_ipv4", "Inbound public IPv4"),
    ):
        response = input_function("%s [%s]: " % (label, updated[key])).strip()
        if response:
            updated[key] = response
    return validate_answers(updated)


def flush_local_dns_cache(command_finder=shutil.which, runner=subprocess.run):
    """Best-effort flush of systemd-resolved's local cache before a retry."""
    resolvectl = command_finder("resolvectl")
    if resolvectl is None:
        return {"attempted": False, "success": False, "reason": "resolvectl unavailable"}
    try:
        completed = runner(
            [resolvectl, "flush-caches"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"attempted": True, "success": False, "reason": str(exc)}
    return {
        "attempted": True,
        "success": completed.returncode == 0,
        "exit_code": completed.returncode,
    }


def wait_for_answer_dns(
    answers,
    resolver=socket.getaddrinfo,
    interactive=True,
    input_function=input,
    output_function=print,
    auto_retry_delays=(0, 2, 5),
    sleep_function=time.sleep,
    cache_flusher=flush_local_dns_cache,
    answers_changed=None,
):
    """Validate DNS with bounded unattended retries and interactive recovery."""
    current = validate_answers(answers)

    def attempt():
        return validate_answer_dns(current, resolver=resolver)

    def refresh_cache():
        result = cache_flusher()
        if result.get("attempted") and result.get("success"):
            output_function("Flushed the local systemd-resolved DNS cache.")
        elif result.get("attempted"):
            output_function(
                "Warning: local DNS cache flush failed; continuing with resolver retry."
            )
        return result

    if not interactive:
        last_error = None
        for index, delay in enumerate(auto_retry_delays):
            if delay:
                sleep_function(delay)
            if index:
                refresh_cache()
            try:
                return current, attempt()
            except InstallerError as exc:
                last_error = exc
        raise InstallerError(
            "DNS validation did not pass after %d bounded attempts: %s"
            % (len(auto_retry_delays), last_error)
        )

    while True:
        try:
            return current, attempt()
        except InstallerError as exc:
            output_function("\nDNS validation is not ready: %s" % exc)
            for dns_name in (current["node_fqdn"], current["shared_fqdn"]):
                output_function(
                    "Propagation check for %s: "
                    "https://toolbox.googleapps.com/apps/dig/#A/%s"
                    % (dns_name, dns_name)
                )
        action = select_option(
            "DNS recovery options:",
            (
                ("retry", "Retry now", True),
                ("wait", "Wait and retry automatically (bounded)", True),
                ("change", "Change FQDN or public IPv4", True),
                ("exit", "Exit safely and resume later", True),
            ),
            input_function=input_function,
            output_function=output_function,
        )
        if action == "retry":
            refresh_cache()
            continue
        if action == "change":
            current = _edit_dns_answers(
                current,
                input_function=input_function,
                output_function=output_function,
            )
            if answers_changed is not None:
                # Persist the validated edit before the next resolver call or
                # a later safe exit, so `resume` never restores stale DNS data.
                answers_changed(dict(current))
            continue
        if action == "exit":
            raise InstallerError(
                "DNS validation was deferred; no host packages or services were changed. "
                "Create/correct the records and use resume."
            )
        last_error = None
        for delay in auto_retry_delays:
            if delay:
                output_function("Waiting %d seconds before DNS retry..." % delay)
                sleep_function(delay)
            refresh_cache()
            try:
                return current, attempt()
            except InstallerError as exc:
                last_error = exc
        output_function(
            "DNS is still not ready after %d attempts: %s"
            % (len(auto_retry_delays), last_error)
        )


def confirm_configuration(
    answers,
    answer_file=None,
    accept_configuration=False,
    input_function=input,
    output_stream=None,
):
    """Present validated configuration and require an explicit safe approval."""
    output_stream = sys.stdout if output_stream is None else output_stream
    output_stream.write("\nValidated Vivolution Controller configuration\n")
    for line in configuration_summary_lines(answers):
        output_stream.write("  %s\n" % line)
    output_stream.flush()
    if answer_file is not None:
        if not accept_configuration:
            raise InstallerError(
                "Unattended answer-file installation requires --accept-configuration"
            )
        return {"method": "answer-file-flag", "accepted": True}
    response = input_function(
        "\nType %s to install this configuration: " % CONFIRMATION_TOKEN
    ).strip()
    if response != CONFIRMATION_TOKEN:
        raise InstallerError(
            "Configuration was not confirmed; no packages or controller services were changed"
        )
    return {"method": "interactive-token", "accepted": True}


def generate_secrets():
    generated = {
        "cp_controller_admin_password": secrets.token_urlsafe(32),
        "cp_db_owner_password": secrets.token_urlsafe(48),
        "cp_db_runtime_password": secrets.token_urlsafe(48),
        "cp_django_secret_key": secrets.token_urlsafe(64),
        "cp_edge_enrollment_token_pepper": secrets.token_hex(32),
        "cp_rls_context_key": secrets.token_hex(32),
    }
    if set(generated) != SECRET_KEYS:
        raise InstallerError("Internal secret schema mismatch")
    return generated


def validate_secrets(secret_values):
    if not isinstance(secret_values, dict) or set(secret_values) != SECRET_KEYS:
        raise InstallerError("Protected installer secret file has an invalid schema")
    for key, value in secret_values.items():
        if not isinstance(value, str) or len(value) < 32 or len(value) > 128:
            raise InstallerError("Protected installer secret is invalid: %s" % key)
        if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise InstallerError("Protected installer secret has unsafe characters: %s" % key)
    if not re.fullmatch(r"[0-9a-f]{64}", secret_values["cp_rls_context_key"]):
        raise InstallerError("cp_rls_context_key must be exactly 64 lowercase hexadecimal characters")
    if not re.fullmatch(
        r"[0-9a-f]{64}", secret_values["cp_edge_enrollment_token_pepper"]
    ):
        raise InstallerError(
            "cp_edge_enrollment_token_pepper must be exactly 64 lowercase hexadecimal characters"
        )
    if secrets.compare_digest(
        secret_values["cp_edge_enrollment_token_pepper"],
        secret_values["cp_rls_context_key"],
    ):
        raise InstallerError("Enrollment and RLS keys must be independent")
    return secret_values


def controller_source_manifest(controller_dir):
    controller_dir = Path(controller_dir)
    if controller_dir.is_symlink() or not controller_dir.is_dir():
        raise InstallerError("Controller source directory is unsafe or missing: %s" % controller_dir)
    selected = []
    for relative in CONTROLLER_REQUIRED_FILES:
        path = controller_dir / relative
        if path.is_symlink() or not path.is_file():
            raise InstallerError("Unsafe or missing controller source: %s" % relative)
        selected.append(relative)
    for tree_name in ("core", "cp1"):
        tree = controller_dir / tree_name
        if tree.is_symlink() or not tree.is_dir():
            raise InstallerError("Controller source tree is unsafe or missing: %s" % tree_name)
        for root, directories, files in os.walk(str(tree), followlinks=False):
            root_path = Path(root)
            for directory in list(directories):
                candidate = root_path / directory
                if candidate.is_symlink():
                    raise InstallerError(
                        "Controller code trees must not contain symbolic links: %s"
                        % candidate.relative_to(controller_dir).as_posix()
                    )
            for filename in files:
                candidate = root_path / filename
                relative_path = candidate.relative_to(controller_dir)
                if candidate.is_symlink():
                    raise InstallerError(
                        "Controller code trees must not contain symbolic links: %s"
                        % relative_path.as_posix()
                    )
                parts = relative_path.parts
                if "__pycache__" in parts:
                    continue
                if filename.endswith((".pyc", ".pyo")) or filename == ".DS_Store":
                    continue
                if any(part.startswith(".") for part in parts[1:]):
                    continue
                if candidate.is_file():
                    selected.append(relative_path.as_posix())
    lines = []
    for relative in sorted(set(selected)):
        path = controller_dir / relative
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append("%s  %s\n" % (digest, relative))
    return "".join(lines).encode("utf-8")


def calculate_controller_release_id(controller_dir):
    manifest = controller_source_manifest(controller_dir)
    # Internal compatibility identifier; never presented as hostname guidance.
    return "cp1-%s" % hashlib.sha256(manifest).hexdigest()


def parse_controller_base_image(controller_dir):
    containerfile = Path(controller_dir) / "Containerfile"
    if containerfile.is_symlink() or not containerfile.is_file():
        raise InstallerError("Controller Containerfile is unsafe or missing")
    pattern = re.compile(
        r"^(?i:FROM)[ \t]+([A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64})"
        r"(?:[ \t]+(?i:AS)[ \t]+[A-Za-z0-9_.-]+)?[ \t]*$",
    )
    try:
        lines = containerfile.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise InstallerError("Could not read Containerfile: %s" % exc)
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.upper().startswith("FROM "):
            match = pattern.fullmatch(stripped)
            if not match:
                raise InstallerError("Controller base image must be pinned by an immutable sha256 digest")
            return match.group(1)
    raise InstallerError("Controller Containerfile does not contain a FROM instruction")


class PhaseLedger:
    def __init__(self, path, value):
        self.path = Path(path)
        self.value = value

    @classmethod
    def create(cls, path, dry_run=False):
        now = utc_now()
        initial_run = {
            "run_number": 1,
            "kind": "install",
            "status": "running",
            "started_at": now,
            "correlation_id": str(uuid.uuid4()),
            "resumed_at": [],
        }
        value = {
            "schema_version": LEDGER_SCHEMA_VERSION,
            "installer_version": INSTALLER_VERSION,
            "installation_id": str(uuid.uuid4()),
            "deployment_mode": "standalone",
            "dry_run": bool(dry_run),
            "created_at": now,
            "updated_at": now,
            "status": "pending",
            "current_phase": None,
            "run_count": 1,
            "reconcile_count": 0,
            "runs": [initial_run],
            "phases": {phase: {"status": "pending"} for phase in PHASES},
        }
        ledger = cls(path, value)
        ledger.save()
        return ledger

    @classmethod
    def load(cls, path):
        value = read_json_file(path)
        if not isinstance(value, dict) or value.get("schema_version") != LEDGER_SCHEMA_VERSION:
            raise InstallerError("Installer ledger has an unsupported schema")
        if value.get("installer_version") != INSTALLER_VERSION:
            raise InstallerError(
                "Installer ledger belongs to a different installer version; use the exact "
                "version-pinned bootstrap that created this run"
            )
        phases = value.get("phases")
        if not isinstance(phases, dict) or set(phases) != set(PHASES):
            raise InstallerError("Installer ledger has an invalid phase set")
        runs = value.get("runs")
        if (
            not isinstance(runs, list)
            or not runs
            or value.get("run_count") != len(runs)
            or not isinstance(value.get("reconcile_count"), int)
        ):
            raise InstallerError("Installer ledger has an invalid run audit trail")
        return cls(path, value)

    def save(self):
        self.value["updated_at"] = utc_now()
        atomic_write_json(self.path, self.value)

    def completed(self, phase):
        return self.value["phases"][phase].get("status") == "completed"

    def start_phase(self, phase):
        previous = self.value["phases"].get(phase, {})
        attempt = int(previous.get("attempt", 0)) + 1
        self.value["status"] = "running"
        self.value["current_phase"] = phase
        self.value["phases"][phase] = {
            "status": "running",
            "started_at": utc_now(),
            "attempt": attempt,
        }
        self.save()

    def complete_phase(self, phase, details=None):
        record = self.value["phases"][phase]
        record["status"] = "completed"
        record["completed_at"] = utc_now()
        if details:
            record["details"] = details
        self.value["current_phase"] = None
        self.save()

    def fail_phase(self, phase, safe_error):
        record = self.value["phases"][phase]
        record["status"] = "failed"
        record["failed_at"] = utc_now()
        record["error"] = safe_error
        self.value["status"] = "failed"
        self.value["current_phase"] = phase
        active_run = self.value["runs"][-1]
        active_run["status"] = "failed"
        active_run["failed_at"] = utc_now()
        active_run["failed_phase"] = phase
        active_run.setdefault("failures", []).append(
            {"failed_at": active_run["failed_at"], "phase": phase, "error": safe_error}
        )
        self.save()

    def finish(self):
        self.value["status"] = "dry-run-complete" if self.value["dry_run"] else "complete"
        self.value["current_phase"] = None
        self.value["completed_at"] = utc_now()
        active_run = self.value["runs"][-1]
        active_run["status"] = self.value["status"]
        active_run["completed_at"] = self.value["completed_at"]
        if active_run.get("kind") == "reconcile":
            self.value["last_reconcile_completed_at"] = self.value["completed_at"]
        self.save()

    def mark_resumed(self):
        active_run = self.value["runs"][-1]
        active_run.setdefault("resumed_at", []).append(utc_now())
        active_run["status"] = "running"
        self.value["status"] = "running"
        self.save()

    def prepare_reconcile(self):
        if self.value.get("dry_run"):
            raise InstallerError("Reconcile is only available for a completed real installation")
        if self.value.get("status") != "complete":
            raise InstallerError("Reconcile requires completed state; use resume for incomplete or failed state")
        if any(not self.completed(phase) for phase in PHASES):
            raise InstallerError("Reconcile requires every installation phase to be complete; use resume")
        now = utc_now()
        self.value["run_count"] += 1
        self.value["reconcile_count"] += 1
        self.value["runs"].append(
            {
                "run_number": self.value["run_count"],
                "kind": "reconcile",
                "reconcile_number": self.value["reconcile_count"],
                "status": "running",
                "started_at": now,
                "correlation_id": str(uuid.uuid4()),
                "resumed_at": [],
            }
        )
        for phase in ("release", "ansible", "summary"):
            self.value["phases"][phase] = {"status": "pending"}
        self.value["status"] = "running"
        self.value["current_phase"] = None
        self.value["last_reconcile_started_at"] = now
        self.save()


def ownership_namespace_roots(paths):
    return [
        str(paths.state_dir),
        str(paths.log_dir),
        "/opt/vivolution",
        "/etc/vivolution",
        "/var/lib/vivolution",
        "/var/log/vivolution",
        "/var/cache/vivolution",
        "/run/vivolution",
    ]


def initialize_ownership_manifest(paths, ledger):
    value = {
        "schema_version": 1,
        "installation_id": ledger.value["installation_id"],
        "created_at": utc_now(),
        "state": "installing",
        # Namespace roots are documentation/placement boundaries, not a
        # recursive deletion allowlist. Lifecycle removal must consume only
        # exact, separately recorded object records.
        "namespace_roots": ownership_namespace_roots(paths),
        "system_integrations": [],
        "packages": {
            "requested": [],
            "preexisting": [],
            "installed_by_installer": [],
        },
        "tombstone_path": str(paths.tombstone),
    }
    atomic_write_json(paths.ownership, value)
    return value


def validate_pre_mutation_ownership_manifest(paths, ledger, ownership):
    """Fail closed unless ownership is the exact pristine schema-1 contract."""
    expected_keys = {
        "schema_version",
        "installation_id",
        "created_at",
        "state",
        "namespace_roots",
        "system_integrations",
        "packages",
        "tombstone_path",
    }
    if not isinstance(ownership, dict) or set(ownership) != expected_keys:
        raise InstallerError(
            "Discard refused an invalid pre-mutation ownership manifest shape"
        )
    if ownership["schema_version"] != 1:
        raise InstallerError("Discard refused an unexpected ownership manifest schema")
    if ownership["installation_id"] != ledger.get("installation_id"):
        raise InstallerError("Discard refused an ownership/ledger installation ID mismatch")
    if not isinstance(ownership["created_at"], str) or not ownership["created_at"]:
        raise InstallerError("Discard refused an invalid ownership creation timestamp")
    if ownership["state"] != "installing":
        raise InstallerError("Discard refused a non-pristine ownership lifecycle state")
    if ownership["namespace_roots"] != ownership_namespace_roots(paths):
        raise InstallerError("Discard refused mismatched ownership namespace roots")
    if ownership["tombstone_path"] != str(paths.tombstone):
        raise InstallerError("Discard refused a mismatched ownership tombstone path")
    if ownership["system_integrations"] != []:
        raise InstallerError("Discard refused ownership system-integration evidence")

    packages = ownership["packages"]
    expected_package_keys = {
        "requested",
        "preexisting",
        "installed_by_installer",
    }
    if not isinstance(packages, dict) or set(packages) != expected_package_keys:
        raise InstallerError("Discard refused an invalid ownership package manifest shape")
    for key in sorted(expected_package_keys):
        if not isinstance(packages[key], list) or packages[key]:
            raise InstallerError(
                "Discard refused ownership package mutation evidence in %s" % key
            )
    return ownership


def update_ownership_packages(paths, requested, preexisting=None, completed=False):
    if paths.ownership.exists():
        value = read_json_file(paths.ownership)
    else:
        raise InstallerError("Installer ownership manifest is missing")
    requested = sorted(set(requested))
    preexisting = sorted(set(preexisting or []))
    value["packages"] = {
        "requested": requested,
        "preexisting": preexisting,
        "installed_by_installer": (
            sorted(set(requested) - set(preexisting)) if completed else []
        ),
    }
    value["updated_at"] = utc_now()
    atomic_write_json(paths.ownership, value)
    return value


def update_ownership_state(paths, state):
    value = read_json_file(paths.ownership)
    value["state"] = str(state)
    value["updated_at"] = utc_now()
    atomic_write_json(paths.ownership, value)
    return value


def query_preexisting_packages(packages, runner=subprocess.run, log=None):
    installed = []
    for package in packages:
        command = [
            "dpkg-query",
            "--show",
            "--showformat=${db:Status-Status}",
            package,
        ]
        if log is not None:
            log.event(
                "command_started",
                level="INFO",
                category="command",
                command=command,
                purpose="preexisting-package-state",
            )
        try:
            completed = runner(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise InstallerError("Could not inspect pre-existing package state: %s" % exc)
        if log is not None:
            log.event(
                "command_completed",
                level="INFO" if completed.returncode in (0, 1) else "ERROR",
                category="command",
                command=command,
                purpose="preexisting-package-state",
                exit_code=completed.returncode,
            )
        if completed.returncode == 0 and (completed.stdout or "").strip() == "installed":
            installed.append(package)
        elif completed.returncode not in (0, 1):
            raise InstallerError(
                "Could not inspect pre-existing package state for %s" % package
            )
    return installed


def detect_legacy_state(paths):
    """Read-only detection for rc3-rc5 schema-4 state at the old locations."""
    if not paths.legacy_state_dir.exists() and not paths.legacy_log_dir.exists():
        return None
    if paths.legacy_state_dir.is_symlink() or paths.legacy_log_dir.is_symlink():
        raise InstallerError("Legacy installer paths must not be symbolic links")
    result = {
        "state_dir": str(paths.legacy_state_dir),
        "log_dir": str(paths.legacy_log_dir),
        "ledger": str(paths.legacy_ledger),
        "schema_version": None,
        "status": "unknown",
    }
    if paths.legacy_ledger.exists():
        value = read_json_file(paths.legacy_ledger)
        if not isinstance(value, dict) or value.get("schema_version") != 4:
            raise InstallerError(
                "Legacy installer state exists but is not a recognized rc3-rc5 schema-4 ledger"
            )
        result.update(
            schema_version=4,
            status=value.get("status", "unknown"),
            installation_id=value.get("installation_id"),
            current_phase=value.get("current_phase"),
            phases={
                key: item.get("status")
                for key, item in value.get("phases", {}).items()
                if isinstance(item, dict)
            },
        )
    return result


def _safe_glob_exists(parent, pattern):
    if not parent.exists():
        return False
    return any(parent.glob(pattern))


def parse_listener_owners(output):
    """Parse ``ss -H -ltnp`` output into a port-to-owner mapping."""
    listeners = {}
    for raw_line in str(output).splitlines():
        line = raw_line.strip()
        if not line:
            continue
        fields = line.split(None, 5)
        if len(fields) < 5:
            raise InstallerError("Could not parse the host TCP listener inventory")
        local_endpoint = fields[3]
        port_text = local_endpoint.rsplit(":", 1)[-1]
        try:
            port = int(port_text)
        except ValueError:
            raise InstallerError("Could not parse the host TCP listener inventory")
        owner = fields[5] if len(fields) == 6 else ""
        listeners.setdefault(port, []).append(owner)
    return listeners


def _read_only_command(command, runner=subprocess.run):
    try:
        completed = runner(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallerError("Read-only preflight command failed: %s" % exc)
    if completed.returncode != 0:
        raise InstallerError(
            "Read-only preflight command exited %d: %s"
            % (completed.returncode, Path(command[0]).name)
        )
    return completed.stdout or ""


def run_runtime_preflight(paths, runner=subprocess.run, command_finder=shutil.which):
    """Check reboot/listener safety and record initial clock state read-only."""
    reboot_marker = paths.host_path("/var/run/reboot-required")
    if reboot_marker.exists() or reboot_marker.is_symlink():
        raise InstallerError(
            "Ubuntu reports a pending reboot; reboot the VM before running the installer"
        )
    timedatectl = command_finder("timedatectl")
    ss_command = command_finder("ss")
    if timedatectl is None or ss_command is None:
        missing = "timedatectl" if timedatectl is None else "ss"
        raise InstallerError("Required read-only preflight command is missing: %s" % missing)
    clock_output = _read_only_command(
        [
            timedatectl,
            "show",
            "--property=NTP",
            "--property=NTPSynchronized",
            "--no-pager",
        ],
        runner=runner,
    )
    clock_values = {}
    for line in clock_output.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            clock_values[key.strip()] = value.strip().lower()
    listener_output = _read_only_command(
        [ss_command, "-H", "-ltnp"], runner=runner
    )
    listeners = parse_listener_owners(listener_output)
    reserved = (80, 443, 5432, 6432, 8000)
    occupied = [port for port in reserved if listeners.get(port)]
    if occupied:
        raise InstallerError(
            "Fresh-host preflight found existing TCP listeners on reserved ports: %s"
            % ", ".join(str(port) for port in occupied)
        )
    ssh_owners = listeners.get(22, [])
    if ssh_owners and any(
        re.search(r"(?<![A-Za-z0-9_-])sshd(?![A-Za-z0-9_-])", owner) is None
        for owner in ssh_owners
    ):
        raise InstallerError("TCP port 22 is listening but is not exclusively owned by sshd")
    return {
        "clock_ntp_enabled": clock_values.get("NTP") == "yes",
        "clock_synchronized": clock_values.get("NTPSynchronized") == "yes",
        "pending_reboot": False,
        "reserved_tcp_ports_free": list(reserved),
        "ssh_listener_verified": bool(ssh_owners),
    }


def validate_host_os(paths):
    os_release = parse_os_release(paths.host_path("/etc/os-release"))
    if os_release.get("ID", "").lower() != SUPPORTED_OS_ID:
        raise InstallerError("Only Ubuntu Server is supported")
    if os_release.get("VERSION_ID") != SUPPORTED_OS_VERSION:
        raise InstallerError("Only Ubuntu Server 24.04 LTS is supported")
    return {
        "os_id": os_release.get("ID"),
        "os_version": os_release.get("VERSION_ID"),
    }


def run_preflight(paths, runner=subprocess.run, command_finder=shutil.which):
    if paths.root == Path("/") and os.geteuid() != 0:
        raise InstallerError("Run the installer as root (for example, sudo ./install.sh)")
    os_identity = validate_host_os(paths)
    if paths.root == Path("/") and not paths.host_path("/run/systemd/system").is_dir():
        raise InstallerError("The target must be booted with systemd")
    markers = (
        paths.host_path("/etc/vivolution/installation-owner"),
        paths.host_path("/var/lib/vivolution/controller"),
        paths.host_path("/etc/containers/systemd/vivolution-cp-web.container"),
    )
    found = [str(path) for path in markers if path.exists() or path.is_symlink()]
    systemd_dir = paths.host_path("/etc/systemd/system")
    if _safe_glob_exists(systemd_dir, "vivolution-*.service"):
        found.append(str(systemd_dir / "vivolution-*.service"))
    if found:
        raise InstallerError(
            "Fresh-host preflight found an existing Vivolution installation: %s"
            % ", ".join(found)
        )
    effective_uid, effective_user = effective_process_identity()
    result = {
        **os_identity,
        "architecture": platform.machine(),
        "effective_uid": effective_uid,
        "effective_user": effective_user,
    }
    if paths.root == Path("/"):
        result.update(
            run_runtime_preflight(
                paths, runner=runner, command_finder=command_finder
            )
        )
    return result


def bootstrap_packages_for_answers(answers):
    normalized = validate_answers(answers)
    packages = list(BASE_BOOTSTRAP_PACKAGES)
    if normalized["firewall_mode"] == "installer":
        packages.extend(INSTALLER_FIREWALL_PACKAGES)
    return tuple(packages)


def bootstrap_commands(apt_get, packages=BOOTSTRAP_PACKAGES):
    """Return the bounded apt operations used by the bootstrap phase."""
    return [
        [apt_get, "update"],
        [
            apt_get,
            "install",
            "--yes",
            "--no-install-recommends",
        ]
        + list(packages),
    ]


def run_bootstrap(
    log,
    runner=subprocess.Popen,
    apt_get="apt-get",
    packages=BOOTSTRAP_PACKAGES,
    verbose=False,
    console_stream=None,
):
    """Install prerequisites while streaming redacted apt output durably."""
    if os.path.sep in apt_get:
        executable = Path(apt_get)
        if not executable.is_file() or not os.access(str(executable), os.X_OK):
            raise InstallerError("apt-get executable is unavailable: %s" % executable)
        resolved_apt = str(executable)
    else:
        resolved_apt = shutil.which(apt_get)
        if resolved_apt is None:
            raise InstallerError("Required command is missing: %s" % apt_get)
    environment = os.environ.copy()
    environment["DEBIAN_FRONTEND"] = "noninteractive"
    environment["APT_LISTCHANGES_FRONTEND"] = "none"
    for command in bootstrap_commands(resolved_apt, packages=packages):
        log.info("Bootstrap command: %s" % " ".join(command))
        log.event("bootstrap_command_started", command=command)
        return_code = run_streamed_command(
            command,
            log,
            "apt",
            runner=runner,
            console_stream=console_stream,
            show_output=verbose,
            env=environment,
        )
        if return_code != 0:
            raise InstallerError(
                "Bootstrap command failed with exit code %d: %s"
                % (return_code, " ".join(command[:2]))
            )
        log.event("bootstrap_command_completed", command=command, exit_code=0)
    return {"packages": list(packages), "result": "completed"}


def resolve_source_path(source_root, candidate):
    path = Path(candidate)
    if not path.is_absolute():
        path = Path(source_root) / path
    return path.resolve()


def build_inventory(ssh_allowed_user):
    return {
        "all": {
            "children": {
                "controllers": {
                    "hosts": {
                        "localhost": {
                            "ansible_connection": "local",
                            "ansible_python_interpreter": "/usr/bin/python3",
                            "ansible_user": ssh_allowed_user,
                        }
                    }
                }
            }
        }
    }


def build_ansible_vars(answers, secret_values, release_id, controller_base_image):
    allowed_hosts = []
    for host in ("127.0.0.1", "localhost", answers["node_fqdn"], answers["shared_fqdn"]):
        if host not in allowed_hosts:
            allowed_hosts.append(host)
    csrf_origins = []
    for host in (answers["node_fqdn"], answers["shared_fqdn"]):
        origin = "https://%s" % host
        if origin not in csrf_origins:
            csrf_origins.append(origin)
    values = {
        "vivo_installer_schema_version": LEDGER_SCHEMA_VERSION,
        "cp_deployment_mode": "standalone",
        "cp_profile": "ubuntu-standalone",
        "cp_expected_hostname": answers["node_fqdn"].split(".", 1)[0],
        "cp_node_fqdn": answers["node_fqdn"],
        "cp_shared_fqdn": answers["shared_fqdn"],
        "cp_public_ipv4": answers["public_ipv4"],
        "cp_firewall_ssh_source_ipv4_cidrs": answers["ssh_source_cidrs"],
        "cp_firewall_mode": answers["firewall_mode"],
        "cp_timezone": answers["timezone"],
        "cp_ntp_mode": answers["ntp_mode"],
        "cp_ntp_servers": answers["ntp_servers"],
        "cp_ssh_allowed_user": answers["ssh_allowed_user"],
        "cp_controller_admin_username": answers["admin_username"],
        "cp_controller_admin_email": answers["admin_email"],
        "cp_acme_email": answers["acme_email"],
        "cp_controller_release_id": release_id,
        "cp_controller_base_image": controller_base_image,
        "cp_ingress_server_name": answers["shared_fqdn"],
        "cp_controller_allowed_hosts": ",".join(allowed_hosts),
        "cp_controller_csrf_origins": ",".join(csrf_origins),
        "cp_install_local_postgres": True,
    }
    values.update(secret_values)
    return values


class InstallerEngine:
    def __init__(
        self,
        paths,
        source_root,
        playbook=DEFAULT_PLAYBOOK,
        ansible_config=DEFAULT_ANSIBLE_CONFIG,
        ansible_playbook="ansible-playbook",
        answer_file=None,
        accept_configuration=False,
        dry_run=False,
        input_function=input,
        output_stream=None,
        runner=subprocess.Popen,
        bootstrap_runner=subprocess.Popen,
        dns_resolver=socket.getaddrinfo,
        apt_get="apt-get",
        verbose=False,
    ):
        self.paths = paths
        self.source_root = Path(source_root).resolve()
        self.playbook = resolve_source_path(self.source_root, playbook)
        self.ansible_config = resolve_source_path(self.source_root, ansible_config)
        self.ansible_playbook = ansible_playbook
        self.answer_file = Path(answer_file).resolve() if answer_file else None
        self.accept_configuration = bool(accept_configuration)
        self.dry_run = bool(dry_run)
        if self.paths.dry_run != self.dry_run:
            raise InstallerError("Installer paths must be selected with the same dry-run setting")
        self.input_function = input_function
        self.output_stream = sys.stdout if output_stream is None else output_stream
        self.runner = runner
        self.bootstrap_runner = bootstrap_runner
        self.dns_resolver = dns_resolver
        self.apt_get = apt_get
        self.verbose = bool(verbose)
        self.redactor = Redactor()
        self.log = InstallerLog(paths.human_log, paths.event_log, self.redactor)
        self.ledger = None

    def _load_secrets_if_present(self):
        if self.paths.secrets.exists():
            values = validate_secrets(read_json_file(self.paths.secrets))
            self.redactor.add_values(values.values())
            return values
        return None

    def _purge_abandoned_vars(self):
        if not self.paths.state_dir.exists():
            return
        for candidate in self.paths.state_dir.glob("ansible-vars-*.json"):
            if candidate.is_file() and not candidate.is_symlink():
                candidate.unlink()

    def _begin(self, resume):
        if self.paths.root == Path("/") and os.geteuid() != 0:
            raise InstallerError("Installer execution and resume require root")
        if (
            self.paths.root != Path("/")
            and not self.dry_run
            and self.runner in (subprocess.Popen, subprocess.run)
        ):
            raise InstallerError("--root overrides require --dry-run outside the unit-test harness")
        legacy = detect_legacy_state(self.paths)
        if legacy is not None and not self.paths.ledger.exists():
            raise InstallerError(
                "Legacy rc3-rc5 installer state was detected at %s. It cannot be "
                "resumed under schema 5; inspect status and use discard-incomplete "
                "only if the plan proves no host mutation occurred."
                % legacy["state_dir"]
            )
        self.paths.ensure_state_log_directories()
        self._purge_abandoned_vars()
        if resume:
            if not self.paths.ledger.exists():
                raise InstallerError("No interrupted installation exists to resume")
            self.ledger = PhaseLedger.load(self.paths.ledger)
            if self.ledger.value.get("status") in ("complete", "dry-run-complete"):
                raise InstallerError("Installation is already complete; use status")
            if bool(self.ledger.value.get("dry_run")) != self.dry_run:
                raise InstallerError("Resume must use the same --dry-run setting as the original run")
            self._load_secrets_if_present()
            self.ledger.mark_resumed()
            if not self.paths.ownership.exists():
                raise InstallerError("Schema-5 ownership manifest is missing; refusing resume")
            self.log.bind(
                installation_id=self.ledger.value["installation_id"],
                run_number=self.ledger.value["run_count"],
                correlation_id=self.ledger.value["runs"][-1]["correlation_id"],
            )
            if self.paths.answers.exists():
                resumed_answers = validate_answers(read_json_file(self.paths.answers))
                self.log.bind(
                    node_fqdn=resumed_answers["node_fqdn"],
                    shared_fqdn=resumed_answers["shared_fqdn"],
                )
            self.log.info("Resuming installation %s" % self.ledger.value["installation_id"])
            self.log.audit("installation_resumed")
        else:
            if self.paths.ledger.exists():
                existing = PhaseLedger.load(self.paths.ledger)
                raise InstallerError(
                    "Installer state already exists with status '%s'; use status or resume"
                    % existing.value.get("status", "unknown")
                )
            self.ledger = PhaseLedger.create(self.paths.ledger, dry_run=self.dry_run)
            initialize_ownership_manifest(self.paths, self.ledger)
            self.log.bind(
                installation_id=self.ledger.value["installation_id"],
                run_number=self.ledger.value["run_count"],
                correlation_id=self.ledger.value["runs"][-1]["correlation_id"],
            )
            self.log.info(
                "Started Controller Plane installation %s"
                % self.ledger.value["installation_id"]
            )
            self.log.audit("installation_started")

    def _begin_reconcile(self):
        if self.dry_run or self.paths.dry_run:
            raise InstallerError("Reconcile is only available for a completed real installation")
        if self.paths.root == Path("/") and os.geteuid() != 0:
            raise InstallerError("Reconcile requires root")
        if self.paths.root != Path("/") and self.runner in (subprocess.Popen, subprocess.run):
            raise InstallerError("--root overrides cannot run a real reconcile")
        self.paths.ensure_state_log_directories()
        self._purge_abandoned_vars()
        if not self.paths.ledger.exists():
            raise InstallerError("No completed real installation exists to reconcile")
        self.ledger = PhaseLedger.load(self.paths.ledger)
        if self.ledger.value.get("dry_run"):
            raise InstallerError("Reconcile refuses a dry-run ledger")
        if self.ledger.value.get("status") != "complete":
            raise InstallerError(
                "Reconcile requires completed state; use resume for incomplete or failed state"
            )
        reconciled_answers = validate_answers(read_json_file(self.paths.answers))
        protected = validate_secrets(read_json_file(self.paths.secrets))
        self.redactor.add_values(protected.values())
        self.ledger.prepare_reconcile()
        self.log.bind(
            installation_id=self.ledger.value["installation_id"],
            run_number=self.ledger.value["run_count"],
            correlation_id=self.ledger.value["runs"][-1]["correlation_id"],
            node_fqdn=reconciled_answers["node_fqdn"],
            shared_fqdn=reconciled_answers["shared_fqdn"],
        )
        self.log.info(
            "Started reconcile %d for installation %s"
            % (self.ledger.value["reconcile_count"], self.ledger.value["installation_id"])
        )
        self.log.audit(
            "reconcile_started",
            reconcile_number=self.ledger.value["reconcile_count"],
        )

    def _run_phase(self, phase, function):
        if self.ledger.completed(phase):
            self.log.info("Skipping completed phase: %s" % phase)
            self.log.event("phase_skipped", phase=phase)
            return
        self.ledger.start_phase(phase)
        self.log.bind(
            phase=phase,
            attempt=self.ledger.value["phases"][phase]["attempt"],
        )
        self.log.info("Starting phase: %s" % phase)
        self.log.event("phase_started", phase=phase)
        try:
            details = function() or None
        except Exception as exc:
            safe_error = self.redactor.text(exc)
            self.ledger.fail_phase(phase, safe_error)
            self.log.error("Phase failed: %s: %s" % (phase, safe_error), category="phase")
            self.log.audit("phase_failed", phase=phase, error=safe_error)
            if isinstance(exc, InstallerError):
                raise
            raise InstallerError("Phase %s failed: %s" % (phase, safe_error))
        self.ledger.complete_phase(phase, details=details)
        self.log.info("Completed phase: %s" % phase)
        self.log.event("phase_completed", phase=phase, details=details or {})
        self.log.bind(phase=None, attempt=None)

    def _phase_preflight(self):
        return run_preflight(self.paths)

    def _phase_bootstrap(self):
        answers = validate_answers(read_json_file(self.paths.answers))
        validate_answer_dns(answers, resolver=self.dns_resolver)
        packages = bootstrap_packages_for_answers(answers)
        preexisting_packages = (
            query_preexisting_packages(packages, log=self.log)
            if self.paths.root == Path("/") and not self.dry_run
            else []
        )
        update_ownership_packages(
            self.paths,
            packages,
            preexisting=preexisting_packages,
            completed=False,
        )
        if self.paths.root == Path("/"):
            # The question/confirmation interval can be arbitrarily long, and
            # resume may occur days later. Recheck mutable host safety at the
            # final read-only boundary immediately before apt.
            run_runtime_preflight(self.paths)
        commands = bootstrap_commands(self.apt_get, packages=packages)
        if self.dry_run:
            self.log.event("bootstrap_planned", commands=commands, dry_run=True)
            return {
                "packages": list(packages),
                "result": "not-executed",
                "reason": "dry-run",
            }
        if self.paths.root != Path("/") and self.bootstrap_runner in (
            subprocess.Popen,
            subprocess.run,
        ):
            self.log.event("bootstrap_planned", commands=commands, filesystem_root=str(self.paths.root))
            return {
                "packages": list(packages),
                "result": "not-executed",
                "reason": "filesystem-root override",
            }
        result = run_bootstrap(
            self.log,
            runner=self.bootstrap_runner,
            apt_get=self.apt_get,
            packages=packages,
            verbose=self.verbose,
            console_stream=self.output_stream,
        )
        update_ownership_packages(
            self.paths,
            packages,
            preexisting=preexisting_packages,
            completed=True,
        )
        return result

    def _phase_answers(self):
        if self.paths.answers.exists():
            answers = validate_answers(read_json_file(self.paths.answers))
        else:
            if self.answer_file is None:
                discovery = discover_public_ipv4()
                self.log.event(
                    "public_ipv4_discovery_completed",
                    level="INFO",
                    category="network",
                    result=discovery,
                )
                answers = prompt_answers(
                    input_function=self.input_function,
                    output_function=(
                        print
                        if self.output_stream is sys.stdout
                        else lambda message: self.output_stream.write("%s\n" % message)
                    ),
                    public_ip_discoverer=lambda: discovery,
                )
            else:
                answers = load_answers(
                    self.answer_file, input_function=self.input_function
                )
            atomic_write_json(self.paths.answers, answers)
        self.log.bind(
            node_fqdn=answers["node_fqdn"],
            shared_fqdn=answers["shared_fqdn"],
        )
        return {
            "deployment_mode": answers["deployment_mode"],
            "node_fqdn": answers["node_fqdn"],
            "shared_fqdn": answers["shared_fqdn"],
        }

    def _phase_confirmation(self):
        answers = validate_answers(read_json_file(self.paths.answers))
        answers, resolved = wait_for_answer_dns(
            answers,
            resolver=self.dns_resolver,
            interactive=self.answer_file is None,
            input_function=self.input_function,
            output_function=lambda message: self.output_stream.write("%s\n" % message),
            answers_changed=lambda updated: atomic_write_json(
                self.paths.answers, updated
            ),
        )
        atomic_write_json(self.paths.answers, answers)
        self.log.audit("dns_validation_passed", dns_names=sorted(resolved))
        lines = configuration_summary_lines(answers)
        self.log.info("Validated configuration presented for confirmation")
        for line in lines:
            self.log.info("configuration: %s" % line)
        self.log.event("configuration_presented", configuration=answers)
        result = confirm_configuration(
            answers,
            answer_file=self.answer_file,
            accept_configuration=self.accept_configuration,
            input_function=self.input_function,
            output_stream=self.output_stream,
        )
        self.log.info("Configuration explicitly accepted using %s" % result["method"])
        self.log.event("configuration_accepted", method=result["method"])
        return {
            "method": result["method"],
            "summary_line_count": len(lines),
            "dns_names_verified": sorted(resolved),
        }

    def _phase_secrets(self):
        secret_values = self._load_secrets_if_present()
        if secret_values is None:
            secret_values = generate_secrets()
            atomic_write_json(self.paths.secrets, secret_values)
            self.redactor.add_values(secret_values.values())
        return {"secret_count": len(secret_values), "storage": str(self.paths.secrets)}

    def _phase_release(self):
        release_id = calculate_controller_release_id(self.source_root / "controller")
        base_image = parse_controller_base_image(self.source_root / "controller")
        self.ledger.value["controller_release_id"] = release_id
        self.ledger.value["controller_base_image"] = base_image
        self.ledger.save()
        return {"controller_release_id": release_id, "controller_base_image": base_image}

    def _validate_ansible_inputs(self, require_executable=True):
        if self.playbook.is_symlink() or not self.playbook.is_file():
            raise InstallerError("Ansible playbook is unsafe or missing: %s" % self.playbook)
        if self.ansible_config.is_symlink() or not self.ansible_config.is_file():
            raise InstallerError("Ansible config is unsafe or missing: %s" % self.ansible_config)
        if not isinstance(self.ansible_playbook, str) or not self.ansible_playbook:
            raise InstallerError("Ansible executable name is invalid")
        if "\0" in self.ansible_playbook or "\n" in self.ansible_playbook or "\r" in self.ansible_playbook:
            raise InstallerError("Ansible executable name is invalid")
        if not require_executable:
            return self.ansible_playbook
        if os.path.sep in self.ansible_playbook:
            executable = Path(self.ansible_playbook)
            if not executable.is_file() or not os.access(str(executable), os.X_OK):
                raise InstallerError("ansible-playbook executable is unavailable: %s" % executable)
            return str(executable)
        executable = shutil.which(self.ansible_playbook)
        if executable is None:
            raise InstallerError("Required command is missing: %s" % self.ansible_playbook)
        return executable

    def _phase_ansible(self):
        executable = self._validate_ansible_inputs(require_executable=not self.dry_run)
        answers = validate_answers(read_json_file(self.paths.answers))
        atomic_write_json(self.paths.answers, answers)
        secret_values = validate_secrets(read_json_file(self.paths.secrets))
        self.redactor.add_values(secret_values.values())
        release_id = self.ledger.value.get("controller_release_id")
        if not isinstance(release_id, str) or not re.fullmatch(
            r"cp1-[0-9a-f]{64}", release_id
        ):
            raise InstallerError("Controller release ID is missing from the installer ledger")
        if release_id != calculate_controller_release_id(self.source_root / "controller"):
            raise InstallerError("Controller source changed after release identity calculation")
        controller_base_image = self.ledger.value.get("controller_base_image")
        if controller_base_image != parse_controller_base_image(self.source_root / "controller"):
            raise InstallerError("Controller base image changed after release identity calculation")
        atomic_write_json(self.paths.inventory, build_inventory(answers["ssh_allowed_user"]))
        ansible_vars = build_ansible_vars(
            answers, secret_values, release_id, controller_base_image
        )
        fd, vars_name = tempfile.mkstemp(
            prefix="ansible-vars-", suffix=".json", dir=str(self.paths.state_dir)
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8", closefd=True) as handle:
                fd = -1
                json.dump(ansible_vars, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            command = [
                executable,
                "--inventory",
                str(self.paths.inventory),
                "--extra-vars",
                "@%s" % vars_name,
                str(self.playbook),
            ]
            safe_command = ["@<protected-vars>" if item == "@%s" % vars_name else item for item in command]
            self.log.info("Ansible command: %s" % " ".join(safe_command))
            self.log.event("ansible_planned", command=safe_command, dry_run=self.dry_run)
            if self.dry_run:
                return {"result": "not-executed", "reason": "dry-run"}
            environment = os.environ.copy()
            environment["ANSIBLE_CONFIG"] = str(self.ansible_config)
            environment["ANSIBLE_NOCOLOR"] = "1"
            return_code = run_streamed_command(
                command,
                self.log,
                "ansible",
                runner=self.runner,
                console_stream=self.output_stream,
                show_output=self.verbose,
                cwd=str(self.source_root),
                env=environment,
            )
            if return_code != 0:
                raise InstallerError("Ansible failed with exit code %d" % return_code)
            return {"result": "completed", "exit_code": return_code}
        finally:
            if fd >= 0:
                os.close(fd)
            with contextlib.suppress(FileNotFoundError):
                os.unlink(vars_name)

    def _phase_summary(self):
        answers = validate_answers(read_json_file(self.paths.answers))
        secret_values = validate_secrets(read_json_file(self.paths.secrets))
        self.redactor.add_values(secret_values.values())
        release_id = self.ledger.value["controller_release_id"]
        summary = {
            "installation_id": self.ledger.value["installation_id"],
            "deployment_mode": "standalone",
            "dry_run": self.dry_run,
            "controller_release_id": release_id,
            "node_fqdn": answers["node_fqdn"],
            "shared_fqdn": answers["shared_fqdn"],
            "console_url": "https://%s/admin/" % answers["shared_fqdn"],
            "documentation_url": "https://%s/docs/" % answers["shared_fqdn"],
            "recovery_url": "https://%s/recovery/" % answers["shared_fqdn"],
            "admin_username": answers["admin_username"],
            "admin_email": answers["admin_email"],
            "acme_email": answers["acme_email"],
            "acme_ca": LETS_ENCRYPT_PRODUCTION_DIRECTORY,
            "firewall_mode": answers["firewall_mode"],
            "timezone": answers["timezone"],
            "ntp_mode": answers["ntp_mode"],
            "ntp_servers": answers["ntp_servers"],
            "credentials_file": str(self.paths.credentials),
            "human_log": str(self.paths.human_log),
            "event_log": str(self.paths.event_log),
            "operation": self.ledger.value["runs"][-1]["kind"],
            "run_count": self.ledger.value["run_count"],
            "reconcile_count": self.ledger.value["reconcile_count"],
        }
        credential_text = (
            "Vivolution Controller credentials\n"
            "Installation ID: {installation_id}\n"
            "Console URL: {console_url}\n"
            "Documentation URL: {documentation_url}\n"
            "Recovery URL: {recovery_url}\n"
            "Administrator: {admin_username}\n"
            "Administrator email: {admin_email}\n"
            "Let's Encrypt ACME email: {acme_email}\n"
            "ACME directory: {acme_ca}\n"
            "Administrator password: {admin_password}\n"
        ).format(admin_password=secret_values["cp_controller_admin_password"], **summary)
        atomic_write_bytes(self.paths.credentials, credential_text.encode("utf-8"), mode=0o600)
        atomic_write_json(self.paths.summary, summary)
        update_ownership_state(
            self.paths, "dry-run-complete" if self.dry_run else "installed"
        )
        return {
            "console_url": summary["console_url"],
            "documentation_url": summary["documentation_url"],
            "recovery_url": summary["recovery_url"],
            "credentials_file": summary["credentials_file"],
        }

    def run(self, resume=False, reconcile=False):
        if resume and reconcile:
            raise InstallerError("resume and reconcile are mutually exclusive")
        with self.paths.exclusive_lock():
            if reconcile:
                self._begin_reconcile()
            else:
                self._begin(resume=resume)
            phase_functions = {
                "preflight": self._phase_preflight,
                "answers": self._phase_answers,
                "confirmation": self._phase_confirmation,
                "bootstrap": self._phase_bootstrap,
                "secrets": self._phase_secrets,
                "release": self._phase_release,
                "ansible": self._phase_ansible,
                "summary": self._phase_summary,
            }
            for phase in PHASES:
                self._run_phase(phase, phase_functions[phase])
            self.ledger.finish()
            operation = "Reconcile" if reconcile else "Installation"
            self.log.info("%s finished with status: %s" % (operation, self.ledger.value["status"]))
            self.log.event(
                "reconcile_completed" if reconcile else "installation_completed",
                installation_id=self.ledger.value["installation_id"],
                status=self.ledger.value["status"],
                run_number=self.ledger.value["run_count"],
                reconcile_number=self.ledger.value["reconcile_count"],
            )
            summary = read_json_file(self.paths.summary)
        return summary


def installer_status(paths):
    if not paths.ledger.exists():
        legacy = detect_legacy_state(paths)
        return {
            "status": "legacy-state-detected" if legacy else "not-installed",
            "dry_run_state": paths.dry_run,
            "state_dir": str(paths.state_dir),
            "log_dir": str(paths.log_dir),
            "ledger": str(paths.ledger),
            "legacy": legacy,
        }
    # Ledger writes use atomic rename, so a reader sees either the prior or the
    # next complete document. Status and diagnostics deliberately do not create
    # or rewrite the volatile lock: `/run` is cleared on reboot, while status
    # must remain available for an existing durable ledger.
    ledger = PhaseLedger.load(paths.ledger).value
    return {
        "status": ledger.get("status"),
        "installation_id": ledger.get("installation_id"),
        "current_phase": ledger.get("current_phase"),
        "controller_release_id": ledger.get("controller_release_id"),
        "dry_run": ledger.get("dry_run"),
        "state_dir": str(paths.state_dir),
        "log_dir": str(paths.log_dir),
        "ledger": str(paths.ledger),
        "run_count": ledger.get("run_count"),
        "reconcile_count": ledger.get("reconcile_count"),
        "runs": ledger.get("runs"),
        "phases": {key: value.get("status") for key, value in ledger["phases"].items()},
    }


def _diagnose_dns_name(name, expected, resolver=socket.getaddrinfo):
    record = {"name": name, "expected_ipv4": expected, "ipv4": [], "ipv6": []}
    for family, key in ((socket.AF_INET, "ipv4"), (socket.AF_INET6, "ipv6")):
        try:
            results = resolver(name, 443, family, socket.SOCK_STREAM)
            record[key] = sorted(
                {
                    item[4][0].split("%", 1)[0]
                    for item in results
                    if len(item) >= 5 and item[4] and item[4][0]
                }
            )
        except (OSError, socket.gaierror) as exc:
            record["%s_error" % key] = str(exc)
    record["ready"] = record["ipv4"] == [expected] and not record["ipv6"]
    return record


def diagnostics_report(
    paths,
    node_fqdn=None,
    shared_fqdn=None,
    public_ipv4=None,
    public_ip_discoverer=discover_public_ipv4,
    resolver=socket.getaddrinfo,
    runner=subprocess.run,
    command_finder=shutil.which,
):
    """Run read-only readiness checks without creating installer state or locks."""
    report = {
        "timestamp": utc_now(),
        "installer_version": INSTALLER_VERSION,
        "state": installer_status(paths),
        "network_contract": {
            "inbound_tcp": [22, 80, 443],
            "outbound_tcp": [53, 80, 443],
            "outbound_udp": [53, 123],
            "never_public": [5432, 6432, 8000],
        },
    }
    try:
        report["host_os"] = {"ready": True, **validate_host_os(paths)}
    except InstallerError as exc:
        report["host_os"] = {"ready": False, "error": str(exc)}
    report["public_ipv4_discovery"] = public_ip_discoverer()

    timedatectl = command_finder("timedatectl")
    if timedatectl:
        try:
            output = _read_only_command(
                [
                    timedatectl,
                    "show",
                    "--property=NTP",
                    "--property=NTPSynchronized",
                    "--property=Timezone",
                    "--no-pager",
                ],
                runner=runner,
            )
            values = dict(
                line.split("=", 1) for line in output.splitlines() if "=" in line
            )
            report["time"] = {
                "ntp_enabled": values.get("NTP", "").lower() == "yes",
                "synchronized": values.get("NTPSynchronized", "").lower() == "yes",
                "timezone": values.get("Timezone"),
            }
        except InstallerError as exc:
            report["time"] = {"error": str(exc)}
    else:
        report["time"] = {"error": "timedatectl is unavailable"}

    if any(value is not None for value in (node_fqdn, shared_fqdn, public_ipv4)):
        if not all((node_fqdn, shared_fqdn, public_ipv4)):
            raise InstallerError(
                "DNS diagnostics require --node-fqdn, --shared-fqdn and --public-ip together"
            )
        expected = validate_public_ipv4(public_ipv4)
        report["dns"] = [
            _diagnose_dns_name(
                validate_fqdn(name), expected, resolver=resolver
            )
            for name in (node_fqdn, shared_fqdn)
        ]
    return report


def _discard_state_descriptor(paths):
    if paths.ledger.exists():
        ledger = PhaseLedger.load(paths.ledger).value
        return {
            "kind": "schema-5",
            "ledger": ledger,
            "state_dir": paths.state_dir,
            "log_dir": paths.log_dir,
            "lock": paths.lock,
            "allowed_state_names": {
                "ledger.json",
                "answers.json",
                "ownership.json",
                "tombstone.json",
                "installer.lock",
            },
        }
    legacy = detect_legacy_state(paths)
    if legacy and paths.legacy_ledger.exists():
        return {
            "kind": "legacy-schema-4",
            "ledger": read_json_file(paths.legacy_ledger),
            "state_dir": paths.legacy_state_dir,
            "log_dir": paths.legacy_log_dir,
            "lock": paths.legacy_lock,
            "allowed_state_names": {
                "ledger.json",
                "answers.json",
                "installer.lock",
            },
        }
    raise InstallerError("No recognized incomplete installer ledger is available to discard")


def _prove_pre_mutation_ledger(descriptor, paths):
    ledger = descriptor["ledger"]
    expected_schema = 5 if descriptor["kind"] == "schema-5" else 4
    if ledger.get("schema_version") != expected_schema:
        raise InstallerError("Discard refused an unexpected installer ledger schema")
    phases = ledger.get("phases")
    if not isinstance(phases, dict):
        raise InstallerError("Discard refused an invalid installer phase ledger")
    for phase in ("bootstrap", "secrets", "ansible", "summary"):
        record = phases.get(phase)
        if not isinstance(record, dict) or record.get("status") != "pending":
            raise InstallerError(
                "Discard is safe only before host mutation; phase %s is %s"
                % (phase, record.get("status") if isinstance(record, dict) else "missing")
            )
    if ledger.get("status") in ("complete", "dry-run-complete"):
        raise InstallerError("Completed installations cannot be discarded as incomplete")
    if descriptor["kind"] == "schema-5":
        ownership = read_json_file(paths.ownership)
        validate_pre_mutation_ownership_manifest(paths, ledger, ownership)
    markers = (
        paths.host_path("/etc/vivolution/installation-owner"),
        paths.host_path("/var/lib/vivolution/controller"),
        paths.host_path("/etc/containers/systemd/vivolution-cp-web.container"),
    )
    if any(path.exists() or path.is_symlink() for path in markers):
        raise InstallerError("Discard refused because installed runtime markers exist")
    return True


def _discard_allowlisted_entries(descriptor):
    state_dir = descriptor["state_dir"]
    log_dir = descriptor["log_dir"]
    if state_dir.is_symlink() or log_dir.is_symlink():
        raise InstallerError("Discard paths must not be symbolic links")
    entries = []
    if state_dir.exists():
        for item in state_dir.iterdir():
            if item.name not in descriptor["allowed_state_names"]:
                raise InstallerError("Discard refused unexpected state object: %s" % item)
            if item.is_symlink() or not item.is_file():
                raise InstallerError("Discard refused unsafe state object: %s" % item)
            entries.append(item)
    if log_dir.exists():
        for item in log_dir.iterdir():
            allowed = re.fullmatch(r"(?:install\.log|events\.jsonl)(?:\.[1-5])?", item.name)
            if not allowed:
                raise InstallerError("Discard refused unexpected log object: %s" % item)
            if item.is_symlink() or not item.is_file():
                raise InstallerError("Discard refused unsafe log object: %s" % item)
            entries.append(item)
    return sorted(entries, key=lambda item: str(item))


def discard_incomplete(
    paths,
    dry_run=False,
    confirmation_token=None,
    input_function=input,
    output_stream=None,
):
    """Discard only a strictly allowlisted pre-mutation installer journal."""
    if paths.root == Path("/") and os.geteuid() != 0:
        raise InstallerError("Discarding incomplete installer state requires root")
    # The schema-5 runtime lock is outside the removable state/log trees.  Hold
    # this same descriptor from the first proof/plan read through the operator
    # prompt, revalidation, and deletion.  This both coordinates compliant
    # installer processes and closes the former plan/confirmation TOCTOU gap.
    with paths.exclusive_lock():
        descriptor = _discard_state_descriptor(paths)
        _prove_pre_mutation_ledger(descriptor, paths)
        entries = _discard_allowlisted_entries(descriptor)
        plan = {
            "action": "discard-incomplete",
            "source": descriptor["kind"],
            "installation_id": descriptor["ledger"].get("installation_id"),
            "pre_mutation_proven": True,
            "packages_removed": [],
            "services_changed": [],
            "files": [str(item) for item in entries],
            "directories": [str(descriptor["state_dir"]), str(descriptor["log_dir"])],
            "dry_run": bool(dry_run),
        }
        if dry_run:
            return plan
        if descriptor["kind"] == "legacy-schema-4":
            raise InstallerError(
                "Legacy rc3-rc5 cleanup is plan-only because its removable lock file "
                "cannot provide race-free concurrency with the old installer. Recreate "
                "the fresh VM or perform reviewed offline cleanup after proving no "
                "installer process is running."
            )
        output_stream = sys.stdout if output_stream is None else output_stream
        output_stream.write(
            "\nExact discard plan (no packages or services will be changed):\n%s\n"
            % json.dumps(plan, indent=2, sort_keys=True)
        )
        output_stream.flush()
        token = confirmation_token
        if token is None:
            token = input_function(
                "Type %s to remove only the listed incomplete installer state: "
                % DISCARD_CONFIRMATION_TOKEN
            ).strip()
        if token != DISCARD_CONFIRMATION_TOKEN:
            raise InstallerError(
                "Incomplete state was not discarded; confirmation token did not match"
            )

        current_descriptor = _discard_state_descriptor(paths)
        _prove_pre_mutation_ledger(current_descriptor, paths)
        current_entries = _discard_allowlisted_entries(current_descriptor)
        if (
            current_descriptor["kind"] != descriptor["kind"]
            or current_descriptor["ledger"].get("installation_id")
            != descriptor["ledger"].get("installation_id")
            or [str(item) for item in current_entries] != plan["files"]
            or [
                str(current_descriptor["state_dir"]),
                str(current_descriptor["log_dir"]),
            ]
            != plan["directories"]
        ):
            raise InstallerError(
                "Incomplete state changed after the displayed discard plan; nothing was deleted"
            )

        # Delete the exact, revalidated set shown to the operator.  Never
        # substitute a newly enumerated set after confirmation.
        for item in entries:
            item.unlink()
        for directory in (descriptor["state_dir"], descriptor["log_dir"]):
            with contextlib.suppress(FileNotFoundError):
                directory.rmdir()
        if descriptor["kind"] == "schema-5":
            for parent in (paths.state_dir.parent, paths.log_dir.parent):
                with contextlib.suppress(FileNotFoundError, OSError):
                    parent.rmdir()
        plan["discarded_at"] = utc_now()
    return plan


def _redacted_file_bytes(path, redactor):
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return b"[binary content omitted]\n"
    if path.suffix == ".json":
        try:
            value = json.loads(raw)
        except ValueError as exc:
            raise InstallerError("Support bundle JSON is invalid in %s: %s" % (path, exc))
        return (
            json.dumps(redactor.value(value), indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
    if path.suffix == ".jsonl":
        records = []
        for line_number, line in enumerate(raw.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except ValueError as exc:
                raise InstallerError(
                    "Support bundle JSONL is invalid in %s at line %d: %s"
                    % (path, line_number, exc)
                )
            records.append(json.dumps(redactor.value(value), sort_keys=True))
        return (("\n".join(records) + "\n") if records else "").encode("utf-8")

    # Human logs retain physical record boundaries. Pattern matching is done
    # over the whole payload so multiline PEM blocks are removed atomically;
    # all other unsafe control bytes remain escaped.
    rendered = redactor.multiline_text(raw)
    if rendered and not rendered.endswith("\n"):
        rendered += "\n"
    return rendered.encode("utf-8")


def create_support_bundle(paths, output_path=None):
    with paths.exclusive_lock():
        if not paths.ledger.exists():
            raise InstallerError("No installer state is available for a support bundle")
        ledger = PhaseLedger.load(paths.ledger).value
        redactor = Redactor()
        if paths.secrets.exists():
            protected = validate_secrets(read_json_file(paths.secrets))
            redactor.add_values(protected.values())
        if output_path is None:
            name = "vivolution-support-%s.tar.gz" % ledger["installation_id"]
            output = Path.cwd() / name
        else:
            output = Path(output_path).resolve()
        if output.exists() or output.is_symlink():
            raise InstallerError("Support bundle output already exists: %s" % output)
        if output.parent.is_symlink():
            raise InstallerError("Support bundle parent must not be a symbolic link: %s" % output.parent)
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not output.parent.is_dir():
            raise InstallerError("Support bundle parent is not a directory: %s" % output.parent)
        fd, temporary = tempfile.mkstemp(prefix=".support-", suffix=".tar.gz", dir=str(output.parent))
        os.close(fd)
        allowlist = (
            (paths.ledger, "installer/ledger.json"),
            (paths.answers, "installer/answers.json"),
            (paths.summary, "installer/summary.json"),
            (paths.inventory, "installer/inventory.json"),
            (paths.ownership, "installer/ownership.json"),
            (paths.human_log, "logs/install.log"),
            (paths.event_log, "logs/events.jsonl"),
        )
        try:
            with tarfile.open(temporary, "w:gz") as archive:
                for source, archive_name in allowlist:
                    if not source.is_file() or source.is_symlink():
                        continue
                    payload = _redacted_file_bytes(source, redactor)
                    info = tarfile.TarInfo(archive_name)
                    info.size = len(payload)
                    info.mode = 0o600
                    info.mtime = 0
                    archive.addfile(info, fileobj=io.BytesIO(payload))
                system_info = {
                    "installer_version": INSTALLER_VERSION,
                    "python_version": platform.python_version(),
                    "platform": platform.platform(),
                    "created_at": utc_now(),
                }
                payload = (json.dumps(system_info, indent=2, sort_keys=True) + "\n").encode("utf-8")
                info = tarfile.TarInfo("system/info.json")
                info.size = len(payload)
                info.mode = 0o600
                info.mtime = 0
                archive.addfile(info, fileobj=io.BytesIO(payload))
            os.chmod(temporary, 0o600)
            os.replace(temporary, str(output))
            _fsync_directory(output.parent)
        except Exception:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)
            raise
        return output


def default_source_root():
    configured = os.environ.get("VIVO_INSTALLER_SOURCE_ROOT")
    if configured:
        return str(Path(configured).resolve())
    return str(Path(__file__).resolve().parent.parent)


def add_common_arguments(
    parser, include_execution=False, include_answers=False, allow_dry_run=False
):
    parser.add_argument("--root", default="/", help="filesystem root override for tests")
    parser.add_argument(
        "--state-dir",
        default=None,
        help="override the real or dry-run default state directory",
    )
    parser.add_argument(
        "--log-dir",
        default=None,
        help="override the real or dry-run default log directory",
    )
    if include_execution:
        parser.add_argument("--source-root", default=default_source_root())
        parser.add_argument("--playbook", default=DEFAULT_PLAYBOOK)
        parser.add_argument("--ansible-config", default=DEFAULT_ANSIBLE_CONFIG)
        parser.add_argument("--ansible-playbook", default="ansible-playbook")
        parser.add_argument(
            "--verbose",
            action="store_true",
            help="show sanitized command output on the console (always retained in protected logs)",
        )
    if include_answers:
        parser.add_argument("--answers", help="validated JSON answer file")
        parser.add_argument(
            "--accept-configuration",
            action="store_true",
            help=(
                "explicitly approve validated --answers configuration for unattended use"
            ),
        )
    if allow_dry_run:
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help=(
                "use isolated dry-run state/log paths; install/resume do not invoke Ansible"
            ),
        )


def build_parser():
    parser = argparse.ArgumentParser(prog="install.sh", description=__doc__)
    parser.add_argument("--version", action="version", version=INSTALLER_VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("menu", help="open the Vivolution Turnkey Installer menu")
    install = subparsers.add_parser(
        "install", help="create a fresh standalone Controller Plane"
    )
    add_common_arguments(
        install, include_execution=True, include_answers=True, allow_dry_run=True
    )
    resume = subparsers.add_parser(
        "resume", help="resume an interrupted Controller Plane installation"
    )
    add_common_arguments(
        resume, include_execution=True, include_answers=True, allow_dry_run=True
    )
    reconcile = subparsers.add_parser(
        "reconcile", help="reconcile source/configuration on a completed real installation"
    )
    add_common_arguments(reconcile, include_execution=True)
    status = subparsers.add_parser("status", help="show durable installer status")
    add_common_arguments(status, allow_dry_run=True)
    support = subparsers.add_parser("support-bundle", help="create a redacted support archive")
    add_common_arguments(support, allow_dry_run=True)
    support.add_argument("--output", help="new support archive path")
    host_os = subparsers.add_parser(
        "check-host-os", help="verify supported host OS metadata without installing"
    )
    add_common_arguments(host_os)
    diagnostics = subparsers.add_parser(
        "diagnostics", help="run read-only host and network readiness diagnostics"
    )
    add_common_arguments(diagnostics)
    diagnostics.add_argument("--node-fqdn")
    diagnostics.add_argument("--shared-fqdn")
    diagnostics.add_argument("--public-ip")
    discard = subparsers.add_parser(
        "discard-incomplete",
        help="discard only installer state proven to predate host mutation",
    )
    add_common_arguments(discard)
    discard.add_argument(
        "--dry-run",
        action="store_true",
        help="print the bounded discard plan without deleting anything",
    )
    discard.add_argument(
        "--confirm",
        metavar=DISCARD_CONFIRMATION_TOKEN,
        help="noninteractive exact confirmation token",
    )
    return parser


def print_summary(summary):
    operation = summary.get("operation", "install")
    print("\nVivolution Controller %s complete" % operation)
    if summary.get("dry_run"):
        print("Result: DRY RUN (Ansible was not executed)")
    print("Console: %s" % summary["console_url"])
    print("Documentation: %s" % summary["documentation_url"])
    print("Recovery: %s" % summary["recovery_url"])
    print("Administrator: %s" % summary["admin_username"])
    print("Credentials: %s" % summary["credentials_file"])
    print("Human log: %s" % summary["human_log"])
    print("JSONL events: %s" % summary["event_log"])


def _engine_from_args(args, paths):
    return InstallerEngine(
        paths=paths,
        source_root=args.source_root,
        playbook=args.playbook,
        ansible_config=args.ansible_config,
        ansible_playbook=args.ansible_playbook,
        answer_file=getattr(args, "answers", None),
        accept_configuration=getattr(args, "accept_configuration", False),
        dry_run=getattr(args, "dry_run", False),
        verbose=getattr(args, "verbose", False),
    )


def main(argv=None):
    if sys.version_info[:2] != (3, 12):
        print("Vivolution Turnkey Installer requires Python 3.12 exactly.", file=sys.stderr)
        return 2
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        arguments = ["menu"]
    parser = build_parser()
    args = parser.parse_args(arguments)
    try:
        # discard-incomplete --dry-run is a deletion-plan flag, not isolated
        # installation state selection.
        dry_run = (
            getattr(args, "dry_run", False)
            if args.command != "discard-incomplete"
            else False
        )
        paths = InstallerPaths(
            getattr(args, "root", "/"),
            getattr(args, "state_dir", None),
            getattr(args, "log_dir", None),
            dry_run=dry_run,
        )
        if args.command == "menu":
            action = select_installer_action()
            if action == "create-controller":
                return main(["install"])
            if action == "diagnostics":
                return main(["diagnostics"])
            if action == "manage":
                managed = select_manage_action(paths)
                if managed == "preview-legacy-cleanup":
                    return main(["discard-incomplete", "--dry-run"])
                return main([managed])
            raise InstallerError("Selected role is not implemented in this release")
        if args.command in ("install", "resume", "reconcile"):
            engine = _engine_from_args(args, paths)
            summary = engine.run(
                resume=args.command == "resume", reconcile=args.command == "reconcile"
            )
            print_summary(summary)
        elif args.command == "status":
            print(json.dumps(installer_status(paths), indent=2, sort_keys=True))
        elif args.command == "support-bundle":
            output = create_support_bundle(paths, output_path=args.output)
            print("Support bundle: %s" % output)
        elif args.command == "check-host-os":
            identity = validate_host_os(paths)
            print(
                "Host OS verified: %s %s"
                % (identity["os_id"], identity["os_version"])
            )
        elif args.command == "diagnostics":
            report = diagnostics_report(
                paths,
                node_fqdn=args.node_fqdn,
                shared_fqdn=args.shared_fqdn,
                public_ipv4=args.public_ip,
            )
            print(json.dumps(report, indent=2, sort_keys=True))
        elif args.command == "discard-incomplete":
            plan = discard_incomplete(
                paths,
                dry_run=args.dry_run,
                confirmation_token=args.confirm,
            )
            print(json.dumps(plan, indent=2, sort_keys=True))
        return 0
    except InstallerError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
