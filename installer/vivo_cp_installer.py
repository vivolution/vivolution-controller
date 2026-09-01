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
import getpass
import hashlib
import io
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid
from pathlib import Path


INSTALLER_VERSION = "0.3.0"
LEDGER_SCHEMA_VERSION = 4
SUPPORTED_OS_ID = "ubuntu"
SUPPORTED_OS_VERSION = "24.04"
DEFAULT_STATE_DIR = "/var/lib/vivolution-installer"
DEFAULT_LOG_DIR = "/var/log/vivolution-installer"
DEFAULT_DRY_RUN_STATE_DIR = "/var/lib/vivolution-installer-dry-run"
DEFAULT_DRY_RUN_LOG_DIR = "/var/log/vivolution-installer-dry-run"
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
BOOTSTRAP_PACKAGES = ("ansible-core", "ca-certificates", "python3-apt", "ufw")
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
}
REQUIRED_ANSWER_KEYS = ANSWER_KEYS - {"ssh_allowed_user", "acme_email"}
SECRET_KEYS = {
    "cp_controller_admin_password",
    "cp_db_owner_password",
    "cp_db_runtime_password",
    "cp_django_secret_key",
    "cp_edge_enrollment_token_pepper",
    "cp_rls_context_key",
}
SENSITIVE_KEY_PARTS = ("password", "secret", "token", "private_key", "credential")
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


def _fsync_directory(path):
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd = os.open(str(path), flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def ensure_private_directory(path):
    path = Path(path)
    if path.is_symlink():
        raise InstallerError("Private directory must not be a symbolic link: %s" % path)
    if path.exists():
        if not path.is_dir():
            raise InstallerError("Private path is not a directory: %s" % path)
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
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, (line.rstrip("\n") + "\n").encode("utf-8", errors="replace"))
        os.fsync(fd)
    finally:
        os.close(fd)


class Redactor:
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

    def text(self, value):
        rendered = str(value).replace("\r", "\\r").replace("\n", "\\n")
        for secret_value in sorted(self._values, key=len, reverse=True):
            rendered = rendered.replace(secret_value, "[REDACTED]")
        return rendered

    def value(self, value, key=None):
        if key is not None and self._sensitive_key(key):
            return "[REDACTED]"
        if isinstance(value, dict):
            return {str(k): self.value(v, key=k) for k, v in value.items()}
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

    def info(self, message):
        append_private_line(
            self.human_path,
            "%s INFO %s" % (utc_now(), self.redactor.text(message)),
        )

    def event(self, event_name, **fields):
        record = {
            "timestamp": utc_now(),
            "event": event_name,
            "fields": self.redactor.value(fields),
        }
        append_private_line(self.event_path, json.dumps(record, sort_keys=True))


def run_streamed_command(
    command,
    log,
    prefix,
    runner=subprocess.Popen,
    console_stream=None,
    **kwargs,
):
    """Run a command while durably logging and displaying each redacted line.

    The production runner is ``subprocess.Popen`` so output is consumed while
    the child is running.  Tests may inject a lightweight runner returning a
    ``CompletedProcess``; that compatibility path is intentionally buffered
    and is not used by the installer CLI.
    """
    console_stream = sys.stdout if console_stream is None else console_stream
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

    def emit(raw_line):
        line = str(raw_line).rstrip("\r\n")
        safe_line = log.redactor.text(line)
        # append_private_line fsyncs every line before it is shown, so a power
        # loss cannot leave console progress that never reached the log.
        log.info("%s: %s" % (prefix, safe_line))
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
    return return_code


class ExclusiveInstallerLock:
    def __init__(self, path):
        self.path = Path(path)
        self._handle = None

    def __enter__(self):
        ensure_private_directory(self.path.parent)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(self.path), flags, 0o600)
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
        self.root = root_path.resolve()
        self.dry_run = bool(dry_run)
        if state_dir is None:
            state_dir = DEFAULT_DRY_RUN_STATE_DIR if self.dry_run else DEFAULT_STATE_DIR
        if log_dir is None:
            log_dir = DEFAULT_DRY_RUN_LOG_DIR if self.dry_run else DEFAULT_LOG_DIR
        self.state_dir = self._rooted(state_dir)
        self.log_dir = self._rooted(log_dir)
        self.ledger = self.state_dir / "ledger.json"
        self.answers = self.state_dir / "answers.json"
        self.secrets = self.state_dir / "secrets.json"
        self.credentials = self.state_dir / "credentials.txt"
        self.summary = self.state_dir / "summary.json"
        self.inventory = self.state_dir / "inventory.json"
        self.lock = self.state_dir / "installer.lock"
        self.human_log = self.log_dir / "install.log"
        self.event_log = self.log_dir / "events.jsonl"

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
    if isinstance(value, str):
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
            "Only standalone CP1 installation is implemented; join/HA mode '%s' is refused"
            % mode
        )
    ssh_user_value = raw_answers.get("ssh_allowed_user")
    if not ssh_user_value:
        environment = os.environ if environment is None else environment
        ssh_user_value = environment.get("SUDO_USER")
    if not ssh_user_value:
        raise InstallerError(
            "ssh_allowed_user is required when a non-root SUDO_USER cannot be detected"
        )
    ssh_cidrs = validate_ssh_cidrs(raw_answers["ssh_source_cidrs"])
    active_client = current_ssh_client_cidr(environment=environment)
    if active_client is not None and active_client not in ssh_cidrs:
        ssh_cidrs = validate_ssh_cidrs(ssh_cidrs + [active_client])
    node_fqdn = validate_fqdn(raw_answers["node_fqdn"], "node_fqdn")
    shared_fqdn = validate_fqdn(raw_answers["shared_fqdn"], "shared_fqdn")
    if node_fqdn == shared_fqdn:
        raise InstallerError("node_fqdn and shared_fqdn must be different DNS names")
    admin_email = validate_admin_email(raw_answers["admin_email"])
    acme_email = validate_acme_email(raw_answers.get("acme_email") or admin_email)
    return {
        "deployment_mode": "standalone",
        "node_fqdn": node_fqdn,
        "shared_fqdn": shared_fqdn,
        "public_ipv4": validate_public_ipv4(raw_answers["public_ipv4"]),
        "ssh_source_cidrs": ssh_cidrs,
        "admin_username": validate_admin_username(raw_answers["admin_username"]),
        "admin_email": admin_email,
        "acme_email": acme_email,
        "ssh_allowed_user": validate_ssh_username(ssh_user_value),
    }


def prompt_answers(input_function=input):
    print("Vivolution CP1 standalone installer")
    print("Join/HA modes are intentionally unavailable in this release.\n")
    detected_ssh_user = os.environ.get("SUDO_USER", "").strip() or None
    questions = (
        ("deployment_mode", "Deployment mode", "standalone"),
        ("node_fqdn", "This controller's public FQDN", None),
        ("shared_fqdn", "Shared controller web FQDN", None),
        ("public_ipv4", "This controller's public IPv4", None),
        ("ssh_source_cidrs", "Allowed administrator SSH /32 CIDRs (comma separated)", None),
        ("admin_username", "Initial web administrator username", "cpadmin"),
        ("admin_email", "Initial web administrator email", None),
    )
    collected = {}
    for key, label, default in questions:
        suffix = " [%s]" % default if default is not None else ""
        response = input_function("%s%s: " % (label, suffix)).strip()
        collected[key] = response if response else default
    acme_default = collected["admin_email"]
    acme_response = input_function(
        "Let's Encrypt ACME contact email [%s]: " % acme_default
    ).strip()
    collected["acme_email"] = acme_response if acme_response else acme_default
    ssh_suffix = " [%s]" % detected_ssh_user if detected_ssh_user is not None else ""
    ssh_response = input_function(
        "Existing non-root Linux SSH administrator%s: " % ssh_suffix
    ).strip()
    collected["ssh_allowed_user"] = ssh_response if ssh_response else detected_ssh_user
    return validate_answers(collected)


def load_answers(answer_file=None, input_function=input):
    if answer_file is None:
        return prompt_answers(input_function=input_function)
    return validate_answers(read_json_file(Path(answer_file)))


def configuration_summary_lines(answers):
    """Return the fixed, non-secret fields shown before host mutation."""
    answers = validate_answers(answers)
    return (
        "Deployment mode: %s" % answers["deployment_mode"],
        "Node FQDN: %s" % answers["node_fqdn"],
        "Shared FQDN: %s" % answers["shared_fqdn"],
        "Public IPv4: %s" % answers["public_ipv4"],
        "SSH administrator: %s" % answers["ssh_allowed_user"],
        "SSH source /32s: %s" % ", ".join(answers["ssh_source_cidrs"]),
        "Web administrator: %s" % answers["admin_username"],
        "Web administrator email: %s" % answers["admin_email"],
        "Let's Encrypt ACME email: %s" % answers["acme_email"],
        "ACME directory: %s" % LETS_ENCRYPT_PRODUCTION_DIRECTORY,
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
        self.value["status"] = "running"
        self.value["current_phase"] = phase
        self.value["phases"][phase] = {"status": "running", "started_at": utc_now()}
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
                "resumed_at": [],
            }
        )
        for phase in ("release", "ansible", "summary"):
            self.value["phases"][phase] = {"status": "pending"}
        self.value["status"] = "running"
        self.value["current_phase"] = None
        self.value["last_reconcile_started_at"] = now
        self.save()


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
    """Check clock/reboot/listener safety without changing the target host."""
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
    if clock_values.get("NTP") != "yes" or clock_values.get("NTPSynchronized") != "yes":
        raise InstallerError(
            "System clock is not NTP-synchronized; fix timedatectl before installation"
        )
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
        "clock_ntp_enabled": True,
        "clock_synchronized": True,
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
        paths.host_path("/etc/vivolution"),
        paths.host_path("/var/lib/vivolution"),
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
    result = {
        **os_identity,
        "architecture": platform.machine(),
        "effective_user": getpass.getuser(),
    }
    if paths.root == Path("/"):
        result.update(
            run_runtime_preflight(
                paths, runner=runner, command_finder=command_finder
            )
        )
    return result


def bootstrap_commands(apt_get):
    """Return the bounded apt operations used by the bootstrap phase."""
    return [
        [apt_get, "update"],
        [
            apt_get,
            "install",
            "--yes",
            "--no-install-recommends",
        ]
        + list(BOOTSTRAP_PACKAGES),
    ]


def run_bootstrap(
    log,
    runner=subprocess.Popen,
    apt_get="apt-get",
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
    for command in bootstrap_commands(resolved_apt):
        log.info("Bootstrap command: %s" % " ".join(command))
        log.event("bootstrap_command_started", command=command)
        return_code = run_streamed_command(
            command,
            log,
            "apt",
            runner=runner,
            console_stream=console_stream,
            env=environment,
        )
        if return_code != 0:
            raise InstallerError(
                "Bootstrap command failed with exit code %d: %s"
                % (return_code, " ".join(command[:2]))
            )
        log.event("bootstrap_command_completed", command=command, exit_code=0)
    return {"packages": list(BOOTSTRAP_PACKAGES), "result": "completed"}


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
        ensure_private_directory(self.paths.state_dir)
        ensure_private_directory(self.paths.log_dir)
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
            self.log.info("Resuming installation %s" % self.ledger.value["installation_id"])
            self.log.event("installation_resumed", installation_id=self.ledger.value["installation_id"])
        else:
            if self.paths.ledger.exists():
                existing = PhaseLedger.load(self.paths.ledger)
                raise InstallerError(
                    "Installer state already exists with status '%s'; use status or resume"
                    % existing.value.get("status", "unknown")
                )
            self.ledger = PhaseLedger.create(self.paths.ledger, dry_run=self.dry_run)
            self.log.info("Started standalone CP1 installation %s" % self.ledger.value["installation_id"])
            self.log.event("installation_started", installation_id=self.ledger.value["installation_id"])

    def _begin_reconcile(self):
        if self.dry_run or self.paths.dry_run:
            raise InstallerError("Reconcile is only available for a completed real installation")
        if self.paths.root == Path("/") and os.geteuid() != 0:
            raise InstallerError("Reconcile requires root")
        if self.paths.root != Path("/") and self.runner in (subprocess.Popen, subprocess.run):
            raise InstallerError("--root overrides cannot run a real reconcile")
        ensure_private_directory(self.paths.state_dir)
        ensure_private_directory(self.paths.log_dir)
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
        validate_answers(read_json_file(self.paths.answers))
        protected = validate_secrets(read_json_file(self.paths.secrets))
        self.redactor.add_values(protected.values())
        self.ledger.prepare_reconcile()
        self.log.info(
            "Started reconcile %d for installation %s"
            % (self.ledger.value["reconcile_count"], self.ledger.value["installation_id"])
        )
        self.log.event(
            "reconcile_started",
            installation_id=self.ledger.value["installation_id"],
            run_number=self.ledger.value["run_count"],
            reconcile_number=self.ledger.value["reconcile_count"],
        )

    def _run_phase(self, phase, function):
        if self.ledger.completed(phase):
            self.log.info("Skipping completed phase: %s" % phase)
            self.log.event("phase_skipped", phase=phase)
            return
        self.ledger.start_phase(phase)
        self.log.info("Starting phase: %s" % phase)
        self.log.event("phase_started", phase=phase)
        try:
            details = function() or None
        except Exception as exc:
            safe_error = self.redactor.text(exc)
            self.ledger.fail_phase(phase, safe_error)
            self.log.info("Phase failed: %s: %s" % (phase, safe_error))
            self.log.event("phase_failed", phase=phase, error=safe_error)
            if isinstance(exc, InstallerError):
                raise
            raise InstallerError("Phase %s failed: %s" % (phase, safe_error))
        self.ledger.complete_phase(phase, details=details)
        self.log.info("Completed phase: %s" % phase)
        self.log.event("phase_completed", phase=phase, details=details or {})

    def _phase_preflight(self):
        return run_preflight(self.paths)

    def _phase_bootstrap(self):
        answers = validate_answers(read_json_file(self.paths.answers))
        validate_answer_dns(answers, resolver=self.dns_resolver)
        if self.paths.root == Path("/"):
            # The question/confirmation interval can be arbitrarily long, and
            # resume may occur days later. Recheck mutable host safety at the
            # final read-only boundary immediately before apt.
            run_runtime_preflight(self.paths)
        commands = bootstrap_commands(self.apt_get)
        if self.dry_run:
            self.log.event("bootstrap_planned", commands=commands, dry_run=True)
            return {
                "packages": list(BOOTSTRAP_PACKAGES),
                "result": "not-executed",
                "reason": "dry-run",
            }
        if self.paths.root != Path("/") and self.bootstrap_runner in (
            subprocess.Popen,
            subprocess.run,
        ):
            self.log.event("bootstrap_planned", commands=commands, filesystem_root=str(self.paths.root))
            return {
                "packages": list(BOOTSTRAP_PACKAGES),
                "result": "not-executed",
                "reason": "filesystem-root override",
            }
        return run_bootstrap(
            self.log,
            runner=self.bootstrap_runner,
            apt_get=self.apt_get,
            console_stream=self.output_stream,
        )

    def _phase_answers(self):
        if self.paths.answers.exists():
            answers = validate_answers(read_json_file(self.paths.answers))
        else:
            answers = load_answers(self.answer_file, input_function=self.input_function)
            atomic_write_json(self.paths.answers, answers)
        return {
            "deployment_mode": answers["deployment_mode"],
            "node_fqdn": answers["node_fqdn"],
            "shared_fqdn": answers["shared_fqdn"],
        }

    def _phase_confirmation(self):
        answers = validate_answers(read_json_file(self.paths.answers))
        resolved = validate_answer_dns(answers, resolver=self.dns_resolver)
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
        if not isinstance(release_id, str) or not re.fullmatch(r"cp1-[0-9a-f]{64}", release_id):
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
        return {
            "console_url": summary["console_url"],
            "documentation_url": summary["documentation_url"],
            "recovery_url": summary["recovery_url"],
            "credentials_file": summary["credentials_file"],
        }

    def run(self, resume=False, reconcile=False):
        if resume and reconcile:
            raise InstallerError("resume and reconcile are mutually exclusive")
        with ExclusiveInstallerLock(self.paths.lock):
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
    with ExclusiveInstallerLock(paths.lock):
        if not paths.ledger.exists():
            return {
                "status": "not-installed",
                "dry_run_state": paths.dry_run,
                "state_dir": str(paths.state_dir),
                "log_dir": str(paths.log_dir),
                "ledger": str(paths.ledger),
            }
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


def _redacted_file_bytes(path, redactor):
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return b"[binary content omitted]\n"
    return (redactor.text(raw) + ("" if raw.endswith("\n") else "\n")).encode("utf-8")


def create_support_bundle(paths, output_path=None):
    with ExclusiveInstallerLock(paths.lock):
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
    install = subparsers.add_parser("install", help="start a fresh standalone CP1 install")
    add_common_arguments(
        install, include_execution=True, include_answers=True, allow_dry_run=True
    )
    resume = subparsers.add_parser("resume", help="resume an interrupted standalone CP1 install")
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
    )


def main(argv=None):
    if sys.version_info[:2] != (3, 12):
        print("Vivolution CP Installer requires Python 3.12 exactly.", file=sys.stderr)
        return 2
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        arguments = ["install"]
    parser = build_parser()
    args = parser.parse_args(arguments)
    try:
        dry_run = getattr(args, "dry_run", False)
        paths = InstallerPaths(args.root, args.state_dir, args.log_dir, dry_run=dry_run)
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
        return 0
    except InstallerError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
