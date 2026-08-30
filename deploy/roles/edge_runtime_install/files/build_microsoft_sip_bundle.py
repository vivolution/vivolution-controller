#!/usr/bin/python3
"""Build the exact Microsoft SIP trust bundle from Debian's public roots."""

from __future__ import annotations

import grp
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path


PYTHON_ROOT = "/usr/lib/vivolution-edge/python"
SOURCE = Path("/etc/ssl/certs/ca-certificates.crt")
DESTINATION = Path("/etc/vivolution-edge/tls/microsoft-ca-bundle.pem")
MAX_BYTES = 2 * 1024 * 1024


def secure_read(path: Path, *, mode: int, gid: int | None = None) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        record = os.fstat(descriptor)
        if (
            not stat.S_ISREG(record.st_mode)
            or record.st_nlink != 1
            or record.st_uid != 0
            or stat.S_IMODE(record.st_mode) != mode
            or (gid is not None and record.st_gid != gid)
            or not 0 < record.st_size <= MAX_BYTES
        ):
            raise ValueError("trust bundle violates its fixed file contract: {}".format(path))
        chunks = []
        remaining = MAX_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) != record.st_size or len(content) > MAX_BYTES:
            raise ValueError("trust bundle changed while being read: {}".format(path))
        return content
    finally:
        os.close(descriptor)


def main() -> int:
    if os.geteuid() != 0:
        raise ValueError("Microsoft SIP bundle builder must run as root")
    sys.path.insert(0, PYTHON_ROOT)
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from edge.runtime.contracts import MICROSOFT_SIP_ROOT_SHA1

    opensips_gid = grp.getgrnam("opensips").gr_gid
    parent_record = DESTINATION.parent.lstat()
    if (
        not stat.S_ISDIR(parent_record.st_mode)
        or stat.S_ISLNK(parent_record.st_mode)
        or parent_record.st_uid != 0
        or parent_record.st_gid != opensips_gid
        or stat.S_IMODE(parent_record.st_mode) != 0o750
    ):
        raise ValueError("Microsoft SIP bundle destination directory is unsafe")

    certificates = x509.load_pem_x509_certificates(secure_read(SOURCE, mode=0o644))
    by_thumbprint = {
        certificate.fingerprint(hashes.SHA1()).hex().upper(): certificate
        for certificate in certificates
    }
    missing = sorted(MICROSOFT_SIP_ROOT_SHA1 - set(by_thumbprint))
    if missing:
        raise ValueError(
            "Debian trust bundle lacks official Microsoft SIP roots {}".format(
                ",".join(missing)
            )
        )
    now = datetime.now(timezone.utc)
    selected = []
    for thumbprint in sorted(MICROSOFT_SIP_ROOT_SHA1):
        certificate = by_thumbprint[thumbprint]
        try:
            if not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError("Microsoft SIP root {} is not a CA".format(thumbprint))
        except x509.ExtensionNotFound as exc:
            raise ValueError("Microsoft SIP root {} lacks Basic Constraints".format(thumbprint)) from exc
        not_before = (
            certificate.not_valid_before_utc
            if hasattr(certificate, "not_valid_before_utc")
            else certificate.not_valid_before.replace(tzinfo=timezone.utc)
        )
        not_after = (
            certificate.not_valid_after_utc
            if hasattr(certificate, "not_valid_after_utc")
            else certificate.not_valid_after.replace(tzinfo=timezone.utc)
        )
        if not not_before <= now < not_after:
            raise ValueError("Microsoft SIP root {} is not currently valid".format(thumbprint))
        selected.append(certificate.public_bytes(serialization.Encoding.PEM))
    content = b"".join(selected)
    changed = True
    try:
        current = secure_read(DESTINATION, mode=0o440, gid=opensips_gid)
    except FileNotFoundError:
        current = None
    if current == content:
        changed = False
    else:
        temporary = DESTINATION.parent / (".{}.{}.tmp".format(DESTINATION.name, os.getpid()))
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o440,
        )
        try:
            os.fchmod(descriptor, 0o440)
            os.fchown(descriptor, 0, opensips_gid)
            offset = 0
            while offset < len(content):
                offset += os.write(descriptor, content[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, DESTINATION)
        parent = os.open(DESTINATION.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    print(
        json.dumps(
            {
                "changed": changed,
                "rootCount": len(selected),
                "sha1Identifiers": sorted(MICROSOFT_SIP_ROOT_SHA1),
                "status": "MICROSOFT_SIP_ROOT_BUNDLE_READY",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyError, OSError, UnicodeError, ValueError) as exc:
        print("Microsoft SIP root bundle rejected: {}".format(exc), file=sys.stderr)
        raise SystemExit(1)
