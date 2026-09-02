#!/usr/bin/python3
"""Reject unsafe ownership, links, modes, or bounds in carrier ACME state."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

MAX_FILES = 128
MAX_TOTAL_BYTES = 16 * 1024 * 1024


class AcmeStateError(ValueError):
    pass


def validate_state(
    root: Path,
    certificate_name: str,
    *,
    require_account: bool,
    require_certificate: bool,
) -> dict[str, object]:
    try:
        root_record = root.lstat()
    except OSError as exc:
        raise AcmeStateError(f"cannot inspect ACME root: {exc}") from exc
    if (
        not stat.S_ISDIR(root_record.st_mode)
        or stat.S_ISLNK(root_record.st_mode)
        or root_record.st_uid != 0
        or root_record.st_gid != 0
        or stat.S_IMODE(root_record.st_mode) != 0o700
    ):
        raise AcmeStateError("ACME root must be an exact root:root 0700 directory")

    file_count = 0
    total_bytes = 0
    account_files = 0
    certificate_files: set[str] = set()
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        for name in names + files:
            path = directory_path / name
            try:
                record = path.lstat()
            except OSError as exc:
                raise AcmeStateError(f"cannot inspect ACME state member: {exc}") from exc
            if stat.S_ISLNK(record.st_mode):
                raise AcmeStateError("ACME state must not contain symbolic links")
            if record.st_uid != 0 or record.st_gid != 0:
                raise AcmeStateError("ACME state member is not root-owned")
            if stat.S_ISDIR(record.st_mode):
                if stat.S_IMODE(record.st_mode) != 0o700:
                    raise AcmeStateError("ACME state directories must be mode 0700")
                continue
            if (
                not stat.S_ISREG(record.st_mode)
                or record.st_nlink != 1
                or stat.S_IMODE(record.st_mode) != 0o600
            ):
                raise AcmeStateError(
                    "ACME state files must be single-link root:root 0600 regular files"
                )
            file_count += 1
            total_bytes += record.st_size
            if file_count > MAX_FILES or total_bytes > MAX_TOTAL_BYTES:
                raise AcmeStateError("ACME state exceeds its file-count or size bound")
            relative = path.relative_to(root)
            if relative.parts and relative.parts[0] == "accounts":
                account_files += 1
            if relative.parent == Path("certificates"):
                certificate_files.add(relative.name)

    if require_account and account_files < 2:
        raise AcmeStateError("protected ACME account state is absent or incomplete")
    required_certificate_files = {
        f"{certificate_name}.crt",
        f"{certificate_name}.issuer.crt",
        f"{certificate_name}.json",
        f"{certificate_name}.key",
    }
    if require_certificate and not required_certificate_files.issubset(certificate_files):
        raise AcmeStateError("protected ACME certificate state is incomplete")
    return {
        "accountFileCount": account_files,
        "fileCount": file_count,
        "status": "CARRIER_ACME_STATE_PROTECTED",
        "totalBytes": total_bytes,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--certificate-name", required=True)
    parser.add_argument("--require-account", action="store_true")
    parser.add_argument("--require-certificate", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        evidence = validate_state(
            args.root,
            args.certificate_name,
            require_account=args.require_account,
            require_certificate=args.require_certificate,
        )
    except AcmeStateError as exc:
        print(f"CARRIER_ACME_STATE_REJECTED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
