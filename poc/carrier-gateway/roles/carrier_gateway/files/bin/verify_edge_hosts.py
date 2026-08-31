#!/usr/bin/env python3
"""Validate the carrier gateway's exact private Edge host-file authority."""

from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path

EXPECTED = {
    "sbc1.vivolution.ae": "10.20.2.6",
    "sbc2.vivolution.ae": "10.20.2.7",
}
MARKERS = {
    "# BEGIN VIVOLUTION CARRIER GATEWAY PRIVATE EDGE DNS",
    "# END VIVOLUTION CARRIER GATEWAY PRIVATE EDGE DNS",
}


class ContractError(RuntimeError):
    pass


def _read(path: Path) -> list[str]:
    if path.is_symlink():
        raise ContractError("host authority must not be a symbolic link")
    stat = path.stat()
    if not path.is_file() or stat.st_nlink != 1:
        raise ContractError("host authority must be one regular single-link file")
    if stat.st_size > 1024 * 1024:
        raise ContractError("host authority exceeds the bounded size")
    return path.read_text(encoding="utf-8").splitlines()


def validate(path: Path, mode: str) -> None:
    lines = _read(path)
    found: dict[str, list[str]] = {name: [] for name in EXPECTED}
    marker_count = {marker: lines.count(marker) for marker in MARKERS}
    for line in lines:
        body = line.split("#", 1)[0].strip()
        if not body:
            continue
        fields = body.split()
        try:
            address = str(ipaddress.ip_address(fields[0]))
        except (ValueError, IndexError):
            continue
        for name in EXPECTED:
            if name in fields[1:]:
                found[name].append(address)

    if mode == "pre":
        for name, addresses in found.items():
            if addresses and addresses != [EXPECTED[name]]:
                raise ContractError(f"{name} has a conflicting host authority")
        if any(count not in (0, 1) for count in marker_count.values()):
            raise ContractError("carrier host markers are duplicated")
    elif mode == "post":
        if any(count != 1 for count in marker_count.values()):
            raise ContractError("carrier host markers are not exact")
        for name, address in EXPECTED.items():
            if found[name] != [address]:
                raise ContractError(f"{name} does not have its one exact private address")
    elif mode == "absent":
        if any(marker_count.values()) or any(found.values()):
            raise ContractError("carrier private Edge host authority remains present")
    else:  # pragma: no cover - argparse constrains this
        raise ContractError("unsupported mode")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("pre", "post", "absent"))
    parser.add_argument("path", nargs="?", default="/etc/hosts")
    args = parser.parse_args()
    try:
        validate(Path(args.path), args.mode)
    except (ContractError, OSError, UnicodeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
