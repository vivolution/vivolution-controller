#!/usr/bin/env python3
"""Inject early Debian preseed files into one existing newc initramfs."""

from __future__ import annotations

import gzip
import os
import stat
import sys
import zlib
from pathlib import Path


NEWC_MAGIC = b"070701"
NEWC_HEADER_BYTES = 110
ARCHIVE_BLOCK_BYTES = 512
INJECTED_INODES = (0x7F000001, 0x7F000002, 0x7F000003)


class InitrdError(RuntimeError):
    pass


def align4(value: int) -> int:
    return (value + 3) & ~3


def gunzip_single_member(blob: bytes) -> bytes:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    plain = decoder.decompress(blob) + decoder.flush()
    if not decoder.eof or decoder.unused_data:
        raise InitrdError("input must contain exactly one complete gzip member")
    return plain


def parse_newc(archive: bytes) -> tuple[list[dict[str, object]], int]:
    entries: list[dict[str, object]] = []
    offset = 0
    while offset + NEWC_HEADER_BYTES <= len(archive):
        header = archive[offset : offset + NEWC_HEADER_BYTES]
        if header[:6] != NEWC_MAGIC:
            raise InitrdError(f"invalid newc magic at byte {offset}")
        try:
            fields = [
                int(header[6 + field * 8 : 14 + field * 8], 16)
                for field in range(13)
            ]
        except ValueError as error:
            raise InitrdError(f"invalid newc header at byte {offset}") from error

        inode, mode, uid, gid = fields[:4]
        file_size = fields[6]
        name_size = fields[11]
        if name_size < 1:
            raise InitrdError(f"invalid newc name length at byte {offset}")
        name_start = offset + NEWC_HEADER_BYTES
        name_end = name_start + name_size
        if name_end > len(archive) or archive[name_end - 1] != 0:
            raise InitrdError(f"truncated newc name at byte {offset}")
        try:
            name = archive[name_start : name_end - 1].decode("utf-8")
        except UnicodeDecodeError as error:
            raise InitrdError(f"non-UTF-8 newc name at byte {offset}") from error
        content_start = align4(name_end)
        content_end = content_start + file_size
        if content_end > len(archive):
            raise InitrdError(f"truncated newc content for {name!r}")
        entries.append(
            {
                "name": name,
                "inode": inode,
                "mode": mode,
                "uid": uid,
                "gid": gid,
                "content": archive[content_start:content_end],
                "start": offset,
            }
        )
        offset = align4(content_end)
        if name == "TRAILER!!!":
            return entries, offset
    raise InitrdError("newc TRAILER!!! entry not found")


def make_newc_entry(name: str, mode: int, content: bytes, inode: int) -> bytes:
    encoded_name = name.encode("utf-8") + b"\0"
    values = (
        inode,
        mode,
        0,
        0,
        1,
        0,
        len(content),
        0,
        0,
        0,
        0,
        len(encoded_name),
        0,
    )
    header = NEWC_MAGIC + b"".join(
        f"{value:08X}".encode("ascii") for value in values
    )
    result = bytearray(header)
    result.extend(encoded_name)
    result.extend(b"\0" * (align4(len(result)) - len(result)))
    result.extend(content)
    result.extend(b"\0" * (align4(len(result)) - len(result)))
    return bytes(result)


def read_regular_file(path: Path, description: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise InitrdError(f"{description} must be a regular non-symlink file: {path}")
    return path.read_bytes()


def inject(input_path: Path, preseed_path: Path, late_path: Path) -> bytes:
    original = gunzip_single_member(read_regular_file(input_path, "input initrd"))
    entries, trailer_end = parse_newc(original)
    if len(entries) < 1000:
        raise InitrdError("input does not resemble the qualified Debian installer initrd")
    if original[trailer_end:].strip(b"\0"):
        raise InitrdError("unexpected non-zero data follows the input newc trailer")

    names = [str(entry["name"]) for entry in entries]
    if len(names) != len(set(names)):
        raise InitrdError("input newc archive contains duplicate names")
    for injected_name in ("preseed.cfg", "late.sh"):
        if injected_name in names:
            raise InitrdError(f"refusing duplicate input entry: {injected_name}")
    input_inodes = {int(entry["inode"]) for entry in entries}
    if input_inodes.intersection(INJECTED_INODES):
        raise InitrdError("reserved injected inode collides with the input archive")

    preseed = read_regular_file(preseed_path, "preseed file")
    late_script = read_regular_file(late_path, "late-command script")
    if not preseed or not late_script.startswith(b"#!/bin/sh\n"):
        raise InitrdError("preseed is empty or late-command script has the wrong interpreter")

    trailer_start = int(entries[-1]["start"])
    prefix = original[:trailer_start]
    if len(prefix) % 4:
        raise InitrdError("input newc trailer is not four-byte aligned")
    output_archive = bytearray(prefix)
    output_archive.extend(
        make_newc_entry("preseed.cfg", stat.S_IFREG | 0o644, preseed, INJECTED_INODES[0])
    )
    output_archive.extend(
        make_newc_entry("late.sh", stat.S_IFREG | 0o755, late_script, INJECTED_INODES[1])
    )
    output_archive.extend(make_newc_entry("TRAILER!!!", 0, b"", INJECTED_INODES[2]))
    output_archive.extend(
        b"\0"
        * ((ARCHIVE_BLOCK_BYTES - len(output_archive) % ARCHIVE_BLOCK_BYTES) % ARCHIVE_BLOCK_BYTES)
    )

    output = gzip.compress(bytes(output_archive), compresslevel=9, mtime=0)
    verified_archive = gunzip_single_member(output)
    verified_entries, verified_end = parse_newc(verified_archive)
    if verified_archive[:trailer_start] != prefix:
        raise InitrdError("original Debian archive prefix changed during injection")
    if verified_archive[verified_end:].strip(b"\0"):
        raise InitrdError("unexpected non-zero data follows the verified newc trailer")
    if len(verified_entries) != len(entries) + 2:
        raise InitrdError("verified archive entry count is incorrect")
    verified = {str(entry["name"]): entry for entry in verified_entries}
    expected = {
        "preseed.cfg": (stat.S_IFREG | 0o644, preseed),
        "late.sh": (stat.S_IFREG | 0o755, late_script),
    }
    for name, (mode, content) in expected.items():
        entry = verified.get(name)
        if entry is None:
            raise InitrdError(f"verified archive is missing {name}")
        if entry["mode"] != mode or entry["uid"] != 0 or entry["gid"] != 0:
            raise InitrdError(f"verified archive metadata is incorrect for {name}")
        if entry["content"] != content:
            raise InitrdError(f"verified archive content is incorrect for {name}")
    return output


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        raise InitrdError(
            "usage: inject-initrd.py input-initrd.gz preseed.cfg late.sh output-initrd.gz"
        )
    input_path, preseed_path, late_path, output_path = map(Path, argv[1:])
    if output_path.exists() or output_path.is_symlink():
        raise InitrdError(f"output path already exists: {output_path}")
    if output_path.parent.is_symlink() or not output_path.parent.is_dir():
        raise InitrdError(f"output parent must be a regular directory: {output_path.parent}")
    output = inject(input_path, preseed_path, late_path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(output_path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(output)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            output_path.unlink()
        except FileNotFoundError:
            pass
        raise
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except (InitrdError, OSError, zlib.error, gzip.BadGzipFile) as error:
        print(f"initrd injection failed: {error}", file=sys.stderr)
        raise SystemExit(1)
