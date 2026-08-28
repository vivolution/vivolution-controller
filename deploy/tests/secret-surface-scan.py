#!/usr/bin/env python3
"""Find protected values without ever emitting them.

Secrets are accepted only as a JSON object on stdin. Output is a compact JSON
document containing controlled secret variable names and sanitized locations.
The scanner never extracts an OCI archive to the filesystem.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
from typing import BinaryIO


EXPECTED_SECRET_NAMES = (
    "cp_db_owner_password",
    "cp_db_runtime_password",
    "cp_django_secret_key",
    "cp_controller_admin_password",
)
CHUNK_SIZE = 1024 * 1024
MAX_STDIN_BYTES = 1024 * 1024
MAX_SAFE_LOCATION_LENGTH = 240


class ControlledScanError(Exception):
    """An error whose message is safe to include in evidence."""


class SecretScanner:
    def __init__(self, secrets: dict[str, bytes]) -> None:
        self.secrets = secrets
        self.findings: list[dict[str, str]] = []
        self._seen: set[tuple[str, str]] = set()
        self.scanned_files = 0
        self.scanned_bytes = 0

    def _safe_location(self, location: str) -> str:
        safe = "".join(character if character.isprintable() else "?" for character in location)
        for value in self.secrets.values():
            decoded = value.decode("utf-8", errors="ignore")
            if decoded:
                safe = safe.replace(decoded, "[redacted]")
        return safe[:MAX_SAFE_LOCATION_LENGTH]

    def _record(self, data: bytes, surface: str, location: str) -> None:
        for name, value in self.secrets.items():
            key = (name, surface)
            if key not in self._seen and value in data:
                self._seen.add(key)
                self.findings.append(
                    {
                        "secret_variable": name,
                        "surface": surface,
                        "path": self._safe_location(location),
                    }
                )

    def scan_stream(self, stream: BinaryIO, surface: str, location: str) -> None:
        overlap_length = max(len(value) for value in self.secrets.values()) - 1
        overlap = b""
        while True:
            chunk = stream.read(CHUNK_SIZE)
            if not chunk:
                break
            self.scanned_bytes += len(chunk)
            combined = overlap + chunk
            self._record(combined, surface, location)
            overlap = combined[-overlap_length:] if overlap_length > 0 else b""
        self.scanned_files += 1

    def scan_path(self, path: Path, surface: str, location: str) -> None:
        with path.open("rb") as stream:
            self.scan_stream(stream, surface, location)


def read_secrets() -> dict[str, bytes]:
    payload = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    if len(payload) > MAX_STDIN_BYTES:
        raise ControlledScanError("secret_input_exceeded_safe_size")
    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ControlledScanError("secret_input_was_not_valid_json") from None
    if not isinstance(decoded, dict):
        raise ControlledScanError("secret_input_was_not_an_object")

    secrets: dict[str, bytes] = {}
    for name in EXPECTED_SECRET_NAMES:
        value = decoded.get(name)
        if not isinstance(value, str):
            raise ControlledScanError(f"missing_secret_variable:{name}")
        encoded = value.encode("utf-8")
        if len(encoded) < 8:
            raise ControlledScanError(f"secret_variable_too_short:{name}")
        secrets[name] = encoded
    return secrets


def scan_local_project(scanner: SecretScanner, project_root: Path) -> list[str]:
    errors: list[str] = []
    try:
        root = project_root.resolve(strict=True)
    except (FileNotFoundError, OSError):
        raise ControlledScanError("project_root_unavailable") from None
    if not root.is_dir():
        raise ControlledScanError("project_root_was_not_a_directory")

    for current_root, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_root)
        relative_directory = current.relative_to(root)
        if relative_directory.parts == ("deploy",):
            directory_names[:] = [name for name in directory_names if name != ".state"]
        directory_names[:] = [name for name in directory_names if name != ".git"]

        for file_name in file_names:
            path = current / file_name
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(root)
            surface = (
                "project_evidence"
                if relative.parts[:2] == ("deploy", "evidence")
                else "project_source"
            )
            try:
                scanner.scan_path(path, surface, relative.as_posix())
            except (OSError, PermissionError):
                errors.append(scanner._safe_location(relative.as_posix()))
    return errors


def scan_oci_archive(scanner: SecretScanner, archive_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        outer = tarfile.open(archive_path, mode="r:*")
    except (OSError, tarfile.TarError):
        raise ControlledScanError("controller_image_archive_unreadable") from None

    with outer:
        members = {member.name: member for member in outer.getmembers() if member.isfile()}

        def json_member(member_name: str) -> object:
            member = members.get(member_name)
            if member is None or member.size > 8 * 1024 * 1024:
                raise ControlledScanError("controller_image_manifest_unreadable")
            stream = outer.extractfile(member)
            if stream is None:
                raise ControlledScanError("controller_image_manifest_unreadable")
            with stream:
                try:
                    return json.load(stream)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise ControlledScanError("controller_image_manifest_unreadable") from None

        index = json_member("index.json")
        if not isinstance(index, dict) or not isinstance(index.get("manifests"), list):
            raise ControlledScanError("controller_image_index_invalid")

        expected_layers: set[str] = set()
        for descriptor in index["manifests"]:
            if not isinstance(descriptor, dict) or not isinstance(descriptor.get("digest"), str):
                raise ControlledScanError("controller_image_descriptor_invalid")
            algorithm, separator, digest = descriptor["digest"].partition(":")
            if algorithm != "sha256" or separator != ":" or len(digest) != 64:
                raise ControlledScanError("controller_image_descriptor_invalid")
            manifest = json_member(f"blobs/sha256/{digest}")
            if not isinstance(manifest, dict) or not isinstance(manifest.get("layers"), list):
                raise ControlledScanError("controller_image_manifest_invalid")
            for layer_descriptor in manifest["layers"]:
                if not isinstance(layer_descriptor, dict) or not isinstance(
                    layer_descriptor.get("digest"), str
                ):
                    raise ControlledScanError("controller_image_layer_descriptor_invalid")
                layer_algorithm, layer_separator, layer_digest = layer_descriptor["digest"].partition(":")
                if (
                    layer_algorithm != "sha256"
                    or layer_separator != ":"
                    or len(layer_digest) != 64
                ):
                    raise ControlledScanError("controller_image_layer_descriptor_invalid")
                expected_layers.add(f"blobs/sha256/{layer_digest}")

        if not expected_layers:
            raise ControlledScanError("controller_image_had_no_layers")

        processed_layers: set[str] = set()
        for outer_member in members.values():
            if not outer_member.isfile():
                continue
            outer_stream = outer.extractfile(outer_member)
            if outer_stream is None:
                errors.append(scanner._safe_location(f"archive:{outer_member.name}"))
                continue

            with outer_stream, tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as spool:
                overlap_length = max(len(value) for value in scanner.secrets.values()) - 1
                overlap = b""
                while True:
                    chunk = outer_stream.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    scanner.scanned_bytes += len(chunk)
                    scanner._record(
                        overlap + chunk,
                        (
                            "controller_image_layer_blob"
                            if outer_member.name in expected_layers
                            else "controller_image_metadata"
                        ),
                        f"archive:{outer_member.name}",
                    )
                    overlap = (overlap + chunk)[-overlap_length:] if overlap_length > 0 else b""
                    spool.write(chunk)
                scanner.scanned_files += 1

                if outer_member.name not in expected_layers:
                    continue

                spool.seek(0)
                try:
                    layer = tarfile.open(fileobj=spool, mode="r:*")
                except tarfile.TarError:
                    errors.append(scanner._safe_location(f"unreadable-layer:{outer_member.name}"))
                    continue
                processed_layers.add(outer_member.name)
                with layer:
                    for layer_member in layer:
                        if not layer_member.isfile():
                            continue
                        layer_stream = layer.extractfile(layer_member)
                        if layer_stream is None:
                            errors.append(
                                scanner._safe_location(
                                    f"layer:{outer_member.name}:{layer_member.name}"
                                )
                            )
                            continue
                        with layer_stream:
                            scanner.scan_stream(
                                layer_stream,
                                "controller_image_layer",
                                f"layer:{outer_member.name}:{layer_member.name}",
                            )
        for missing_layer in sorted(expected_layers - processed_layers):
            safe_error = scanner._safe_location(f"unscanned-layer:{missing_layer}")
            if safe_error not in errors:
                errors.append(safe_error)
    return errors


def scan_process_arguments(scanner: SecretScanner) -> list[str]:
    errors: list[str] = []
    proc_root = Path("/proc")
    for process_directory in proc_root.iterdir():
        if not process_directory.name.isdigit():
            continue
        command_line = process_directory / "cmdline"
        try:
            with command_line.open("rb") as stream:
                scanner.scan_stream(
                    stream,
                    "process_argv",
                    f"pid:{process_directory.name}",
                )
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            # Processes routinely exit during /proc traversal; this is not a coverage error.
            continue
        except OSError:
            errors.append(f"pid:{process_directory.name}")
    return errors


def scan_remote_surfaces(
    scanner: SecretScanner,
    image_archive: Path,
    image_history: Path,
    service_journals: Path,
) -> list[str]:
    errors: list[str] = []
    for path, surface, label in (
        (image_history, "controller_image_history", "active-controller-history"),
        (service_journals, "service_journal", "qualified-controller-services"),
    ):
        try:
            scanner.scan_path(path, surface, label)
        except (OSError, PermissionError):
            errors.append(label)
    errors.extend(scan_oci_archive(scanner, image_archive))
    errors.extend(scan_process_arguments(scanner))
    return errors


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=True)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    local = subparsers.add_parser("local")
    local.add_argument("--project-root", type=Path, required=True)
    remote = subparsers.add_parser("remote")
    remote.add_argument("--image-archive", type=Path, required=True)
    remote.add_argument("--image-history", type=Path, required=True)
    remote.add_argument("--service-journals", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    try:
        arguments = parse_arguments()
        scanner = SecretScanner(read_secrets())
        if arguments.mode == "local":
            errors = scan_local_project(scanner, arguments.project_root)
        else:
            errors = scan_remote_surfaces(
                scanner,
                arguments.image_archive,
                arguments.image_history,
                arguments.service_journals,
            )
        status = "error" if errors else ("failed" if scanner.findings else "passed")
        result = {
            "status": status,
            "findings": scanner.findings,
            "coverage_errors": errors[:20],
            "scanned_files": scanner.scanned_files,
            "scanned_bytes": scanner.scanned_bytes,
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 2 if errors else 0
    except ControlledScanError as error:
        print(
            json.dumps(
                {
                    "status": "error",
                    "findings": [],
                    "coverage_errors": [str(error)],
                    "scanned_files": 0,
                    "scanned_bytes": 0,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 2
    except Exception:
        # Never echo an uncontrolled exception: it could contain a secret-bearing path.
        print(
            '{"coverage_errors":["scanner_runtime_error"],"findings":[],'
            '"scanned_bytes":0,"scanned_files":0,"status":"error"}'
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
