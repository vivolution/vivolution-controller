#!/usr/bin/env python3
"""Normalize bounded carrier CDRs without exporting telephone numbers."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import stat
from datetime import datetime
from pathlib import Path
from typing import Any

FIELD_COUNT = 14
ALLOWED_ACCOUNTS = {
    "vivo-carrier-test-in": "EDGE_TO_LOCAL_TEST",
    "vivo-carrier-test-out": "LOCAL_TO_EDGE_TEST",
    "vivo-carrier-twilio-out": "EDGE_TO_TWILIO_OUTBOUND",
}
ALLOWED_DISPOSITIONS = {"ANSWERED", "BUSY", "FAILED", "NO ANSWER", "CONGESTION"}
SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


class EvidenceError(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _regular_file(path: Path) -> os.stat_result:
    if path.is_symlink():
        raise EvidenceError("input must not be a symbolic link")
    status = path.stat()
    if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
        raise EvidenceError("input must be one regular single-link file")
    if status.st_size > 8 * 1024 * 1024:
        raise EvidenceError("input exceeds the 8 MiB bound")
    return status


def normalize(path: Path) -> dict[str, Any]:
    _regular_file(path)
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for index, row in enumerate(csv.reader(handle), 1):
            if len(row) != FIELD_COUNT:
                raise EvidenceError(f"CDR row {index} has an invalid field count")
            start, answer, end, duration, billsec, disposition = row[:6]
            accountcode, userfield = row[12:14]
            if accountcode not in ALLOWED_ACCOUNTS:
                raise EvidenceError(f"CDR row {index} has an unknown account code")
            if disposition not in ALLOWED_DISPOSITIONS:
                raise EvidenceError(f"CDR row {index} has an unknown disposition")
            try:
                duration_value = int(duration)
                billsec_value = int(billsec)
            except ValueError as exc:
                raise EvidenceError(f"CDR row {index} has a non-integer duration") from exc
            if not 0 <= billsec_value <= duration_value <= 3600:
                raise EvidenceError(f"CDR row {index} has an invalid duration bound")
            for label, value in (("start", start), ("end", end)):
                try:
                    datetime.fromisoformat(value)
                except ValueError as exc:
                    raise EvidenceError(f"CDR row {index} has an invalid {label} timestamp") from exc
            if answer:
                try:
                    datetime.fromisoformat(answer)
                except ValueError as exc:
                    raise EvidenceError(f"CDR row {index} has an invalid answer timestamp") from exc
            if not SAFE_ID.fullmatch(userfield):
                raise EvidenceError(f"CDR row {index} has an unsafe evidence identifier")
            # Hash the complete source row to preserve audit binding while never
            # exporting src, dst, channel names, unique IDs, or credentials.
            source_bytes = _canonical(row)
            records.append(
                {
                    "billsec": billsec_value,
                    "direction": ALLOWED_ACCOUNTS[accountcode],
                    "disposition": disposition,
                    "duration": duration_value,
                    "evidenceId": userfield,
                    "recordDigest": _digest(source_bytes),
                    "row": index,
                }
            )
    result = {
        "apiVersion": "poc.vivolution.ae/carrier-cdr-evidence/v0.1",
        "kind": "CarrierGatewayCdrEvidence",
        "recordCount": len(records),
        "records": records,
        "status": "NORMALIZED_NO_TELEPHONE_NUMBERS",
    }
    return result


def write_new(output: Path, result: dict[str, Any]) -> None:
    if output.exists() or output.is_symlink():
        raise EvidenceError("output directory must not already exist")
    output.mkdir(mode=0o700)
    payload = _canonical(result)
    evidence = output / "evidence.json"
    evidence.write_bytes(payload)
    evidence.chmod(0o600)
    manifest = f"{hashlib.sha256(payload).hexdigest()}  evidence.json\n".encode()
    manifest_path = output / "MANIFEST.sha256"
    manifest_path.write_bytes(manifest)
    manifest_path.chmod(0o600)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        write_new(args.output, normalize(args.input))
    except (EvidenceError, OSError, UnicodeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
