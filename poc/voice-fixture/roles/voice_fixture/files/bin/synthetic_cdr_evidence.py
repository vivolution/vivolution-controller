#!/usr/bin/env python3
"""Normalize and reconcile bounded no-PSTN fixture/Edge call evidence.

The ``normalize-fixture`` command runs as root on CP1 after one serialized
fixture test.  ``reconcile`` runs offline on the deployment controller against
one protected five-file collection directory.  Neither command performs any
network operation or accepts arbitrary tenant/call identifiers.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Mapping, Sequence


FIXTURE_API_VERSION = "edge.vivolution.ae/synthetic-fixture-cdr/v0.1"
EDGE_API_VERSION = "edge.vivolution.ae/synthetic-edge-cdr/v0.1"
RECONCILIATION_API_VERSION = "edge.vivolution.ae/synthetic-cdr-reconciliation/v0.1"
SCOPE = "SYNTHETIC_PRIVATE_NO_PSTN"
LIVE_M365_STATUS = "NOT_ASSERTED"
CALLED_NUMBER = "+9710000001001"
DIRECTIONS = (
    "TEAMS_FIXTURE_TO_PBX_FIXTURE",
    "PBX_FIXTURE_TO_TEAMS_FIXTURE",
)
ACCOUNT_CODES = {
    DIRECTIONS[0]: "vivo-synth-t2p",
    DIRECTIONS[1]: "vivo-synth-p2t",
}
TEST_ID_RE = re.compile(r"\A([0-9]{8}T[0-9]{6}Z)-(sbc[12])-([0-9]{1,10})\Z")
CDR_TIMESTAMP_RE = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\Z")
ASTERISK_ID_RE = re.compile(r"\A[0-9A-Za-z_.:-]{1,128}\Z")
DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
MANIFEST_LINE_RE = re.compile(r"\A([0-9a-f]{64})  (\./[^\x00\r\n]+)\Z")
MAX_CDR_BYTES = 128 * 1024
MAX_CDR_RECORDS = 32
MAX_EVIDENCE_BYTES = 256 * 1024

FIXTURE_FIELDS = {
    "apiVersion",
    "calledNumber",
    "fixtureCdrDigest",
    "kind",
    "liveM365Interoperability",
    "nodeId",
    "rawRecordCount",
    "records",
    "scope",
    "status",
    "testId",
}
FIXTURE_RECORD_FIELDS = {
    "answeredAt",
    "billableSeconds",
    "direction",
    "disposition",
    "durationSeconds",
    "endedAt",
    "linkedCallDigest",
    "recordDigest",
    "startedAt",
}
EDGE_FIELDS = {
    "apiVersion",
    "calls",
    "edgeCdrDigest",
    "kind",
    "liveM365Interoperability",
    "nodeIdentity",
    "scope",
    "sourceJournal",
    "status",
    "testId",
}
EDGE_NODE_FIELDS = {
    "allocationId",
    "clusterId",
    "generation",
    "nodeFactsDigest",
    "nodeId",
    "routeToken",
    "runtimeAuthorityDigest",
    "serviceInstanceId",
    "slot",
    "tenantContextId",
}
EDGE_CALL_FIELDS = {
    "direction",
    "elapsedMilliseconds",
    "finalJournalRecordDigest",
    "finalRealtimeUnixMicroseconds",
    "journalBootIdDigest",
    "result",
    "startJournalRecordDigest",
    "startRealtimeUnixMicroseconds",
}
EDGE_JOURNAL_FIELDS = {
    "marker",
    "opensipsUid",
    "recordCount",
    "systemdUnit",
}


class CdrEvidenceError(ValueError):
    """Input cannot prove the exact bounded synthetic CDR contract."""


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def sha256_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _exact_mapping(value: object, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise CdrEvidenceError(f"{label} must have exact keys {sorted(fields)}")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CdrEvidenceError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise CdrEvidenceError(f"{label} is outside its fixed bounds")
    return value


def _test_identity(test_id: object, node_id: object | None = None) -> tuple[str, str, int]:
    if not isinstance(test_id, str):
        raise CdrEvidenceError("test ID must be a string")
    match = TEST_ID_RE.fullmatch(test_id)
    if match is None:
        raise CdrEvidenceError("test ID is outside the fixed synthetic format")
    node = match.group(2)
    if node_id is not None and node_id != node:
        raise CdrEvidenceError("test ID node does not match the selected Edge")
    started = datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ").replace(
        tzinfo=timezone.utc
    )
    return test_id, node, int(started.timestamp())


def _parse_json(raw: bytes, label: str, *, canonical: bool = True) -> Mapping[str, Any]:
    if not raw or len(raw) > MAX_EVIDENCE_BYTES:
        raise CdrEvidenceError(f"{label} is empty or oversized")
    try:
        text = raw.decode("utf-8")
        value = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CdrEvidenceError(f"{label} is not one UTF-8 JSON document") from exc
    if not isinstance(value, dict):
        raise CdrEvidenceError(f"{label} must be a JSON object")
    if canonical and canonical_bytes(value).decode("utf-8") != text:
        raise CdrEvidenceError(f"{label} is not canonical newline-terminated JSON")
    return value


def _cdr_rows(raw: bytes) -> list[tuple[list[str], bytes]]:
    if not raw or len(raw) > MAX_CDR_BYTES or not raw.endswith(b"\n") or b"\r" in raw:
        raise CdrEvidenceError("Asterisk CDR delta must be bounded LF-terminated UTF-8")
    lines = raw.splitlines(keepends=True)
    if not 2 <= len(lines) <= MAX_CDR_RECORDS:
        raise CdrEvidenceError("Asterisk CDR delta has an invalid record count")
    result: list[tuple[list[str], bytes]] = []
    for line in lines:
        if len(line) > 8192:
            raise CdrEvidenceError("Asterisk CDR record is oversized")
        try:
            text = line[:-1].decode("utf-8")
            parsed = list(csv.reader(io.StringIO(text), strict=True))
        except (UnicodeDecodeError, csv.Error) as exc:
            raise CdrEvidenceError("Asterisk CDR delta contains invalid CSV") from exc
        if len(parsed) != 1 or len(parsed[0]) != 14:
            raise CdrEvidenceError("Asterisk CDR record does not have exactly 14 fields")
        result.append((parsed[0], line))
    return result


def _selected_record(
    row: Sequence[str], raw_line: bytes, direction: str, test_epoch: int
) -> Mapping[str, Any]:
    start, answer, end, duration, billsec, disposition = row[:6]
    unique_id, linked_id = row[10], row[11]
    parsed_times = []
    for value, label in ((start, "start"), (answer, "answer"), (end, "end")):
        if CDR_TIMESTAMP_RE.fullmatch(value) is None:
            raise CdrEvidenceError(f"selected Asterisk CDR {label} timestamp is invalid")
        try:
            parsed_times.append(
                datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(
                    tzinfo=timezone.utc
                )
            )
        except ValueError as exc:
            raise CdrEvidenceError(
                f"selected Asterisk CDR {label} timestamp is invalid"
            ) from exc
    started, answered, ended = parsed_times
    if not started <= answered <= ended:
        raise CdrEvidenceError("selected Asterisk CDR timestamps are not ordered")
    if not test_epoch - 5 <= int(started.timestamp()) <= test_epoch + 120:
        raise CdrEvidenceError("selected Asterisk CDR is outside the fixture test window")
    if int(ended.timestamp()) > test_epoch + 180:
        raise CdrEvidenceError("selected Asterisk CDR end exceeds the fixture test window")
    duration_value = _integer_from_text(duration, "duration", 1, 120)
    billsec_value = _integer_from_text(billsec, "billsec", 1, duration_value)
    wall_seconds = int((ended - started).total_seconds())
    if abs(duration_value - wall_seconds) > 1:
        raise CdrEvidenceError("selected Asterisk CDR duration contradicts its timestamps")
    if disposition != "ANSWERED":
        raise CdrEvidenceError("selected Asterisk CDR was not ANSWERED")
    if ASTERISK_ID_RE.fullmatch(unique_id) is None or ASTERISK_ID_RE.fullmatch(linked_id) is None:
        raise CdrEvidenceError("selected Asterisk CDR identity is invalid")
    return {
        "answeredAt": answer,
        "billableSeconds": billsec_value,
        "direction": direction,
        "disposition": disposition,
        "durationSeconds": duration_value,
        "endedAt": end,
        "linkedCallDigest": sha256_digest(linked_id.encode("ascii")),
        "recordDigest": sha256_digest(raw_line),
        "startedAt": start,
    }


def _integer_from_text(value: str, label: str, minimum: int, maximum: int) -> int:
    if not value.isdigit():
        raise CdrEvidenceError(f"Asterisk CDR {label} is not an integer")
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise CdrEvidenceError(f"Asterisk CDR {label} is outside the test bound")
    return parsed


def compile_fixture_cdr(raw: bytes, test_id: str, node_id: str) -> Mapping[str, Any]:
    """Select exactly two logical fixture CDRs from bounded Asterisk leg rows."""

    test_id, node, test_epoch = _test_identity(test_id, node_id)
    extension = "9201" if node == "sbc1" else "9202"
    rows = _cdr_rows(raw)
    selected: dict[str, tuple[Sequence[str], bytes]] = {}
    parsed_rows: list[Sequence[str]] = []
    for row, raw_line in rows:
        parsed_rows.append(row)
        src, dst, channel, dst_channel = row[6:10]
        account_code, user_field = row[12:14]
        direction: str | None = None
        if (
            account_code == ACCOUNT_CODES[DIRECTIONS[0]]
            and user_field == test_id
            and src == CALLED_NUMBER
            and dst == CALLED_NUMBER
            and re.fullmatch(r"PJSIP/edge-inbound-[0-9A-Za-z_.:-]+", channel)
            and dst_channel == ""
        ):
            direction = DIRECTIONS[0]
        elif (
            account_code == ACCOUNT_CODES[DIRECTIONS[1]]
            and user_field == test_id
            and dst == extension
            and re.fullmatch(
                rf"Local/{extension}@fixture-origin-[0-9A-Za-z_.:-]+;2", channel
            )
            and re.fullmatch(rf"PJSIP/{node}-[0-9A-Za-z_.:-]+", dst_channel)
        ):
            direction = DIRECTIONS[1]
        if direction is not None:
            if direction in selected:
                raise CdrEvidenceError(f"fixture emitted duplicate logical {direction} CDRs")
            selected[direction] = (row, raw_line)

    if set(selected) != set(DIRECTIONS):
        raise CdrEvidenceError("fixture did not emit exactly both logical CDR directions")

    outbound_linked_id = selected[DIRECTIONS[1]][0][11]
    inbound_linked_id = selected[DIRECTIONS[0]][0][11]
    if inbound_linked_id == outbound_linked_id:
        raise CdrEvidenceError("fixture directions do not identify two distinct calls")
    for row in parsed_rows:
        account_code, user_field = row[12:14]
        linked_id = row[11]
        if linked_id not in {inbound_linked_id, outbound_linked_id}:
            raise CdrEvidenceError("CDR delta contains a call outside this serialized test")
        if user_field not in {"", test_id}:
            raise CdrEvidenceError("CDR delta contains another test identity")
        if account_code not in {"", *ACCOUNT_CODES.values()}:
            raise CdrEvidenceError("CDR delta contains a non-fixture account code")
        if CALLED_NUMBER not in {row[6], row[7]} and extension not in {row[6], row[7]}:
            raise CdrEvidenceError("CDR delta contains a non-synthetic number")

    records = [
        _selected_record(*selected[direction], direction, test_epoch)
        for direction in DIRECTIONS
    ]
    unsigned: dict[str, Any] = {
        "apiVersion": FIXTURE_API_VERSION,
        "calledNumber": CALLED_NUMBER,
        "kind": "SyntheticFixtureCdrEvidence",
        "liveM365Interoperability": LIVE_M365_STATUS,
        "nodeId": node,
        "rawRecordCount": len(rows),
        "records": records,
        "scope": SCOPE,
        "status": "TWO_LOGICAL_SYNTHETIC_CALLS_ACCOUNTED",
        "testId": test_id,
    }
    evidence = dict(unsigned)
    evidence["fixtureCdrDigest"] = sha256_digest(canonical_bytes(unsigned))
    return evidence


def validate_fixture_cdr(value: object) -> Mapping[str, Any]:
    record = _exact_mapping(value, FIXTURE_FIELDS, "fixture CDR evidence")
    unsigned = dict(record)
    claimed = unsigned.pop("fixtureCdrDigest")
    if not isinstance(claimed, str) or claimed != sha256_digest(canonical_bytes(unsigned)):
        raise CdrEvidenceError("fixture CDR evidence self-digest is invalid")
    if (
        record["apiVersion"] != FIXTURE_API_VERSION
        or record["kind"] != "SyntheticFixtureCdrEvidence"
        or record["scope"] != SCOPE
        or record["status"] != "TWO_LOGICAL_SYNTHETIC_CALLS_ACCOUNTED"
        or record["liveM365Interoperability"] != LIVE_M365_STATUS
        or record["calledNumber"] != CALLED_NUMBER
    ):
        raise CdrEvidenceError("fixture CDR evidence expands beyond the synthetic contract")
    test_id, node, _ = _test_identity(record["testId"], record["nodeId"])
    _integer(record["rawRecordCount"], "fixture rawRecordCount", 2, MAX_CDR_RECORDS)
    records = record["records"]
    if not isinstance(records, list) or len(records) != 2:
        raise CdrEvidenceError("fixture CDR evidence must contain two logical records")
    for expected, item in zip(DIRECTIONS, records):
        call = _exact_mapping(item, FIXTURE_RECORD_FIELDS, "fixture CDR record")
        if call["direction"] != expected or call["disposition"] != "ANSWERED":
            raise CdrEvidenceError("fixture CDR direction or disposition is invalid")
        for field in ("recordDigest", "linkedCallDigest"):
            if not isinstance(call[field], str) or DIGEST_RE.fullmatch(call[field]) is None:
                raise CdrEvidenceError(f"fixture CDR {field} is invalid")
        _integer(call["durationSeconds"], "fixture duration", 1, 120)
        _integer(call["billableSeconds"], "fixture billsec", 1, call["durationSeconds"])
        for field in ("startedAt", "answeredAt", "endedAt"):
            if not isinstance(call[field], str) or CDR_TIMESTAMP_RE.fullmatch(call[field]) is None:
                raise CdrEvidenceError(f"fixture CDR {field} is invalid")
    return record


def validate_edge_cdr(value: object) -> Mapping[str, Any]:
    record = _exact_mapping(value, EDGE_FIELDS, "Edge CDR evidence")
    unsigned = dict(record)
    claimed = unsigned.pop("edgeCdrDigest")
    if not isinstance(claimed, str) or claimed != sha256_digest(canonical_bytes(unsigned)):
        raise CdrEvidenceError("Edge CDR evidence self-digest is invalid")
    if (
        record["apiVersion"] != EDGE_API_VERSION
        or record["kind"] != "SyntheticEdgeCdrEvidence"
        or record["scope"] != SCOPE
        or record["status"] != "TWO_LOGICAL_SYNTHETIC_CALLS_ACCOUNTED"
        or record["liveM365Interoperability"] != LIVE_M365_STATUS
    ):
        raise CdrEvidenceError("Edge CDR evidence expands beyond the synthetic contract")
    node = _exact_mapping(record["nodeIdentity"], EDGE_NODE_FIELDS, "Edge node identity")
    test_id, node_id, _ = _test_identity(record["testId"], node["nodeId"])
    if node_id not in {"sbc1", "sbc2"} or node["slot"] != ("A" if node_id == "sbc1" else "B"):
        raise CdrEvidenceError("Edge evidence is not a fixed POC node/slot")
    _integer(node["generation"], "Edge generation", 1, 2**31 - 1)
    if not isinstance(node["routeToken"], str) or re.fullmatch(r"[0-9A-F]{12}", node["routeToken"]) is None:
        raise CdrEvidenceError("Edge route token is invalid")
    for field in ("nodeFactsDigest", "runtimeAuthorityDigest"):
        if not isinstance(node[field], str) or DIGEST_RE.fullmatch(node[field]) is None:
            raise CdrEvidenceError(f"Edge {field} is invalid")
    for field in ("allocationId", "clusterId", "serviceInstanceId", "tenantContextId"):
        if not isinstance(node[field], str) or re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?", node[field]) is None:
            raise CdrEvidenceError(f"Edge {field} is invalid")
    journal = _exact_mapping(record["sourceJournal"], EDGE_JOURNAL_FIELDS, "Edge source journal")
    if (
        journal["marker"] != "VIVO_SYNTHETIC_CDR_V1"
        or journal["systemdUnit"] != "opensips.service"
        or journal["recordCount"] != 4
    ):
        raise CdrEvidenceError("Edge source journal contract is invalid")
    _integer(journal["opensipsUid"], "OpenSIPS UID", 1, 2**31 - 1)
    calls = record["calls"]
    if not isinstance(calls, list) or len(calls) != 2:
        raise CdrEvidenceError("Edge CDR evidence must contain two logical calls")
    for expected, item in zip(DIRECTIONS, calls):
        call = _exact_mapping(item, EDGE_CALL_FIELDS, "Edge CDR record")
        if call["direction"] != expected or call["result"] != "ACCEPTED":
            raise CdrEvidenceError("Edge CDR direction or result is invalid")
        start = _integer(call["startRealtimeUnixMicroseconds"], "Edge call start", 1, 2**63 - 1)
        final = _integer(call["finalRealtimeUnixMicroseconds"], "Edge call final", start, 2**63 - 1)
        elapsed = _integer(call["elapsedMilliseconds"], "Edge call elapsed", 0, 120000)
        if elapsed != (final - start) // 1000:
            raise CdrEvidenceError("Edge call elapsed time is inconsistent")
        for field in (
            "startJournalRecordDigest",
            "finalJournalRecordDigest",
            "journalBootIdDigest",
        ):
            if not isinstance(call[field], str) or DIGEST_RE.fullmatch(call[field]) is None:
                raise CdrEvidenceError(f"Edge CDR {field} is invalid")
    return record


def _manifest_entries(raw: bytes) -> Mapping[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CdrEvidenceError("fixture manifest is not UTF-8") from exc
    if not text.endswith("\n"):
        raise CdrEvidenceError("fixture manifest is not newline terminated")
    result: dict[str, str] = {}
    previous = ""
    for line in text.splitlines():
        match = MANIFEST_LINE_RE.fullmatch(line)
        if match is None or match.group(2) in result or (previous and match.group(2) <= previous):
            raise CdrEvidenceError("fixture manifest is malformed, duplicated, or unsorted")
        result[match.group(2)] = match.group(1)
        previous = match.group(2)
    return result


def _secure_directory(path: Path) -> Path:
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.geteuid()
    ):
        raise CdrEvidenceError("reconciliation directory must be runner-owned real mode 0700")
    return path.resolve(strict=True)


def _secure_read(path: Path, maximum: int) -> bytes:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.geteuid()
        or not 1 <= metadata.st_size <= maximum
    ):
        raise CdrEvidenceError(f"{path.name} violates the protected input contract")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_mode != metadata.st_mode
            or opened.st_uid != metadata.st_uid
            or opened.st_nlink != metadata.st_nlink
            or opened.st_size != metadata.st_size
        ):
            raise CdrEvidenceError(f"{path.name} changed before it was opened")
        raw = _read_descriptor(descriptor, maximum)
    finally:
        os.close(descriptor)
    if len(raw) != metadata.st_size:
        raise CdrEvidenceError(f"{path.name} changed while read")
    return raw


def _read_descriptor(descriptor: int, maximum: int) -> bytes:
    chunks = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise CdrEvidenceError("bounded input grew beyond its maximum size")


def _bounded_real_read(path: Path, maximum: int) -> bytes:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or not 1 <= metadata.st_size <= maximum
    ):
        raise CdrEvidenceError(f"{path} is not one bounded real input file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_mode != metadata.st_mode
            or opened.st_uid != metadata.st_uid
            or opened.st_nlink != metadata.st_nlink
            or opened.st_size != metadata.st_size
        ):
            raise CdrEvidenceError(f"{path} changed before it was opened")
        raw = _read_descriptor(descriptor, maximum)
    finally:
        os.close(descriptor)
    if len(raw) != metadata.st_size:
        raise CdrEvidenceError(f"{path} changed while read")
    return raw


def compile_reconciliation(directory: Path) -> Mapping[str, Any]:
    root = _secure_directory(directory)
    expected = {
        "edge-cdr.json",
        "fixture-asterisk-cdr-delta.csv",
        "fixture-cdr.json",
        "fixture-MANIFEST.sha256",
        "fixture-RESULT",
    }
    if {entry.name for entry in root.iterdir()} != expected:
        raise CdrEvidenceError("reconciliation directory has an unexpected file set")
    edge_raw = _secure_read(root / "edge-cdr.json", MAX_EVIDENCE_BYTES)
    fixture_raw = _secure_read(root / "fixture-cdr.json", MAX_EVIDENCE_BYTES)
    asterisk_raw = _secure_read(root / "fixture-asterisk-cdr-delta.csv", MAX_CDR_BYTES)
    manifest_raw = _secure_read(root / "fixture-MANIFEST.sha256", MAX_EVIDENCE_BYTES)
    result_raw = _secure_read(root / "fixture-RESULT", 64)
    if result_raw != b"PASS\n":
        raise CdrEvidenceError("fixture RESULT is not PASS")

    fixture = validate_fixture_cdr(_parse_json(fixture_raw, "fixture-cdr.json"))
    rebuilt = compile_fixture_cdr(asterisk_raw, fixture["testId"], fixture["nodeId"])
    if rebuilt != fixture:
        raise CdrEvidenceError("fixture CDR evidence differs from the raw Asterisk delta")
    edge = validate_edge_cdr(_parse_json(edge_raw, "edge-cdr.json"))
    if edge["testId"] != fixture["testId"] or edge["nodeIdentity"]["nodeId"] != fixture["nodeId"]:
        raise CdrEvidenceError("Edge and fixture evidence name different test/node identities")

    manifest = _manifest_entries(manifest_raw)
    for name, raw in (
        ("./RESULT", result_raw),
        ("./asterisk-cdr-delta.csv", asterisk_raw),
        ("./fixture-cdr.json", fixture_raw),
    ):
        if manifest.get(name) != hashlib.sha256(raw).hexdigest():
            raise CdrEvidenceError(f"fixture manifest does not bind {name}")

    matched_calls = []
    for direction, fixture_call, edge_call in zip(
        DIRECTIONS, fixture["records"], edge["calls"]
    ):
        if fixture_call["direction"] != direction or edge_call["direction"] != direction:
            raise CdrEvidenceError("CDR arrays are not in exact logical direction order")
        matched_calls.append(
            {
                "direction": direction,
                "edgeElapsedMilliseconds": edge_call["elapsedMilliseconds"],
                "edgeResult": "ACCEPTED",
                "fixtureBillableSeconds": fixture_call["billableSeconds"],
                "fixtureDisposition": "ANSWERED",
                "fixtureRecordDigest": fixture_call["recordDigest"],
            }
        )
    unsigned: dict[str, Any] = {
        "apiVersion": RECONCILIATION_API_VERSION,
        "calledNumber": CALLED_NUMBER,
        "kind": "SyntheticEdgeFixtureCdrReconciliation",
        "liveM365Interoperability": LIVE_M365_STATUS,
        "matchedCalls": matched_calls,
        "nodeIdentity": edge["nodeIdentity"],
        "scope": SCOPE,
        "sourceDigests": {
            "edgeCdr": sha256_digest(edge_raw),
            "fixtureCdr": sha256_digest(fixture_raw),
            "fixtureManifest": sha256_digest(manifest_raw),
        },
        "status": "SYNTHETIC_EDGE_FIXTURE_CDR_RECONCILED",
        "testId": fixture["testId"],
    }
    result = dict(unsigned)
    result["reconciliationDigest"] = sha256_digest(canonical_bytes(unsigned))
    return result


def _atomic_new(path: Path, content: bytes, mode: int) -> None:
    if path.exists() or path.is_symlink():
        raise CdrEvidenceError(f"refusing to replace existing {path}")
    parent = path.parent
    metadata = parent.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise CdrEvidenceError("output parent must be a real directory")
    temporary = parent / f".{path.name}.{os.getpid()}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        mode,
    )
    try:
        _write_all(descriptor, content)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    os.replace(temporary, path)
    directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _write_all(descriptor: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("bounded evidence write made no progress")
        remaining = remaining[written:]


def _normalize_command(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise CdrEvidenceError("fixture normalization must run as root")
    raw = _bounded_real_read(Path(args.cdr_csv), MAX_CDR_BYTES)
    evidence = compile_fixture_cdr(raw, args.test_id, args.node)
    _atomic_new(Path(args.output), canonical_bytes(evidence), 0o640)
    print(f"SYNTHETIC_FIXTURE_CDR_WRITTEN {evidence['fixtureCdrDigest']}")
    return 0


def _reconcile_command(args: argparse.Namespace) -> int:
    evidence = compile_reconciliation(Path(args.evidence_dir))
    path = Path(args.evidence_dir) / "reconciliation.json"
    _atomic_new(path, canonical_bytes(evidence), 0o600)
    print(f"SYNTHETIC_CDR_RECONCILIATION_WRITTEN {evidence['reconciliationDigest']}")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    modes = result.add_subparsers(dest="command", required=True)
    normalize = modes.add_parser("normalize-fixture")
    normalize.add_argument("--cdr-csv", required=True)
    normalize.add_argument("--node", choices=("sbc1", "sbc2"), required=True)
    normalize.add_argument("--output", required=True)
    normalize.add_argument("--test-id", required=True)
    normalize.set_defaults(handler=_normalize_command)
    reconcile = modes.add_parser("reconcile")
    reconcile.add_argument("--evidence-dir", required=True)
    reconcile.set_defaults(handler=_reconcile_command)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        return args.handler(args)
    except (CdrEvidenceError, OSError) as exc:
        print(f"synthetic CDR evidence rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
