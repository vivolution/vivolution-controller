#!/usr/bin/python3
"""Export one bounded root-owned synthetic OpenSIPS CDR evidence record.

This tool is deliberately unavailable for Direct Routing.  It reads only the
fixed root authority/facts, the ``opensips.service`` journal window derived
from one fixture test ID, and the fixed local evidence directory.  It performs
no network operation and never records SIP identities, Call-IDs, or numbers.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence


sys.path.insert(0, "/usr/lib/vivolution-edge/python")
from edge.compiler.core import NodeFacts  # noqa: E402
from edge.runtime.contracts import RuntimeAuthority  # noqa: E402


API_VERSION = "edge.vivolution.ae/synthetic-edge-cdr/v0.1"
SCOPE = "SYNTHETIC_PRIVATE_NO_PSTN"
LIVE_M365_STATUS = "NOT_ASSERTED"
MARKER = "VIVO_SYNTHETIC_CDR_V1"
OPENSIPS_SCRIPT_LOG_PREFIX = "NOTICE:script: "
DIRECTIONS = (
    "TEAMS_FIXTURE_TO_PBX_FIXTURE",
    "PBX_FIXTURE_TO_TEAMS_FIXTURE",
)
FINAL_RESULTS = {
    "ACCEPTED",
    "MEDIA_ANCHOR_FAILED",
    "RELAY_FAILED",
    "SIP_FAILURE",
}
TEST_ID_RE = re.compile(r"\A([0-9]{8}T[0-9]{6}Z)-(sbc[12])-([0-9]{1,10})\Z")
BOOT_ID_RE = re.compile(r"\A[0-9a-f]{32}\Z")
START_RE = re.compile(
    rf"\A{MARKER}\|event=START\|route=([0-9A-F]{{12}})"
    r"\|direction=(TEAMS_FIXTURE_TO_PBX_FIXTURE|PBX_FIXTURE_TO_TEAMS_FIXTURE)"
    r"\|test_id=([0-9]{8}T[0-9]{6}Z-sbc[12]-[0-9]{1,10})\Z"
)
FINAL_RE = re.compile(
    rf"\A{MARKER}\|event=FINAL\|route=([0-9A-F]{{12}})"
    r"\|direction=(TEAMS_FIXTURE_TO_PBX_FIXTURE|PBX_FIXTURE_TO_TEAMS_FIXTURE)"
    r"\|test_id=([0-9]{8}T[0-9]{6}Z-sbc[12]-[0-9]{1,10})"
    r"\|result=(ACCEPTED|MEDIA_ANCHOR_FAILED|RELAY_FAILED|SIP_FAILURE)\Z"
)
NODE_FACTS_PATH = Path("/etc/vivolution-edge/node-facts.json")
RUNTIME_AUTHORITY_PATH = Path("/var/lib/vivolution-edge/runtime/runtime-authority.json")
EVIDENCE_ROOT = Path("/var/lib/vivolution-edge/synthetic-cdr-evidence")
JOURNALCTL = "/usr/bin/journalctl"
MAX_AUTHORITY_BYTES = 256 * 1024
MAX_JOURNAL_BYTES = 1024 * 1024
MAX_JOURNAL_RECORDS = 4096
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_EVIDENCE_FILES = 512
MAX_EVIDENCE_TOTAL_BYTES = 16 * 1024 * 1024


class EdgeCdrExportError(ValueError):
    """The local host cannot prove the exact synthetic CDR contract."""


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def sha256_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _route_token(facts: NodeFacts) -> str:
    material = "{}\0{}\0{}".format(
        facts.tenant_context_id, facts.allocation_id, facts.node_id
    ).encode("ascii")
    return hashlib.sha256(material).hexdigest()[:12].upper()


def _test_identity(test_id: str, node_id: str | None = None) -> tuple[str, int]:
    match = TEST_ID_RE.fullmatch(test_id)
    if match is None:
        raise EdgeCdrExportError("test ID is outside the fixed synthetic format")
    if node_id is not None and match.group(2) != node_id:
        raise EdgeCdrExportError("test ID node does not match local immutable facts")
    timestamp = datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ").replace(
        tzinfo=timezone.utc
    )
    return match.group(2), int(timestamp.timestamp())


def _secure_read(path: Path, mode: int, maximum: int) -> bytes:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != mode
        or not 1 <= metadata.st_size <= maximum
    ):
        raise EdgeCdrExportError(f"{path} violates its fixed root-owned file contract")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_mode != metadata.st_mode
            or opened.st_uid != metadata.st_uid
            or opened.st_gid != metadata.st_gid
            or opened.st_nlink != metadata.st_nlink
            or opened.st_size != metadata.st_size
        ):
            raise EdgeCdrExportError(f"{path} changed before it was opened")
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise EdgeCdrExportError(f"{path} grew beyond its size bound")
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(raw) != metadata.st_size:
        raise EdgeCdrExportError(f"{path} changed while read")
    return raw


def _json_mapping(raw: bytes, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EdgeCdrExportError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise EdgeCdrExportError(f"{label} must be an object")
    return value


def _journal_rows(test_id: str, test_epoch: int) -> list[Mapping[str, Any]]:
    since = f"@{test_epoch - 30}"
    until = f"@{test_epoch + 180}"
    command = [
        JOURNALCTL,
        "--no-pager",
        "--quiet",
        "--output=json",
        "--unit=opensips.service",
        f"--since={since}",
        f"--until={until}",
        f"--grep={test_id}",
    ]
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=errors,
                timeout=10,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise EdgeCdrExportError("bounded OpenSIPS journal query timed out") from exc
        output_size = os.fstat(output.fileno()).st_size
        error_size = os.fstat(errors.fileno()).st_size
        if output_size > MAX_JOURNAL_BYTES or error_size > 64 * 1024:
            raise EdgeCdrExportError("bounded OpenSIPS journal query was oversized")
        output.seek(0)
        errors.seek(0)
        raw = output.read()
        error = errors.read().decode("utf-8", errors="replace").strip()
    if completed.returncode != 0:
        raise EdgeCdrExportError(
            "OpenSIPS journal query failed: " + (error[:300] or "unknown journalctl error")
        )
    rows: list[Mapping[str, Any]] = []
    for line in raw.splitlines():
        if len(rows) >= MAX_JOURNAL_RECORDS or len(line) > 64 * 1024:
            raise EdgeCdrExportError("OpenSIPS journal record bound was exceeded")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EdgeCdrExportError("journalctl emitted invalid JSON") from exc
        if not isinstance(value, dict):
            raise EdgeCdrExportError("journalctl emitted a non-object record")
        rows.append(value)
    return rows


def _marker_from_message(message: object) -> str | None:
    if not isinstance(message, str) or "\x00" in message or "\r" in message:
        return None
    stripped = message.rstrip("\n")
    if "\n" in stripped:
        if MARKER in stripped:
            raise EdgeCdrExportError("OpenSIPS CDR marker spans multiple log lines")
        return None
    if stripped.startswith(MARKER):
        marker = stripped
    elif stripped.startswith(OPENSIPS_SCRIPT_LOG_PREFIX + MARKER):
        marker = stripped[len(OPENSIPS_SCRIPT_LOG_PREFIX) :]
    elif MARKER in stripped:
        raise EdgeCdrExportError("OpenSIPS CDR marker has an unexpected log prefix")
    else:
        return None
    if marker.find(MARKER, len(MARKER)) >= 0:
        raise EdgeCdrExportError("one journal message contains duplicate CDR markers")
    return marker


def compile_edge_cdr(
    rows: Sequence[Mapping[str, Any]],
    facts: NodeFacts,
    authority: RuntimeAuthority,
    *,
    node_facts_raw: bytes,
    runtime_authority_raw: bytes,
    opensips_uid: int,
    test_id: str,
) -> Mapping[str, Any]:
    """Validate four trusted journal events and return canonical Edge evidence."""

    _, test_epoch = _test_identity(test_id, facts.node_id)
    if (
        authority.profile != "SYNTHETIC_PRIVATE"
        or authority.node_id != facts.node_id
        or authority.slot != facts.slot
        or authority.generation != facts.generation
        or facts.node_id not in {"sbc1", "sbc2"}
        or facts.slot != ("A" if facts.node_id == "sbc1" else "B")
    ):
        raise EdgeCdrExportError("Edge CDR export is restricted to the fixed synthetic node authority")
    token = _route_token(facts)
    events: dict[tuple[str, str], Mapping[str, Any]] = {}
    marker_cursors: set[str] = set()
    for row in rows:
        marker = _marker_from_message(row.get("MESSAGE"))
        if marker is None:
            continue
        if (
            row.get("_SYSTEMD_UNIT") != "opensips.service"
            or row.get("_UID") != str(opensips_uid)
            or not (
                row.get("_COMM") == "opensips"
                or row.get("SYSLOG_IDENTIFIER") == "opensips"
            )
        ):
            raise EdgeCdrExportError("CDR marker lacks trusted opensips.service journal provenance")
        boot_id = row.get("_BOOT_ID")
        cursor = row.get("__CURSOR")
        realtime = row.get("__REALTIME_TIMESTAMP")
        if (
            not isinstance(boot_id, str)
            or BOOT_ID_RE.fullmatch(boot_id) is None
            or not isinstance(cursor, str)
            or not 1 <= len(cursor) <= 512
            or not isinstance(realtime, str)
            or not realtime.isdigit()
        ):
            raise EdgeCdrExportError("CDR journal provenance fields are invalid")
        realtime_value = int(realtime)
        if not (test_epoch - 5) * 1_000_000 <= realtime_value <= (test_epoch + 120) * 1_000_000:
            raise EdgeCdrExportError("CDR journal timestamp is outside the fixture test window")
        start_match = START_RE.fullmatch(marker)
        final_match = FINAL_RE.fullmatch(marker)
        if start_match is not None:
            event, route, direction, marker_test, result = (
                "START",
                start_match.group(1),
                start_match.group(2),
                start_match.group(3),
                None,
            )
        elif final_match is not None:
            event, route, direction, marker_test, result = (
                "FINAL",
                final_match.group(1),
                final_match.group(2),
                final_match.group(3),
                final_match.group(4),
            )
        else:
            raise EdgeCdrExportError("OpenSIPS CDR marker has an invalid exact shape")
        if route != token or marker_test != test_id or direction not in DIRECTIONS:
            raise EdgeCdrExportError("OpenSIPS CDR marker differs from immutable route/test identity")
        if result is not None and result not in FINAL_RESULTS:
            raise EdgeCdrExportError("OpenSIPS CDR final result is unsupported")
        if cursor in marker_cursors:
            raise EdgeCdrExportError("OpenSIPS CDR markers reuse a journal cursor")
        marker_cursors.add(cursor)
        key = (direction, event)
        if key in events:
            raise EdgeCdrExportError(f"duplicate OpenSIPS {direction} {event} CDR marker")
        minimal = {
            "bootId": boot_id,
            "cursor": cursor,
            "event": event,
            "message": marker,
            "realtimeUnixMicroseconds": realtime_value,
            "result": result,
        }
        events[key] = minimal

    expected = {(direction, event) for direction in DIRECTIONS for event in ("START", "FINAL")}
    if set(events) != expected:
        raise EdgeCdrExportError("OpenSIPS journal does not contain exactly two complete call records")
    calls = []
    for direction in DIRECTIONS:
        start = events[(direction, "START")]
        final = events[(direction, "FINAL")]
        if final["realtimeUnixMicroseconds"] < start["realtimeUnixMicroseconds"]:
            raise EdgeCdrExportError("OpenSIPS final CDR marker predates its start")
        if final["bootId"] != start["bootId"]:
            raise EdgeCdrExportError("one synthetic call crossed a journal boot identity")
        elapsed = (final["realtimeUnixMicroseconds"] - start["realtimeUnixMicroseconds"]) // 1000
        if elapsed > 120_000:
            raise EdgeCdrExportError("one synthetic call exceeded the bounded accounting window")
        calls.append(
            {
                "direction": direction,
                "elapsedMilliseconds": elapsed,
                "finalJournalRecordDigest": sha256_digest(canonical_bytes(final)),
                "finalRealtimeUnixMicroseconds": final["realtimeUnixMicroseconds"],
                "journalBootIdDigest": sha256_digest(final["bootId"].encode("ascii")),
                "result": final["result"],
                "startJournalRecordDigest": sha256_digest(canonical_bytes(start)),
                "startRealtimeUnixMicroseconds": start["realtimeUnixMicroseconds"],
            }
        )
    accepted = all(call["result"] == "ACCEPTED" for call in calls)
    unsigned: dict[str, Any] = {
        "apiVersion": API_VERSION,
        "calls": calls,
        "kind": "SyntheticEdgeCdrEvidence",
        "liveM365Interoperability": LIVE_M365_STATUS,
        "nodeIdentity": {
            "allocationId": facts.allocation_id,
            "clusterId": facts.cluster_id,
            "generation": facts.generation,
            "nodeFactsDigest": sha256_digest(node_facts_raw),
            "nodeId": facts.node_id,
            "routeToken": token,
            "runtimeAuthorityDigest": sha256_digest(runtime_authority_raw),
            "serviceInstanceId": facts.service_instance_id,
            "slot": facts.slot,
            "tenantContextId": facts.tenant_context_id,
        },
        "scope": SCOPE,
        "sourceJournal": {
            "marker": MARKER,
            "opensipsUid": opensips_uid,
            "recordCount": len(events),
            "systemdUnit": "opensips.service",
        },
        "status": (
            "TWO_LOGICAL_SYNTHETIC_CALLS_ACCOUNTED"
            if accepted
            else "SYNTHETIC_CALL_FAILURE_ACCOUNTED"
        ),
        "testId": test_id,
    }
    evidence = dict(unsigned)
    evidence["edgeCdrDigest"] = sha256_digest(canonical_bytes(unsigned))
    return evidence


def _validate_evidence_root() -> tuple[int, int]:
    metadata = EVIDENCE_ROOT.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise EdgeCdrExportError("synthetic CDR evidence root violates its fixed root-only contract")
    count = 0
    total = 0
    for entry in EVIDENCE_ROOT.iterdir():
        entry_metadata = entry.lstat()
        if (
            TEST_ID_RE.fullmatch(entry.stem) is None
            or entry.suffix != ".json"
            or not stat.S_ISREG(entry_metadata.st_mode)
            or stat.S_ISLNK(entry_metadata.st_mode)
            or entry_metadata.st_nlink != 1
            or entry_metadata.st_uid != 0
            or entry_metadata.st_gid != 0
            or stat.S_IMODE(entry_metadata.st_mode) != 0o400
            or not 1 <= entry_metadata.st_size <= MAX_EVIDENCE_BYTES
        ):
            raise EdgeCdrExportError("synthetic CDR evidence root contains an invalid entry")
        count += 1
        total += entry_metadata.st_size
    if count > MAX_EVIDENCE_FILES or total > MAX_EVIDENCE_TOTAL_BYTES:
        raise EdgeCdrExportError("synthetic CDR evidence spool exceeded its fixed bound")
    return count, total


def _persist(test_id: str, content: bytes) -> None:
    count, total = _validate_evidence_root()
    destination = EVIDENCE_ROOT / f"{test_id}.json"
    if destination.exists() or destination.is_symlink():
        if _secure_read(destination, 0o400, MAX_EVIDENCE_BYTES) != content:
            raise EdgeCdrExportError("existing immutable CDR evidence differs from the journal")
        return
    if count >= MAX_EVIDENCE_FILES or total + len(content) > MAX_EVIDENCE_TOTAL_BYTES:
        raise EdgeCdrExportError("synthetic CDR evidence spool has no remaining capacity")
    temporary = EVIDENCE_ROOT / f".{test_id}.{os.getpid()}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o400,
    )
    try:
        remaining = memoryview(content)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("bounded evidence write made no progress")
            remaining = remaining[written:]
        os.fchmod(descriptor, 0o400)
        os.fchown(descriptor, 0, 0)
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    os.replace(temporary, destination)
    directory_fd = os.open(EVIDENCE_ROOT, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def export(test_id: str) -> Mapping[str, Any]:
    if os.geteuid() != 0:
        raise EdgeCdrExportError("synthetic Edge CDR export must run as root")
    node_raw = _secure_read(NODE_FACTS_PATH, 0o600, MAX_AUTHORITY_BYTES)
    authority_raw = _secure_read(RUNTIME_AUTHORITY_PATH, 0o600, MAX_AUTHORITY_BYTES)
    facts = NodeFacts.from_mapping(_json_mapping(node_raw, "node facts"))
    authority = RuntimeAuthority.from_mapping(_json_mapping(authority_raw, "runtime authority"))
    _, epoch = _test_identity(test_id, facts.node_id)
    opensips_uid = pwd.getpwnam("opensips").pw_uid
    if opensips_uid <= 0:
        raise EdgeCdrExportError("OpenSIPS must remain an unprivileged service identity")
    rows = _journal_rows(test_id, epoch)
    evidence = compile_edge_cdr(
        rows,
        facts,
        authority,
        node_facts_raw=node_raw,
        runtime_authority_raw=authority_raw,
        opensips_uid=opensips_uid,
        test_id=test_id,
    )
    content = canonical_bytes(evidence)
    if len(content) > MAX_EVIDENCE_BYTES:
        raise EdgeCdrExportError("compiled Edge CDR evidence is oversized")
    _persist(test_id, content)
    return evidence


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--test-id", required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        evidence = export(args.test_id)
    except (EdgeCdrExportError, KeyError, OSError, ValueError) as exc:
        print(f"synthetic Edge CDR export rejected: {exc}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_bytes(evidence))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
