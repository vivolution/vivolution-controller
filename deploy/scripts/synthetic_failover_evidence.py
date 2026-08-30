#!/usr/bin/env python3
"""Compile strict, non-secret evidence for the private SBC failover exercise.

The Ansible workflow collects three independently manifested fixture calls in
one protected local directory.  This compiler accepts only that fixed layout,
checks the call/CDR/RTP summaries and the 120-second timing contract, and emits
canonical evidence.  It does not perform network operations.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping


REQUEST_API_VERSION = "edge.vivolution.ae/synthetic-failover-request/v0.2"
EVIDENCE_API_VERSION = "edge.vivolution.ae/synthetic-failover-evidence/v0.2"
BUNDLE_API_VERSION = "edge.vivolution.ae/synthetic-fixture-result-bundle/v0.1"
ACKNOWLEDGEMENT = "RUN_SYNTHETIC_SBC1_TO_SBC2_FAILOVER_WITHIN_120_SECONDS"
LIVE_M365_STATUS = "NOT_ASSERTED"
GATE_SECONDS = 120
CALLED_NUMBER = "+9710000001001"

_REQUEST_KEYS = {
    "acknowledgement",
    "alternate",
    "apiVersion",
    "completedAtEpochMs",
    "completedAtMonotonicNs",
    "failureStartedAtEpochMs",
    "failureStartedAtMonotonicNs",
    "gateSeconds",
    "liveM365Interoperability",
    "primary",
    "restoredPrimary",
    "routeIdentity",
    "testedFailure",
}
_NODE_KEYS = {
    "activeManifestDigest",
    "activeSequence",
    "generation",
    "nodeId",
    "privateIpv4",
    "slot",
}
_ROUTE_KEYS = {
    "allocationId",
    "calledNumber",
    "clusterId",
    "customerAccountId",
    "directions",
    "m365TenantId",
    "serviceInstanceId",
    "tenantContextId",
}
_FAILURE_KEYS = {
    "injection",
    "primaryNodeId",
    "servicesStopped",
    "signalingListener",
}
_SUMMARY_KEYS = {
    "cdr_records",
    "node",
    "rtp_echo_delta",
    "rtp_selected_peer_delta",
    "rtp_uas_delta",
    "target",
    "test_id",
}
_PHASES = ("primary", "alternate", "restored")
_BUNDLE_KEYS = {"apiVersion", "artifacts", "manifestBase64", "testId"}
_RECONCILIATION_KEYS = {
    "apiVersion",
    "calledNumber",
    "kind",
    "liveM365Interoperability",
    "matchedCalls",
    "nodeIdentity",
    "reconciliationDigest",
    "scope",
    "sourceDigests",
    "status",
    "testId",
}
_RECONCILIATION_NODE_KEYS = {
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
_RECONCILIATION_CALL_KEYS = {
    "direction",
    "edgeElapsedMilliseconds",
    "edgeResult",
    "fixtureBillableSeconds",
    "fixtureDisposition",
    "fixtureRecordDigest",
}
_RECONCILIATION_SOURCE_KEYS = {"edgeCdr", "fixtureCdr", "fixtureManifest"}
_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_ID_RE = re.compile(r"\A[a-z0-9][a-z0-9_.:-]{0,127}\Z")
_TEST_ID_RE = re.compile(r"\A([0-9]{8}T[0-9]{6}Z)-(sbc[12])-[0-9]+\Z")
_MANIFEST_LINE_RE = re.compile(
    r"\A([0-9a-f]{64})  (\./[A-Za-z0-9][A-Za-z0-9._-]{0,127})\Z"
)

# The fixture writes only these bounded, non-secret result artifacts.  The
# manifest can omit the two PBX/UAS snapshots when their upstream optional
# files did not exist, but it cannot introduce arbitrary paths or logs.
_PERMITTED_MANIFEST_ARTIFACTS = {
    "RESULT",
    "asterisk-cdr-delta.csv",
    "asterisk-originate.log",
    "asterisk-set-test-id.log",
    "fixture-cdr-normalization.log",
    "fixture-cdr.json",
    "fixture-journal.log",
    "listeners.txt",
    "nftables.txt",
    "pbx-to-teams-peer-rtp-before.count",
    "pbx-to-teams-rtp-after.json",
    "pbx-to-teams-rtp-before.count",
    "pbx-to-teams-rtp-echo-before.count",
    "pbx-to-teams-sipp-errors.log",
    "readiness.txt",
    "summary.txt",
    "teams-to-pbx-rtp.json",
    "teams-to-pbx-runner.log",
    "teams-to-pbx-sipp-errors.log",
    "teams-to-pbx-sipp-stats.csv",
    "teams-to-pbx-summary.json",
    "unit-policy.txt",
}
_REQUIRED_MANIFEST_ARTIFACTS = {
    "RESULT",
    "asterisk-cdr-delta.csv",
    "fixture-cdr.json",
    "readiness.txt",
    "summary.txt",
    "teams-to-pbx-rtp.json",
    "teams-to-pbx-summary.json",
}
_FIXTURE_OWNED_ARTIFACTS = {
    "teams-to-pbx-rtp.json",
    "teams-to-pbx-sipp-errors.log",
    "teams-to-pbx-sipp-stats.csv",
    "teams-to-pbx-summary.json",
}
_EMPTY_PERMITTED_ARTIFACTS = {
    "fixture-cdr-normalization.log",
    "fixture-journal.log",
    "pbx-to-teams-sipp-errors.log",
    "teams-to-pbx-runner.log",
    "teams-to-pbx-sipp-errors.log",
}
_MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
_MAX_BUNDLE_BYTES = 40 * 1024 * 1024


class FailoverEvidenceError(ValueError):
    """The collected workflow evidence does not satisfy the fixed contract."""


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _exact_mapping(value: object, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise FailoverEvidenceError(f"{label} must have exact keys {sorted(keys)}")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FailoverEvidenceError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise FailoverEvidenceError(f"{label} is outside its fixed bounds")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise FailoverEvidenceError(f"{label} is not a bounded identifier")
    return value


def _validate_directory(directory: Path) -> Path:
    try:
        metadata = directory.lstat()
    except FileNotFoundError as exc:
        raise FailoverEvidenceError("evidence directory does not exist") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise FailoverEvidenceError("evidence directory must be a real directory")
    if stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != os.getuid():
        raise FailoverEvidenceError("evidence directory must be owned by the runner and mode 0700")
    return directory.resolve(strict=True)


def _validate_evidence_layout(directory: Path) -> None:
    expected = {
        "request.json",
        *(f"{phase}-bundle.json" for phase in _PHASES),
        *(f"{phase}-cdr-reconciliation.json" for phase in _PHASES),
        *(f"{phase}-edge-cdr.json" for phase in _PHASES),
    }
    actual = {entry.name for entry in os.scandir(directory)}
    if "acceptance.json" in actual:
        actual.remove("acceptance.json")
    if actual != expected:
        raise FailoverEvidenceError(
            "evidence directory must contain only request.json, three result bundles, three Edge CDRs, and three CDR reconciliations"
        )


def _read_fixed_file(directory: Path, name: str, maximum: int = 1024 * 1024) -> bytes:
    path = directory / name
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise FailoverEvidenceError(f"{name} must be runner-owned, single-link, regular mode 0600")
    if metadata.st_size < 1 or metadata.st_size > maximum:
        raise FailoverEvidenceError(f"{name} is empty or oversized")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
            raise FailoverEvidenceError(f"{name} changed before it was read")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(content) != metadata.st_size
        or after.st_size != metadata.st_size
        or after.st_mtime_ns != metadata.st_mtime_ns
        or after.st_ctime_ns != metadata.st_ctime_ns
    ):
        raise FailoverEvidenceError(f"{name} changed while it was read")
    return content


def _read_source_file(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
    minimum: int = 1,
    maximum: int = _MAX_ARTIFACT_BYTES,
) -> bytes:
    """Read one fixture file without following or accepting mutable aliases."""

    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise FailoverEvidenceError(f"fixture artifact {path.name} is missing") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != expected_uid
        or before.st_gid != expected_gid
        or stat.S_IMODE(before.st_mode) != expected_mode
    ):
        raise FailoverEvidenceError(
            f"fixture artifact {path.name} has unsafe type, links, owner, group, or mode"
        )
    if before.st_size < minimum or before.st_size > maximum:
        raise FailoverEvidenceError(f"fixture artifact {path.name} is empty or oversized")

    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size != before.st_size
        ):
            raise FailoverEvidenceError(f"fixture artifact {path.name} changed before read")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(content) != before.st_size
        or after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_size != before.st_size
        or after.st_mtime_ns != before.st_mtime_ns
        or after.st_ctime_ns != before.st_ctime_ns
    ):
        raise FailoverEvidenceError(f"fixture artifact {path.name} changed while read")
    return content


def _parse_json(raw: bytes, label: str) -> Mapping[str, Any]:
    try:
        text = raw.decode("utf-8")
        value = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FailoverEvidenceError(f"{label} is not one UTF-8 JSON document") from exc
    if _canonical_bytes(value).decode("utf-8") != text:
        raise FailoverEvidenceError(f"{label} is not canonical JSON")
    if not isinstance(value, dict):
        raise FailoverEvidenceError(f"{label} must be a JSON object")
    return value


def _parse_summary(raw: bytes, phase: str) -> Mapping[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FailoverEvidenceError(f"{phase} summary is not UTF-8") from exc
    if not text.endswith("\n"):
        raise FailoverEvidenceError(f"{phase} summary is not newline terminated")
    result: dict[str, str] = {}
    for line in text.splitlines():
        if line.count("=") != 1:
            raise FailoverEvidenceError(f"{phase} summary contains an invalid line")
        key, value = line.split("=", 1)
        if key in result:
            raise FailoverEvidenceError(f"{phase} summary repeats {key}")
        result[key] = value
    if set(result) != _SUMMARY_KEYS:
        raise FailoverEvidenceError(f"{phase} summary has an unexpected shape")
    for key in (
        "cdr_records",
        "rtp_echo_delta",
        "rtp_selected_peer_delta",
        "rtp_uas_delta",
    ):
        if not result[key].isdigit() or int(result[key]) < 1:
            raise FailoverEvidenceError(f"{phase} summary {key} did not prove traffic")
    if int(result["cdr_records"]) < 2:
        raise FailoverEvidenceError(f"{phase} summary did not prove both call directions")
    match = _TEST_ID_RE.fullmatch(result["test_id"])
    if match is None or match.group(2) != result["node"]:
        raise FailoverEvidenceError(f"{phase} summary test identity is invalid")
    return {
        "cdrRecords": int(result["cdr_records"]),
        "nodeId": result["node"],
        "rtpEchoDelta": int(result["rtp_echo_delta"]),
        "rtpSelectedPeerDelta": int(result["rtp_selected_peer_delta"]),
        "rtpUasDelta": int(result["rtp_uas_delta"]),
        "target": result["target"],
        "testId": result["test_id"],
    }


def _parse_manifest(raw: bytes, phase: str) -> Mapping[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FailoverEvidenceError(f"{phase} manifest is not UTF-8") from exc
    if not text.endswith("\n"):
        raise FailoverEvidenceError(f"{phase} manifest is not newline terminated")
    entries: dict[str, str] = {}
    previous = ""
    for line in text.splitlines():
        match = _MANIFEST_LINE_RE.fullmatch(line)
        if match is None:
            raise FailoverEvidenceError(f"{phase} manifest has an invalid line")
        path = match.group(2)
        if path in entries or (previous and path <= previous):
            raise FailoverEvidenceError(f"{phase} manifest is duplicated or unsorted")
        entries[path] = match.group(1)
        previous = path
    artifact_names = {path.removeprefix("./") for path in entries}
    if not artifact_names <= _PERMITTED_MANIFEST_ARTIFACTS:
        unexpected = sorted(artifact_names - _PERMITTED_MANIFEST_ARTIFACTS)
        raise FailoverEvidenceError(f"{phase} manifest contains unpermitted artifacts {unexpected}")
    missing = _REQUIRED_MANIFEST_ARTIFACTS - artifact_names
    if missing:
        raise FailoverEvidenceError(f"{phase} manifest omits required artifacts {sorted(missing)}")
    return entries


def _decode_base64(value: object, label: str, maximum: int, minimum: int = 1) -> bytes:
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
        raise FailoverEvidenceError(f"{label} is not bounded base64")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise FailoverEvidenceError(f"{label} is not strict base64") from exc
    if len(decoded) < minimum or len(decoded) > maximum:
        raise FailoverEvidenceError(f"{label} is empty or oversized")
    return decoded


def _collect_fixture_result(
    directory: Path,
    *,
    root_uid: int = 0,
    root_gid: int = 0,
    fixture_uid: int = 10002,
    fixture_gid: int = 10002,
) -> Mapping[str, Any]:
    """Build a complete canonical bundle from one protected fixture result."""

    try:
        directory_metadata = directory.lstat()
    except FileNotFoundError as exc:
        raise FailoverEvidenceError("fixture result directory does not exist") from exc
    if (
        not stat.S_ISDIR(directory_metadata.st_mode)
        or stat.S_ISLNK(directory_metadata.st_mode)
        or directory_metadata.st_uid != fixture_uid
        or directory_metadata.st_gid != fixture_gid
        or stat.S_IMODE(directory_metadata.st_mode) != 0o750
    ):
        raise FailoverEvidenceError(
            "fixture result directory must be fixture-owned, real, and mode 0750"
        )
    test_id = directory.name
    if _TEST_ID_RE.fullmatch(test_id) is None:
        raise FailoverEvidenceError("fixture result directory has an invalid test ID")
    resolved = directory.resolve(strict=True)
    manifest = _read_source_file(
        resolved / "MANIFEST.sha256",
        expected_uid=root_uid,
        expected_gid=root_gid,
        expected_mode=0o440,
        maximum=64 * 1024,
    )
    entries = _parse_manifest(manifest, "fixture")
    expected_names = {"MANIFEST.sha256", *(path.removeprefix("./") for path in entries)}
    actual_names = {entry.name for entry in os.scandir(resolved)}
    if actual_names != expected_names:
        raise FailoverEvidenceError(
            "fixture result directory has missing, extra, or unmanifested entries"
        )

    artifacts: dict[str, str] = {}
    total = len(manifest)
    for manifest_path, expected_digest in entries.items():
        name = manifest_path.removeprefix("./")
        expected_uid, expected_gid = _expected_artifact_identity(
            name,
            root_uid=root_uid,
            root_gid=root_gid,
            fixture_uid=fixture_uid,
            fixture_gid=fixture_gid,
        )
        content = _read_source_file(
            resolved / name,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            expected_mode=0o640,
            minimum=0 if name in _EMPTY_PERMITTED_ARTIFACTS else 1,
        )
        if hashlib.sha256(content).hexdigest() != expected_digest:
            raise FailoverEvidenceError(f"fixture artifact {name} differs from its manifest")
        total += len(content)
        if total > _MAX_BUNDLE_BYTES:
            raise FailoverEvidenceError("fixture result bundle exceeds its aggregate limit")
        artifacts[name] = base64.b64encode(content).decode("ascii")

    if {entry.name for entry in os.scandir(resolved)} != expected_names:
        raise FailoverEvidenceError("fixture result directory changed during collection")
    return {
        "apiVersion": BUNDLE_API_VERSION,
        "artifacts": artifacts,
        "manifestBase64": base64.b64encode(manifest).decode("ascii"),
        "testId": test_id,
    }


def _expected_artifact_identity(
    name: str,
    *,
    root_uid: int,
    root_gid: int,
    fixture_uid: int,
    fixture_gid: int,
) -> tuple[int, int]:
    if name in _FIXTURE_OWNED_ARTIFACTS:
        return fixture_uid, fixture_gid
    return root_uid, root_gid


def _load_cdr_contract() -> Any:
    contract_path = (
        Path(__file__).resolve().parents[2]
        / "poc"
        / "voice-fixture"
        / "roles"
        / "voice_fixture"
        / "files"
        / "bin"
        / "synthetic_cdr_evidence.py"
    )
    specification = importlib.util.spec_from_file_location(
        "vivolution_synthetic_cdr_contract", contract_path
    )
    if specification is None or specification.loader is None:
        raise FailoverEvidenceError("synthetic CDR contract cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _parse_bundle(raw: bytes, phase: str) -> tuple[Mapping[str, bytes], bytes, str]:
    bundle = _exact_mapping(_parse_json(raw, f"{phase} bundle"), _BUNDLE_KEYS, f"{phase} bundle")
    if bundle["apiVersion"] != BUNDLE_API_VERSION:
        raise FailoverEvidenceError(f"{phase} bundle apiVersion is unsupported")
    test_id = bundle["testId"]
    if not isinstance(test_id, str) or _TEST_ID_RE.fullmatch(test_id) is None:
        raise FailoverEvidenceError(f"{phase} bundle test ID is invalid")
    manifest = _decode_base64(bundle["manifestBase64"], f"{phase} manifest", 64 * 1024)
    entries = _parse_manifest(manifest, phase)
    encoded_artifacts = bundle["artifacts"]
    if not isinstance(encoded_artifacts, dict):
        raise FailoverEvidenceError(f"{phase} bundle artifacts must be a mapping")
    expected_names = {path.removeprefix("./") for path in entries}
    if set(encoded_artifacts) != expected_names:
        raise FailoverEvidenceError(
            f"{phase} bundle has missing, extra, or unverified manifested artifacts"
        )
    artifacts: dict[str, bytes] = {}
    total = len(manifest)
    for manifest_path, expected_digest in entries.items():
        name = manifest_path.removeprefix("./")
        content = _decode_base64(
            encoded_artifacts[name],
            f"{phase} artifact {name}",
            _MAX_ARTIFACT_BYTES,
            minimum=0 if name in _EMPTY_PERMITTED_ARTIFACTS else 1,
        )
        total += len(content)
        if total > _MAX_BUNDLE_BYTES:
            raise FailoverEvidenceError(f"{phase} bundle exceeds its aggregate limit")
        if hashlib.sha256(content).hexdigest() != expected_digest:
            raise FailoverEvidenceError(f"{phase} artifact {name} differs from its manifest")
        artifacts[name] = content
    return artifacts, manifest, test_id


def _validate_cdr_reconciliation(
    raw: bytes,
    *,
    edge_cdr_raw: bytes,
    fixture_artifacts: Mapping[str, bytes],
    fixture_manifest_raw: bytes,
    phase: str,
    test_id: str,
    node_id: str,
    expected_generation: int,
    route_identity: Mapping[str, Any],
) -> str:
    cdr_contract = _load_cdr_contract()
    try:
        fixture_cdr = cdr_contract.validate_fixture_cdr(
            _parse_json(fixture_artifacts["fixture-cdr.json"], f"{phase} fixture CDR")
        )
        rebuilt_fixture_cdr = cdr_contract.compile_fixture_cdr(
            fixture_artifacts["asterisk-cdr-delta.csv"], test_id, node_id
        )
        edge_cdr = cdr_contract.validate_edge_cdr(
            _parse_json(edge_cdr_raw, f"{phase} Edge CDR")
        )
    except cdr_contract.CdrEvidenceError as exc:
        raise FailoverEvidenceError(f"{phase} raw CDR contract is invalid: {exc}") from exc
    if rebuilt_fixture_cdr != fixture_cdr:
        raise FailoverEvidenceError(f"{phase} fixture CDR differs from its raw records")
    if (
        fixture_cdr["testId"] != test_id
        or fixture_cdr["nodeId"] != node_id
        or edge_cdr["testId"] != test_id
        or edge_cdr["nodeIdentity"]["nodeId"] != node_id
    ):
        raise FailoverEvidenceError(f"{phase} raw CDR evidence names another call or Edge")
    record = _exact_mapping(
        _parse_json(raw, f"{phase} CDR reconciliation"),
        _RECONCILIATION_KEYS,
        f"{phase} CDR reconciliation",
    )
    if (
        record["apiVersion"] != "edge.vivolution.ae/synthetic-cdr-reconciliation/v0.1"
        or record["kind"] != "SyntheticEdgeFixtureCdrReconciliation"
        or record["scope"] != "SYNTHETIC_PRIVATE_NO_PSTN"
        or record["status"] != "SYNTHETIC_EDGE_FIXTURE_CDR_RECONCILED"
        or record["liveM365Interoperability"] != LIVE_M365_STATUS
        or record["calledNumber"] != CALLED_NUMBER
        or record["testId"] != test_id
    ):
        raise FailoverEvidenceError(f"{phase} CDR reconciliation identity is invalid")
    node = _exact_mapping(
        record["nodeIdentity"], _RECONCILIATION_NODE_KEYS, f"{phase} CDR node identity"
    )
    expected_slot = "A" if node_id == "sbc1" else "B"
    generation = _integer(
        node["generation"], f"{phase} CDR node generation", 1, 2**31 - 1
    )
    if (
        node["nodeId"] != node_id
        or node["slot"] != expected_slot
        or generation != expected_generation
    ):
        raise FailoverEvidenceError(
            f"{phase} CDR reconciliation names the wrong Edge or generation"
        )
    if not isinstance(node["routeToken"], str) or re.fullmatch(
        r"[0-9A-F]{12}", node["routeToken"]
    ) is None:
        raise FailoverEvidenceError(f"{phase} CDR route token is invalid")
    for field in ("nodeFactsDigest", "runtimeAuthorityDigest"):
        if not isinstance(node[field], str) or _DIGEST_RE.fullmatch(node[field]) is None:
            raise FailoverEvidenceError(f"{phase} CDR {field} is invalid")
    for field in (
        "allocationId",
        "clusterId",
        "serviceInstanceId",
        "tenantContextId",
    ):
        if not isinstance(node[field], str) or re.fullmatch(
            r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?", node[field]
        ) is None:
            raise FailoverEvidenceError(f"{phase} CDR {field} is invalid")
        if node[field] != route_identity[field]:
            raise FailoverEvidenceError(f"{phase} CDR is outside the logical tenant route")
    matched = record["matchedCalls"]
    if not isinstance(matched, list) or len(matched) != 2:
        raise FailoverEvidenceError(f"{phase} CDR reconciliation does not match two calls")
    directions = ["TEAMS_FIXTURE_TO_PBX_FIXTURE", "PBX_FIXTURE_TO_TEAMS_FIXTURE"]
    for index, (expected_direction, value) in enumerate(zip(directions, matched)):
        item = _exact_mapping(
            value, _RECONCILIATION_CALL_KEYS, f"{phase} matched CDR call"
        )
        if (
            item["direction"] != expected_direction
            or item["edgeResult"] != "ACCEPTED"
            or item["fixtureDisposition"] != "ANSWERED"
            or not isinstance(item["fixtureRecordDigest"], str)
            or _DIGEST_RE.fullmatch(item["fixtureRecordDigest"]) is None
        ):
            raise FailoverEvidenceError(f"{phase} CDR reconciliation does not match two calls")
        _integer(item["edgeElapsedMilliseconds"], f"{phase} Edge CDR elapsed", 0, 120000)
        _integer(item["fixtureBillableSeconds"], f"{phase} fixture billable seconds", 1, 120)
        expected_match = {
            "direction": expected_direction,
            "edgeElapsedMilliseconds": edge_cdr["calls"][index]["elapsedMilliseconds"],
            "edgeResult": edge_cdr["calls"][index]["result"],
            "fixtureBillableSeconds": fixture_cdr["records"][index]["billableSeconds"],
            "fixtureDisposition": fixture_cdr["records"][index]["disposition"],
            "fixtureRecordDigest": fixture_cdr["records"][index]["recordDigest"],
        }
        if dict(item) != expected_match:
            raise FailoverEvidenceError(f"{phase} matched CDR call differs from raw sources")
    sources = _exact_mapping(
        record["sourceDigests"], _RECONCILIATION_SOURCE_KEYS, f"{phase} CDR sources"
    )
    if any(
        not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None
        for value in sources.values()
    ):
        raise FailoverEvidenceError(f"{phase} CDR source digest is invalid")
    expected_sources = {
        "edgeCdr": _sha256(edge_cdr_raw),
        "fixtureCdr": _sha256(fixture_artifacts["fixture-cdr.json"]),
        "fixtureManifest": _sha256(fixture_manifest_raw),
    }
    if dict(sources) != expected_sources:
        raise FailoverEvidenceError(f"{phase} CDR reconciliation source digests are unbound")
    if dict(record["nodeIdentity"]) != dict(edge_cdr["nodeIdentity"]):
        raise FailoverEvidenceError(f"{phase} reconciliation and raw Edge CDR identities differ")
    digest = record["reconciliationDigest"]
    unsigned = dict(record)
    unsigned.pop("reconciliationDigest", None)
    if not isinstance(digest, str) or digest != _sha256(_canonical_bytes(unsigned)):
        raise FailoverEvidenceError(f"{phase} CDR reconciliation digest is invalid")
    return digest


def _test_start_epoch_ms(test_id: str) -> int:
    match = _TEST_ID_RE.fullmatch(test_id)
    assert match is not None
    timestamp = datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ").replace(
        tzinfo=timezone.utc
    )
    return int(timestamp.timestamp() * 1000)


def _validate_node(value: object, *, node: str, address: str, slot: str) -> Mapping[str, Any]:
    record = _exact_mapping(value, _NODE_KEYS, f"{node} runtime identity")
    if record["nodeId"] != node or record["privateIpv4"] != address or record["slot"] != slot:
        raise FailoverEvidenceError(f"{node} runtime identity is not the fixed POC node")
    sequence = _integer(record["activeSequence"], f"{node} active sequence", 1, 2**53 - 1)
    generation = _integer(record["generation"], f"{node} generation", 1, 2**31 - 1)
    digest = record["activeManifestDigest"]
    if not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None:
        raise FailoverEvidenceError(f"{node} active manifest digest is invalid")
    return {
        "activeManifestDigest": digest,
        "activeSequence": sequence,
        "generation": generation,
        "nodeId": node,
        "privateIpv4": address,
        "slot": slot,
    }


def _validate_request(
    request: Mapping[str, Any],
) -> tuple[dict[str, Any], int, int, int, int, int]:
    record = _exact_mapping(request, _REQUEST_KEYS, "failover request")
    if record["apiVersion"] != REQUEST_API_VERSION:
        raise FailoverEvidenceError("failover request apiVersion is unsupported")
    if record["acknowledgement"] != ACKNOWLEDGEMENT:
        raise FailoverEvidenceError("the exact disruptive failover acknowledgement is absent")
    if record["gateSeconds"] != GATE_SECONDS:
        raise FailoverEvidenceError("the synthetic failover gate must remain exactly 120 seconds")
    if record["liveM365Interoperability"] != LIVE_M365_STATUS:
        raise FailoverEvidenceError("synthetic failover must not assert live M365 interoperability")

    started = _integer(record["failureStartedAtEpochMs"], "failure start", 1, 2**63 - 1)
    completed = _integer(record["completedAtEpochMs"], "failover completion", 1, 2**63 - 1)
    if completed < started:
        raise FailoverEvidenceError("the fixture wall-clock correlation window is invalid")
    started_monotonic = _integer(
        record["failureStartedAtMonotonicNs"], "monotonic failure start", 1, 2**63 - 1
    )
    completed_monotonic = _integer(
        record["completedAtMonotonicNs"], "monotonic failover completion", 1, 2**63 - 1
    )
    elapsed_ns = completed_monotonic - started_monotonic
    if elapsed_ns < 0 or elapsed_ns > GATE_SECONDS * 1_000_000_000:
        raise FailoverEvidenceError("the alternate new call did not complete inside 120 seconds")
    elapsed_ms = (elapsed_ns + 999_999) // 1_000_000

    primary = _validate_node(record["primary"], node="sbc1", address="10.20.2.4", slot="A")
    alternate = _validate_node(record["alternate"], node="sbc2", address="10.20.2.5", slot="B")
    restored = _validate_node(
        record["restoredPrimary"], node="sbc1", address="10.20.2.4", slot="A"
    )
    if primary != restored:
        raise FailoverEvidenceError("restored SBC1 is not the exact pre-failure active runtime")
    if primary["generation"] != alternate["generation"]:
        raise FailoverEvidenceError(
            "SBC1 and SBC2 must use one common positive fleet generation"
        )

    route = _exact_mapping(record["routeIdentity"], _ROUTE_KEYS, "logical tenant route")
    for key in (
        "allocationId",
        "clusterId",
        "customerAccountId",
        "serviceInstanceId",
        "tenantContextId",
    ):
        _identifier(route[key], f"logical tenant route {key}")
    if (
        not isinstance(route["m365TenantId"], str)
        or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", route["m365TenantId"])
        is None
    ):
        raise FailoverEvidenceError("logical tenant route m365TenantId is invalid")
    if route["calledNumber"] != CALLED_NUMBER:
        raise FailoverEvidenceError("logical tenant route is not the fixed invalid no-PSTN number")
    if route["directions"] != [
        "TEAMS_FIXTURE_TO_PBX_FIXTURE",
        "PBX_FIXTURE_TO_TEAMS_FIXTURE",
    ]:
        raise FailoverEvidenceError("logical tenant route directions are not exact")

    failure = _exact_mapping(record["testedFailure"], _FAILURE_KEYS, "tested failure")
    if (
        failure["injection"] != "SYSTEMD_STOP_COMPLETE_DATA_PLANE"
        or failure["primaryNodeId"] != "sbc1"
        or failure["servicesStopped"]
        != ["opensips.service", "rtpengine-daemon.service"]
        or failure["signalingListener"] != "CLOSED_FROM_FIXTURE_CONTROLLER"
    ):
        raise FailoverEvidenceError("tested failure is not the exact bounded SBC1 outage")

    normalized = {
        "alternate": alternate,
        "primary": primary,
        "restoredPrimary": restored,
        "routeIdentity": dict(route),
        "testedFailure": dict(failure),
    }
    return (
        normalized,
        started,
        completed,
        started_monotonic,
        completed_monotonic,
        elapsed_ms,
    )


def compile_evidence(directory: Path) -> Mapping[str, Any]:
    """Validate one fixed collection directory and return canonical evidence."""

    root = _validate_directory(directory)
    _validate_evidence_layout(root)
    request = _parse_json(_read_fixed_file(root, "request.json"), "request.json")
    (
        normalized,
        started,
        completed,
        started_monotonic,
        completed_monotonic,
        elapsed_ms,
    ) = _validate_request(request)

    calls: list[dict[str, Any]] = []
    expected = {
        "primary": ("sbc1", "10.20.2.4", "PRIMARY_BASELINE"),
        "alternate": ("sbc2", "10.20.2.5", "ALTERNATE_AFTER_PRIMARY_STOP"),
        "restored": ("sbc1", "10.20.2.4", "PRIMARY_AFTER_RESTORE"),
    }
    for phase in _PHASES:
        artifacts, manifest_raw, bundle_test_id = _parse_bundle(
            _read_fixed_file(root, f"{phase}-bundle.json", _MAX_BUNDLE_BYTES * 2), phase
        )
        summary_raw = artifacts["summary.txt"]
        result_raw = artifacts["RESULT"]
        if result_raw != b"PASS\n":
            raise FailoverEvidenceError(f"{phase} fixture result is not PASS")
        summary = _parse_summary(summary_raw, phase)
        if summary["testId"] != bundle_test_id:
            raise FailoverEvidenceError(f"{phase} summary and bundle test IDs differ")
        expected_node, expected_target, evidence_phase = expected[phase]
        if summary["nodeId"] != expected_node or summary["target"] != expected_target:
            raise FailoverEvidenceError(f"{phase} call did not use its exact fixed node")
        reconciliation_digest = _validate_cdr_reconciliation(
            _read_fixed_file(root, f"{phase}-cdr-reconciliation.json"),
            edge_cdr_raw=_read_fixed_file(root, f"{phase}-edge-cdr.json"),
            fixture_artifacts=artifacts,
            fixture_manifest_raw=manifest_raw,
            phase=phase,
            test_id=summary["testId"],
            node_id=expected_node,
            expected_generation=(
                normalized["alternate"]["generation"]
                if phase == "alternate"
                else normalized["primary"]["generation"]
            ),
            route_identity=normalized["routeIdentity"],
        )
        calls.append(
            {
                **summary,
                "cdrReconciliationDigest": reconciliation_digest,
                "cdrReconciliationStatus": "SYNTHETIC_EDGE_FIXTURE_CDR_RECONCILED",
                "fixtureManifestDigest": _sha256(manifest_raw),
                "phase": evidence_phase,
                "result": "PASS",
            }
        )

    if len({call["testId"] for call in calls}) != 3:
        raise FailoverEvidenceError("fixture call test IDs are not unique")
    if _test_start_epoch_ms(calls[0]["testId"]) > started + 999:
        raise FailoverEvidenceError("primary baseline was not completed before failure injection")
    alternate_start = _test_start_epoch_ms(calls[1]["testId"])
    if alternate_start < started - 999 or alternate_start > completed + 999:
        raise FailoverEvidenceError("alternate call timestamp is outside the failure window")
    if _test_start_epoch_ms(calls[2]["testId"]) < completed - 999:
        raise FailoverEvidenceError("restoration call predates failover completion")

    record: dict[str, Any] = {
        "activeCallMigration": "NOT_TESTED_NOT_CLAIMED",
        "apiVersion": EVIDENCE_API_VERSION,
        "completedAtEpochMs": completed,
        "completedAtMonotonicNs": completed_monotonic,
        "failoverElapsedMilliseconds": elapsed_ms,
        "failureStartedAtEpochMs": started,
        "failureStartedAtMonotonicNs": started_monotonic,
        "fixtureCalls": calls,
        "gateSeconds": GATE_SECONDS,
        "kind": "SyntheticNewCallFailoverEvidence",
        "liveM365Interoperability": LIVE_M365_STATUS,
        "primaryRestoredAndRetested": True,
        "routeIdentity": normalized["routeIdentity"],
        "runtimeNodes": [normalized["primary"], normalized["alternate"]],
        "status": "SYNTHETIC_NEW_CALL_FAILOVER_ACCEPTED",
        "testedFailure": normalized["testedFailure"],
    }
    record["evidenceDigest"] = _sha256(_canonical_bytes(record))
    return record


def _atomic_write(path: Path, content: bytes) -> None:
    if path.exists() or path.is_symlink():
        current = _read_fixed_file(path.parent, path.name)
        if current != content:
            raise FailoverEvidenceError("existing acceptance evidence differs")
        return
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    mode = result.add_mutually_exclusive_group(required=True)
    mode.add_argument("--evidence-dir", type=Path)
    mode.add_argument("--collect-result-dir", type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.collect_result_dir is not None:
            if os.geteuid() != 0:
                raise FailoverEvidenceError("fixture collection must run as root")
            bundle = _collect_fixture_result(args.collect_result_dir)
            os.sys.stdout.buffer.write(_canonical_bytes(bundle))
            return 0
        evidence = compile_evidence(args.evidence_dir)
        _atomic_write(args.evidence_dir / "acceptance.json", _canonical_bytes(evidence))
    except (FailoverEvidenceError, OSError) as exc:
        print(f"synthetic failover evidence rejected: {exc}", file=os.sys.stderr)
        return 2
    print(f"SYNTHETIC_FAILOVER_ACCEPTANCE_WRITTEN {evidence['evidenceDigest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
