#!/usr/bin/env python3
"""Compile strict evidence for one forced synthetic fixture leaf rotation."""

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
import sys
from typing import Any, Mapping


API_VERSION = "edge.vivolution.ae/forced-fixture-leaf-rotation-evidence/v0.1"
ACKNOWLEDGEMENT = "FORCE_SYNTHETIC_FIXTURE_LEAVES_ONCE_AND_REPIN_BOTH_EDGES"
SCOPE = "BOUNDED_PRIVATE_SYNTHETIC_POC"
LIVE_M365_STATUS = "NOT_ASSERTED"
PSTN_STATUS = "NOT_TESTED_NOT_CLAIMED"
LEAF_NAMES = ("asterisk", "sipp", "sbc1", "sbc2")
NODE_TARGETS = {"sbc1": "10.20.2.4", "sbc2": "10.20.2.5"}
PHASES = (
    "fleet-pre",
    "sbc1-pre",
    "sbc1-post",
    "sbc2-pre",
    "sbc2-post",
    "post-calls",
)
PHASE_API_VERSION = (
    "edge.vivolution.ae/forced-fixture-leaf-rotation-fleet-phase/v0.1"
)
EDGE_SNAPSHOT_API_VERSION = (
    "edge.vivolution.ae/forced-fixture-leaf-rotation-edge-snapshot/v0.1"
)
EDGE_EVIDENCE_KEYS = {
    "apiVersion",
    "authorityDigest",
    "evidenceDigest",
    "fixtureCaDigest",
    "fixtureClientCertificateDigest",
    "kind",
    "nodeId",
    "opensipsRestarted",
    "status",
    "timestamp",
}
DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
REQUEST_ID_RE = re.compile(r"\A[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}\Z")
TIMESTAMP_RE = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
TEST_ID_RE = re.compile(r"\A([0-9]{8}T[0-9]{6}Z)-(sbc[12])-[0-9]{1,10}\Z")
MAX_FILE_BYTES = 80 * 1024 * 1024


class ForcedFixtureRotationEvidenceError(ValueError):
    """Collected rotation material violates the fixed synthetic contract."""


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def sha256_digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _load_module(name: str, path: Path) -> Any:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise ForcedFixtureRotationEvidenceError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


SCRIPT_ROOT = Path(__file__).resolve().parent
state_contract = _load_module(
    "vivolution_forced_fixture_rotation_state",
    SCRIPT_ROOT / "forced_fixture_leaf_rotation_state.py",
)
fixture_contract = _load_module(
    "vivolution_synthetic_fixture_bundle",
    SCRIPT_ROOT / "synthetic_failover_evidence.py",
)
active_edge_contract = _load_module(
    "vivolution_forced_fixture_rotation_active_edge_contract",
    SCRIPT_ROOT / "active_edge_reboot_evidence.py",
)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ForcedFixtureRotationEvidenceError("JSON contains duplicate members")
        result[key] = value
    return result


def _parse_json(raw: bytes, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ForcedFixtureRotationEvidenceError(
            f"{label} is not one UTF-8 JSON object"
        ) from exc
    if not isinstance(value, dict) or canonical_bytes(value) != raw:
        raise ForcedFixtureRotationEvidenceError(f"{label} is not canonical JSON")
    return value


def _validate_directory(directory: Path) -> Path:
    record = directory.lstat()
    if (
        not stat.S_ISDIR(record.st_mode)
        or stat.S_ISLNK(record.st_mode)
        or record.st_uid != os.getuid()
        or stat.S_IMODE(record.st_mode) != 0o700
    ):
        raise ForcedFixtureRotationEvidenceError(
            "evidence directory must be runner-owned, real, and mode 0700"
        )
    return directory.resolve(strict=True)


def _read_file(directory: Path, name: str, maximum: int = MAX_FILE_BYTES) -> bytes:
    path = directory / name
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or not 0 < before.st_size <= maximum
    ):
        raise ForcedFixtureRotationEvidenceError(f"unsafe evidence file {name}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
            or opened.st_size != before.st_size
        ):
            raise ForcedFixtureRotationEvidenceError(f"{name} changed before read")
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
        raise ForcedFixtureRotationEvidenceError(f"{name} changed while read")
    return content


def _validate_layout(directory: Path) -> None:
    names = {entry.name for entry in os.scandir(directory)}
    required = {
        "active-server-leaves.json",
        "state.json",
        "sbc1-edge.json",
        "sbc1-edge-cdr.json",
        "sbc1-cdr-reconciliation.json",
        "sbc1-bundle.json",
        "sbc2-edge.json",
        "sbc2-edge-cdr.json",
        "sbc2-cdr-reconciliation.json",
        "sbc2-bundle.json",
        "credential-digests.json",
        *(f"{phase}.json" for phase in PHASES),
    }
    if names not in (required, required | {"acceptance.json"}):
        raise ForcedFixtureRotationEvidenceError(
            "evidence directory has missing, extra, or transient files"
        )


def _decode_json(value: object, label: str) -> tuple[bytes, Mapping[str, Any]]:
    if not isinstance(value, str) or len(value) > 1024 * 1024:
        raise ForcedFixtureRotationEvidenceError(f"{label} is not bounded base64")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ForcedFixtureRotationEvidenceError(f"{label} is not strict base64") from exc
    if not 0 < len(raw) <= 512 * 1024:
        raise ForcedFixtureRotationEvidenceError(f"{label} is empty or oversized")
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ForcedFixtureRotationEvidenceError(f"{label} is not JSON") from exc
    if not isinstance(parsed, dict):
        raise ForcedFixtureRotationEvidenceError(f"{label} is not a JSON object")
    return raw, parsed


def _validate_metadata(value: object, label: str, *, agent: bool = False) -> Mapping[str, Any]:
    record = value
    if not isinstance(record, dict) or set(record) != {"group", "mode", "nlink", "owner"}:
        raise ForcedFixtureRotationEvidenceError(f"{label} metadata is not exact")
    expected_identity = "vivolution-edge-agent" if agent else "root"
    if (
        record["owner"] != expected_identity
        or record["group"] != expected_identity
        or record["mode"] != "0600"
        or record["nlink"] != 1
    ):
        raise ForcedFixtureRotationEvidenceError(f"{label} metadata is unprotected")
    return record


def _validate_edge_snapshot(
    value: object, node_id: str
) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
    if not isinstance(value, dict) or set(value) != {
        "apiVersion",
        "capturedAtEpochMs",
        "fixtureRotationJournalPresent",
        "identitySources",
        "nodeId",
        "snapshot",
    }:
        raise ForcedFixtureRotationEvidenceError(f"{node_id} Edge snapshot is not exact")
    captured = value["capturedAtEpochMs"]
    if (
        value["apiVersion"] != EDGE_SNAPSHOT_API_VERSION
        or value["nodeId"] != node_id
        or value["fixtureRotationJournalPresent"] is not False
        or isinstance(captured, bool)
        or not isinstance(captured, int)
        or captured < 1
    ):
        raise ForcedFixtureRotationEvidenceError(f"{node_id} Edge snapshot identity is invalid")
    sources = value["identitySources"]
    if not isinstance(sources, dict) or set(sources) != {
        "nodeFactsBase64",
        "nodeFactsMetadata",
        "nodeFactsSha256",
        "runtimeAuthorityBase64",
        "runtimeAuthorityMetadata",
        "runtimeAuthoritySha256",
    }:
        raise ForcedFixtureRotationEvidenceError(f"{node_id} identity sources are not exact")
    facts_raw, facts = _decode_json(sources["nodeFactsBase64"], f"{node_id} node facts")
    authority_raw, authority = _decode_json(
        sources["runtimeAuthorityBase64"], f"{node_id} runtime authority"
    )
    if (
        sources["nodeFactsSha256"] != sha256_digest(facts_raw)
        or sources["runtimeAuthoritySha256"] != sha256_digest(authority_raw)
    ):
        raise ForcedFixtureRotationEvidenceError(f"{node_id} identity source digest is unbound")
    _validate_metadata(sources["nodeFactsMetadata"], f"{node_id} node facts")
    _validate_metadata(sources["runtimeAuthorityMetadata"], f"{node_id} runtime authority")
    try:
        facts = active_edge_contract._validate_facts(facts, node_id)
        authority = active_edge_contract._validate_authority(authority, node_id, facts)
        active_edge_contract._validate_snapshot(value["snapshot"], node_id)
    except active_edge_contract.ActiveEdgeRebootEvidenceError as exc:
        raise ForcedFixtureRotationEvidenceError(
            f"{node_id} protected active state is invalid: {exc}"
        ) from exc
    return value, facts, authority


def _validate_phase(
    raw: bytes, expected_phase: str
) -> Mapping[str, tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]]:
    value = _parse_json(raw, f"{expected_phase} fleet phase")
    if set(value) != {"apiVersion", "phase", "snapshots"}:
        raise ForcedFixtureRotationEvidenceError(f"{expected_phase} phase is not exact")
    if value["apiVersion"] != PHASE_API_VERSION or value["phase"] != expected_phase:
        raise ForcedFixtureRotationEvidenceError(f"{expected_phase} phase identity is invalid")
    snapshots = value["snapshots"]
    if not isinstance(snapshots, dict) or set(snapshots) != {"sbc1", "sbc2"}:
        raise ForcedFixtureRotationEvidenceError(f"{expected_phase} fleet is incomplete")
    return {
        node_id: _validate_edge_snapshot(snapshots[node_id], node_id)
        for node_id in ("sbc1", "sbc2")
    }


def _without_capture(snapshot: Mapping[str, Any]) -> Mapping[str, Any]:
    result = dict(snapshot)
    result.pop("capturedAtEpochMs", None)
    return result


def _authority_without_rotating_secrets(authority: Mapping[str, Any]) -> Mapping[str, Any]:
    result = dict(authority)
    secrets = dict(result["secretDigests"])
    secrets.pop("fixtureClientCrt", None)
    secrets.pop("fixtureClientKey", None)
    result["secretDigests"] = secrets
    return result


def _validate_fleet_continuity(
    phases: Mapping[
        str,
        Mapping[str, tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]],
    ],
    credential_digests: Mapping[str, Any],
) -> Mapping[str, Any]:
    expected_credential_keys = {"fixtureCaCrt", "sbc1", "sbc2"}
    if set(credential_digests) != expected_credential_keys:
        raise ForcedFixtureRotationEvidenceError("credential digest inventory is not exact")
    for node_id in ("sbc1", "sbc2"):
        node_credentials = credential_digests[node_id]
        if not isinstance(node_credentials, dict) or set(node_credentials) != {
            "fixtureClientCrt",
            "fixtureClientKey",
        }:
            raise ForcedFixtureRotationEvidenceError(f"{node_id} credential digests are not exact")
    all_digests = [credential_digests["fixtureCaCrt"]] + [
        credential_digests[node][name]
        for node in ("sbc1", "sbc2")
        for name in ("fixtureClientCrt", "fixtureClientKey")
    ]
    if any(not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None for value in all_digests):
        raise ForcedFixtureRotationEvidenceError("credential digest inventory is invalid")

    baseline: dict[str, tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]] = {}
    for node_id in ("sbc1", "sbc2"):
        baseline[node_id] = phases["fleet-pre"][node_id]
        base_snapshot, base_facts, _ = baseline[node_id]
        for phase in PHASES:
            snapshot, facts, _ = phases[phase][node_id]
            if snapshot["identitySources"]["nodeFactsSha256"] != base_snapshot["identitySources"]["nodeFactsSha256"] or facts != base_facts:
                raise ForcedFixtureRotationEvidenceError(f"{node_id} immutable node facts changed")
            if snapshot["snapshot"] != base_snapshot["snapshot"]:
                raise ForcedFixtureRotationEvidenceError(
                    f"{node_id} runtime, Agent, boot, unit, or health state changed"
                )

    shared_fields = (
        "allocationId",
        "clusterId",
        "customerAccountId",
        "generation",
        "m365TenantId",
        "serviceInstanceId",
        "tenantContextId",
    )
    for field in shared_fields:
        if baseline["sbc1"][1][field] != baseline["sbc2"][1][field]:
            raise ForcedFixtureRotationEvidenceError(
                "the two Edges do not share one immutable tenant route"
            )

    old_authority = {
        node: phases["fleet-pre"][node][2] for node in ("sbc1", "sbc2")
    }
    new_authority = {
        node: phases["post-calls"][node][2] for node in ("sbc1", "sbc2")
    }
    expected_authority_by_phase = {
        "fleet-pre": {"sbc1": old_authority["sbc1"], "sbc2": old_authority["sbc2"]},
        "sbc1-pre": {"sbc1": old_authority["sbc1"], "sbc2": old_authority["sbc2"]},
        "sbc1-post": {"sbc1": new_authority["sbc1"], "sbc2": old_authority["sbc2"]},
        "sbc2-pre": {"sbc1": new_authority["sbc1"], "sbc2": old_authority["sbc2"]},
        "sbc2-post": {"sbc1": new_authority["sbc1"], "sbc2": new_authority["sbc2"]},
        "post-calls": {"sbc1": new_authority["sbc1"], "sbc2": new_authority["sbc2"]},
    }
    for phase, nodes in expected_authority_by_phase.items():
        for node_id, expected in nodes.items():
            if phases[phase][node_id][2] != expected:
                raise ForcedFixtureRotationEvidenceError(
                    f"{node_id} authority changed outside its serialized re-pin"
                )
    for node_id in ("sbc1", "sbc2"):
        old = old_authority[node_id]
        new = new_authority[node_id]
        if old == new or _authority_without_rotating_secrets(old) != _authority_without_rotating_secrets(new):
            raise ForcedFixtureRotationEvidenceError(
                f"{node_id} authority did not change only its fixture client pair"
            )
        secrets = new["secretDigests"]
        if (
            secrets["fixtureCaCrt"] != credential_digests["fixtureCaCrt"]
            or secrets["fixtureClientCrt"]
            != credential_digests[node_id]["fixtureClientCrt"]
            or secrets["fixtureClientKey"]
            != credential_digests[node_id]["fixtureClientKey"]
        ):
            raise ForcedFixtureRotationEvidenceError(
                f"{node_id} authority does not pin the selected credential set"
            )
    return {
        "allocationId": baseline["sbc1"][1]["allocationId"],
        "clusterId": baseline["sbc1"][1]["clusterId"],
        "customerAccountId": baseline["sbc1"][1]["customerAccountId"],
        "generation": baseline["sbc1"][1]["generation"],
        "m365TenantId": baseline["sbc1"][1]["m365TenantId"],
        "serviceInstanceId": baseline["sbc1"][1]["serviceInstanceId"],
        "tenantContextId": baseline["sbc1"][1]["tenantContextId"],
    }


def _validate_edge_evidence(
    raw: bytes, node_id: str, state: Mapping[str, Any]
) -> Mapping[str, Any]:
    value = _parse_json(raw, f"{node_id} Edge evidence")
    if set(value) != EDGE_EVIDENCE_KEYS:
        raise ForcedFixtureRotationEvidenceError(
            f"{node_id} Edge evidence has unexpected keys"
        )
    if (
        value["apiVersion"] != "edge.vivolution.ae/fixture-pki-rotation/v0.1"
        or value["kind"] != "SyntheticFixturePkiRotationEvidence"
        or value["nodeId"] != node_id
        or value["status"] not in {"FIXTURE_PKI_ROTATED", "FIXTURE_PKI_UNCHANGED"}
        or not isinstance(value["opensipsRestarted"], bool)
        or TIMESTAMP_RE.fullmatch(value["timestamp"] or "") is None
    ):
        raise ForcedFixtureRotationEvidenceError(
            f"{node_id} Edge rotation identity is invalid"
        )
    for name in (
        "authorityDigest",
        "evidenceDigest",
        "fixtureCaDigest",
        "fixtureClientCertificateDigest",
    ):
        if not isinstance(value[name], str) or DIGEST_RE.fullmatch(value[name]) is None:
            raise ForcedFixtureRotationEvidenceError(f"{node_id} {name} is invalid")
    unsigned = dict(value)
    actual_evidence_digest = unsigned.pop("evidenceDigest")
    expected_evidence_digest = sha256_digest(canonical_bytes(unsigned).rstrip(b"\n"))
    if actual_evidence_digest != expected_evidence_digest:
        raise ForcedFixtureRotationEvidenceError(
            f"{node_id} Edge evidence digest is invalid"
        )
    after = state["after"]
    if (
        value["fixtureCaDigest"] != "sha256:" + after["ca"]["pemSha256"]
        or value["fixtureClientCertificateDigest"]
        != "sha256:" + after["leaves"][node_id]["pemSha256"]
    ):
        raise ForcedFixtureRotationEvidenceError(
            f"{node_id} did not re-pin the selected fixture generation"
        )
    if value["status"] == "FIXTURE_PKI_ROTATED" and not value["opensipsRestarted"]:
        raise ForcedFixtureRotationEvidenceError(
            f"{node_id} changed credentials without a proven OpenSIPS restart"
        )
    if value["status"] == "FIXTURE_PKI_UNCHANGED" and value["opensipsRestarted"]:
        raise ForcedFixtureRotationEvidenceError(
            f"{node_id} unchanged evidence unexpectedly claims a restart"
        )
    return {
        "authorityDigest": value["authorityDigest"],
        "evidenceDigest": value["evidenceDigest"],
        "nodeId": node_id,
        "status": value["status"],
    }


def _test_epoch_ms(test_id: str, node_id: str) -> int:
    match = TEST_ID_RE.fullmatch(test_id)
    if match is None or match.group(2) != node_id:
        raise ForcedFixtureRotationEvidenceError(f"{node_id} test ID is invalid")
    try:
        parsed = datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ForcedFixtureRotationEvidenceError(
            f"{node_id} test timestamp is invalid"
        ) from exc
    return int(parsed.timestamp() * 1000)


def _validate_call(
    raw: bytes,
    *,
    edge_cdr_raw: bytes,
    reconciliation_raw: bytes,
    node_id: str,
    selected_at_ms: int,
    expected_generation: int,
    route_identity: Mapping[str, Any],
    expected_node_facts_digest: str,
    expected_runtime_authority_digest: str,
) -> Mapping[str, Any]:
    try:
        artifacts, manifest, bundle_test_id = fixture_contract._parse_bundle(raw, node_id)
        if artifacts["RESULT"] != b"PASS\n":
            raise ForcedFixtureRotationEvidenceError(
                f"{node_id} fixture result is not PASS"
            )
        summary = fixture_contract._parse_summary(artifacts["summary.txt"], node_id)
    except fixture_contract.FailoverEvidenceError as exc:
        raise ForcedFixtureRotationEvidenceError(
            f"{node_id} fixture bundle is invalid: {exc}"
        ) from exc
    cdr_contract = fixture_contract._load_cdr_contract()
    try:
        fixture_cdr = cdr_contract.validate_fixture_cdr(
            fixture_contract._parse_json(
                artifacts["fixture-cdr.json"], f"{node_id} fixture CDR"
            )
        )
        rebuilt_cdr = cdr_contract.compile_fixture_cdr(
            artifacts["asterisk-cdr-delta.csv"], bundle_test_id, node_id
        )
    except cdr_contract.CdrEvidenceError as exc:
        raise ForcedFixtureRotationEvidenceError(
            f"{node_id} fixture CDR is invalid: {exc}"
        ) from exc
    if fixture_cdr != rebuilt_cdr:
        raise ForcedFixtureRotationEvidenceError(
            f"{node_id} normalized fixture CDR differs from its raw records"
        )
    if (
        fixture_cdr["testId"] != bundle_test_id
        or fixture_cdr["nodeId"] != node_id
        or fixture_cdr["status"] != "TWO_LOGICAL_SYNTHETIC_CALLS_ACCOUNTED"
        or fixture_cdr["liveM365Interoperability"] != LIVE_M365_STATUS
        or [record["direction"] for record in fixture_cdr["records"]]
        != ["TEAMS_FIXTURE_TO_PBX_FIXTURE", "PBX_FIXTURE_TO_TEAMS_FIXTURE"]
        or {record["disposition"] for record in fixture_cdr["records"]} != {"ANSWERED"}
    ):
        raise ForcedFixtureRotationEvidenceError(
            f"{node_id} CDR did not prove both answered synthetic directions"
        )
    if (
        summary["testId"] != bundle_test_id
        or summary["nodeId"] != node_id
        or summary["target"] != NODE_TARGETS[node_id]
    ):
        raise ForcedFixtureRotationEvidenceError(
            f"{node_id} fixture call did not target the exact selected Edge"
        )
    # Test IDs have one-second precision.  The inclusive 999 ms allowance
    # permits a call started later in the same UTC second as selection while
    # rejecting every call from an earlier second.
    if _test_epoch_ms(bundle_test_id, node_id) + 999 < selected_at_ms:
        raise ForcedFixtureRotationEvidenceError(
            f"{node_id} fixture call predates the forced leaf selection"
        )
    try:
        reconciliation_digest = fixture_contract._validate_cdr_reconciliation(
            reconciliation_raw,
            edge_cdr_raw=edge_cdr_raw,
            fixture_artifacts=artifacts,
            fixture_manifest_raw=manifest,
            phase=node_id,
            test_id=bundle_test_id,
            node_id=node_id,
            expected_generation=expected_generation,
            route_identity=route_identity,
        )
        edge_cdr = cdr_contract.validate_edge_cdr(
            fixture_contract._parse_json(edge_cdr_raw, f"{node_id} Edge CDR")
        )
    except (
        fixture_contract.FailoverEvidenceError,
        cdr_contract.CdrEvidenceError,
    ) as exc:
        raise ForcedFixtureRotationEvidenceError(
            f"{node_id} Edge/fixture CDR reconciliation is invalid: {exc}"
        ) from exc
    if (
        edge_cdr["nodeIdentity"]["nodeFactsDigest"] != expected_node_facts_digest
        or edge_cdr["nodeIdentity"]["runtimeAuthorityDigest"]
        != expected_runtime_authority_digest
    ):
        raise ForcedFixtureRotationEvidenceError(
            f"{node_id} call CDR is not bound to the accepted post-rotation identity"
        )
    return {
        **summary,
        "cdrReconciliationDigest": reconciliation_digest,
        "edgeCdrDigest": sha256_digest(edge_cdr_raw),
        "fixtureCdrDigest": sha256_digest(artifacts["fixture-cdr.json"]),
        "fixtureManifestDigest": sha256_digest(manifest),
        "result": "PASS",
    }


def compile_evidence(directory: Path) -> Mapping[str, Any]:
    root = _validate_directory(directory)
    _validate_layout(root)
    state_raw = _read_file(root, "state.json", 256 * 1024)
    state = _parse_json(state_raw, "state.json")
    request_id = state.get("requestId")
    if not isinstance(request_id, str) or REQUEST_ID_RE.fullmatch(request_id) is None:
        raise ForcedFixtureRotationEvidenceError("request ID is invalid")
    try:
        state = state_contract.validate_state(state, request_id)
        if state["phase"] != "SELECTED":
            raise ForcedFixtureRotationEvidenceError("forced rotation is not selected")
        state_contract.validate_transition(state["before"], state["after"])
    except state_contract.ForcedFixtureRotationStateError as exc:
        raise ForcedFixtureRotationEvidenceError(f"state contract is invalid: {exc}") from exc

    active_server_raw = _read_file(root, "active-server-leaves.json", 64 * 1024)
    active_server_leaves = _parse_json(
        active_server_raw, "active-server-leaves.json"
    )
    if (
        set(active_server_leaves) != {"asterisk", "sipp"}
        or active_server_leaves["asterisk"]
        != state["after"]["leaves"]["asterisk"]["sha256Fingerprint"]
        or active_server_leaves["sipp"]
        != state["after"]["leaves"]["sipp"]["sha256Fingerprint"]
    ):
        raise ForcedFixtureRotationEvidenceError(
            "active fixture server leaves differ from the selected generation"
        )

    source_digests: dict[str, str] = {
        "active-server-leaves.json": sha256_digest(active_server_raw),
        "state.json": sha256_digest(state_raw),
    }
    credential_raw = _read_file(root, "credential-digests.json", 64 * 1024)
    credential_digests = _parse_json(
        credential_raw, "credential-digests.json"
    )
    source_digests["credential-digests.json"] = sha256_digest(credential_raw)
    phases: dict[
        str,
        Mapping[str, tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]],
    ] = {}
    for phase in PHASES:
        phase_name = f"{phase}.json"
        phase_raw = _read_file(root, phase_name, 4 * 1024 * 1024)
        source_digests[phase_name] = sha256_digest(phase_raw)
        phases[phase] = _validate_phase(phase_raw, phase)
    route_identity = _validate_fleet_continuity(phases, credential_digests)

    edge_repins: list[Mapping[str, Any]] = []
    calls: list[Mapping[str, Any]] = []
    for node_id in ("sbc1", "sbc2"):
        edge_name = f"{node_id}-edge.json"
        bundle_name = f"{node_id}-bundle.json"
        edge_cdr_name = f"{node_id}-edge-cdr.json"
        reconciliation_name = f"{node_id}-cdr-reconciliation.json"
        edge_raw = _read_file(root, edge_name, 256 * 1024)
        bundle_raw = _read_file(root, bundle_name)
        edge_cdr_raw = _read_file(root, edge_cdr_name, 4 * 1024 * 1024)
        reconciliation_raw = _read_file(root, reconciliation_name, 4 * 1024 * 1024)
        source_digests[edge_name] = sha256_digest(edge_raw)
        source_digests[bundle_name] = sha256_digest(bundle_raw)
        source_digests[edge_cdr_name] = sha256_digest(edge_cdr_raw)
        source_digests[reconciliation_name] = sha256_digest(reconciliation_raw)
        edge_repin = _validate_edge_evidence(edge_raw, node_id, state)
        post_snapshot = phases["post-calls"][node_id][0]
        if (
            edge_repin["authorityDigest"]
            != post_snapshot["identitySources"]["runtimeAuthoritySha256"]
        ):
            raise ForcedFixtureRotationEvidenceError(
                f"{node_id} re-pin evidence is not bound to final runtime authority"
            )
        edge_repins.append(edge_repin)
        calls.append(
            _validate_call(
                bundle_raw,
                edge_cdr_raw=edge_cdr_raw,
                reconciliation_raw=reconciliation_raw,
                node_id=node_id,
                selected_at_ms=int(state["selectedAtEpochMs"]),
                expected_generation=int(route_identity["generation"]),
                route_identity=route_identity,
                expected_node_facts_digest=post_snapshot["identitySources"][
                    "nodeFactsSha256"
                ],
                expected_runtime_authority_digest=post_snapshot["identitySources"][
                    "runtimeAuthoritySha256"
                ],
            )
        )
    if calls[0]["testId"] == calls[1]["testId"]:
        raise ForcedFixtureRotationEvidenceError("fixture call test IDs are not unique")

    record: dict[str, Any] = {
        "acknowledgement": ACKNOWLEDGEMENT,
        "activeServerLeafFingerprints": active_server_leaves,
        "apiVersion": API_VERSION,
        "edgeRepins": edge_repins,
        "fixtureCalls": calls,
        "fixtureCaUnchanged": True,
        "fleetContinuity": {
            "generation": route_identity["generation"],
            "peerContinuity": "HEALTHY_AND_UNCHANGED_ACROSS_SERIAL_REPINS",
            "routeIdentity": {
                key: route_identity[key]
                for key in (
                    "allocationId",
                    "clusterId",
                    "customerAccountId",
                    "m365TenantId",
                    "serviceInstanceId",
                    "tenantContextId",
                )
            },
            "runtimeAndAgentState": "ACTIVE_CANDIDATES_UNCHANGED_AND_HEALTHY",
        },
        "kind": "ForcedSyntheticFixtureLeafRotationEvidence",
        "leafCertificatesChanged": list(LEAF_NAMES),
        "liveM365Interoperability": LIVE_M365_STATUS,
        "newGeneration": Path(state["after"]["generation"]).name,
        "previousGeneration": Path(state["before"]["generation"]).name,
        "pstnInteroperability": PSTN_STATUS,
        "requestId": request_id,
        "scope": SCOPE,
        "selectedAtEpochMs": state["selectedAtEpochMs"],
        "sourceDigests": source_digests,
        "status": "SYNTHETIC_FIXTURE_LEAF_ROTATION_ACCEPTED",
    }
    record["evidenceDigest"] = sha256_digest(canonical_bytes(record))
    return record


def _atomic_write(path: Path, content: bytes) -> None:
    if path.exists() or path.is_symlink():
        if _read_file(path.parent, path.name) != content:
            raise ForcedFixtureRotationEvidenceError(
                "existing acceptance evidence differs"
            )
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
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--evidence-dir", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        evidence = compile_evidence(args.evidence_dir)
        _atomic_write(args.evidence_dir / "acceptance.json", canonical_bytes(evidence))
    except (ForcedFixtureRotationEvidenceError, OSError) as exc:
        print(f"forced fixture leaf rotation evidence rejected: {exc}", file=sys.stderr)
        return 2
    print(f"FORCED_FIXTURE_LEAF_ROTATION_ACCEPTED {evidence['evidenceDigest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
