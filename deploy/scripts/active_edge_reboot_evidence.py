#!/usr/bin/env python3
"""Compile strict evidence for serialized active Edge reboot qualification.

The live playbook writes two canonical node observations and two complete
fixture-result bundles into one protected, ignored inventory directory.  This
offline compiler accepts only that fixed layout, binds every source by
SHA-256, and proves that each active candidate and its peer stayed identical
and healthy across an observed SSH outage and a changed kernel boot ID.

Only hashes, public/runtime identity, health results, timing, and synthetic
fixture summaries are emitted.  No credential or private key is read.
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


REQUEST_API_VERSION = "edge.vivolution.ae/active-edge-reboot-request/v0.1"
OBSERVATION_API_VERSION = "edge.vivolution.ae/active-edge-reboot-observation/v0.1"
EVIDENCE_API_VERSION = "edge.vivolution.ae/active-edge-reboot-evidence/v0.1"
ACKNOWLEDGEMENT = "REBOOT_ACTIVE_SYNTHETIC_EDGES_SBC1_THEN_SBC2_ONCE"
SCOPE = "BOUNDED_PRIVATE_SYNTHETIC_POC"
LIVE_M365_STATUS = "NOT_ASSERTED"
REBOOT_ORDER = ("sbc1", "sbc2")
SSH_LOSS_TIMEOUT_SECONDS = 60
SSH_RECONNECT_TIMEOUT_SECONDS = 300
TOTAL_RECONNECT_BOUND_SECONDS = 360
TOTAL_READY_BOUND_SECONDS = 480

REQUIRED_RUNTIME_CHECKS = (
    "systemd-nftables",
    "systemd-rtpengine-daemon",
    "systemd-opensips",
    "opensips-active-parse",
    "nft-owned-default-deny",
    "rtpengine-ng-ping",
    "listeners-exact",
    "rtpengine-control-loopback",
)
REQUIRED_ACTIVE_UNITS = (
    "nftables.service",
    "ntpsec.service",
    "opensips.service",
    "rtpengine-daemon.service",
    "ssh.service",
    "vivolution-edge-certificate.timer",
)

_REQUEST_KEYS = {
    "acknowledgement",
    "apiVersion",
    "liveM365Interoperability",
    "observations",
    "rebootOrder",
    "scope",
}
_REFERENCE_KEYS = {"fileName", "nodeId", "sha256"}
_OBSERVATION_KEYS = {
    "apiVersion",
    "completedAtEpochMs",
    "completedAtMonotonicNs",
    "fixture",
    "nodeId",
    "peer",
    "peerNodeId",
    "reboot",
    "target",
    "targetIdentitySources",
}
_IDENTITY_SOURCE_KEYS = {
    "nodeFactsAfterSha256",
    "nodeFactsBase64",
    "nodeFactsMetadata",
    "nodeFactsSha256",
    "runtimeAuthorityAfterSha256",
    "runtimeAuthorityBase64",
    "runtimeAuthorityMetadata",
    "runtimeAuthoritySha256",
}
_FILE_METADATA_KEYS = {"group", "mode", "nlink", "owner"}
_TARGET_KEYS = {"postCall", "postReboot", "pre"}
_PEER_KEYS = {
    "afterTargetCall",
    "before",
    "duringTargetSshLoss",
    "identitySources",
}
_SNAPSHOT_KEYS = {
    "agentState",
    "agentStatus",
    "bootId",
    "health",
    "recoveryUnitEnabled",
    "status",
    "transactionJournalPresent",
    "unitStates",
}
_AGENT_STATE_KEYS = {"group", "mode", "nlink", "owner", "sha256"}
_AGENT_STATUS_KEYS = {
    "activeLastKnownGood",
    "apiVersion",
    "highestSeenSequence",
    "kind",
    "lastAbortedCandidate",
    "pendingCandidate",
}
_AGENT_CANDIDATE_KEYS = {"manifestDigest", "sequence"}
_REBOOT_KEYS = {
    "readyObservedAtEpochMs",
    "readyObservedAtMonotonicNs",
    "rebootScheduledAtEpochMs",
    "rebootScheduledAtMonotonicNs",
    "scheduledUnit",
    "sshLossObservedAtEpochMs",
    "sshLossObservedAtMonotonicNs",
    "sshLossTimeoutSeconds",
    "sshReconnectObservedAtEpochMs",
    "sshReconnectObservedAtMonotonicNs",
    "sshReconnectTimeoutSeconds",
    "totalReconnectBoundSeconds",
    "totalReadyBoundSeconds",
}
_FIXTURE_KEYS = {
    "bundleFile",
    "bundleSha256",
    "cdrReconciliationFile",
    "cdrReconciliationSha256",
    "edgeCdrFile",
    "edgeCdrSha256",
    "startedAtEpochMs",
    "startedAtMonotonicNs",
    "testId",
}
_STATUS_KEYS = {
    "active",
    "apiVersion",
    "highestSeenSequence",
    "journalPresent",
    "kind",
    "lastEvidenceDigest",
    "previous",
}
_ACTIVE_KEYS = {
    "kind",
    "manifestDigest",
    "relativePath",
    "releaseDigest",
    "sequence",
    "slot",
}
_HEALTH_KEYS = {
    "active",
    "apiVersion",
    "highestSeenSequence",
    "kind",
    "runtimeChecks",
}
_RUNTIME_CHECK_KEYS = {"name", "status"}
_FACT_KEYS = {
    "allocationId",
    "authorizedPbxSourceIpv4Cidrs",
    "clusterId",
    "clusterMediaPortEnd",
    "clusterMediaPortStart",
    "customerAccountId",
    "generation",
    "m365TenantId",
    "nodeFqdn",
    "nodeId",
    "privateIpv4",
    "publicIpv4",
    "pbxMediaDestinationPortEnd",
    "pbxMediaDestinationPortStart",
    "rtpengineNgHost",
    "rtpengineNgPort",
    "serviceInstanceId",
    "slot",
    "syntheticTeamsSourceIpv4Cidrs",
    "teamsMediaSourceIpv4Cidrs",
    "teamsSignalingSourceIpv4Cidrs",
    "teamsTlsPort",
    "tenantContextId",
    "tenantListenerPort",
    "tenantMediaPortEnd",
    "tenantMediaPortStart",
}
_AUTHORITY_KEYS = {
    "administratorSourceIpv4Cidrs",
    "apiVersion",
    "azureDhcpServerIpv4",
    "generation",
    "nodeId",
    "profile",
    "secretDigests",
    "slot",
}
_SYNTHETIC_SECRET_NAMES = {
    "edgeCertificateChainPem",
    "edgePrivateKeyPem",
    "fixtureCaCrt",
    "fixtureClientCrt",
    "fixtureClientKey",
    "microsoftCaBundlePem",
    "pbxCaBundlePem",
    "publicCaBundlePem",
}

_DIGEST_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_HEX_DIGEST_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_UUID_RE = re.compile(
    r"\A[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_TEST_ID_RE = re.compile(r"\A([0-9]{8}T[0-9]{6}Z)-(sbc[12])-[0-9]{1,10}\Z")
_RUN_ID_RE = re.compile(r"\A[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}\Z")
_IDENTIFIER_RE = re.compile(r"\A[a-z0-9][a-z0-9_.:-]{0,127}\Z")


class ActiveEdgeRebootEvidenceError(ValueError):
    """Collected reboot material violates the fixed private POC contract."""


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def sha256_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _exact_mapping(value: object, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ActiveEdgeRebootEvidenceError(
            f"{label} must have exact keys {sorted(keys)}"
        )
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ActiveEdgeRebootEvidenceError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise ActiveEdgeRebootEvidenceError(f"{label} is outside its fixed bounds")
    return value


def _clock_interval(
    start_epoch_ms: int,
    start_monotonic_ns: int,
    end_epoch_ms: int,
    end_monotonic_ns: int,
    label: str,
    *,
    bound_ns: int | None = None,
) -> None:
    """Bind a positive interval to one controller monotonic clock origin."""

    monotonic_delta = end_monotonic_ns - start_monotonic_ns
    epoch_delta_ns = (end_epoch_ms - start_epoch_ms) * 1_000_000
    if (
        monotonic_delta <= 0
        or epoch_delta_ns <= 0
        or (bound_ns is not None and monotonic_delta > bound_ns)
        or (bound_ns is not None and epoch_delta_ns > bound_ns)
        or abs(epoch_delta_ns - monotonic_delta) > 2_000_000_000
    ):
        raise ActiveEdgeRebootEvidenceError(
            f"{label} exceeded its bound or changed controller clock origin"
        )


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ActiveEdgeRebootEvidenceError(f"{label} is not a SHA-256 digest")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ActiveEdgeRebootEvidenceError(f"{label} is not a bounded identifier")
    return value


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ActiveEdgeRebootEvidenceError("JSON contains a duplicate member")
        result[key] = value
    return result


def _parse_json(raw: bytes, label: str, *, canonical: bool = True) -> Mapping[str, Any]:
    try:
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ActiveEdgeRebootEvidenceError(
            f"{label} is not one UTF-8 JSON document"
        ) from exc
    if not isinstance(value, dict):
        raise ActiveEdgeRebootEvidenceError(f"{label} must be a JSON object")
    if canonical and canonical_bytes(value) != raw:
        raise ActiveEdgeRebootEvidenceError(f"{label} is not canonical JSON")
    return value


def _decode_json(value: object, label: str, maximum: int = 512 * 1024) -> tuple[bytes, Mapping[str, Any]]:
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
        raise ActiveEdgeRebootEvidenceError(f"{label} is not bounded base64")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ActiveEdgeRebootEvidenceError(f"{label} is not strict base64") from exc
    if not raw or len(raw) > maximum:
        raise ActiveEdgeRebootEvidenceError(f"{label} is empty or oversized")
    return raw, _parse_json(raw, label, canonical=False)


def _read_fixed_file(directory: Path, name: str, maximum: int = 80 * 1024 * 1024) -> bytes:
    path = directory / name
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise ActiveEdgeRebootEvidenceError(f"{name} is absent") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_size < 1
        or before.st_size > maximum
    ):
        raise ActiveEdgeRebootEvidenceError(
            f"{name} must be a bounded runner-owned single-link mode-0600 file"
        )
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    after = path.lstat()
    if len(raw) > maximum or (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ):
        raise ActiveEdgeRebootEvidenceError(f"{name} changed while read")
    return raw


def _validate_directory(directory: Path) -> Path:
    try:
        metadata = directory.lstat()
    except FileNotFoundError as exc:
        raise ActiveEdgeRebootEvidenceError("evidence directory is absent") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or _RUN_ID_RE.fullmatch(directory.name) is None
    ):
        raise ActiveEdgeRebootEvidenceError(
            "evidence directory must be a real runner-owned mode-0700 run ID"
        )
    return directory.resolve(strict=True)


def _validate_layout(directory: Path) -> None:
    expected = {
        "request.json",
        "sbc1-observation.json",
        "sbc2-observation.json",
        "sbc1-fixture-bundle.json",
        "sbc2-fixture-bundle.json",
        "sbc1-edge-cdr.json",
        "sbc2-edge-cdr.json",
        "sbc1-cdr-reconciliation.json",
        "sbc2-cdr-reconciliation.json",
    }
    actual = {entry.name for entry in os.scandir(directory)}
    actual.discard("acceptance.json")
    if actual != expected:
        raise ActiveEdgeRebootEvidenceError(
            "evidence layout must contain only the request, two observations, "
            "two fixture bundles, two Edge CDRs, and two CDR reconciliations"
        )


def _validate_release_ref(
    value: object, node: str, label: str, *, candidate_required: bool
) -> Mapping[str, Any]:
    release = _exact_mapping(value, _ACTIVE_KEYS, f"{node} {label}")
    kind = release["kind"]
    sequence = _integer(release["sequence"], f"{node} {label} sequence", 0, 2**53 - 1)
    release_digest = _digest(release["releaseDigest"], f"{node} {label} release digest")
    if candidate_required and kind != "CANDIDATE":
        raise ActiveEdgeRebootEvidenceError(f"{node} active release is not a candidate")
    if kind == "BOOTSTRAP":
        if (
            candidate_required
            or release["slot"] != "NONE"
            or sequence != 0
            or release["manifestDigest"] is not None
            or release["relativePath"] != "bootstrap"
        ):
            raise ActiveEdgeRebootEvidenceError(f"{node} bootstrap release identity is invalid")
        return release
    if kind != "CANDIDATE" or release["slot"] not in {"A", "B"} or sequence < 1:
        raise ActiveEdgeRebootEvidenceError(f"{node} candidate release identity is invalid")
    manifest_digest = _digest(
        release["manifestDigest"], f"{node} {label} manifest digest"
    )
    expected_relative = "slots/{}/{:016d}-{}".format(
        release["slot"], sequence, manifest_digest.split(":", 1)[1]
    )
    if release["relativePath"] != expected_relative or not release_digest:
        raise ActiveEdgeRebootEvidenceError(f"{node} candidate release path is not canonical")
    return release


def _validate_status(value: object, node: str) -> Mapping[str, Any]:
    status = _exact_mapping(value, _STATUS_KEYS, f"{node} runtime status")
    if (
        status["apiVersion"] != "edge.vivolution.ae/runtime/v0.1"
        or status["kind"] != "EdgeRuntimeStatus"
        or status["journalPresent"] is not False
    ):
        raise ActiveEdgeRebootEvidenceError(f"{node} runtime status is not journal-free")
    active = _validate_release_ref(status["active"], node, "active candidate", candidate_required=True)
    sequence = active["sequence"]
    highest = _integer(
        status["highestSeenSequence"],
        f"{node} runtime replay floor",
        1,
        2**53 - 1,
    )
    if highest != sequence:
        raise ActiveEdgeRebootEvidenceError(f"{node} active candidate sequence is not current")
    if status["previous"] is not None:
        _validate_release_ref(status["previous"], node, "previous release", candidate_required=False)
    _digest(status["lastEvidenceDigest"], f"{node} last evidence digest")
    return status


def _validate_health(
    value: object, node: str, status: Mapping[str, Any]
) -> Mapping[str, Any]:
    health = _exact_mapping(value, _HEALTH_KEYS, f"{node} runtime health")
    highest = _integer(
        health["highestSeenSequence"],
        f"{node} health replay floor",
        1,
        2**53 - 1,
    )
    if (
        health["apiVersion"] != "edge.vivolution.ae/runtime/v0.1"
        or health["kind"] != "EdgeRuntimeHealth"
        or health["active"] != status["active"]
        or highest != status["highestSeenSequence"]
    ):
        raise ActiveEdgeRebootEvidenceError(f"{node} runtime health identity is invalid")
    checks = health["runtimeChecks"]
    if not isinstance(checks, list) or len(checks) != len(REQUIRED_RUNTIME_CHECKS):
        raise ActiveEdgeRebootEvidenceError(f"{node} runtime checks are incomplete")
    normalized: list[str] = []
    for value in checks:
        check = _exact_mapping(value, _RUNTIME_CHECK_KEYS, f"{node} runtime check")
        if check["status"] != "PASSED" or not isinstance(check["name"], str):
            raise ActiveEdgeRebootEvidenceError(f"{node} runtime check did not pass")
        normalized.append(check["name"])
    if tuple(normalized) != REQUIRED_RUNTIME_CHECKS:
        raise ActiveEdgeRebootEvidenceError(
            f"{node} runtime checks differ from the complete ordered baseline"
        )
    return health


def _validate_agent_candidate(value: object, node: str, label: str) -> Mapping[str, Any]:
    candidate = _exact_mapping(value, _AGENT_CANDIDATE_KEYS, f"{node} {label}")
    _integer(candidate["sequence"], f"{node} {label} sequence", 1, 2**53 - 1)
    _digest(candidate["manifestDigest"], f"{node} {label} manifest digest")
    return candidate


def _validate_agent_status(
    value: object, node: str, runtime_status: Mapping[str, Any]
) -> Mapping[str, Any]:
    agent = _exact_mapping(value, _AGENT_STATUS_KEYS, f"{node} Agent status")
    if (
        agent["apiVersion"] != "edge.vivolution.ae/agent-state/v0.1"
        or agent["kind"] != "EdgeAgentProtectedStateStatus"
        or agent["pendingCandidate"] is not None
    ):
        raise ActiveEdgeRebootEvidenceError(
            f"{node} Agent state is absent, pending, or not committed"
        )
    lkg = _validate_agent_candidate(agent["activeLastKnownGood"], node, "Agent LKG")
    highest = _integer(
        agent["highestSeenSequence"],
        f"{node} Agent replay floor",
        1,
        2**53 - 1,
    )
    expected_lkg = {
        "manifestDigest": runtime_status["active"]["manifestDigest"],
        "sequence": runtime_status["active"]["sequence"],
    }
    if (
        dict(lkg) != expected_lkg
        or highest != runtime_status["highestSeenSequence"]
    ):
        raise ActiveEdgeRebootEvidenceError(
            f"{node} Agent LKG differs from the active runtime candidate"
        )
    if agent["lastAbortedCandidate"] is not None:
        aborted = _validate_agent_candidate(
            agent["lastAbortedCandidate"], node, "last aborted candidate"
        )
        if aborted["sequence"] > highest:
            raise ActiveEdgeRebootEvidenceError(
                f"{node} Agent abort tombstone exceeds its replay floor"
            )
    return agent


def _validate_agent_state(value: object, node: str) -> Mapping[str, Any]:
    state = _exact_mapping(value, _AGENT_STATE_KEYS, f"{node} Agent state file")
    links = _integer(state["nlink"], f"{node} Agent state link count", 1, 1)
    if (
        state["owner"] != "vivolution-edge-agent"
        or state["group"] != "vivolution-edge-agent"
        or state["mode"] != "0600"
        or links != 1
    ):
        raise ActiveEdgeRebootEvidenceError(f"{node} Agent state file is unprotected")
    _digest(state["sha256"], f"{node} Agent state file digest")
    return state


def _validate_snapshot(value: object, node: str) -> Mapping[str, Any]:
    snapshot = _exact_mapping(value, _SNAPSHOT_KEYS, f"{node} snapshot")
    if not isinstance(snapshot["bootId"], str) or _UUID_RE.fullmatch(snapshot["bootId"]) is None:
        raise ActiveEdgeRebootEvidenceError(f"{node} boot ID is invalid")
    if snapshot["transactionJournalPresent"] is not False:
        raise ActiveEdgeRebootEvidenceError(f"{node} runtime transaction journal is present")
    if snapshot["recoveryUnitEnabled"] != "enabled":
        raise ActiveEdgeRebootEvidenceError(f"{node} boot recovery unit is not enabled")
    units = snapshot["unitStates"]
    if not isinstance(units, dict) or set(units) != set(REQUIRED_ACTIVE_UNITS):
        raise ActiveEdgeRebootEvidenceError(f"{node} active unit inventory is incomplete")
    if any(value != "active" for value in units.values()):
        raise ActiveEdgeRebootEvidenceError(f"{node} has an inactive required unit")
    status = _validate_status(snapshot["status"], node)
    _validate_health(snapshot["health"], node, status)
    _validate_agent_status(snapshot["agentStatus"], node, status)
    _validate_agent_state(snapshot["agentState"], node)
    return snapshot


def _validate_facts(value: object, node: str) -> Mapping[str, Any]:
    facts = _exact_mapping(value, _FACT_KEYS, f"{node} node facts")
    expected = {
        "sbc1": ("A", "10.20.2.4", "sbc1.voice.vivolution.ae"),
        "sbc2": ("B", "10.20.2.5", "sbc2.voice.vivolution.ae"),
    }[node]
    if (
        facts["nodeId"] != node
        or facts["slot"] != expected[0]
        or facts["privateIpv4"] != expected[1]
        or facts["nodeFqdn"] != expected[2]
        or facts["authorizedPbxSourceIpv4Cidrs"] != ["10.20.1.4/32"]
        or facts["syntheticTeamsSourceIpv4Cidrs"] != []
        or facts["teamsTlsPort"] != 5061
        or facts["tenantListenerPort"] != 15061
        or facts["tenantMediaPortStart"] != 20000
        or facts["tenantMediaPortEnd"] != 20255
        or facts["clusterMediaPortStart"] != 20000
        or facts["clusterMediaPortEnd"] != 29999
        or facts["rtpengineNgHost"] != "127.0.0.1"
        or facts["rtpengineNgPort"] != 2223
    ):
        raise ActiveEdgeRebootEvidenceError(f"{node} facts are outside the fixed private POC")
    _integer(facts["generation"], f"{node} generation", 1, 2**31 - 1)
    for name in (
        "allocationId",
        "clusterId",
        "customerAccountId",
        "serviceInstanceId",
        "tenantContextId",
    ):
        _identifier(facts[name], f"{node} {name}")
    if not isinstance(facts["m365TenantId"], str) or _UUID_RE.fullmatch(facts["m365TenantId"]) is None:
        raise ActiveEdgeRebootEvidenceError(f"{node} M365 tenant ID is invalid")
    if not isinstance(facts["publicIpv4"], str) or not facts["publicIpv4"]:
        raise ActiveEdgeRebootEvidenceError(f"{node} public address is invalid")
    return facts


def _validate_authority(
    value: object, node: str, facts: Mapping[str, Any]
) -> Mapping[str, Any]:
    authority = _exact_mapping(value, _AUTHORITY_KEYS, f"{node} runtime authority")
    generation = _integer(
        authority["generation"], f"{node} authority generation", 1, 2**31 - 1
    )
    if (
        authority["apiVersion"] != "edge.vivolution.ae/runtime-authority/v0.1"
        or authority["nodeId"] != node
        or generation != facts["generation"]
        or authority["slot"] != facts["slot"]
        or authority["profile"] != "SYNTHETIC_PRIVATE"
        or authority["azureDhcpServerIpv4"] != "168.63.129.16"
    ):
        raise ActiveEdgeRebootEvidenceError(f"{node} runtime authority is invalid")
    secrets = authority["secretDigests"]
    if not isinstance(secrets, dict) or set(secrets) != _SYNTHETIC_SECRET_NAMES:
        raise ActiveEdgeRebootEvidenceError(f"{node} synthetic secret digest set is incomplete")
    for name, digest in secrets.items():
        _digest(digest, f"{node} secret digest {name}")
    return authority


def _validate_identity_sources(
    value: object, node: str
) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
    sources = _exact_mapping(value, _IDENTITY_SOURCE_KEYS, f"{node} identity sources")
    facts_raw, facts = _decode_json(sources["nodeFactsBase64"], f"{node} node facts")
    authority_raw, authority = _decode_json(
        sources["runtimeAuthorityBase64"], f"{node} runtime authority"
    )
    facts_digest = sha256_digest(facts_raw)
    authority_digest = sha256_digest(authority_raw)
    if (
        sources["nodeFactsSha256"] != facts_digest
        or sources["nodeFactsAfterSha256"] != facts_digest
        or sources["runtimeAuthoritySha256"] != authority_digest
        or sources["runtimeAuthorityAfterSha256"] != authority_digest
    ):
        raise ActiveEdgeRebootEvidenceError(f"{node} immutable identity bytes changed")
    for key in ("nodeFactsMetadata", "runtimeAuthorityMetadata"):
        metadata = _exact_mapping(sources[key], _FILE_METADATA_KEYS, f"{node} {key}")
        links = _integer(metadata["nlink"], f"{node} {key} link count", 1, 1)
        if (
            metadata["group"] != "root"
            or metadata["mode"] != "0600"
            or links != 1
            or metadata["owner"] != "root"
        ):
            raise ActiveEdgeRebootEvidenceError(
                f"{node} immutable identity source metadata is unprotected"
            )
    facts = _validate_facts(facts, node)
    authority = _validate_authority(authority, node, facts)
    return sources, facts, authority


def _validate_reboot(value: object, node: str) -> Mapping[str, Any]:
    reboot = _exact_mapping(value, _REBOOT_KEYS, f"{node} reboot timing")
    if (
        reboot["scheduledUnit"] != "vivolution-active-edge-reboot-qualifier"
        or reboot["sshLossTimeoutSeconds"] != SSH_LOSS_TIMEOUT_SECONDS
        or reboot["sshReconnectTimeoutSeconds"] != SSH_RECONNECT_TIMEOUT_SECONDS
        or reboot["totalReconnectBoundSeconds"] != TOTAL_RECONNECT_BOUND_SECONDS
        or reboot["totalReadyBoundSeconds"] != TOTAL_READY_BOUND_SECONDS
    ):
        raise ActiveEdgeRebootEvidenceError(f"{node} reboot bounds are not exact")
    scheduled = _integer(
        reboot["rebootScheduledAtMonotonicNs"], f"{node} reboot start", 1, 2**63 - 1
    )
    lost = _integer(
        reboot["sshLossObservedAtMonotonicNs"], f"{node} SSH loss", 1, 2**63 - 1
    )
    reconnected = _integer(
        reboot["sshReconnectObservedAtMonotonicNs"],
        f"{node} SSH reconnect",
        1,
        2**63 - 1,
    )
    ready = _integer(
        reboot["readyObservedAtMonotonicNs"], f"{node} runtime readiness", 1, 2**63 - 1
    )
    if not scheduled < lost < reconnected <= ready:
        raise ActiveEdgeRebootEvidenceError(f"{node} reboot monotonic sequence is invalid")
    if lost - scheduled > SSH_LOSS_TIMEOUT_SECONDS * 1_000_000_000:
        raise ActiveEdgeRebootEvidenceError(f"{node} SSH loss exceeded its bound")
    if reconnected - lost > SSH_RECONNECT_TIMEOUT_SECONDS * 1_000_000_000:
        raise ActiveEdgeRebootEvidenceError(f"{node} SSH reconnect exceeded its bound")
    if reconnected - scheduled > TOTAL_RECONNECT_BOUND_SECONDS * 1_000_000_000:
        raise ActiveEdgeRebootEvidenceError(f"{node} total reboot exceeded its bound")
    if ready - scheduled > TOTAL_READY_BOUND_SECONDS * 1_000_000_000:
        raise ActiveEdgeRebootEvidenceError(f"{node} runtime readiness exceeded its bound")
    epoch_values: dict[str, int] = {}
    for key in (
        "rebootScheduledAtEpochMs",
        "sshLossObservedAtEpochMs",
        "sshReconnectObservedAtEpochMs",
        "readyObservedAtEpochMs",
    ):
        epoch_values[key] = _integer(reboot[key], f"{node} {key}", 1, 2**63 - 1)
    _clock_interval(
        epoch_values["rebootScheduledAtEpochMs"],
        scheduled,
        epoch_values["sshLossObservedAtEpochMs"],
        lost,
        f"{node} SSH-loss observation",
        bound_ns=SSH_LOSS_TIMEOUT_SECONDS * 1_000_000_000,
    )
    _clock_interval(
        epoch_values["sshLossObservedAtEpochMs"],
        lost,
        epoch_values["sshReconnectObservedAtEpochMs"],
        reconnected,
        f"{node} SSH reconnect",
        bound_ns=SSH_RECONNECT_TIMEOUT_SECONDS * 1_000_000_000,
    )
    _clock_interval(
        epoch_values["rebootScheduledAtEpochMs"],
        scheduled,
        epoch_values["sshReconnectObservedAtEpochMs"],
        reconnected,
        f"{node} total reconnect",
        bound_ns=TOTAL_RECONNECT_BOUND_SECONDS * 1_000_000_000,
    )
    _clock_interval(
        epoch_values["rebootScheduledAtEpochMs"],
        scheduled,
        epoch_values["readyObservedAtEpochMs"],
        ready,
        f"{node} runtime readiness",
        bound_ns=TOTAL_READY_BOUND_SECONDS * 1_000_000_000,
    )
    return reboot


def _load_fixture_contract() -> Any:
    path = Path(__file__).with_name("synthetic_failover_evidence.py")
    specification = importlib.util.spec_from_file_location(
        "vivolution_active_reboot_fixture_contract", path
    )
    if specification is None or specification.loader is None:
        raise ActiveEdgeRebootEvidenceError("fixture bundle contract cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _validate_fixture(
    directory: Path,
    value: object,
    node: str,
    reconnect: Mapping[str, Any],
    facts: Mapping[str, Any],
    identity_sources: Mapping[str, Any],
) -> Mapping[str, Any]:
    fixture = _exact_mapping(value, _FIXTURE_KEYS, f"{node} fixture identity")
    expected_file = f"{node}-fixture-bundle.json"
    if fixture["bundleFile"] != expected_file:
        raise ActiveEdgeRebootEvidenceError(f"{node} fixture bundle name is invalid")
    started_monotonic = _integer(
        fixture["startedAtMonotonicNs"], f"{node} fixture start", 1, 2**63 - 1
    )
    if started_monotonic < reconnect["readyObservedAtMonotonicNs"]:
        raise ActiveEdgeRebootEvidenceError(
            f"{node} fixture call predates full runtime readiness"
        )
    started_epoch = _integer(
        fixture["startedAtEpochMs"], f"{node} fixture epoch", 1, 2**63 - 1
    )
    _clock_interval(
        reconnect["readyObservedAtEpochMs"],
        reconnect["readyObservedAtMonotonicNs"],
        started_epoch,
        started_monotonic,
        f"{node} readiness-to-fixture interval",
    )
    raw = _read_fixed_file(directory, expected_file)
    if fixture["bundleSha256"] != sha256_digest(raw):
        raise ActiveEdgeRebootEvidenceError(f"{node} fixture bundle digest differs")
    contract = _load_fixture_contract()
    try:
        artifacts, manifest, test_id = contract._parse_bundle(raw, f"{node} reboot")
        summary = contract._parse_summary(artifacts["summary.txt"], f"{node} reboot")
    except contract.FailoverEvidenceError as exc:
        raise ActiveEdgeRebootEvidenceError(f"{node} fixture bundle is invalid: {exc}") from exc
    expected_target = "10.20.2.4" if node == "sbc1" else "10.20.2.5"
    if (
        fixture["testId"] != test_id
        or summary["testId"] != test_id
        or summary["nodeId"] != node
        or summary["target"] != expected_target
        or artifacts["RESULT"] != b"PASS\n"
    ):
        raise ActiveEdgeRebootEvidenceError(f"{node} fixture did not prove the exact node")
    match = _TEST_ID_RE.fullmatch(test_id)
    assert match is not None
    call_epoch = int(
        datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ")
        .replace(tzinfo=timezone.utc)
        .timestamp()
        * 1000
    )
    if not fixture["startedAtEpochMs"] - 2000 <= call_epoch <= fixture["startedAtEpochMs"] + 30000:
        raise ActiveEdgeRebootEvidenceError(
            f"{node} fixture test ID is outside the fresh-call start window"
        )
    expected_edge_file = f"{node}-edge-cdr.json"
    expected_reconciliation_file = f"{node}-cdr-reconciliation.json"
    if (
        fixture["edgeCdrFile"] != expected_edge_file
        or fixture["cdrReconciliationFile"] != expected_reconciliation_file
    ):
        raise ActiveEdgeRebootEvidenceError(
            f"{node} CDR evidence file names are invalid"
        )
    edge_cdr_raw = _read_fixed_file(directory, expected_edge_file, 1024 * 1024)
    reconciliation_raw = _read_fixed_file(
        directory, expected_reconciliation_file, 1024 * 1024
    )
    if fixture["edgeCdrSha256"] != sha256_digest(edge_cdr_raw):
        raise ActiveEdgeRebootEvidenceError(f"{node} Edge CDR digest differs")
    if fixture["cdrReconciliationSha256"] != sha256_digest(reconciliation_raw):
        raise ActiveEdgeRebootEvidenceError(
            f"{node} CDR reconciliation digest differs"
        )
    try:
        cdr_reconciliation_digest = contract._validate_cdr_reconciliation(
            reconciliation_raw,
            edge_cdr_raw=edge_cdr_raw,
            fixture_artifacts=artifacts,
            fixture_manifest_raw=manifest,
            phase=f"{node} reboot",
            test_id=test_id,
            node_id=node,
            expected_generation=facts["generation"],
            route_identity={
                "allocationId": facts["allocationId"],
                "clusterId": facts["clusterId"],
                "serviceInstanceId": facts["serviceInstanceId"],
                "tenantContextId": facts["tenantContextId"],
            },
        )
    except contract.FailoverEvidenceError as exc:
        raise ActiveEdgeRebootEvidenceError(
            f"{node} fixture/Edge CDR reconciliation is invalid: {exc}"
        ) from exc
    reconciliation = _parse_json(
        reconciliation_raw, f"{node} CDR reconciliation"
    )
    if (
        reconciliation["nodeIdentity"]["nodeFactsDigest"]
        != identity_sources["nodeFactsSha256"]
        or reconciliation["nodeIdentity"]["runtimeAuthorityDigest"]
        != identity_sources["runtimeAuthoritySha256"]
    ):
        raise ActiveEdgeRebootEvidenceError(
            f"{node} CDR evidence is not bound to the qualified identity sources"
        )
    return {
        **summary,
        "bundleDigest": fixture["bundleSha256"],
        "cdrReconciliationDigest": cdr_reconciliation_digest,
        "cdrReconciliationFileDigest": fixture["cdrReconciliationSha256"],
        "cdrReconciliationStatus": "SYNTHETIC_EDGE_FIXTURE_CDR_RECONCILED",
        "edgeCdrDigest": fixture["edgeCdrSha256"],
        "fixtureManifestDigest": sha256_digest(manifest),
        "result": "PASS",
        "startedAtEpochMs": fixture["startedAtEpochMs"],
        "startedAtMonotonicNs": fixture["startedAtMonotonicNs"],
    }


def _snapshot_digest(snapshot: Mapping[str, Any]) -> str:
    return sha256_digest(canonical_bytes(snapshot))


def _validate_observation(
    directory: Path, raw: bytes, node: str
) -> tuple[dict[str, Any], Mapping[str, Any], Mapping[str, Any]]:
    observation = _exact_mapping(
        _parse_json(raw, f"{node} observation"),
        _OBSERVATION_KEYS,
        f"{node} observation",
    )
    peer_node = "sbc2" if node == "sbc1" else "sbc1"
    if (
        observation["apiVersion"] != OBSERVATION_API_VERSION
        or observation["nodeId"] != node
        or observation["peerNodeId"] != peer_node
    ):
        raise ActiveEdgeRebootEvidenceError(f"{node} observation identity is invalid")
    completed_epoch = _integer(
        observation["completedAtEpochMs"], f"{node} observation completion", 1, 2**63 - 1
    )
    completed_monotonic = _integer(
        observation["completedAtMonotonicNs"],
        f"{node} observation monotonic completion",
        1,
        2**63 - 1,
    )

    target_sources, facts, authority = _validate_identity_sources(
        observation["targetIdentitySources"], node
    )
    target = _exact_mapping(observation["target"], _TARGET_KEYS, f"{node} target")
    target_pre = _validate_snapshot(target["pre"], node)
    target_post = _validate_snapshot(target["postReboot"], node)
    target_post_call = _validate_snapshot(target["postCall"], node)
    if target_pre["bootId"] == target_post["bootId"]:
        raise ActiveEdgeRebootEvidenceError(f"{node} kernel boot ID did not change")
    if target_post["bootId"] != target_post_call["bootId"]:
        raise ActiveEdgeRebootEvidenceError(f"{node} rebooted again during its fixture call")
    for key in (
        "agentState",
        "agentStatus",
        "status",
        "health",
        "unitStates",
        "recoveryUnitEnabled",
    ):
        if target_pre[key] != target_post[key] or target_pre[key] != target_post_call[key]:
            raise ActiveEdgeRebootEvidenceError(
                f"{node} {key} differs across reboot qualification"
            )

    peer = _exact_mapping(observation["peer"], _PEER_KEYS, f"{node} peer")
    peer_sources, peer_facts, peer_authority = _validate_identity_sources(
        peer["identitySources"], peer_node
    )
    peer_before = _validate_snapshot(peer["before"], peer_node)
    peer_during = _validate_snapshot(peer["duringTargetSshLoss"], peer_node)
    peer_after = _validate_snapshot(peer["afterTargetCall"], peer_node)
    if peer_before != peer_during or peer_before != peer_after:
        raise ActiveEdgeRebootEvidenceError(
            f"{node} peer changed while the target reboot was qualified"
        )

    for key in (
        "allocationId",
        "clusterId",
        "customerAccountId",
        "generation",
        "m365TenantId",
        "serviceInstanceId",
        "tenantContextId",
    ):
        if facts[key] != peer_facts[key]:
            raise ActiveEdgeRebootEvidenceError(
                f"{node} and its peer do not share one immutable tenant route"
            )

    reboot = _validate_reboot(observation["reboot"], node)
    fixture = _validate_fixture(
        directory,
        observation["fixture"],
        node,
        reboot,
        facts,
        target_sources,
    )
    if completed_monotonic <= fixture["startedAtMonotonicNs"]:
        raise ActiveEdgeRebootEvidenceError(
            f"{node} observation completion predates its fixture call"
        )
    _clock_interval(
        fixture["startedAtEpochMs"],
        fixture["startedAtMonotonicNs"],
        completed_epoch,
        completed_monotonic,
        f"{node} fixture-to-observation interval",
    )
    record = {
        "fixtureCall": fixture,
        "nodeFacts": facts,
        "nodeFactsDigest": target_sources["nodeFactsSha256"],
        "nodeId": node,
        "observationCompletedAtEpochMs": completed_epoch,
        "observationCompletedAtMonotonicNs": completed_monotonic,
        "peerContinuity": {
            "agentStateDigest": peer_before["agentState"]["sha256"],
            "agentStatusDigest": _snapshot_digest(peer_before["agentStatus"]),
            "bootId": peer_before["bootId"],
            "healthDigest": _snapshot_digest(peer_before["health"]),
            "nodeFactsDigest": peer_sources["nodeFactsSha256"],
            "nodeId": peer_node,
            "runtimeAuthorityDigest": peer_sources["runtimeAuthoritySha256"],
            "runtimeStatusDigest": _snapshot_digest(peer_before["status"]),
            "status": "HEALTHY_AND_UNCHANGED",
        },
        "reboot": {
            "bootIdAfter": target_post["bootId"],
            "bootIdBefore": target_pre["bootId"],
            "readyElapsedMilliseconds": (
                reboot["readyObservedAtMonotonicNs"]
                - reboot["rebootScheduledAtMonotonicNs"]
                + 999_999
            )
            // 1_000_000,
            "readyObservedAtEpochMs": reboot["readyObservedAtEpochMs"],
            "readyObservedAtMonotonicNs": reboot["readyObservedAtMonotonicNs"],
            "rebootScheduledAtEpochMs": reboot["rebootScheduledAtEpochMs"],
            "rebootScheduledAtMonotonicNs": reboot["rebootScheduledAtMonotonicNs"],
            "reconnectElapsedMilliseconds": (
                reboot["sshReconnectObservedAtMonotonicNs"]
                - reboot["rebootScheduledAtMonotonicNs"]
                + 999_999
            )
            // 1_000_000,
            "sshLossObserved": True,
            "sshLossObservedAtEpochMs": reboot["sshLossObservedAtEpochMs"],
            "sshLossObservedAtMonotonicNs": reboot["sshLossObservedAtMonotonicNs"],
            "sshLossTimeoutSeconds": reboot["sshLossTimeoutSeconds"],
            "sshReconnectObservedAtEpochMs": reboot["sshReconnectObservedAtEpochMs"],
            "sshReconnectObservedAtMonotonicNs": reboot[
                "sshReconnectObservedAtMonotonicNs"
            ],
            "sshReconnectTimeoutSeconds": reboot["sshReconnectTimeoutSeconds"],
            "totalReadyBoundSeconds": reboot["totalReadyBoundSeconds"],
            "totalReconnectBoundSeconds": reboot["totalReconnectBoundSeconds"],
        },
        "runtime": {
            "activeCandidate": target_pre["status"]["active"],
            "agentStateDigest": target_pre["agentState"]["sha256"],
            "agentStatusDigest": _snapshot_digest(target_pre["agentStatus"]),
            "healthDigest": _snapshot_digest(target_pre["health"]),
            "lastEvidenceDigest": target_pre["status"]["lastEvidenceDigest"],
            "runtimeChecks": target_pre["health"]["runtimeChecks"],
            "runtimeStatusDigest": _snapshot_digest(target_pre["status"]),
        },
        "runtimeAuthority": {
            "generation": authority["generation"],
            "nodeId": authority["nodeId"],
            "profile": authority["profile"],
            "slot": authority["slot"],
        },
        "runtimeAuthorityDigest": target_sources["runtimeAuthoritySha256"],
        "status": "ACTIVE_EDGE_REBOOT_QUALIFIED",
    }
    bridge = {
        "peerBefore": peer_before,
        "peerIdentitySources": peer_sources,
        "targetIdentitySources": target_sources,
        "targetPre": target_pre,
        "targetPostCall": target_post_call,
    }
    return record, facts, bridge


def compile_evidence(directory: Path) -> Mapping[str, Any]:
    root = _validate_directory(directory)
    _validate_layout(root)
    request = _exact_mapping(
        _parse_json(_read_fixed_file(root, "request.json"), "request.json"),
        _REQUEST_KEYS,
        "reboot request",
    )
    if (
        request["apiVersion"] != REQUEST_API_VERSION
        or request["acknowledgement"] != ACKNOWLEDGEMENT
        or request["scope"] != SCOPE
        or request["liveM365Interoperability"] != LIVE_M365_STATUS
        or request["rebootOrder"] != list(REBOOT_ORDER)
    ):
        raise ActiveEdgeRebootEvidenceError("reboot request authority is not exact")
    references = request["observations"]
    if not isinstance(references, list) or len(references) != 2:
        raise ActiveEdgeRebootEvidenceError("request must bind exactly two observations")

    nodes: list[dict[str, Any]] = []
    facts_by_node: dict[str, Mapping[str, Any]] = {}
    bridges: dict[str, Mapping[str, Any]] = {}
    for index, node in enumerate(REBOOT_ORDER):
        reference = _exact_mapping(
            references[index], _REFERENCE_KEYS, f"{node} observation reference"
        )
        expected_file = f"{node}-observation.json"
        if reference["nodeId"] != node or reference["fileName"] != expected_file:
            raise ActiveEdgeRebootEvidenceError("observation references are not ordered")
        raw = _read_fixed_file(root, expected_file)
        if reference["sha256"] != sha256_digest(raw):
            raise ActiveEdgeRebootEvidenceError(f"{node} observation digest differs")
        record, facts, bridge = _validate_observation(root, raw, node)
        nodes.append(record)
        facts_by_node[node] = facts
        bridges[node] = bridge

    shared = (
        "allocationId",
        "clusterId",
        "customerAccountId",
        "generation",
        "m365TenantId",
        "serviceInstanceId",
        "tenantContextId",
    )
    if any(facts_by_node["sbc1"][key] != facts_by_node["sbc2"][key] for key in shared):
        raise ActiveEdgeRebootEvidenceError("fleet observations name different tenant routes")
    test_ids = [record["fixtureCall"]["testId"] for record in nodes]
    if len(set(test_ids)) != 2:
        raise ActiveEdgeRebootEvidenceError("reboot fixture calls are not fresh and unique")
    if (
        bridges["sbc1"]["peerBefore"] != bridges["sbc2"]["targetPre"]
        or bridges["sbc1"]["peerIdentitySources"]
        != bridges["sbc2"]["targetIdentitySources"]
        or bridges["sbc1"]["targetPostCall"] != bridges["sbc2"]["peerBefore"]
        or bridges["sbc1"]["targetIdentitySources"]
        != bridges["sbc2"]["peerIdentitySources"]
    ):
        raise ActiveEdgeRebootEvidenceError(
            "same-node identity or protected state drifted between serialized observations"
        )
    if not (
        nodes[0]["reboot"]["rebootScheduledAtMonotonicNs"]
        < nodes[0]["fixtureCall"]["startedAtMonotonicNs"]
        < nodes[0]["observationCompletedAtMonotonicNs"]
        < nodes[1]["reboot"]["rebootScheduledAtMonotonicNs"]
        < nodes[1]["fixtureCall"]["startedAtMonotonicNs"]
    ):
        raise ActiveEdgeRebootEvidenceError(
            "node observations do not prove serialized SBC1-then-SBC2 execution"
        )
    _clock_interval(
        nodes[0]["observationCompletedAtEpochMs"],
        nodes[0]["observationCompletedAtMonotonicNs"],
        nodes[1]["reboot"]["rebootScheduledAtEpochMs"],
        nodes[1]["reboot"]["rebootScheduledAtMonotonicNs"],
        "serialized SBC1-to-SBC2 interval",
    )

    route = {key: facts_by_node["sbc1"][key] for key in shared}
    evidence: dict[str, Any] = {
        "apiVersion": EVIDENCE_API_VERSION,
        "kind": "ActiveEdgeRebootQualificationEvidence",
        "liveM365Interoperability": LIVE_M365_STATUS,
        "rebootOrder": list(REBOOT_ORDER),
        "routeIdentity": route,
        "runtimeNodes": nodes,
        "scope": SCOPE,
        "status": "ACTIVE_SYNTHETIC_EDGE_REBOOTS_QUALIFIED",
    }
    evidence["evidenceDigest"] = sha256_digest(canonical_bytes(evidence))
    return evidence


def _atomic_write(path: Path, content: bytes) -> None:
    if path.exists() or path.is_symlink():
        existing = _read_fixed_file(path.parent, path.name)
        if existing != content:
            raise ActiveEdgeRebootEvidenceError("existing acceptance evidence differs")
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
    result.add_argument("--evidence-dir", required=True, type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        evidence = compile_evidence(args.evidence_dir)
        _atomic_write(args.evidence_dir / "acceptance.json", canonical_bytes(evidence))
    except (ActiveEdgeRebootEvidenceError, OSError) as exc:
        print(f"active Edge reboot evidence rejected: {exc}", file=os.sys.stderr)
        return 2
    print(f"ACTIVE_EDGE_REBOOT_EVIDENCE_WRITTEN {evidence['evidenceDigest']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
