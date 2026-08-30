#!/usr/bin/env python3
"""Collect one protected, non-secret active Edge identity snapshot.

The forced fixture-leaf rotation qualifier uses this helper immediately before
and after each serialized re-pin and after the fresh fixture calls.  It reads
the protected identity sources without following links, validates the active
runtime and Agent through their installed CLIs, and emits canonical JSON.  No
private key bytes are read or emitted; runtime authority contains digests only.
"""

from __future__ import annotations

import argparse
import base64
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import time
from typing import Any, Mapping


API_VERSION = "edge.vivolution.ae/forced-fixture-leaf-rotation-edge-snapshot/v0.1"
NODE_FACTS = Path("/etc/vivolution-edge/node-facts.json")
RUNTIME_AUTHORITY = Path(
    "/var/lib/vivolution-edge/runtime/runtime-authority.json"
)
RUNTIME_TRANSACTION = Path("/var/lib/vivolution-edge/runtime/transaction.json")
FIXTURE_ROTATION_JOURNAL = Path(
    "/var/lib/vivolution-edge/fixture-pki-rotation/transaction.json"
)
AGENT_STATE_ROOT = Path("/var/lib/vivolution-edge/agent-state/tenant")
AGENT_STATE_V3 = AGENT_STATE_ROOT / "edge-state-v3.json"
AGENT_STATE_V2 = AGENT_STATE_ROOT / "edge-state-v2.json"
AGENT_STATE_V1 = AGENT_STATE_ROOT / "accepted-state-v1.json"
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
REQUIRED_UNITS = (
    "nftables.service",
    "ntpsec.service",
    "opensips.service",
    "rtpengine-daemon.service",
    "ssh.service",
    "vivolution-edge-certificate.timer",
)
MAX_JSON_BYTES = 512 * 1024


class EdgeSnapshotError(ValueError):
    """The protected Edge cannot produce one exact active snapshot."""


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def sha256_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EdgeSnapshotError("JSON contains a duplicate member")
        result[key] = value
    return result


def _parse_json(raw: bytes, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EdgeSnapshotError(f"{label} is not one UTF-8 JSON object") from exc
    if not isinstance(value, dict):
        raise EdgeSnapshotError(f"{label} must be a JSON object")
    return value


def _secure_read(
    path: Path,
    *,
    uid: int,
    gid: int,
    mode: int,
    maximum: int = MAX_JSON_BYTES,
) -> tuple[bytes, Mapping[str, Any]]:
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != uid
            or before.st_gid != gid
            or stat.S_IMODE(before.st_mode) != mode
            or not 0 < before.st_size <= maximum
        ):
            raise EdgeSnapshotError(f"unsafe protected file {path}")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        len(raw) != before.st_size
        or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    ):
        raise EdgeSnapshotError(f"protected file changed while read: {path}")
    metadata = {
        "group": grp.getgrgid(before.st_gid).gr_name,
        "mode": format(stat.S_IMODE(before.st_mode), "04o"),
        "nlink": before.st_nlink,
        "owner": pwd.getpwuid(before.st_uid).pw_name,
    }
    return raw, metadata


def _path_absent(path: Path, label: str) -> bool:
    try:
        value = path.lstat()
    except FileNotFoundError:
        return True
    if stat.S_ISLNK(value.st_mode):
        raise EdgeSnapshotError(f"{label} is an unexpected symlink")
    return False


def _run(
    argv: list[str],
    label: str,
    *,
    uid: int | None = None,
    gid: int | None = None,
) -> str:
    def demote() -> None:
        assert uid is not None and gid is not None
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)

    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
            check=False,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
            preexec_fn=demote if uid is not None else None,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise EdgeSnapshotError(f"{label} could not execute: {exc}") from exc
    if result.returncode != 0 or result.stderr.strip():
        detail = (result.stderr or result.stdout).strip().replace("\n", " ")[:400]
        raise EdgeSnapshotError(f"{label} failed: {detail or result.returncode}")
    return result.stdout


def _agent_argv(facts: Mapping[str, Any]) -> list[str]:
    required = {
        "allocationId",
        "authorizedPbxSourceIpv4Cidrs",
        "clusterId",
        "clusterMediaPortEnd",
        "clusterMediaPortStart",
        "customerAccountId",
        "generation",
        "m365TenantId",
        "nodeId",
        "pbxMediaDestinationPortEnd",
        "pbxMediaDestinationPortStart",
        "publicIpv4",
        "serviceInstanceId",
        "slot",
        "tenantContextId",
        "tenantListenerPort",
        "tenantMediaPortEnd",
        "tenantMediaPortStart",
    }
    if not required.issubset(facts):
        raise EdgeSnapshotError("node facts are missing Agent status context")
    sources = facts["authorizedPbxSourceIpv4Cidrs"]
    if sources != ["10.20.1.4/32"]:
        raise EdgeSnapshotError("node facts are outside the fixed synthetic PBX route")
    return [
        "/usr/local/bin/vivolution-edge-agent",
        "status",
        "--state-dir",
        str(AGENT_STATE_ROOT),
        "--scope",
        "TENANT",
        "--cluster-id",
        str(facts["clusterId"]),
        "--node-id",
        str(facts["nodeId"]),
        "--generation",
        str(facts["generation"]),
        "--slot",
        str(facts["slot"]),
        "--customer-account-id",
        str(facts["customerAccountId"]),
        "--m365-tenant-id",
        str(facts["m365TenantId"]),
        "--tenant-context-id",
        str(facts["tenantContextId"]),
        "--service-instance-id",
        str(facts["serviceInstanceId"]),
        "--allocation-id",
        str(facts["allocationId"]),
        "--tenant-listener-port",
        str(facts["tenantListenerPort"]),
        "--tenant-media-port-start",
        str(facts["tenantMediaPortStart"]),
        "--tenant-media-port-end",
        str(facts["tenantMediaPortEnd"]),
        "--pbx-media-destination-port-start",
        str(facts["pbxMediaDestinationPortStart"]),
        "--pbx-media-destination-port-end",
        str(facts["pbxMediaDestinationPortEnd"]),
        "--cluster-media-port-start",
        str(facts["clusterMediaPortStart"]),
        "--cluster-media-port-end",
        str(facts["clusterMediaPortEnd"]),
        "--expected-advertised-public-ip",
        str(facts["publicIpv4"]),
        "--authorized-pbx-source-cidr",
        "10.20.1.4/32",
    ]


def collect(expected_node_id: str) -> Mapping[str, Any]:
    if os.geteuid() != 0:
        raise EdgeSnapshotError("Edge snapshot collector must run as root")
    agent_identity = pwd.getpwnam("vivolution-edge-agent")
    facts_raw, facts_metadata = _secure_read(
        NODE_FACTS, uid=0, gid=0, mode=0o600
    )
    authority_raw, authority_metadata = _secure_read(
        RUNTIME_AUTHORITY, uid=0, gid=0, mode=0o600
    )
    facts = _parse_json(facts_raw, "node facts")
    authority = _parse_json(authority_raw, "runtime authority")
    if facts.get("nodeId") != expected_node_id or authority.get("nodeId") != expected_node_id:
        raise EdgeSnapshotError("protected identity names another Edge")
    if authority.get("profile") != "SYNTHETIC_PRIVATE":
        raise EdgeSnapshotError("snapshot collector refuses Direct Routing")
    agent_raw, agent_metadata = _secure_read(
        AGENT_STATE_V3,
        uid=agent_identity.pw_uid,
        gid=agent_identity.pw_gid,
        mode=0o600,
    )
    _parse_json(agent_raw, "Agent v3 state")
    if not _path_absent(AGENT_STATE_V2, "legacy Agent v2 state") or not _path_absent(
        AGENT_STATE_V1, "legacy Agent v1 state"
    ):
        raise EdgeSnapshotError("a legacy Agent state generation remains installed")

    runtime_status = _parse_json(
        _run(
            ["/usr/local/sbin/vivolution-edge-runtime", "status"],
            "runtime status",
        ).encode(),
        "runtime status",
    )
    runtime_health = _parse_json(
        _run(
            ["/usr/local/sbin/vivolution-edge-runtime", "health"],
            "runtime health",
        ).encode(),
        "runtime health",
    )
    agent_status = _parse_json(
        _run(
            _agent_argv(facts),
            "Agent protected status",
            uid=agent_identity.pw_uid,
            gid=agent_identity.pw_gid,
        ).encode(),
        "Agent protected status",
    )
    boot_id = BOOT_ID.read_text(encoding="ascii").strip()
    unit_states = {
        unit: _run(["/usr/bin/systemctl", "is-active", unit], unit).strip()
        for unit in REQUIRED_UNITS
    }
    recovery_enabled = _run(
        [
            "/usr/bin/systemctl",
            "is-enabled",
            "vivolution-edge-runtime-recover.service",
        ],
        "runtime recovery unit",
    ).strip()
    return {
        "apiVersion": API_VERSION,
        "capturedAtEpochMs": time.time_ns() // 1_000_000,
        "fixtureRotationJournalPresent": not _path_absent(
            FIXTURE_ROTATION_JOURNAL, "fixture rotation transaction journal"
        ),
        "identitySources": {
            "nodeFactsBase64": base64.b64encode(facts_raw).decode("ascii"),
            "nodeFactsMetadata": facts_metadata,
            "nodeFactsSha256": sha256_digest(facts_raw),
            "runtimeAuthorityBase64": base64.b64encode(authority_raw).decode("ascii"),
            "runtimeAuthorityMetadata": authority_metadata,
            "runtimeAuthoritySha256": sha256_digest(authority_raw),
        },
        "nodeId": expected_node_id,
        "snapshot": {
            "agentState": {
                **agent_metadata,
                "sha256": sha256_digest(agent_raw),
            },
            "agentStatus": agent_status,
            "bootId": boot_id,
            "health": runtime_health,
            "recoveryUnitEnabled": recovery_enabled,
            "status": runtime_status,
            "transactionJournalPresent": not _path_absent(
                RUNTIME_TRANSACTION, "runtime transaction journal"
            ),
            "unitStates": unit_states,
        },
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--expected-node-id", choices=("sbc1", "sbc2"), required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        record = collect(args.expected_node_id)
    except (EdgeSnapshotError, KeyError, OSError, ValueError) as exc:
        print(f"forced fixture rotation Edge snapshot rejected: {exc}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_bytes(record))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
