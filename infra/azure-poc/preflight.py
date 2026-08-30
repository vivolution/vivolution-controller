#!/usr/bin/env python3
"""Fail-closed local preflight for the POC Bicep deployment inputs."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Sequence, Set


MICROSOFT_DIRECT_ROUTING_CIDRS = {
    "52.112.0.0/14",
    "52.120.0.0/14",
}
CP1_PRIVATE_FIXTURE_CIDRS = {"10.20.1.4/32"}
MAX_ADMIN_CIDRS = 4
MAX_PBX_MEDIA_DESTINATION_PORTS = 4096
FIXTURE_PBX_MEDIA_DESTINATION_RANGE = (21000, 21127)
RESERVED_SIGNALING_AND_CONTROL_PORTS = frozenset({2223, 2224, 5061, 15061})

FIXED_VALUES = {
    "namePrefix": "viv-sbc-poc",
    "environmentName": "poc",
    "adminUsername": "cpadmin",
    "pbxTlsListenerPort": 15061,
    "cp1VmSize": "Standard_D2as_v5",
    "sbc1VmSize": "Standard_B2als_v2",
    "sbc2VmSize": "Standard_B2als_v2",
    "cp1OsDiskSizeGiB": 64,
    "sbc1OsDiskSizeGiB": 32,
    "sbc2OsDiskSizeGiB": 32,
    "osDiskSku": "StandardSSD_LRS",
    "enableTrustedLaunch": True,
    "rtpMediaPortStart": 20000,
    "rtpMediaPortCount": 10000,
    "tenantRtpMediaPortStart": 20000,
    "tenantRtpMediaPortCount": 256,
    "microsoftMediaIcePortRange": "3478-3481",
    "microsoftMediaHighPortRange": "49152-53247",
}


class PreflightError(ValueError):
    pass


def _values(document: Mapping[str, Any]) -> Dict[str, Any]:
    parameters = document.get("parameters")
    if not isinstance(parameters, dict):
        raise PreflightError("compiled deployment parameters are missing")
    values: Dict[str, Any] = {}
    for name, wrapped in parameters.items():
        if not isinstance(name, str) or not isinstance(wrapped, dict) or set(wrapped) != {"value"}:
            raise PreflightError("parameter {!r} is not a single explicit value".format(name))
        values[name] = wrapped["value"]
    return values


def _cidr_set(value: Any, name: str, *, allow_empty: bool = False) -> Set[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise PreflightError("{} must be an array of IPv4 CIDR strings".format(name))
    if not value and not allow_empty:
        raise PreflightError("{} must not be empty".format(name))
    if len(value) != len(set(value)):
        raise PreflightError("{} contains a duplicate CIDR".format(name))
    normalized: Set[str] = set()
    for item in value:
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError as exc:
            raise PreflightError("{} contains invalid CIDR {}".format(name, item)) from exc
        if network.version != 4:
            raise PreflightError("{} must contain IPv4 CIDRs only".format(name))
        normalized.add(str(network))
    canonical = sorted(
        value,
        key=lambda item: (
            int(ipaddress.ip_network(item, strict=True).network_address),
            ipaddress.ip_network(item, strict=True).prefixlen,
        ),
    )
    if value != canonical:
        raise PreflightError("{} must be in canonical network order".format(name))
    return normalized


def _ssh_fingerprint(public_key: Any) -> str:
    if not isinstance(public_key, str) or "PRIVATE KEY" in public_key or "\n" in public_key:
        raise PreflightError("sshPublicKey must be one single-line public key")
    parts = public_key.split()
    if len(parts) not in {2, 3} or parts[0] != "ssh-ed25519":
        raise PreflightError("sshPublicKey must use the reviewed ED25519 key type")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PreflightError("sshPublicKey has invalid base64") from exc
    if base64.b64encode(blob).decode("ascii") != parts[1]:
        raise PreflightError("sshPublicKey base64 is not canonical")
    # An OpenSSH Ed25519 blob is: string("ssh-ed25519") + string(32-byte key).
    if len(blob) != 51 or blob[:15] != b"\x00\x00\x00\x0bssh-ed25519" or blob[15:19] != b"\x00\x00\x00\x20":
        raise PreflightError("sshPublicKey is not a canonical 32-byte ED25519 blob")
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return "SHA256:" + digest


def _media_destination_range(
    values: Mapping[str, Any], node: str
) -> tuple[int, int]:
    start_name = node + "PbxMediaDestinationPortStart"
    end_name = node + "PbxMediaDestinationPortEnd"
    start = values.get(start_name)
    end = values.get(end_name)
    if (
        isinstance(start, bool)
        or not isinstance(start, int)
        or isinstance(end, bool)
        or not isinstance(end, int)
    ):
        raise PreflightError(
            "{} and {} must be explicit integer UDP ports".format(
                start_name, end_name
            )
        )
    if not 1024 <= start <= 65534 or not 1025 <= end <= 65535:
        raise PreflightError("{} PBX media destination range is outside UDP bounds".format(node))
    if start % 2 != 0 or end % 2 != 1 or start > end:
        raise PreflightError(
            "{} PBX media destination range must start even, end odd, and be ordered".format(
                node
            )
        )
    if end - start + 1 > MAX_PBX_MEDIA_DESTINATION_PORTS:
        raise PreflightError(
            "{} PBX media destination range exceeds {} ports".format(
                node, MAX_PBX_MEDIA_DESTINATION_PORTS
            )
        )
    collisions = sorted(
        port
        for port in RESERVED_SIGNALING_AND_CONTROL_PORTS
        if start <= port <= end
    )
    if collisions:
        raise PreflightError(
            "{} PBX media destination range collides with signaling/control ports {}".format(
                node, collisions
            )
        )
    return start, end


def validate_parameters(
    document: Mapping[str, Any],
    *,
    approved_admin_cidrs: Iterable[str],
    expected_ssh_fingerprint: str,
) -> Dict[str, Any]:
    values = _values(document)
    errors = []

    for name, expected in FIXED_VALUES.items():
        if values.get(name) != expected:
            errors.append("{} must equal {!r}".format(name, expected))

    try:
        admin = _cidr_set(values.get("administratorSourcePrefixes"), "administratorSourcePrefixes")
        approved = _cidr_set(list(approved_admin_cidrs), "approved administrator CIDRs")
        if len(admin) > MAX_ADMIN_CIDRS:
            errors.append("administratorSourcePrefixes exceeds the four-address POC limit")
        for cidr in admin:
            network = ipaddress.ip_network(cidr, strict=True)
            if network.prefixlen != 32 or not network.network_address.is_global:
                errors.append("administrator CIDR {} must be one globally routable /32".format(cidr))
        if admin != approved:
            errors.append("administratorSourcePrefixes does not equal the separately approved set")
    except PreflightError as exc:
        errors.append(str(exc))
        admin = set()

    for name in ("microsoftSignalingSourcePrefixes", "microsoftMediaSourcePrefixes"):
        try:
            actual = _cidr_set(values.get(name), name)
            if actual != MICROSOFT_DIRECT_ROUTING_CIDRS:
                errors.append("{} does not equal the reviewed Microsoft Direct Routing set".format(name))
        except PreflightError as exc:
            errors.append(str(exc))

    peer_sets: Dict[str, Set[str]] = {}
    for name in (
        "syntheticTeamsSourcePrefixes",
        "sbc1PbxSourcePrefixes",
        "sbc2PbxSourcePrefixes",
    ):
        try:
            actual = _cidr_set(values.get(name), name, allow_empty=True)
            peer_sets[name] = actual
        except PreflightError as exc:
            errors.append(str(exc))

    profile = values.get("edgeRuntimeProfile")
    fixture_enabled = values.get("enableSyntheticVoiceFixture")
    pbx_media_ranges: Dict[str, tuple[int, int]] = {}
    for node in ("sbc1", "sbc2"):
        try:
            pbx_media_ranges[node] = _media_destination_range(values, node)
        except PreflightError as exc:
            errors.append(str(exc))
    if not isinstance(fixture_enabled, bool):
        errors.append("enableSyntheticVoiceFixture must be boolean")
    if profile == "SYNTHETIC_PRIVATE":
        if fixture_enabled is not True:
            errors.append("SYNTHETIC_PRIVATE requires enableSyntheticVoiceFixture=true")
        for name in (
            "syntheticTeamsSourcePrefixes",
            "sbc1PbxSourcePrefixes",
            "sbc2PbxSourcePrefixes",
        ):
            if peer_sets.get(name) != CP1_PRIVATE_FIXTURE_CIDRS:
                errors.append(
                    "{} must equal the private CP1 fixture /32 in SYNTHETIC_PRIVATE".format(
                        name
                    )
                )
        for node in ("sbc1", "sbc2"):
            if pbx_media_ranges.get(node) != FIXTURE_PBX_MEDIA_DESTINATION_RANGE:
                errors.append(
                    "{} PBX media destination range must equal fixed CP1 fixture ports {}-{} in SYNTHETIC_PRIVATE".format(
                        node, *FIXTURE_PBX_MEDIA_DESTINATION_RANGE
                    )
                )
    elif profile == "DIRECT_ROUTING":
        if fixture_enabled is not False:
            errors.append("DIRECT_ROUTING requires enableSyntheticVoiceFixture=false")
        if peer_sets.get("syntheticTeamsSourcePrefixes") != set():
            errors.append("DIRECT_ROUTING forbids syntheticTeamsSourcePrefixes")
        for name in ("sbc1PbxSourcePrefixes", "sbc2PbxSourcePrefixes"):
            actual = peer_sets.get(name, set())
            if not actual:
                errors.append("{} must not be empty in DIRECT_ROUTING".format(name))
            if len(actual) > 16:
                errors.append("{} exceeds the sixteen-CIDR Direct Routing limit".format(name))
            for cidr in actual:
                network = ipaddress.ip_network(cidr, strict=True)
                if network.prefixlen < 24 or not network.network_address.is_global:
                    errors.append(
                        "{} CIDR {} must be globally routable and no broader than /24".format(
                            name, cidr
                        )
                    )
        for node in ("sbc1", "sbc2"):
            media_range = pbx_media_ranges.get(node)
            if media_range == FIXTURE_PBX_MEDIA_DESTINATION_RANGE:
                errors.append(
                    "{} DIRECT_ROUTING PBX media destination range must not retain the synthetic fixture contract".format(
                        node
                    )
                )
            if media_range is not None and media_range[1] - media_range[0] + 1 < 100:
                errors.append(
                    "{} DIRECT_ROUTING PBX media destination range must provide at least 100 UDP ports".format(
                        node
                    )
                )
    else:
        errors.append("edgeRuntimeProfile must be SYNTHETIC_PRIVATE or DIRECT_ROUTING")

    try:
        fingerprint = _ssh_fingerprint(values.get("sshPublicKey"))
        if fingerprint != expected_ssh_fingerprint:
            errors.append("sshPublicKey fingerprint does not match the separately approved key")
    except PreflightError as exc:
        errors.append(str(exc))
        fingerprint = "INVALID"

    if errors:
        raise PreflightError("; ".join(errors))

    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "administratorCidrCount": len(admin),
        "compiledParametersSha256": hashlib.sha256(canonical).hexdigest(),
        "microsoftDirectRoutingCidrVersion": "learn.microsoft.com checked 2026-08-30",
        "microsoftMediaProcessorUdpPortRanges": ["3478-3481", "49152-53247"],
        "pbxMediaDestinationPortRanges": {
            node: {"end": value[1], "start": value[0]}
            for node, value in sorted(pbx_media_ranges.items())
        },
        "edgeRuntimeProfile": profile,
        "fixedNtpServerPrefixes": ["162.159.200.1/32", "162.159.200.123/32"],
        "sshPublicKeyFingerprint": fingerprint,
        "status": "POC_DEPLOYMENT_INPUTS_VALID",
    }


def compile_bicep_parameters(path: Path) -> Dict[str, Any]:
    result = subprocess.run(
        ["az", "bicep", "build-params", "--file", str(path), "--stdout"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise PreflightError("Bicep parameter compilation failed: {}".format(result.stderr.strip()))
    try:
        outer = json.loads(result.stdout)
        parameters_json = outer["parametersJson"]
        document = json.loads(parameters_json)
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise PreflightError("Bicep returned malformed compiled parameters") from exc
    if not isinstance(document, dict):
        raise PreflightError("compiled deployment parameters are not an object")
    return document


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("parameters", type=Path)
    parser.add_argument("--approved-admin-cidr", action="append", required=True)
    parser.add_argument("--expected-ssh-fingerprint", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        evidence = validate_parameters(
            compile_bicep_parameters(args.parameters),
            approved_admin_cidrs=args.approved_admin_cidr,
            expected_ssh_fingerprint=args.expected_ssh_fingerprint,
        )
    except PreflightError as exc:
        print("POC_DEPLOYMENT_INPUTS_REJECTED: {}".format(exc), file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
