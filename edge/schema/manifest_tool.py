#!/usr/bin/env python3
"""Dependency-free v0.1 Edge manifest canonicalization and preflight checks.

The JSON Schema is the portable structural contract.  This module deliberately
duplicates its security-critical checks so a minimal Edge image can reject bad
targets, replay, cross-tenant references, stale lineage, and digest drift
without adding a Python package dependency.

It does *not* verify Ed25519 cryptography.  Production acceptance must verify a
signature against an authorized, pinned key before calling an apply path.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


API_VERSION = "edge.vivolution.ae/v0.1"
KIND = "SignedDesiredState"
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_ACTIVATION_TTL_SECONDS = 3600
MAX_ISSUED_AT_PAST_SKEW_SECONDS = 3600
MAX_ISSUED_AT_FUTURE_SKEW_SECONDS = 300
MAX_PBX_MEDIA_DESTINATION_PORTS = 4096
RESERVED_SIGNALING_AND_CONTROL_PORTS = frozenset({2223, 2224, 5061, 15061})
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
E164_PREFIX_RE = re.compile(r"^\+[1-9][0-9]{0,14}$")
M365_TENANT_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

TENANT_RESOURCE_TYPES = {
    "tenant.connector",
    "tenant.listener",
    "tenant.route",
    "tenant.media",
    "tenant.capacity",
}
CLUSTER_RESOURCE_TYPES = {
    "cluster.software",
    "cluster.shared-listener",
    "cluster.firewall-policy",
}
TENANT_ARTIFACT_KINDS = {
    "OPENSIPS_TENANT_CONFIG",
    "RTPENGINE_TENANT_CONFIG",
    "NFTABLES_TENANT_POLICY",
}
CLUSTER_ARTIFACT_KINDS = {
    "SOFTWARE_PACKAGE",
    "OPENSIPS_SHARED_CONFIG",
    "NFTABLES_CLUSTER_POLICY",
    "TRUST_BUNDLE",
}
TENANT_SECRET_PURPOSES = {
    "PBX_CLIENT_MTLS_IDENTITY",
    "PBX_SERVER_TLS_IDENTITY",
    "PBX_CLIENT_CA_BUNDLE",
    "RTPENGINE_CONTROL_CREDENTIAL",
}
CLUSTER_SECRET_PURPOSES = {
    "TEAMS_TLS_IDENTITY",
    "NODE_MANAGEMENT_IDENTITY",
    "RTPENGINE_CONTROL_CREDENTIAL",
}
TENANT_GATE_TYPES = {
    "ARTIFACT_DIGESTS",
    "OPENSIPS_CONFIG",
    "RTPENGINE_READY",
}
CLUSTER_GATE_TYPES = {
    "NODE_BASELINE",
    "ARTIFACT_DIGESTS",
    "OPENSIPS_CONFIG",
    "RTPENGINE_READY",
    "PEER_N_MINUS_ONE_CAPACITY",
}
TENANT_ABSENCE_GATE_TYPE = "TENANT_RESOURCES_ABSENT"
CLUSTER_DECOMMISSION_GATE_TYPE = "NODE_DECOMMISSIONED"

TENANT_ACTIVE_GATE_RESOURCES = {
    "ARTIFACT_DIGESTS": TENANT_RESOURCE_TYPES,
    "OPENSIPS_CONFIG": {"tenant.connector", "tenant.listener", "tenant.route"},
    "RTPENGINE_READY": {"tenant.media"},
}
FORBIDDEN_SECRET_KEYS = {
    "credential",
    "credentialvalue",
    "password",
    "passwordvalue",
    "plaintext",
    "privatekey",
    "privatekeypem",
    "secret",
    "secretvalue",
    "token",
    "tokenvalue",
}


class DuplicateKeyError(ValueError):
    """Raised before validation if an input JSON object repeats a member."""


class ContractError(ValueError):
    """Raised when an envelope fails contract preflight."""

    def __init__(self, errors: Sequence[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


@dataclass(frozen=True)
class ValidationContext:
    expected_cluster_id: str
    expected_node_id: str
    expected_generation: int
    accepted_sequence: int
    accepted_digest: Optional[str]
    now: datetime
    expected_tenant_context_id: Optional[str] = None
    expected_allocation_id: Optional[str] = None
    expected_tenant_listener_port: Optional[int] = None
    expected_media_port_start: Optional[int] = None
    expected_media_port_end: Optional[int] = None
    expected_pbx_media_destination_port_start: Optional[int] = None
    expected_pbx_media_destination_port_end: Optional[int] = None
    expected_advertised_public_ip: Optional[str] = None
    authorized_pbx_source_cidrs: Tuple[str, ...] = ()
    authorized_microsoft_source_cidrs: Tuple[str, ...] = ()


def _reject_duplicate_keys(pairs: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError("duplicate JSON member: {!r}".format(key))
        result[key] = value
    return result


def parse_json_text(text: str) -> Any:
    """Parse JSON while rejecting duplicate members and non-standard numbers."""

    return json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_int=_parse_bounded_integer,
        parse_float=lambda value: (_ for _ in ()).throw(
            ValueError(
                "floating-point or exponent JSON number {!r} is outside the v0.1 canonical domain".format(
                    value
                )
            )
        ),
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError("non-finite JSON number: {}".format(value))
        ),
    )


def _parse_bounded_integer(value: str) -> int:
    parsed = int(value, 10)
    if abs(parsed) > MAX_SAFE_INTEGER:
        raise ValueError(
            "JSON integer {} exceeds the interoperable v0.1 range +/-{}".format(
                value, MAX_SAFE_INTEGER
            )
        )
    return parsed


def load_json(path: Path) -> Any:
    return parse_json_text(path.read_text(encoding="utf-8"))


def _check_canonical_domain(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str):
            value.encode("utf-8")
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError(
                "{}: integer exceeds the interoperable v0.1 range +/-{}".format(
                    path, MAX_SAFE_INTEGER
                )
            )
        return
    if isinstance(value, float):
        raise ValueError("{}: floating-point numbers are outside the v0.1 canonical domain".format(path))
    if isinstance(value, list):
        for index, item in enumerate(value):
            _check_canonical_domain(item, "{}[{}]".format(path, index))
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("{}: object member names must be strings".format(path))
            try:
                key.encode("ascii")
            except UnicodeEncodeError as exc:
                raise ValueError("{}: object member names must be ASCII".format(path)) from exc
            _check_canonical_domain(item, "{}.{}".format(path, key))
        return
    raise ValueError("{}: unsupported JSON value type {}".format(path, type(value).__name__))


def canonical_json_bytes(value: Any) -> bytes:
    """Return the constrained RFC 8785-compatible canonical JSON byte form.

    The v0.1 schema admits integers but no floating-point values, and all member
    names are ASCII.  Those constraints avoid cross-runtime number and key-sort
    ambiguity while preserving UTF-8 string values without normalization.
    """

    _check_canonical_domain(value)
    rendered = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return rendered.encode("utf-8")


def manifest_digest(manifest: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()


def _error(errors: List[str], path: str, message: str) -> None:
    errors.append("{}: {}".format(path, message))


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _object(
    value: Any,
    path: str,
    required: Set[str],
    errors: List[str],
) -> Optional[Dict[str, Any]]:
    if not isinstance(value, dict):
        _error(errors, path, "must be an object")
        return None
    actual = set(value)
    missing = sorted(required - actual)
    extra = sorted(actual - required)
    if missing:
        _error(errors, path, "missing members {}".format(missing))
    if extra:
        _error(errors, path, "unknown members {}".format(extra))
    return value


def _array(
    value: Any,
    path: str,
    errors: List[str],
    minimum: int = 0,
    maximum: Optional[int] = None,
) -> List[Any]:
    if not isinstance(value, list):
        _error(errors, path, "must be an array")
        return []
    if len(value) < minimum:
        _error(errors, path, "must contain at least {} item(s)".format(minimum))
    if maximum is not None and len(value) > maximum:
        _error(errors, path, "must contain no more than {} item(s)".format(maximum))
    return value


def _identifier(value: Any, path: str, errors: List[str]) -> None:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        _error(errors, path, "must be a lowercase v0.1 identifier")


def _digest(value: Any, path: str, errors: List[str]) -> None:
    if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
        _error(errors, path, "must be a lowercase sha256:<64 hex> digest")


def _integer(
    value: Any,
    path: str,
    errors: List[str],
    minimum: int,
    maximum: Optional[int] = None,
) -> None:
    maximum = MAX_SAFE_INTEGER if maximum is None else min(maximum, MAX_SAFE_INTEGER)
    if not _is_int(value) or value < minimum or (maximum is not None and value > maximum):
        limit = ">= {}".format(minimum)
        if maximum is not None:
            limit += " and <= {}".format(maximum)
        _error(errors, path, "must be an integer {}".format(limit))


def parse_utc_timestamp(value: Any, path: str, errors: List[str]) -> Optional[datetime]:
    if not isinstance(value, str) or not UTC_RE.fullmatch(value):
        _error(errors, path, "must be an RFC 3339 UTC timestamp with whole seconds")
        return None
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        _error(errors, path, "is not a real UTC timestamp")
        return None
    return parsed


def _cidrs(value: Any, path: str, errors: List[str], maximum: int = 64) -> None:
    items = _array(value, path, errors, minimum=1, maximum=maximum)
    seen: Set[str] = set()
    for index, item in enumerate(items):
        item_path = "{}[{}]".format(path, index)
        if not isinstance(item, str):
            _error(errors, item_path, "must be a canonical CIDR string")
            continue
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError:
            _error(errors, item_path, "must be a canonical CIDR network")
            continue
        if str(network) != item.lower():
            _error(errors, item_path, "must use canonical network notation")
        if network.prefixlen == 0:
            _error(errors, item_path, "must not authorize an all-addresses /0 network")
        if item in seen:
            _error(errors, item_path, "duplicates an earlier CIDR")
        seen.add(item)


def _trusted_networks(
    values: Sequence[str],
    path: str,
    errors: List[str],
) -> List[ipaddress._BaseNetwork]:
    """Validate locally trusted CIDR inputs and return normalized networks."""

    if not values:
        _error(errors, path, "must contain at least one locally authorized CIDR")
        return []
    networks: List[ipaddress._BaseNetwork] = []
    seen: Set[str] = set()
    for index, raw in enumerate(values):
        item_path = "{}[{}]".format(path, index)
        if not isinstance(raw, str):
            _error(errors, item_path, "must be a canonical CIDR string")
            continue
        try:
            network = ipaddress.ip_network(raw, strict=True)
        except ValueError:
            _error(errors, item_path, "must be a canonical CIDR network")
            continue
        if str(network) != raw.lower():
            _error(errors, item_path, "must use canonical network notation")
        if network.prefixlen == 0:
            _error(errors, item_path, "must not authorize an all-addresses /0 network")
        if raw in seen:
            _error(errors, item_path, "duplicates an earlier CIDR")
        seen.add(raw)
        networks.append(network)
    return networks


def _require_cidr_subset(
    values: Any,
    authorized: Sequence[ipaddress._BaseNetwork],
    path: str,
    errors: List[str],
) -> None:
    if not isinstance(values, list):
        return
    for index, raw in enumerate(values):
        if not isinstance(raw, str):
            continue
        try:
            network = ipaddress.ip_network(raw, strict=True)
        except ValueError:
            continue
        if not any(
            network.version == allowed.version and network.subnet_of(allowed)
            for allowed in authorized
        ):
            _error(
                errors,
                "{}[{}]".format(path, index),
                "is outside the locally authorized source CIDR set",
            )


def _ip_address(value: Any, path: str, errors: List[str]) -> None:
    if not isinstance(value, str):
        _error(errors, path, "must be an IP address")
        return
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        _error(errors, path, "must be an IP address")
        return
    if str(parsed) != value.lower():
        _error(errors, path, "must use canonical IP notation")


def _host(value: Any, path: str, errors: List[str]) -> None:
    if not isinstance(value, str) or not (1 <= len(value) <= 253):
        _error(errors, path, "must be a host name or IP address")
        return
    try:
        ipaddress.ip_address(value)
        return
    except ValueError:
        pass
    labels = value.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    ):
        _error(errors, path, "must be a syntactically valid ASCII host name or IP address")


def _unique_strings(items: Any, path: str, errors: List[str], minimum: int = 1) -> List[str]:
    values = _array(items, path, errors, minimum=minimum)
    result: List[str] = []
    seen: Set[str] = set()
    for index, value in enumerate(values):
        item_path = "{}[{}]".format(path, index)
        _identifier(value, item_path, errors)
        if isinstance(value, str):
            if value in seen:
                _error(errors, item_path, "duplicates an earlier value")
            seen.add(value)
            result.append(value)
    return result


def _scan_for_secret_values(value: Any, path: str, errors: List[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = re.sub(r"[-_]", "", key).lower()
            if normalized in FORBIDDEN_SECRET_KEYS:
                _error(errors, "{}.{}".format(path, key), "secret values are forbidden; use a typed reference")
            _scan_for_secret_values(item, "{}.{}".format(path, key), errors)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan_for_secret_values(item, "{}[{}]".format(path, index), errors)
    elif isinstance(value, str) and "-----BEGIN" in value and "PRIVATE KEY-----" in value:
        _error(errors, path, "private-key material is forbidden")


def _validate_target(
    target_value: Any,
    errors: List[str],
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    path = "$.manifest.target"
    if not isinstance(target_value, dict):
        _error(errors, path, "must be an object")
        return None, None
    scope = target_value.get("scope")
    if scope == "TENANT":
        expected = {"scope", "clusterId", "nodeId", "slot", "generation", "tenant"}
    elif scope == "CLUSTER":
        expected = {"scope", "clusterId", "nodeId", "slot", "generation"}
    else:
        _error(errors, path + ".scope", "must be TENANT or CLUSTER")
        expected = set(target_value)
    target = _object(target_value, path, expected, errors)
    if target is None:
        return None, None
    _identifier(target.get("clusterId"), path + ".clusterId", errors)
    _identifier(target.get("nodeId"), path + ".nodeId", errors)
    if target.get("slot") not in {"A", "B"}:
        _error(errors, path + ".slot", "must be A or B")
    _integer(target.get("generation"), path + ".generation", errors, 1)
    tenant: Optional[Dict[str, Any]] = None
    if scope == "TENANT":
        tenant = _object(
            target.get("tenant"),
            path + ".tenant",
            {
                "customerAccountId",
                "m365TenantId",
                "tenantContextId",
                "serviceInstanceId",
                "allocationId",
            },
            errors,
        )
        if tenant is not None:
            for field in ("customerAccountId", "tenantContextId", "serviceInstanceId", "allocationId"):
                _identifier(tenant.get(field), path + ".tenant." + field, errors)
            m365_id = tenant.get("m365TenantId")
            if not isinstance(m365_id, str) or not M365_TENANT_RE.fullmatch(m365_id):
                _error(errors, path + ".tenant.m365TenantId", "must be a lowercase RFC 4122 UUID")
    return target, tenant


def _validate_artifacts(
    value: Any,
    scope: str,
    tenant: Optional[Dict[str, Any]],
    active: bool,
    errors: List[str],
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    artifacts: Dict[str, Dict[str, Any]] = {}
    kinds: Dict[str, str] = {}
    for index, raw in enumerate(
        _array(value, "$.manifest.resourceSet.artifacts", errors, 1 if active else 0, 64)
    ):
        path = "$.manifest.resourceSet.artifacts[{}]".format(index)
        if scope == "TENANT":
            fields = {
                "artifactId",
                "scope",
                "tenantContextId",
                "allocationId",
                "kind",
                "mediaType",
                "sizeBytes",
                "sha256",
                "fetchPath",
                "applyOrder",
            }
            allowed_kinds = TENANT_ARTIFACT_KINDS
            allowed_media = {"application/json", "application/toml", "text/plain"}
            max_size = 16 * 1024 * 1024
        else:
            fields = {
                "artifactId",
                "scope",
                "kind",
                "mediaType",
                "sizeBytes",
                "sha256",
                "fetchPath",
                "applyOrder",
            }
            allowed_kinds = CLUSTER_ARTIFACT_KINDS
            allowed_media = {
                "application/json",
                "application/octet-stream",
                "application/toml",
                "text/plain",
            }
            max_size = 512 * 1024 * 1024
        artifact = _object(raw, path, fields, errors)
        if artifact is None:
            continue
        artifact_id = artifact.get("artifactId")
        _identifier(artifact_id, path + ".artifactId", errors)
        if artifact.get("scope") != scope:
            _error(errors, path + ".scope", "must equal target scope {}".format(scope))
        if scope == "TENANT" and tenant is not None:
            for field in ("tenantContextId", "allocationId"):
                _identifier(artifact.get(field), path + "." + field, errors)
                if artifact.get(field) != tenant.get(field):
                    _error(errors, path + "." + field, "cross-scope artifact identity")
        kind = artifact.get("kind")
        if kind not in allowed_kinds:
            _error(errors, path + ".kind", "is not allowed for {} scope".format(scope))
        if artifact.get("mediaType") not in allowed_media:
            _error(errors, path + ".mediaType", "is not allowed for {} scope".format(scope))
        _integer(artifact.get("sizeBytes"), path + ".sizeBytes", errors, 1, max_size)
        digest = artifact.get("sha256")
        _digest(digest, path + ".sha256", errors)
        if isinstance(digest, str) and DIGEST_RE.fullmatch(digest):
            expected_path = "/v0.1/artifacts/sha256/" + digest.split(":", 1)[1]
            if artifact.get("fetchPath") != expected_path:
                _error(errors, path + ".fetchPath", "must be content-addressed by sha256")
        _integer(artifact.get("applyOrder"), path + ".applyOrder", errors, 1, 1000)
        if isinstance(artifact_id, str):
            if artifact_id in artifacts:
                _error(errors, path + ".artifactId", "duplicates an earlier artifactId")
            artifacts[artifact_id] = artifact
            if isinstance(kind, str):
                kinds[artifact_id] = kind
    return artifacts, kinds


def _validate_secret_references(
    value: Any,
    scope: str,
    tenant: Optional[Dict[str, Any]],
    errors: List[str],
) -> Dict[str, Dict[str, Any]]:
    references: Dict[str, Dict[str, Any]] = {}
    for index, raw in enumerate(_array(value, "$.manifest.resourceSet.secretReferences", errors, 0, 64)):
        path = "$.manifest.resourceSet.secretReferences[{}]".format(index)
        if scope == "TENANT":
            fields = {
                "secretRefId",
                "scope",
                "tenantContextId",
                "allocationId",
                "purpose",
                "version",
                "requiredOnNode",
                "offlineValiditySeconds",
            }
            purposes = TENANT_SECRET_PURPOSES
        else:
            fields = {
                "secretRefId",
                "scope",
                "purpose",
                "version",
                "requiredOnNode",
                "offlineValiditySeconds",
            }
            purposes = CLUSTER_SECRET_PURPOSES
        reference = _object(raw, path, fields, errors)
        if reference is None:
            continue
        ref_id = reference.get("secretRefId")
        _identifier(ref_id, path + ".secretRefId", errors)
        if reference.get("scope") != scope:
            _error(errors, path + ".scope", "must equal target scope {}".format(scope))
        if scope == "TENANT" and tenant is not None:
            for field in ("tenantContextId", "allocationId"):
                _identifier(reference.get(field), path + "." + field, errors)
                if reference.get(field) != tenant.get(field):
                    _error(errors, path + "." + field, "cross-scope secret reference identity")
        if reference.get("purpose") not in purposes:
            _error(errors, path + ".purpose", "is not allowed for {} scope".format(scope))
        _identifier(reference.get("version"), path + ".version", errors)
        if not isinstance(reference.get("requiredOnNode"), bool):
            _error(errors, path + ".requiredOnNode", "must be a boolean")
        _integer(reference.get("offlineValiditySeconds"), path + ".offlineValiditySeconds", errors, 0, 31536000)
        if isinstance(ref_id, str):
            if ref_id in references:
                _error(errors, path + ".secretRefId", "duplicates an earlier secretRefId")
            references[ref_id] = reference
    return references


def _validate_connector(spec: Any, path: str, errors: List[str]) -> Set[str]:
    fields = {
        "role",
        "transport",
        "remoteHost",
        "remotePort",
        "mediaDestinationPortStart",
        "mediaDestinationPortEnd",
        "tlsServerName",
        "sourceCidrs",
        "authentication",
        "credentialSecretRef",
        "optionsIntervalSeconds",
    }
    value = _object(spec, path, fields, errors)
    if value is None:
        return set()
    if value.get("role") != "PBX":
        _error(errors, path + ".role", "must be PBX")
    if value.get("transport") != "TLS":
        _error(errors, path + ".transport", "must be TLS")
    _host(value.get("remoteHost"), path + ".remoteHost", errors)
    _integer(value.get("remotePort"), path + ".remotePort", errors, 1, 65535)
    media_start = value.get("mediaDestinationPortStart")
    media_end = value.get("mediaDestinationPortEnd")
    _integer(media_start, path + ".mediaDestinationPortStart", errors, 1024, 65534)
    _integer(media_end, path + ".mediaDestinationPortEnd", errors, 1025, 65535)
    if _is_int(media_start) and _is_int(media_end):
        if media_start % 2 != 0 or media_end % 2 != 1 or media_start > media_end:
            _error(
                errors,
                path,
                "PBX media destination range must start even, end odd, and be ordered",
            )
        elif media_end - media_start + 1 > MAX_PBX_MEDIA_DESTINATION_PORTS:
            _error(
                errors,
                path,
                "PBX media destination range exceeds {} UDP ports".format(
                    MAX_PBX_MEDIA_DESTINATION_PORTS
                ),
            )
        reserved = RESERVED_SIGNALING_AND_CONTROL_PORTS | {
            value.get("remotePort")
        }
        collisions = sorted(
            port
            for port in reserved
            if _is_int(port) and media_start <= port <= media_end
        )
        if collisions:
            _error(
                errors,
                path,
                "PBX media destination range collides with signaling/control ports {}".format(
                    collisions
                ),
            )
    _host(value.get("tlsServerName"), path + ".tlsServerName", errors)
    _cidrs(value.get("sourceCidrs"), path + ".sourceCidrs", errors)
    if value.get("authentication") not in {"MTLS", "MTLS_AND_IP_ACL"}:
        _error(errors, path + ".authentication", "must require mTLS")
    _identifier(value.get("credentialSecretRef"), path + ".credentialSecretRef", errors)
    _integer(value.get("optionsIntervalSeconds"), path + ".optionsIntervalSeconds", errors, 15, 300)
    return {value["credentialSecretRef"]} if isinstance(value.get("credentialSecretRef"), str) else set()


def _validate_listener(spec: Any, path: str, errors: List[str]) -> Set[str]:
    fields = {
        "role",
        "transport",
        "bindAddress",
        "port",
        "allowedSourceCidrs",
        "certificateSecretRef",
        "mutualTls",
        "clientCaSecretRef",
    }
    value = _object(spec, path, fields, errors)
    if value is None:
        return set()
    if value.get("role") != "PBX":
        _error(errors, path + ".role", "tenant listeners may only serve PBX ingress")
    if value.get("transport") != "TLS":
        _error(errors, path + ".transport", "must be TLS")
    if value.get("bindAddress") not in {"0.0.0.0", "::"}:
        _error(errors, path + ".bindAddress", "must be 0.0.0.0 or ::")
    _integer(value.get("port"), path + ".port", errors, 1024, 65535)
    if value.get("port") == 5061:
        _error(errors, path + ".port", "tenant listener must not collide with shared Teams port 5061")
    _cidrs(value.get("allowedSourceCidrs"), path + ".allowedSourceCidrs", errors)
    _identifier(value.get("certificateSecretRef"), path + ".certificateSecretRef", errors)
    if value.get("mutualTls") is not True:
        _error(errors, path + ".mutualTls", "must be true")
    _identifier(value.get("clientCaSecretRef"), path + ".clientCaSecretRef", errors)
    return {
        ref
        for ref in (value.get("certificateSecretRef"), value.get("clientCaSecretRef"))
        if isinstance(ref, str)
    }


def _validate_route(spec: Any, path: str, errors: List[str]) -> Tuple[Optional[str], Optional[Tuple[Any, ...]]]:
    fields = {"direction", "priority", "calledNumberPrefix", "connectorRef", "enabled"}
    value = _object(spec, path, fields, errors)
    if value is None:
        return None, None
    if value.get("direction") not in {"TEAMS_TO_PBX", "PBX_TO_TEAMS"}:
        _error(errors, path + ".direction", "must be TEAMS_TO_PBX or PBX_TO_TEAMS")
    _integer(value.get("priority"), path + ".priority", errors, 1, 10000)
    prefix = value.get("calledNumberPrefix")
    if not isinstance(prefix, str) or not E164_PREFIX_RE.fullmatch(prefix):
        _error(errors, path + ".calledNumberPrefix", "must be an E.164 prefix")
    _identifier(value.get("connectorRef"), path + ".connectorRef", errors)
    if not isinstance(value.get("enabled"), bool):
        _error(errors, path + ".enabled", "must be a boolean")
    key = (value.get("direction"), value.get("priority"), prefix)
    return value.get("connectorRef") if isinstance(value.get("connectorRef"), str) else None, key


def _validate_media(spec: Any, path: str, errors: List[str]) -> Optional[Tuple[int, int, int]]:
    fields = {
        "engine",
        "unitKey",
        "advertisedAddress",
        "portStart",
        "portEnd",
        "rtcpMux",
        "codecs",
        "maxSessions",
    }
    value = _object(spec, path, fields, errors)
    if value is None:
        return None
    if value.get("engine") != "RTPENGINE":
        _error(errors, path + ".engine", "must be RTPENGINE")
    _identifier(value.get("unitKey"), path + ".unitKey", errors)
    _ip_address(value.get("advertisedAddress"), path + ".advertisedAddress", errors)
    start = value.get("portStart")
    end = value.get("portEnd")
    sessions = value.get("maxSessions")
    _integer(start, path + ".portStart", errors, 1024, 65534)
    _integer(end, path + ".portEnd", errors, 1025, 65535)
    _integer(sessions, path + ".maxSessions", errors, 1, 100000)
    if _is_int(start) and start % 2:
        _error(errors, path + ".portStart", "must be even")
    if _is_int(end) and end % 2 != 1:
        _error(errors, path + ".portEnd", "must be odd")
    if _is_int(start) and _is_int(end) and start > end:
        _error(errors, path, "portStart must not exceed portEnd")
    if _is_int(start) and _is_int(end) and _is_int(sessions) and end - start + 1 < 4 * sessions:
        _error(errors, path, "media block must reserve at least four UDP ports per session")
    if not isinstance(value.get("rtcpMux"), bool):
        _error(errors, path + ".rtcpMux", "must be a boolean")
    codecs = _array(value.get("codecs"), path + ".codecs", errors, 1, 8)
    seen: Set[str] = set()
    for index, codec in enumerate(codecs):
        if codec not in {"PCMA", "PCMU"}:
            _error(errors, "{}.codecs[{}]".format(path, index), "must be PCMA or PCMU")
        if codec in seen:
            _error(errors, "{}.codecs[{}]".format(path, index), "duplicates an earlier codec")
        seen.add(codec)
    if _is_int(start) and _is_int(end) and _is_int(sessions):
        return start, end, sessions
    return None


def _validate_capacity(spec: Any, path: str, errors: List[str]) -> Optional[Tuple[int, int]]:
    fields = {
        "reservedConcurrentSessions",
        "maxConcurrentSessions",
        "maxCallsPerSecond",
        "maxBandwidthKbps",
    }
    value = _object(spec, path, fields, errors)
    if value is None:
        return None
    reserved = value.get("reservedConcurrentSessions")
    maximum = value.get("maxConcurrentSessions")
    _integer(reserved, path + ".reservedConcurrentSessions", errors, 1, 100000)
    _integer(maximum, path + ".maxConcurrentSessions", errors, 1, 100000)
    _integer(value.get("maxCallsPerSecond"), path + ".maxCallsPerSecond", errors, 1, 10000)
    _integer(value.get("maxBandwidthKbps"), path + ".maxBandwidthKbps", errors, 128, 100000000)
    if _is_int(reserved) and _is_int(maximum) and reserved > maximum:
        _error(errors, path, "reservedConcurrentSessions must not exceed maxConcurrentSessions")
    if _is_int(reserved) and _is_int(maximum):
        return reserved, maximum
    return None


def _validate_cluster_spec(
    resource_type: str,
    spec: Any,
    path: str,
    errors: List[str],
) -> Tuple[Set[str], Optional[str]]:
    secrets: Set[str] = set()
    software_artifact: Optional[str] = None
    if resource_type == "cluster.software":
        value = _object(spec, path, {"component", "version", "artifactId"}, errors)
        if value is not None:
            if value.get("component") not in {"EDGE_AGENT", "ROOT_HELPER", "OPENSIPS", "RTPENGINE"}:
                _error(errors, path + ".component", "is not an allowed component")
            _identifier(value.get("version"), path + ".version", errors)
            _identifier(value.get("artifactId"), path + ".artifactId", errors)
            if isinstance(value.get("artifactId"), str):
                software_artifact = value["artifactId"]
    elif resource_type == "cluster.shared-listener":
        fields = {"role", "transport", "bindAddress", "port", "allowedSourceCidrs", "certificateSecretRef"}
        value = _object(spec, path, fields, errors)
        if value is not None:
            if value.get("role") != "TEAMS":
                _error(errors, path + ".role", "must be TEAMS")
            if value.get("transport") != "TLS":
                _error(errors, path + ".transport", "must be TLS")
            if value.get("bindAddress") not in {"0.0.0.0", "::"}:
                _error(errors, path + ".bindAddress", "must be 0.0.0.0 or ::")
            if value.get("port") != 5061:
                _error(errors, path + ".port", "must be 5061")
            _cidrs(value.get("allowedSourceCidrs"), path + ".allowedSourceCidrs", errors, 256)
            _identifier(value.get("certificateSecretRef"), path + ".certificateSecretRef", errors)
            if isinstance(value.get("certificateSecretRef"), str):
                secrets.add(value["certificateSecretRef"])
    elif resource_type == "cluster.firewall-policy":
        fields = {"policy", "teamsSourceCidrs", "managementEgressHosts"}
        value = _object(spec, path, fields, errors)
        if value is not None:
            if value.get("policy") != "DEFAULT_DENY":
                _error(errors, path + ".policy", "must be DEFAULT_DENY")
            _cidrs(value.get("teamsSourceCidrs"), path + ".teamsSourceCidrs", errors, 256)
            hosts = _array(value.get("managementEgressHosts"), path + ".managementEgressHosts", errors, 1, 32)
            for index, host in enumerate(hosts):
                _host(host, "{}.managementEgressHosts[{}]".format(path, index), errors)
    return secrets, software_artifact


def _validate_resources(
    value: Any,
    scope: str,
    tenant: Optional[Dict[str, Any]],
    artifacts: Dict[str, Dict[str, Any]],
    artifact_kinds: Dict[str, str],
    secrets: Dict[str, Dict[str, Any]],
    active: bool,
    errors: List[str],
) -> Tuple[Dict[str, Dict[str, Any]], Set[str], Set[str]]:
    resources: Dict[str, Dict[str, Any]] = {}
    used_artifacts: Set[str] = set()
    used_secrets: Set[str] = set()
    route_connector_refs: List[Tuple[str, str]] = []
    route_keys: Set[Tuple[Any, ...]] = set()
    media_ranges: List[Tuple[int, int, int, str]] = []
    capacities: List[Tuple[int, int, str]] = []
    pbx_media_destination_ranges: List[Tuple[int, int, str]] = []
    seen_types: Set[str] = set()
    secret_purposes: Dict[str, Set[str]] = {}

    def consume_secret(ref: Any, purpose: str) -> None:
        if isinstance(ref, str):
            secret_purposes.setdefault(ref, set()).add(purpose)

    for index, raw in enumerate(
        _array(value, "$.manifest.resourceSet.resources", errors, 1 if active else 0, 256)
    ):
        path = "$.manifest.resourceSet.resources[{}]".format(index)
        if scope == "TENANT":
            fields = {"type", "resourceId", "tenantContextId", "allocationId", "artifactIds", "spec"}
            allowed_types = TENANT_RESOURCE_TYPES
        else:
            fields = {"type", "resourceId", "artifactIds", "spec"}
            allowed_types = CLUSTER_RESOURCE_TYPES
        resource = _object(raw, path, fields, errors)
        if resource is None:
            continue
        resource_type = resource.get("type")
        if resource_type not in allowed_types:
            _error(errors, path + ".type", "is not allowed for {} scope".format(scope))
        elif isinstance(resource_type, str):
            seen_types.add(resource_type)
        resource_id = resource.get("resourceId")
        _identifier(resource_id, path + ".resourceId", errors)
        if scope == "TENANT" and tenant is not None:
            for field in ("tenantContextId", "allocationId"):
                _identifier(resource.get(field), path + "." + field, errors)
                if resource.get(field) != tenant.get(field):
                    _error(errors, path + "." + field, "cross-scope resource identity")
        artifact_ids = _unique_strings(resource.get("artifactIds"), path + ".artifactIds", errors)
        for artifact_id in artifact_ids:
            if artifact_id not in artifacts:
                _error(errors, path + ".artifactIds", "references unknown artifact {}".format(artifact_id))
            used_artifacts.add(artifact_id)

        spec_path = path + ".spec"
        if resource_type == "tenant.connector":
            used_secrets.update(_validate_connector(resource.get("spec"), spec_path, errors))
            if isinstance(resource.get("spec"), dict):
                pbx_media_start = resource["spec"].get("mediaDestinationPortStart")
                pbx_media_end = resource["spec"].get("mediaDestinationPortEnd")
                if _is_int(pbx_media_start) and _is_int(pbx_media_end):
                    pbx_media_destination_ranges.append(
                        (pbx_media_start, pbx_media_end, str(resource_id))
                    )
                consume_secret(
                    resource["spec"].get("credentialSecretRef"),
                    "PBX_CLIENT_MTLS_IDENTITY",
                )
            allowed_artifact_kinds = {"OPENSIPS_TENANT_CONFIG"}
        elif resource_type == "tenant.listener":
            used_secrets.update(_validate_listener(resource.get("spec"), spec_path, errors))
            if isinstance(resource.get("spec"), dict):
                consume_secret(
                    resource["spec"].get("certificateSecretRef"),
                    "PBX_SERVER_TLS_IDENTITY",
                )
                consume_secret(
                    resource["spec"].get("clientCaSecretRef"),
                    "PBX_CLIENT_CA_BUNDLE",
                )
            allowed_artifact_kinds = {"OPENSIPS_TENANT_CONFIG", "NFTABLES_TENANT_POLICY"}
        elif resource_type == "tenant.route":
            connector_ref, route_key = _validate_route(resource.get("spec"), spec_path, errors)
            if connector_ref and isinstance(resource_id, str):
                route_connector_refs.append((resource_id, connector_ref))
            if route_key:
                if route_key in route_keys:
                    _error(errors, spec_path, "duplicates a direction/priority/prefix route key")
                route_keys.add(route_key)
            allowed_artifact_kinds = {"OPENSIPS_TENANT_CONFIG"}
        elif resource_type == "tenant.media":
            media = _validate_media(resource.get("spec"), spec_path, errors)
            if media and isinstance(resource_id, str):
                media_ranges.append((media[0], media[1], media[2], resource_id))
            allowed_artifact_kinds = {"RTPENGINE_TENANT_CONFIG", "NFTABLES_TENANT_POLICY"}
        elif resource_type == "tenant.capacity":
            capacity = _validate_capacity(resource.get("spec"), spec_path, errors)
            if capacity and isinstance(resource_id, str):
                capacities.append((capacity[0], capacity[1], resource_id))
            allowed_artifact_kinds = {"OPENSIPS_TENANT_CONFIG", "RTPENGINE_TENANT_CONFIG"}
        elif isinstance(resource_type, str) and resource_type in CLUSTER_RESOURCE_TYPES:
            refs, software_artifact = _validate_cluster_spec(resource_type, resource.get("spec"), spec_path, errors)
            used_secrets.update(refs)
            if resource_type == "cluster.shared-listener" and isinstance(resource.get("spec"), dict):
                consume_secret(
                    resource["spec"].get("certificateSecretRef"),
                    "TEAMS_TLS_IDENTITY",
                )
            if software_artifact:
                if software_artifact not in artifact_ids:
                    _error(errors, spec_path + ".artifactId", "must also appear in resource artifactIds")
            allowed_artifact_kinds = {
                "cluster.software": {"SOFTWARE_PACKAGE"},
                "cluster.shared-listener": {"OPENSIPS_SHARED_CONFIG"},
                "cluster.firewall-policy": {"NFTABLES_CLUSTER_POLICY"},
            }[resource_type]
        else:
            allowed_artifact_kinds = set()

        for artifact_id in artifact_ids:
            kind = artifact_kinds.get(artifact_id)
            if kind is not None and kind not in allowed_artifact_kinds:
                _error(
                    errors,
                    path + ".artifactIds",
                    "artifact {} kind {} cannot configure {}".format(artifact_id, kind, resource_type),
                )
        if isinstance(resource_id, str):
            if resource_id in resources:
                _error(errors, path + ".resourceId", "duplicates an earlier resourceId")
            resources[resource_id] = resource

    if active and scope == "TENANT":
        missing_types = sorted(TENANT_RESOURCE_TYPES - seen_types)
        if missing_types:
            _error(errors, "$.manifest.resourceSet.resources", "missing required tenant resource types {}".format(missing_types))
        type_counts = {
            resource_type: sum(1 for resource in resources.values() if resource.get("type") == resource_type)
            for resource_type in TENANT_RESOURCE_TYPES
        }
        for singleton in (
            "tenant.connector",
            "tenant.listener",
            "tenant.media",
            "tenant.capacity",
        ):
            if type_counts[singleton] != 1:
                _error(
                    errors,
                    "$.manifest.resourceSet.resources",
                    "ACTIVE tenant requires exactly one {} resource".format(singleton),
                )
        route_directions = {
            resource.get("spec", {}).get("direction")
            for resource in resources.values()
            if resource.get("type") == "tenant.route" and isinstance(resource.get("spec"), dict)
        }
        if route_directions != {"TEAMS_TO_PBX", "PBX_TO_TEAMS"}:
            _error(
                errors,
                "$.manifest.resourceSet.resources",
                "ACTIVE tenant routes must cover both TEAMS_TO_PBX and PBX_TO_TEAMS",
            )
    if active and scope == "CLUSTER":
        missing_types = sorted(CLUSTER_RESOURCE_TYPES - seen_types)
        if missing_types:
            _error(
                errors,
                "$.manifest.resourceSet.resources",
                "missing required cluster resource types {}".format(missing_types),
            )
        for singleton in ("cluster.shared-listener", "cluster.firewall-policy"):
            count = sum(1 for resource in resources.values() if resource.get("type") == singleton)
            if count != 1:
                _error(
                    errors,
                    "$.manifest.resourceSet.resources",
                    "ACTIVE cluster requires exactly one {} resource".format(singleton),
                )
        components = [
            resource.get("spec", {}).get("component")
            for resource in resources.values()
            if resource.get("type") == "cluster.software" and isinstance(resource.get("spec"), dict)
        ]
        required_components = {"EDGE_AGENT", "ROOT_HELPER", "OPENSIPS", "RTPENGINE"}
        if set(components) != required_components or len(components) != len(required_components):
            _error(
                errors,
                "$.manifest.resourceSet.resources",
                "ACTIVE cluster requires exactly one software resource for each of {}".format(
                    sorted(required_components)
                ),
            )
    for route_id, connector_ref in route_connector_refs:
        connector = resources.get(connector_ref)
        if connector is None or connector.get("type") != "tenant.connector":
            _error(errors, "$.manifest.resourceSet.resources", "route {} references non-connector {}".format(route_id, connector_ref))
    for first_index, first in enumerate(media_ranges):
        for second in media_ranges[first_index + 1 :]:
            if first[0] <= second[1] and second[0] <= first[1]:
                _error(errors, "$.manifest.resourceSet.resources", "media ranges {} and {} overlap".format(first[3], second[3]))
    total_media_sessions = sum(item[2] for item in media_ranges)
    for start, end, resource_id in pbx_media_destination_ranges:
        if end >= start and (end - start + 1) // 2 < total_media_sessions:
            _error(
                errors,
                "$.manifest.resourceSet.resources",
                "connector {} PBX media destination range cannot serve all non-muxed media sessions".format(
                    resource_id
                ),
            )
    for reserved, maximum, resource_id in capacities:
        if maximum > total_media_sessions:
            _error(errors, "$.manifest.resourceSet.resources", "capacity {} exceeds media maxSessions".format(resource_id))
        if reserved > total_media_sessions:
            _error(errors, "$.manifest.resourceSet.resources", "capacity {} reserves unavailable media sessions".format(resource_id))

    for secret_ref in sorted(used_secrets):
        if secret_ref not in secrets:
            _error(errors, "$.manifest.resourceSet.resources", "references unknown secret {}".format(secret_ref))
            continue
        reference = secrets[secret_ref]
        if reference.get("requiredOnNode") is not True:
            _error(
                errors,
                "$.manifest.resourceSet.secretReferences",
                "used secret {} must set requiredOnNode=true".format(secret_ref),
            )
        expected_purposes = secret_purposes.get(secret_ref, set())
        if len(expected_purposes) != 1 or reference.get("purpose") not in expected_purposes:
            _error(
                errors,
                "$.manifest.resourceSet.secretReferences",
                "used secret {} purpose {!r} does not match consuming field purpose {}".format(
                    secret_ref,
                    reference.get("purpose"),
                    sorted(expected_purposes),
                ),
            )
    unused_artifacts = sorted(set(artifacts) - used_artifacts)
    if unused_artifacts:
        _error(errors, "$.manifest.resourceSet.artifacts", "unreferenced exact artifacts {}".format(unused_artifacts))
    unused_secrets = sorted(set(secrets) - used_secrets)
    if unused_secrets:
        _error(errors, "$.manifest.resourceSet.secretReferences", "unreferenced secret references {}".format(unused_secrets))
    return resources, used_artifacts, used_secrets


def _validate_cleanup_intent(
    value: Any,
    scope: str,
    lifecycle: str,
    target: Optional[Dict[str, Any]],
    tenant: Optional[Dict[str, Any]],
    errors: List[str],
) -> None:
    path = "$.manifest.resourceSet.cleanupIntent"
    if lifecycle == "ACTIVE":
        if value is not None:
            _error(errors, path, "must be null for ACTIVE desired state")
        return
    if scope == "TENANT" and lifecycle == "ABSENT":
        intent = _object(
            value,
            path,
            {"type", "tenantContextId", "allocationId"},
            errors,
        )
        if intent is None:
            return
        if intent.get("type") != "TENANT_RESOURCES_ABSENT":
            _error(errors, path + ".type", "must be TENANT_RESOURCES_ABSENT")
        if tenant is not None:
            for field in ("tenantContextId", "allocationId"):
                _identifier(intent.get(field), path + "." + field, errors)
                if intent.get(field) != tenant.get(field):
                    _error(errors, path + "." + field, "cross-scope cleanup identity")
        return
    if scope == "CLUSTER" and lifecycle == "DECOMMISSION":
        intent = _object(
            value,
            path,
            {"type", "clusterId", "nodeId", "generation"},
            errors,
        )
        if intent is None:
            return
        if intent.get("type") != "NODE_DECOMMISSION":
            _error(errors, path + ".type", "must be NODE_DECOMMISSION")
        if target is not None:
            for field in ("clusterId", "nodeId", "generation"):
                if intent.get(field) != target.get(field):
                    _error(errors, path + "." + field, "must equal the exact node target")
        return
    _error(errors, path, "cleanup intent is not defined for this scope/lifecycle")


def _expected_gate_refs(
    scope: str,
    gate_type: str,
    resources: Dict[str, Dict[str, Any]],
) -> Set[str]:
    if scope == "TENANT":
        types = TENANT_ACTIVE_GATE_RESOURCES.get(gate_type, set())
        return {
            resource_id
            for resource_id, resource in resources.items()
            if resource.get("type") in types
        }
    if gate_type == "NODE_BASELINE":
        return {
            resource_id
            for resource_id, resource in resources.items()
            if resource.get("type") == "cluster.software"
        }
    if gate_type == "ARTIFACT_DIGESTS":
        return set(resources)
    if gate_type == "OPENSIPS_CONFIG":
        return {
            resource_id
            for resource_id, resource in resources.items()
            if resource.get("type") == "cluster.shared-listener"
            or (
                resource.get("type") == "cluster.software"
                and resource.get("spec", {}).get("component") == "OPENSIPS"
            )
        }
    if gate_type == "RTPENGINE_READY":
        return {
            resource_id
            for resource_id, resource in resources.items()
            if resource.get("type") == "cluster.software"
            and resource.get("spec", {}).get("component") == "RTPENGINE"
        }
    if gate_type == "PEER_N_MINUS_ONE_CAPACITY":
        return {
            resource_id
            for resource_id, resource in resources.items()
            if resource.get("type") == "cluster.shared-listener"
        }
    return set()


def _validate_health_gates(
    value: Any,
    scope: str,
    lifecycle: str,
    tenant: Optional[Dict[str, Any]],
    resources: Dict[str, Dict[str, Any]],
    errors: List[str],
) -> None:
    seen_ids: Set[str] = set()
    seen_types: Set[str] = set()
    gates = _array(value, "$.manifest.healthGates", errors, 1, 32)
    for index, raw in enumerate(gates):
        path = "$.manifest.healthGates[{}]".format(index)
        if scope == "TENANT":
            fields = {
                "gateId",
                "type",
                "tenantContextId",
                "allocationId",
                "resourceRefs",
                "timeoutSeconds",
                "maxAttempts",
                "onFailure",
            }
            allowed_types = (
                TENANT_GATE_TYPES if lifecycle == "ACTIVE" else {TENANT_ABSENCE_GATE_TYPE}
            )
        else:
            fields = {"gateId", "type", "resourceRefs", "timeoutSeconds", "maxAttempts", "onFailure"}
            allowed_types = (
                CLUSTER_GATE_TYPES
                if lifecycle == "ACTIVE"
                else {CLUSTER_DECOMMISSION_GATE_TYPE}
            )
        gate = _object(raw, path, fields, errors)
        if gate is None:
            continue
        gate_id = gate.get("gateId")
        _identifier(gate_id, path + ".gateId", errors)
        if isinstance(gate_id, str):
            if gate_id in seen_ids:
                _error(errors, path + ".gateId", "duplicates an earlier gateId")
            seen_ids.add(gate_id)
        gate_type = gate.get("type")
        if gate_type not in allowed_types:
            _error(errors, path + ".type", "is not allowed for {} scope".format(scope))
        elif isinstance(gate_type, str):
            if gate_type in seen_types:
                _error(errors, path + ".type", "duplicates an earlier health gate type")
            seen_types.add(gate_type)
        if scope == "TENANT" and tenant is not None:
            for field in ("tenantContextId", "allocationId"):
                _identifier(gate.get(field), path + "." + field, errors)
                if gate.get(field) != tenant.get(field):
                    _error(errors, path + "." + field, "cross-scope health-gate identity")
        refs = _unique_strings(
            gate.get("resourceRefs"),
            path + ".resourceRefs",
            errors,
            minimum=1 if lifecycle == "ACTIVE" else 0,
        )
        for ref in refs:
            if ref not in resources:
                _error(errors, path + ".resourceRefs", "references unknown resource {}".format(ref))
        _integer(gate.get("timeoutSeconds"), path + ".timeoutSeconds", errors, 1, 600)
        _integer(gate.get("maxAttempts"), path + ".maxAttempts", errors, 1, 10)
        if gate.get("onFailure") != "ROLLBACK_TO_TARGET":
            _error(errors, path + ".onFailure", "must be ROLLBACK_TO_TARGET")
        if isinstance(gate_type, str) and gate_type in allowed_types:
            expected_refs = _expected_gate_refs(scope, gate_type, resources)
            if set(refs) != expected_refs:
                _error(
                    errors,
                    path + ".resourceRefs",
                    "{} must reference exactly the relevant resources {}".format(
                        gate_type, sorted(expected_refs)
                    ),
                )
    required_types = (
        TENANT_GATE_TYPES
        if scope == "TENANT" and lifecycle == "ACTIVE"
        else CLUSTER_GATE_TYPES
        if scope == "CLUSTER" and lifecycle == "ACTIVE"
        else {TENANT_ABSENCE_GATE_TYPE}
        if scope == "TENANT"
        else {CLUSTER_DECOMMISSION_GATE_TYPE}
    )
    missing = sorted(required_types - seen_types)
    extra = sorted(seen_types - required_types)
    if missing:
        _error(errors, "$.manifest.healthGates", "missing required health gate types {}".format(missing))
    if extra:
        _error(errors, "$.manifest.healthGates", "contains lifecycle-incompatible health gate types {}".format(extra))


def _validate_rollback(
    value: Any,
    manifest: Dict[str, Any],
    target: Optional[Dict[str, Any]],
    tenant: Optional[Dict[str, Any]],
    errors: List[str],
) -> None:
    sequence = manifest.get("sequence")
    previous_digest = manifest.get("previousDigest")
    path = "$.manifest.rollbackTarget"
    if sequence == 1:
        if previous_digest is not None:
            _error(errors, "$.manifest.previousDigest", "must be null for sequence 1")
        if value is not None:
            _error(errors, path, "must be null for sequence 1")
        return
    _digest(previous_digest, "$.manifest.previousDigest", errors)
    if target is None:
        return
    if target.get("scope") == "TENANT":
        fields = {
            "scope",
            "clusterId",
            "nodeId",
            "generation",
            "tenantContextId",
            "allocationId",
            "sequence",
            "manifestDigest",
            "artifactDigests",
        }
    else:
        fields = {
            "scope",
            "clusterId",
            "nodeId",
            "generation",
            "sequence",
            "manifestDigest",
            "artifactDigests",
        }
    rollback = _object(value, path, fields, errors)
    if rollback is None:
        return
    for field in ("clusterId", "nodeId"):
        _identifier(rollback.get(field), path + "." + field, errors)
        if rollback.get(field) != target.get(field):
            _error(errors, path + "." + field, "must equal the current target")
    if rollback.get("scope") != target.get("scope"):
        _error(errors, path + ".scope", "must equal the current target scope")
    _integer(rollback.get("generation"), path + ".generation", errors, 1)
    if rollback.get("generation") != target.get("generation"):
        _error(errors, path + ".generation", "must equal the current target generation")
    if target.get("scope") == "TENANT" and tenant is not None:
        for field in ("tenantContextId", "allocationId"):
            _identifier(rollback.get(field), path + "." + field, errors)
            if rollback.get(field) != tenant.get(field):
                _error(errors, path + "." + field, "cross-scope rollback identity")
    rollback_sequence = rollback.get("sequence")
    _integer(rollback_sequence, path + ".sequence", errors, 1)
    if _is_int(sequence) and _is_int(rollback_sequence) and rollback_sequence >= sequence:
        _error(errors, path + ".sequence", "must be lower than the new manifest sequence")
    rollback_digest = rollback.get("manifestDigest")
    _digest(rollback_digest, path + ".manifestDigest", errors)
    if rollback_digest != previous_digest:
        _error(errors, path + ".manifestDigest", "must equal previousDigest")
    digests = _array(rollback.get("artifactDigests"), path + ".artifactDigests", errors, 0, 64)
    seen: Set[str] = set()
    for index, digest in enumerate(digests):
        _digest(digest, "{}.artifactDigests[{}]".format(path, index), errors)
        if isinstance(digest, str):
            if digest in seen:
                _error(errors, "{}.artifactDigests[{}]".format(path, index), "duplicates an earlier digest")
            seen.add(digest)


def _validate_signatures(value: Any, issued: Optional[datetime], expires: Optional[datetime], errors: List[str]) -> None:
    signatures = _array(value, "$.signatures", errors, 1, 4)
    seen_keys: Set[str] = set()
    for index, raw in enumerate(signatures):
        path = "$.signatures[{}]".format(index)
        signature = _object(raw, path, {"keyId", "algorithm", "createdAt", "value"}, errors)
        if signature is None:
            continue
        key_id = signature.get("keyId")
        _identifier(key_id, path + ".keyId", errors)
        if isinstance(key_id, str):
            if key_id in seen_keys:
                _error(errors, path + ".keyId", "duplicates an earlier signing key")
            seen_keys.add(key_id)
        if signature.get("algorithm") != "Ed25519":
            _error(errors, path + ".algorithm", "must be Ed25519")
        created = parse_utc_timestamp(signature.get("createdAt"), path + ".createdAt", errors)
        if created is not None and issued is not None and created < issued:
            _error(errors, path + ".createdAt", "must not predate issuedAt")
        if created is not None and expires is not None and created >= expires:
            _error(errors, path + ".createdAt", "must predate expiresAt")
        encoded = signature.get("value")
        if not isinstance(encoded, str):
            _error(errors, path + ".value", "must be base64")
            continue
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            _error(errors, path + ".value", "must be canonical base64")
            continue
        if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != encoded:
            _error(errors, path + ".value", "must encode exactly 64 Ed25519 signature bytes")


def validate_envelope(envelope: Any, context: ValidationContext) -> None:
    """Raise ContractError if structural or contextual preflight fails."""

    errors: List[str] = []
    _scan_for_secret_values(envelope, "$", errors)
    top = _object(
        envelope,
        "$",
        {"apiVersion", "kind", "manifestDigest", "manifest", "signatures"},
        errors,
    )
    if top is None:
        raise ContractError(errors)
    if top.get("apiVersion") != API_VERSION:
        _error(errors, "$.apiVersion", "must be {}".format(API_VERSION))
    if top.get("kind") != KIND:
        _error(errors, "$.kind", "must be {}".format(KIND))
    _digest(top.get("manifestDigest"), "$.manifestDigest", errors)
    manifest = _object(
        top.get("manifest"),
        "$.manifest",
        {
            "manifestId",
            "target",
            "lifecycle",
            "sequence",
            "issuedAt",
            "expiresAt",
            "previousDigest",
            "resourceSet",
            "healthGates",
            "rollbackTarget",
        },
        errors,
    )
    if manifest is None:
        _validate_signatures(top.get("signatures"), None, None, errors)
        raise ContractError(errors)

    _identifier(manifest.get("manifestId"), "$.manifest.manifestId", errors)
    target, tenant = _validate_target(manifest.get("target"), errors)
    lifecycle = manifest.get("lifecycle")
    sequence = manifest.get("sequence")
    _integer(sequence, "$.manifest.sequence", errors, 1)
    issued = parse_utc_timestamp(manifest.get("issuedAt"), "$.manifest.issuedAt", errors)
    expires = parse_utc_timestamp(manifest.get("expiresAt"), "$.manifest.expiresAt", errors)
    if issued is not None and expires is not None and expires <= issued:
        _error(errors, "$.manifest.expiresAt", "must be later than issuedAt")
    if issued is not None and expires is not None:
        ttl = int((expires - issued).total_seconds())
        if ttl > MAX_ACTIVATION_TTL_SECONDS:
            _error(
                errors,
                "$.manifest.expiresAt",
                "activation TTL must not exceed {} seconds".format(
                    MAX_ACTIVATION_TTL_SECONDS
                ),
            )
    if context.now.tzinfo is None:
        _error(errors, "$context.now", "must be timezone-aware")
    else:
        now = context.now.astimezone(timezone.utc)
        if issued is not None and issued > now + timedelta(seconds=MAX_ISSUED_AT_FUTURE_SKEW_SECONDS):
            _error(
                errors,
                "$.manifest.issuedAt",
                "exceeds the allowed {} second future clock skew".format(
                    MAX_ISSUED_AT_FUTURE_SKEW_SECONDS
                ),
            )
        if issued is not None and issued < now - timedelta(seconds=MAX_ISSUED_AT_PAST_SKEW_SECONDS):
            _error(
                errors,
                "$.manifest.issuedAt",
                "exceeds the allowed {} second past activation skew".format(
                    MAX_ISSUED_AT_PAST_SKEW_SECONDS
                ),
            )
        if expires is not None and now >= expires:
            _error(errors, "$.manifest.expiresAt", "manifest activation has expired")

    scope = target.get("scope") if target else ""
    allowed_lifecycles = (
        {"ACTIVE", "ABSENT"}
        if scope == "TENANT"
        else {"ACTIVE", "DECOMMISSION"}
        if scope == "CLUSTER"
        else set()
    )
    if lifecycle not in allowed_lifecycles:
        _error(
            errors,
            "$.manifest.lifecycle",
            "is not allowed for {} scope; allowed values are {}".format(
                scope or "unknown", sorted(allowed_lifecycles)
            ),
        )
    active = lifecycle == "ACTIVE"
    resource_set = _object(
        manifest.get("resourceSet"),
        "$.manifest.resourceSet",
        {"mode", "cleanupIntent", "artifacts", "secretReferences", "resources"},
        errors,
    )
    if resource_set is not None:
        if resource_set.get("mode") != "COMPLETE":
            _error(errors, "$.manifest.resourceSet.mode", "must be COMPLETE")
        _validate_cleanup_intent(
            resource_set.get("cleanupIntent"),
            scope,
            lifecycle if isinstance(lifecycle, str) else "",
            target,
            tenant,
            errors,
        )
        artifacts, artifact_kinds = _validate_artifacts(
            resource_set.get("artifacts"), scope, tenant, active, errors
        )
        secrets = _validate_secret_references(resource_set.get("secretReferences"), scope, tenant, errors)
        resources, _, _ = _validate_resources(
            resource_set.get("resources"),
            scope,
            tenant,
            artifacts,
            artifact_kinds,
            secrets,
            active,
            errors,
        )
        if not active:
            for field in ("artifacts", "secretReferences", "resources"):
                if resource_set.get(field) != []:
                    _error(
                        errors,
                        "$.manifest.resourceSet." + field,
                        "must be empty for {} lifecycle".format(lifecycle),
                    )
    else:
        resources = {}
    _validate_health_gates(
        manifest.get("healthGates"),
        scope,
        lifecycle if isinstance(lifecycle, str) else "",
        tenant,
        resources,
        errors,
    )
    _validate_rollback(manifest.get("rollbackTarget"), manifest, target, tenant, errors)
    _validate_signatures(top.get("signatures"), issued, expires, errors)

    try:
        calculated_digest = manifest_digest(manifest)
    except (TypeError, ValueError, UnicodeError) as exc:
        _error(errors, "$.manifest", "cannot be canonicalized: {}".format(exc))
        calculated_digest = None
    if calculated_digest is not None and top.get("manifestDigest") != calculated_digest:
        _error(
            errors,
            "$.manifestDigest",
            "does not match canonical manifest bytes (expected {})".format(calculated_digest),
        )

    if target is not None:
        expected_pairs = (
            ("clusterId", context.expected_cluster_id),
            ("nodeId", context.expected_node_id),
            ("generation", context.expected_generation),
        )
        for field, expected in expected_pairs:
            if target.get(field) != expected:
                _error(
                    errors,
                    "$.manifest.target." + field,
                    "wrong target: expected {!r}".format(expected),
                )
        if scope == "TENANT":
            if context.expected_tenant_context_id is None or context.expected_allocation_id is None:
                _error(errors, "$context", "tenant target requires expected tenantContextId and allocationId")
            elif tenant is not None:
                if tenant.get("tenantContextId") != context.expected_tenant_context_id:
                    _error(errors, "$.manifest.target.tenant.tenantContextId", "wrong authorized tenant target")
                if tenant.get("allocationId") != context.expected_allocation_id:
                    _error(errors, "$.manifest.target.tenant.allocationId", "wrong authorized allocation target")

            allocation_values = (
                context.expected_tenant_listener_port,
                context.expected_media_port_start,
                context.expected_media_port_end,
                context.expected_pbx_media_destination_port_start,
                context.expected_pbx_media_destination_port_end,
            )
            if active and any(value is None for value in allocation_values):
                _error(
                    errors,
                    "$context",
                    "tenant target requires expected listener and media allocation ports",
                )
            elif active:
                _integer(
                    context.expected_tenant_listener_port,
                    "$context.expected_tenant_listener_port",
                    errors,
                    1024,
                    65535,
                )
                if context.expected_tenant_listener_port == 5061:
                    _error(
                        errors,
                        "$context.expected_tenant_listener_port",
                        "must not collide with shared Teams port 5061",
                    )
                _integer(
                    context.expected_media_port_start,
                    "$context.expected_media_port_start",
                    errors,
                    1024,
                    65534,
                )
                _integer(
                    context.expected_media_port_end,
                    "$context.expected_media_port_end",
                    errors,
                    1025,
                    65535,
                )
                _integer(
                    context.expected_pbx_media_destination_port_start,
                    "$context.expected_pbx_media_destination_port_start",
                    errors,
                    1024,
                    65534,
                )
                _integer(
                    context.expected_pbx_media_destination_port_end,
                    "$context.expected_pbx_media_destination_port_end",
                    errors,
                    1025,
                    65535,
                )

                listeners = [
                    resource
                    for resource in resources.values()
                    if resource.get("type") == "tenant.listener"
                ]
                media_resources = [
                    resource
                    for resource in resources.values()
                    if resource.get("type") == "tenant.media"
                ]
                if len(listeners) != 1:
                    _error(
                        errors,
                        "$.manifest.resourceSet.resources",
                        "authorized v0.1 tenant allocation requires exactly one listener",
                    )
                elif listeners[0].get("spec", {}).get("port") != context.expected_tenant_listener_port:
                    _error(
                        errors,
                        "$.manifest.resourceSet.resources",
                        "tenant listener does not match locally authorized port {}".format(
                            context.expected_tenant_listener_port
                        ),
                    )
                if len(media_resources) != 1:
                    _error(
                        errors,
                        "$.manifest.resourceSet.resources",
                        "authorized v0.1 tenant allocation requires exactly one media block",
                    )
                else:
                    media_spec = media_resources[0].get("spec", {})
                    if (
                        media_spec.get("portStart") != context.expected_media_port_start
                        or media_spec.get("portEnd") != context.expected_media_port_end
                    ):
                        _error(
                            errors,
                            "$.manifest.resourceSet.resources",
                            "tenant media block does not match locally authorized ports {}-{}".format(
                                context.expected_media_port_start,
                                context.expected_media_port_end,
                            ),
                        )
                connectors = [
                    resource
                    for resource in resources.values()
                    if resource.get("type") == "tenant.connector"
                ]
                if len(connectors) != 1:
                    _error(
                        errors,
                        "$.manifest.resourceSet.resources",
                        "authorized v0.1 tenant allocation requires exactly one connector",
                    )
                else:
                    connector_spec = connectors[0].get("spec", {})
                    if (
                        connector_spec.get("mediaDestinationPortStart")
                        != context.expected_pbx_media_destination_port_start
                        or connector_spec.get("mediaDestinationPortEnd")
                        != context.expected_pbx_media_destination_port_end
                    ):
                        _error(
                            errors,
                            "$.manifest.resourceSet.resources",
                            "PBX media destination range does not match locally authorized ports {}-{}".format(
                                context.expected_pbx_media_destination_port_start,
                                context.expected_pbx_media_destination_port_end,
                            ),
                        )
                if context.expected_advertised_public_ip is None:
                    _error(
                        errors,
                        "$context.expected_advertised_public_ip",
                        "ACTIVE tenant requires the locally trusted node public IP",
                    )
                else:
                    _ip_address(
                        context.expected_advertised_public_ip,
                        "$context.expected_advertised_public_ip",
                        errors,
                    )
                    if (
                        len(media_resources) == 1
                        and media_resources[0].get("spec", {}).get("advertisedAddress")
                        != context.expected_advertised_public_ip
                    ):
                        _error(
                            errors,
                            "$.manifest.resourceSet.resources",
                            "tenant media advertisedAddress must exactly equal locally trusted public IP {}".format(
                                context.expected_advertised_public_ip
                            ),
                        )
                pbx_networks = _trusted_networks(
                    context.authorized_pbx_source_cidrs,
                    "$context.authorized_pbx_source_cidrs",
                    errors,
                )
                for resource in resources.values():
                    spec = resource.get("spec", {})
                    if resource.get("type") == "tenant.connector":
                        _require_cidr_subset(
                            spec.get("sourceCidrs"),
                            pbx_networks,
                            "$.manifest.resourceSet.resources[{}].spec.sourceCidrs".format(
                                resource.get("resourceId")
                            ),
                            errors,
                        )
                    elif resource.get("type") == "tenant.listener":
                        _require_cidr_subset(
                            spec.get("allowedSourceCidrs"),
                            pbx_networks,
                            "$.manifest.resourceSet.resources[{}].spec.allowedSourceCidrs".format(
                                resource.get("resourceId")
                            ),
                            errors,
                        )
        elif scope == "CLUSTER" and active:
            microsoft_networks = _trusted_networks(
                context.authorized_microsoft_source_cidrs,
                "$context.authorized_microsoft_source_cidrs",
                errors,
            )
            listener_cidrs: Optional[Set[str]] = None
            firewall_cidrs: Optional[Set[str]] = None
            for resource in resources.values():
                spec = resource.get("spec", {})
                if resource.get("type") == "cluster.shared-listener":
                    _require_cidr_subset(
                        spec.get("allowedSourceCidrs"),
                        microsoft_networks,
                        "$.manifest.resourceSet.resources[{}].spec.allowedSourceCidrs".format(
                            resource.get("resourceId")
                        ),
                        errors,
                    )
                    if isinstance(spec.get("allowedSourceCidrs"), list):
                        listener_cidrs = set(spec["allowedSourceCidrs"])
                elif resource.get("type") == "cluster.firewall-policy":
                    _require_cidr_subset(
                        spec.get("teamsSourceCidrs"),
                        microsoft_networks,
                        "$.manifest.resourceSet.resources[{}].spec.teamsSourceCidrs".format(
                            resource.get("resourceId")
                        ),
                        errors,
                    )
                    if isinstance(spec.get("teamsSourceCidrs"), list):
                        firewall_cidrs = set(spec["teamsSourceCidrs"])
            if listener_cidrs is not None and firewall_cidrs is not None and listener_cidrs != firewall_cidrs:
                _error(
                    errors,
                    "$.manifest.resourceSet.resources",
                    "shared listener and firewall must authorize the same Microsoft source CIDR set",
                )

    _integer(context.accepted_sequence, "$context.accepted_sequence", errors, 0)
    if _is_int(sequence):
        if sequence <= context.accepted_sequence:
            _error(
                errors,
                "$.manifest.sequence",
                "replay/downgrade: {} is not above accepted high-water {}".format(
                    sequence, context.accepted_sequence
                ),
            )
        if context.accepted_sequence == 0:
            if manifest.get("previousDigest") is not None or manifest.get("rollbackTarget") is not None:
                _error(errors, "$.manifest", "initial high-water state requires null lineage")
        else:
            _digest(context.accepted_digest, "$context.accepted_digest", errors)
            if manifest.get("previousDigest") != context.accepted_digest:
                _error(errors, "$.manifest.previousDigest", "does not match accepted last-known-good digest")
            rollback = manifest.get("rollbackTarget")
            if isinstance(rollback, dict):
                if rollback.get("sequence") != context.accepted_sequence:
                    _error(errors, "$.manifest.rollbackTarget.sequence", "must equal accepted high-water sequence")
                if rollback.get("manifestDigest") != context.accepted_digest:
                    _error(errors, "$.manifest.rollbackTarget.manifestDigest", "must equal accepted last-known-good digest")

    if errors:
        raise ContractError(errors)


def _context_from_args(args: argparse.Namespace) -> ValidationContext:
    errors: List[str] = []
    now = parse_utc_timestamp(args.now, "--now", errors) if args.now else datetime.now(timezone.utc)
    if now is None:
        raise ContractError(errors)
    return ValidationContext(
        expected_cluster_id=args.expected_cluster_id,
        expected_node_id=args.expected_node_id,
        expected_generation=args.expected_generation,
        accepted_sequence=args.accepted_sequence,
        accepted_digest=args.accepted_digest,
        now=now,
        expected_tenant_context_id=args.expected_tenant_context_id,
        expected_allocation_id=args.expected_allocation_id,
        expected_tenant_listener_port=args.expected_tenant_listener_port,
        expected_media_port_start=args.expected_media_port_start,
        expected_media_port_end=args.expected_media_port_end,
        expected_pbx_media_destination_port_start=(
            args.expected_pbx_media_destination_port_start
        ),
        expected_pbx_media_destination_port_end=(
            args.expected_pbx_media_destination_port_end
        ),
        expected_advertised_public_ip=args.expected_advertised_public_ip,
        authorized_pbx_source_cidrs=tuple(args.authorized_pbx_source_cidr or ()),
        authorized_microsoft_source_cidrs=tuple(
            args.authorized_microsoft_source_cidr or ()
        ),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    digest_parser = subparsers.add_parser("digest", help="print SHA-256 of canonical manifest bytes")
    digest_parser.add_argument("envelope", type=Path)

    canonical_parser = subparsers.add_parser("canonical", help="write canonical manifest JSON")
    canonical_parser.add_argument("envelope", type=Path)

    validate_parser = subparsers.add_parser(
        "validate",
        help="run structural, digest, scope, target, time and replay preflight",
    )
    validate_parser.add_argument("envelope", type=Path)
    validate_parser.add_argument("--expected-cluster-id", required=True)
    validate_parser.add_argument("--expected-node-id", required=True)
    validate_parser.add_argument("--expected-generation", required=True, type=int)
    validate_parser.add_argument("--accepted-sequence", required=True, type=int)
    validate_parser.add_argument("--accepted-digest")
    validate_parser.add_argument("--expected-tenant-context-id")
    validate_parser.add_argument("--expected-allocation-id")
    validate_parser.add_argument("--expected-tenant-listener-port", type=int)
    validate_parser.add_argument("--expected-media-port-start", type=int)
    validate_parser.add_argument("--expected-media-port-end", type=int)
    validate_parser.add_argument(
        "--expected-pbx-media-destination-port-start", type=int
    )
    validate_parser.add_argument(
        "--expected-pbx-media-destination-port-end", type=int
    )
    validate_parser.add_argument("--expected-advertised-public-ip")
    validate_parser.add_argument(
        "--authorized-pbx-source-cidr",
        action="append",
        help="repeat for each locally authorized PBX source network",
    )
    validate_parser.add_argument(
        "--authorized-microsoft-source-cidr",
        action="append",
        help="repeat for each locally authorized Microsoft source network",
    )
    validate_parser.add_argument("--now", help="fixed UTC timestamp for reproducible evidence")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        envelope = load_json(args.envelope)
        if not isinstance(envelope, dict) or not isinstance(envelope.get("manifest"), dict):
            raise ContractError(["$: expected a signed envelope containing manifest"])
        if args.command == "digest":
            print(manifest_digest(envelope["manifest"]))
            return 0
        if args.command == "canonical":
            sys.stdout.buffer.write(canonical_json_bytes(envelope["manifest"]) + b"\n")
            return 0
        context = _context_from_args(args)
        validate_envelope(envelope, context)
        evidence = {
            "manifestDigest": manifest_digest(envelope["manifest"]),
            "sequence": envelope["manifest"]["sequence"],
            "signatureCryptography": "NOT_VERIFIED",
            "status": "PREFLIGHT_VALID",
            "target": envelope["manifest"]["target"],
        }
        print(canonical_json_bytes(evidence).decode("utf-8"))
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, DuplicateKeyError, ContractError, ValueError) as exc:
        if isinstance(exc, ContractError):
            for error in exc.errors:
                print("ERROR: " + error, file=sys.stderr)
        else:
            print("ERROR: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
