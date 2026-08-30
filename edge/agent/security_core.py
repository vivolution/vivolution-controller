#!/usr/bin/env python3
"""Verify and atomically stage signed Edge desired-state metadata.

This module intentionally has no activation, artifact-fetch, secret-fetch,
command-execution, privilege-escalation, or network-listener capability.
"""

from __future__ import annotations

import base64
import binascii
import errno
import fcntl
import grp
import hashlib
import ipaddress
import json
import os
import secrets
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePath
from types import MappingProxyType
from typing import Any, Dict, Iterator, Mapping, Optional, Sequence, Tuple

from edge.schema import manifest_tool


SIGNED_BYTES_PREFIX = b"edge.vivolution.ae/SignedDesiredState/v0.1\0"
MAX_ENVELOPE_BYTES = 4 * 1024 * 1024
MAX_STATE_BYTES = 128 * 1024
MAX_RUNTIME_EVIDENCE_BYTES = 256 * 1024
STATE_FORMAT_VERSION = 3
AGENT_STATUS_API_VERSION = "edge.vivolution.ae/agent-state/v0.1"
LOCAL_HEALTH_PLAN_API_VERSION = "edge.vivolution.ae/local-health-plan/v0.1"
LOCAL_HEALTH_PLAN_KIND = "TenantLocalHealthGatePlan"
RUNTIME_API_VERSION = "edge.vivolution.ae/runtime/v0.1"
RUNTIME_EVIDENCE_DIRECTORY = Path("/var/lib/vivolution-edge/runtime/evidence")
RUNTIME_EVIDENCE_ROOT_UID = 0
RUNTIME_EVIDENCE_GROUP_NAME = "vivolution-edge-agent"
RUNTIME_SUCCESS_STATUS = "RUNTIME_APPLIED_HEALTHY"
LOCAL_HEALTH_GATE_FIELDS = frozenset(
    {
        "allocationId",
        "gateId",
        "maxAttempts",
        "onFailure",
        "resourceRefs",
        "tenantContextId",
        "timeoutSeconds",
        "type",
    }
)
LOCAL_HEALTH_GATE_ORDER = (
    "ARTIFACT_DIGESTS",
    "OPENSIPS_CONFIG",
    "RTPENGINE_READY",
)
LOCAL_HEALTH_GATE_PARAMETERS = MappingProxyType(
    {
        "ARTIFACT_DIGESTS": (30, 1),
        "OPENSIPS_CONFIG": (30, 1),
        "RTPENGINE_READY": (30, 3),
    }
)
LOCAL_HEALTH_GATE_PROOFS = MappingProxyType(
    {
        "ARTIFACT_DIGESTS": (
            "compiler-artifact-digests",
            "runtime-handoff-artifact-digests",
            "immutable-release-digests",
        ),
        "OPENSIPS_CONFIG": (
            "opensips-offline-parse",
            "opensips-active-parse",
            "opensips-active-release-exact",
            "opensips-profile-routing-identity",
        ),
        "RTPENGINE_READY": (
            "rtpengine-typed-config",
            "systemd-rtpengine-daemon",
            "rtpengine-ng-ping",
            "rtpengine-control-loopback",
            "rtpengine-active-config-exact",
            "rtpengine-profile-advertisement",
        ),
    }
)
RUNTIME_CHECKS_COMMON = (
    "package-opensips-3.6.8",
    "package-rtpengine-26.0.1.22",
    "opensips-offline-parse",
    "nftables-offline-parse",
    "rtpengine-typed-config",
    "systemd-nftables",
    "systemd-rtpengine-daemon",
    "systemd-opensips",
    "opensips-active-parse",
    "nft-owned-default-deny",
    "rtpengine-ng-ping",
    "listeners-exact",
    "rtpengine-control-loopback",
)
RUNTIME_CHECKS_BY_PROFILE = MappingProxyType(
    {
        "SYNTHETIC_PRIVATE": RUNTIME_CHECKS_COMMON
        + (
            "synthetic-private-fixture-routing",
            "rtpengine-synthetic-private-advertisement",
            "nft-bounded-ingress",
            "nft-bounded-egress",
        ),
        "DIRECT_ROUTING": RUNTIME_CHECKS_COMMON
        + (
            "teams-three-hub-failover",
            "rtpengine-direct-public-advertisement",
            "nft-bounded-ingress",
            "nft-bounded-egress",
        ),
    }
)
DESIRED_STATE_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "schema"
    / "edge-desired-state-v0.1.schema.json"
)
MAX_SCHEMA_BYTES = 2 * 1024 * 1024
MAX_AUTHORIZED_SOURCE_CIDRS = 64
MIN_PBX_SOURCE_PREFIX_LENGTH = 24
MIN_MICROSOFT_SOURCE_PREFIX_LENGTH = 14
MAX_PBX_MEDIA_DESTINATION_PORTS = 4096
RESERVED_SIGNALING_AND_CONTROL_PORTS = frozenset({2223, 2224, 5061, 15061})
EXPECTED_SCHEMA_ID = "https://schemas.voice.vivolution.ae/edge/desired-state/v0.1"


class AgentError(RuntimeError):
    """Base class for bounded verifier failures."""


class DependencyUnavailable(AgentError):
    """A required Debian runtime dependency is unavailable."""


class SchemaValidationUnavailable(AgentError):
    """The checked-in Draft 2020-12 contract cannot be safely loaded."""


class EnvelopeRejected(AgentError):
    """The desired-state envelope failed contract or local-context checks."""


class SignatureVerificationError(EnvelopeRejected):
    """No authorized Ed25519 signature verified."""


class StateSecurityError(AgentError):
    """A state path, owner, type, link, or permission invariant failed."""


class StateCorruptionError(AgentError):
    """Existing protected state is malformed or internally inconsistent."""


class StateVersionError(StateCorruptionError):
    """Protected state requires an explicit, reviewed migration."""


class StateLifecycleError(AgentError):
    """A stage, commit, or abort transition is not currently legal."""


def _is_identifier(value: object) -> bool:
    return isinstance(value, str) and manifest_tool.ID_RE.fullmatch(value) is not None


def _require_identifier(value: object, name: str) -> str:
    if not _is_identifier(value):
        raise ValueError("{} must be a lowercase v0.1 identifier".format(name))
    return str(value)


def _require_public_ipv4(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError("{} must be a canonical public IPv4 address".format(name))
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(
            "{} must be a canonical public IPv4 address".format(name)
        ) from exc
    if (
        not isinstance(parsed, ipaddress.IPv4Address)
        or str(parsed) != value
        or not parsed.is_global
    ):
        raise ValueError("{} must be a canonical public IPv4 address".format(name))
    return value


def _require_authorized_ipv4_networks(
    values: object,
    name: str,
    *,
    minimum_prefix_length: int,
    require_global: bool,
) -> Tuple[str, ...]:
    if not isinstance(values, tuple) or not values:
        raise ValueError("{} must be a non-empty tuple of canonical IPv4 CIDRs".format(name))
    if len(values) > MAX_AUTHORIZED_SOURCE_CIDRS:
        raise ValueError(
            "{} must contain at most {} CIDRs".format(
                name, MAX_AUTHORIZED_SOURCE_CIDRS
            )
        )

    networks = []
    for raw in values:
        if not isinstance(raw, str):
            raise ValueError("{} must contain only canonical IPv4 CIDR strings".format(name))
        try:
            network = ipaddress.ip_network(raw, strict=True)
        except ValueError as exc:
            raise ValueError(
                "{} contains a non-canonical IPv4 network {!r}".format(name, raw)
            ) from exc
        if not isinstance(network, ipaddress.IPv4Network) or str(network) != raw:
            raise ValueError(
                "{} contains a non-canonical IPv4 network {!r}".format(name, raw)
            )
        if network.prefixlen < minimum_prefix_length:
            raise ValueError(
                "{} CIDR {!r} is broader than the authorized /{} limit".format(
                    name, raw, minimum_prefix_length
                )
            )
        if require_global and not network.is_global:
            raise ValueError("{} CIDR {!r} must be globally routable".format(name, raw))
        if (
            network.is_loopback
            or network.is_link_local
            or network.is_multicast
            or network.is_unspecified
        ):
            raise ValueError("{} CIDR {!r} is not an authorized unicast network".format(name, raw))
        networks.append(network)

    canonical_order = tuple(
        str(network)
        for network in sorted(
            networks,
            key=lambda item: (int(item.network_address), item.prefixlen),
        )
    )
    if tuple(values) != canonical_order:
        raise ValueError(
            "{} must be unique and sorted by network address/prefix length".format(name)
        )
    for index, network in enumerate(networks):
        for earlier in networks[:index]:
            if network.overlaps(earlier):
                raise ValueError(
                    "{} must not contain duplicate or overlapping CIDRs".format(name)
                )
    return canonical_order


@dataclass(frozen=True)
class LocalContext:
    """Immutable node and optional tenant identity provisioned outside a manifest."""

    scope: str
    cluster_id: str
    node_id: str
    generation: int
    slot: str
    customer_account_id: Optional[str] = None
    m365_tenant_id: Optional[str] = None
    tenant_context_id: Optional[str] = None
    service_instance_id: Optional[str] = None
    allocation_id: Optional[str] = None
    tenant_listener_port: Optional[int] = None
    tenant_media_port_start: Optional[int] = None
    tenant_media_port_end: Optional[int] = None
    pbx_media_destination_port_start: Optional[int] = None
    pbx_media_destination_port_end: Optional[int] = None
    cluster_media_port_start: Optional[int] = None
    cluster_media_port_end: Optional[int] = None
    expected_advertised_public_ip: Optional[str] = None
    authorized_pbx_source_cidrs: Tuple[str, ...] = ()
    authorized_microsoft_source_cidrs: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.scope not in {"CLUSTER", "TENANT"}:
            raise ValueError("scope must be CLUSTER or TENANT")
        _require_identifier(self.cluster_id, "cluster_id")
        _require_identifier(self.node_id, "node_id")
        if isinstance(self.generation, bool) or not isinstance(self.generation, int):
            raise ValueError("generation must be an integer >= 1")
        if self.generation < 1:
            raise ValueError("generation must be an integer >= 1")
        if self.slot not in {"A", "B"}:
            raise ValueError("slot must be A or B")

        tenant_values = (
            self.customer_account_id,
            self.m365_tenant_id,
            self.tenant_context_id,
            self.service_instance_id,
            self.allocation_id,
        )
        allocation_values = (
            self.tenant_listener_port,
            self.tenant_media_port_start,
            self.tenant_media_port_end,
            self.pbx_media_destination_port_start,
            self.pbx_media_destination_port_end,
            self.cluster_media_port_start,
            self.cluster_media_port_end,
        )
        if self.scope == "CLUSTER":
            if any(value is not None for value in tenant_values + allocation_values):
                raise ValueError(
                    "CLUSTER context must not contain tenant identity or allocation"
                )
            if self.expected_advertised_public_ip is not None or self.authorized_pbx_source_cidrs:
                raise ValueError(
                    "CLUSTER context must not contain tenant network authority"
                )
            _require_authorized_ipv4_networks(
                self.authorized_microsoft_source_cidrs,
                "authorized_microsoft_source_cidrs",
                minimum_prefix_length=MIN_MICROSOFT_SOURCE_PREFIX_LENGTH,
                require_global=True,
            )
            return


        if self.authorized_microsoft_source_cidrs:
            raise ValueError(
                "TENANT context must not contain cluster Microsoft network authority"
            )

        names_and_values = (
            ("customer_account_id", self.customer_account_id),
            ("tenant_context_id", self.tenant_context_id),
            ("service_instance_id", self.service_instance_id),
            ("allocation_id", self.allocation_id),
        )
        for name, value in names_and_values:
            _require_identifier(value, name)
        if (
            not isinstance(self.m365_tenant_id, str)
            or manifest_tool.M365_TENANT_RE.fullmatch(self.m365_tenant_id) is None
        ):
            raise ValueError("m365_tenant_id must be a lowercase RFC 4122 UUID")

        allocation_names_and_values = (
            ("tenant_listener_port", self.tenant_listener_port),
            ("tenant_media_port_start", self.tenant_media_port_start),
            ("tenant_media_port_end", self.tenant_media_port_end),
            (
                "pbx_media_destination_port_start",
                self.pbx_media_destination_port_start,
            ),
            ("pbx_media_destination_port_end", self.pbx_media_destination_port_end),
            ("cluster_media_port_start", self.cluster_media_port_start),
            ("cluster_media_port_end", self.cluster_media_port_end),
        )
        for name, value in allocation_names_and_values:
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1024 <= value <= 65535
            ):
                raise ValueError(
                    "{} must be an integer from 1024 through 65535".format(name)
                )
        if self.tenant_listener_port == 5061:
            raise ValueError(
                "tenant listener port 5061 is reserved for the shared Teams listener"
            )
        if self.tenant_media_port_start % 2 != 0 or self.tenant_media_port_end % 2 != 1:
            raise ValueError("tenant media allocation must start even and end odd")
        if self.cluster_media_port_start % 2 != 0 or self.cluster_media_port_end % 2 != 1:
            raise ValueError("cluster media pool must start even and end odd")
        if self.tenant_media_port_start > self.tenant_media_port_end:
            raise ValueError("tenant media allocation start must not exceed its end")
        if (
            self.pbx_media_destination_port_start % 2 != 0
            or self.pbx_media_destination_port_end % 2 != 1
            or self.pbx_media_destination_port_start
            > self.pbx_media_destination_port_end
        ):
            raise ValueError(
                "PBX media destination range must start even, end odd, and be ordered"
            )
        if (
            self.pbx_media_destination_port_end
            - self.pbx_media_destination_port_start
            + 1
            > MAX_PBX_MEDIA_DESTINATION_PORTS
        ):
            raise ValueError(
                "PBX media destination range must contain at most {} UDP ports".format(
                    MAX_PBX_MEDIA_DESTINATION_PORTS
                )
            )
        collisions = sorted(
            port
            for port in RESERVED_SIGNALING_AND_CONTROL_PORTS
            if self.pbx_media_destination_port_start
            <= port
            <= self.pbx_media_destination_port_end
        )
        if collisions:
            raise ValueError(
                "PBX media destination range collides with signaling/control ports {}".format(
                    collisions
                )
            )
        if self.cluster_media_port_start > self.cluster_media_port_end:
            raise ValueError("cluster media pool start must not exceed its end")
        if not (
            self.cluster_media_port_start
            <= self.tenant_media_port_start
            <= self.tenant_media_port_end
            <= self.cluster_media_port_end
        ):
            raise ValueError(
                "tenant media allocation must be contained in the cluster media pool"
            )
        _require_public_ipv4(
            self.expected_advertised_public_ip,
            "expected_advertised_public_ip",
        )
        _require_authorized_ipv4_networks(
            self.authorized_pbx_source_cidrs,
            "authorized_pbx_source_cidrs",
            minimum_prefix_length=MIN_PBX_SOURCE_PREFIX_LENGTH,
            require_global=False,
        )

    def target_identity_record(self) -> Dict[str, Any]:
        identity: Dict[str, Any] = {
            "clusterId": self.cluster_id,
            "generation": self.generation,
            "nodeId": self.node_id,
            "scope": self.scope,
            "slot": self.slot,
        }
        if self.scope == "TENANT":
            identity["tenant"] = {
                "allocationId": self.allocation_id,
                "customerAccountId": self.customer_account_id,
                "m365TenantId": self.m365_tenant_id,
                "serviceInstanceId": self.service_instance_id,
                "tenantContextId": self.tenant_context_id,
            }
        return identity

    def identity_record(self) -> Dict[str, Any]:
        identity = self.target_identity_record()
        if self.scope == "TENANT":
            identity["tenantAllocation"] = {
                "clusterMediaPortEnd": self.cluster_media_port_end,
                "clusterMediaPortStart": self.cluster_media_port_start,
                "listenerPort": self.tenant_listener_port,
                "mediaPortEnd": self.tenant_media_port_end,
                "mediaPortStart": self.tenant_media_port_start,
                "pbxMediaDestinationPortEnd": self.pbx_media_destination_port_end,
                "pbxMediaDestinationPortStart": self.pbx_media_destination_port_start,
            }
            identity["tenantNetworkAuthority"] = {
                "advertisedPublicIpv4": self.expected_advertised_public_ip,
                "authorizedPbxSourceCidrs": list(self.authorized_pbx_source_cidrs),
            }
        else:
            identity["clusterNetworkAuthority"] = {
                "authorizedMicrosoftSourceCidrs": list(
                    self.authorized_microsoft_source_cidrs
                ),
            }
        return identity


class PinnedKeyring:
    """Explicit immutable key-id allowlist containing raw Ed25519 public keys."""

    def __init__(self, keys: Mapping[str, bytes]):
        if not keys:
            raise ValueError("at least one pinned signing key is required")
        checked: Dict[str, bytes] = {}
        for key_id, public_bytes in keys.items():
            _require_identifier(key_id, "pinned key id")
            if not isinstance(public_bytes, bytes) or len(public_bytes) != 32:
                raise ValueError(
                    "pinned key {!r} must contain exactly 32 raw Ed25519 public-key bytes".format(
                        key_id
                    )
                )
            checked[key_id] = bytes(public_bytes)
        self._keys: Mapping[str, bytes] = MappingProxyType(checked)

    @property
    def key_ids(self) -> Tuple[str, ...]:
        return tuple(sorted(self._keys))

    def get(self, key_id: object) -> Optional[bytes]:
        return self._keys.get(key_id) if isinstance(key_id, str) else None


def _sha256_digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _build_local_health_gate_plan(envelope: Mapping[str, Any]) -> Dict[str, Any]:
    """Bind the complete signed health-gate array to one manifest digest."""

    manifest = envelope.get("manifest")
    manifest_digest = envelope.get("manifestDigest")
    if not isinstance(manifest, Mapping) or not isinstance(
        manifest.get("healthGates"), list
    ):
        raise EnvelopeRejected("verified manifest does not contain health gates")
    if (
        not isinstance(manifest_digest, str)
        or manifest_tool.DIGEST_RE.fullmatch(manifest_digest) is None
    ):
        raise EnvelopeRejected("verified envelope manifest digest is invalid")
    return {
        "apiVersion": LOCAL_HEALTH_PLAN_API_VERSION,
        "healthGates": manifest["healthGates"],
        "kind": LOCAL_HEALTH_PLAN_KIND,
        "manifestDigest": manifest_digest,
    }


def _local_health_gate_plan_digest(plan: Mapping[str, Any]) -> str:
    try:
        canonical = manifest_tool.canonical_json_bytes(plan)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise EnvelopeRejected(
            "local health-gate plan is outside the canonical domain"
        ) from exc
    return _sha256_digest(canonical)


@dataclass(frozen=True)
class StageResult:
    manifest_digest: str
    manifest_id: str
    sequence: int
    local_health_gate_plan_digest: str
    verified_key_ids: Tuple[str, ...]

    def evidence(self) -> Dict[str, Any]:
        return {
            "localHealthGatePlanDigest": self.local_health_gate_plan_digest,
            "manifestDigest": self.manifest_digest,
            "manifestId": self.manifest_id,
            "sequence": self.sequence,
            "status": "VERIFIED_AND_STAGED_METADATA_ONLY",
            "verifiedKeyIds": list(self.verified_key_ids),
        }


@dataclass(frozen=True)
class CommitResult:
    manifest_digest: str
    sequence: int
    local_health_gate_plan_digest: str
    runtime_evidence_digest: str
    runtime_release_digest: str
    health_gates: Tuple[Mapping[str, Any], ...]

    def evidence(self) -> Dict[str, Any]:
        return {
            "activeManifestDigest": self.manifest_digest,
            "activeSequence": self.sequence,
            "healthGates": [
                {
                    "attemptsUsed": result["attemptsUsed"],
                    "gateId": result["gateId"],
                    "proofs": [dict(proof) for proof in result["proofs"]],
                    "status": result["status"],
                    "type": result["type"],
                }
                for result in self.health_gates
            ],
            "localHealthGatePlanDigest": self.local_health_gate_plan_digest,
            "runtimeEvidenceDigest": self.runtime_evidence_digest,
            "runtimeReleaseDigest": self.runtime_release_digest,
            "status": "PENDING_COMMITTED_AFTER_SIGNED_LOCAL_HEALTH",
        }


@dataclass(frozen=True)
class AbortResult:
    manifest_digest: str
    sequence: int

    def evidence(self) -> Dict[str, Any]:
        return {
            "abortedManifestDigest": self.manifest_digest,
            "abortedSequence": self.sequence,
            "status": "PENDING_ABORTED_ACTIVE_LKG_PRESERVED",
        }


def parse_envelope_bytes(raw: bytes) -> Dict[str, Any]:
    """Use the schema tool's duplicate-safe parser for a bounded UTF-8 input."""

    if not isinstance(raw, bytes):
        raise EnvelopeRejected("envelope input must be bytes")
    if not raw:
        raise EnvelopeRejected("envelope input is empty")
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise EnvelopeRejected("envelope exceeds the {} byte limit".format(MAX_ENVELOPE_BYTES))
    try:
        parsed = manifest_tool.parse_json_text(raw.decode("utf-8"))
    except (
        UnicodeError,
        json.JSONDecodeError,
        manifest_tool.DuplicateKeyError,
        RecursionError,
        ValueError,
    ) as exc:
        raise EnvelopeRejected("invalid duplicate-safe UTF-8 JSON: {}".format(exc)) from exc
    if not isinstance(parsed, dict):
        raise EnvelopeRejected("envelope must be a JSON object")
    return parsed


def _jsonschema_types():
    try:
        from jsonschema import Draft202012Validator, FormatChecker
        from jsonschema.exceptions import SchemaError
    except Exception as exc:
        raise DependencyUnavailable(
            "Draft 2020-12 structural validation requires Debian package "
            "python3-jsonschema and a loadable dependency set"
        ) from exc
    return Draft202012Validator, FormatChecker, SchemaError


def _load_checked_in_schema() -> Dict[str, Any]:
    try:
        raw = DESIRED_STATE_SCHEMA_PATH.read_bytes()
    except OSError as exc:
        raise SchemaValidationUnavailable(
            "checked-in desired-state schema is unavailable: {}".format(exc)
        ) from exc
    if not raw or len(raw) > MAX_SCHEMA_BYTES:
        raise SchemaValidationUnavailable(
            "checked-in desired-state schema is empty or exceeds the protected size limit"
        )
    try:
        parsed = manifest_tool.parse_json_text(raw.decode("utf-8"))
    except (
        UnicodeError,
        json.JSONDecodeError,
        manifest_tool.DuplicateKeyError,
        RecursionError,
        ValueError,
    ) as exc:
        raise SchemaValidationUnavailable(
            "checked-in desired-state schema is invalid duplicate-safe UTF-8 JSON: {}".format(
                exc
            )
        ) from exc
    if not isinstance(parsed, dict):
        raise SchemaValidationUnavailable(
            "checked-in desired-state schema must be a JSON object"
        )
    if parsed.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise SchemaValidationUnavailable(
            "checked-in desired-state schema does not declare Draft 2020-12"
        )
    if parsed.get("$id") != EXPECTED_SCHEMA_ID:
        raise SchemaValidationUnavailable(
            "checked-in desired-state schema has an unexpected contract identifier"
        )
    return parsed


def _schema_error_location(error: Any) -> str:
    path = "$"
    for component in error.absolute_path:
        if isinstance(component, int):
            path += "[{}]".format(component)
        else:
            path += ".{}".format(component)
    return path


def validate_structural_envelope(envelope: Mapping[str, Any]) -> None:
    """Fail closed unless the envelope passes the checked-in Draft 2020-12 schema."""

    Draft202012Validator, FormatChecker, SchemaError = _jsonschema_types()
    schema = _load_checked_in_schema()
    try:
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        )
        errors = sorted(
            validator.iter_errors(envelope),
            key=lambda error: (
                tuple(str(component) for component in error.absolute_path),
                error.message,
            ),
        )
    except SchemaError as exc:
        raise SchemaValidationUnavailable(
            "checked-in desired-state schema fails Draft 2020-12 meta-validation: {}".format(
                exc
            )
        ) from exc
    except Exception as exc:
        raise SchemaValidationUnavailable(
            "checked-in desired-state schema could not be evaluated safely: {}".format(
                exc
            )
        ) from exc
    if errors:
        rendered = [
            "{}: {}".format(_schema_error_location(error), error.message)
            for error in errors[:16]
        ]
        if len(errors) > len(rendered):
            rendered.append(
                "$: {} additional structural errors omitted".format(
                    len(errors) - len(rendered)
                )
            )
        raise EnvelopeRejected(
            "Draft 2020-12 structural validation failed: {}".format(
                "; ".join(rendered)
            )
        )


def _cryptography_types():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise DependencyUnavailable(
            "Ed25519 verification requires Debian package python3-cryptography"
        ) from exc
    return Ed25519PublicKey, InvalidSignature


def verify_authorized_signatures(
    envelope: Mapping[str, Any], keyring: PinnedKeyring
) -> Tuple[str, ...]:
    """Return authorized key IDs whose Ed25519 signature verifies."""

    manifest = envelope.get("manifest")
    signatures = envelope.get("signatures")
    if not isinstance(manifest, dict) or not isinstance(signatures, list):
        raise SignatureVerificationError("envelope lacks a manifest or signature list")

    try:
        signed_bytes = SIGNED_BYTES_PREFIX + manifest_tool.canonical_json_bytes(manifest)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise SignatureVerificationError(
            "manifest cannot be canonicalized: {}".format(exc)
        ) from exc

    Ed25519PublicKey, InvalidSignature = _cryptography_types()
    verified = []
    for signature in signatures:
        if not isinstance(signature, dict) or signature.get("algorithm") != "Ed25519":
            continue
        key_id = signature.get("keyId")
        public_bytes = keyring.get(key_id)
        if public_bytes is None:
            continue
        encoded = signature.get("value")
        if not isinstance(encoded, str):
            continue
        try:
            signature_bytes = base64.b64decode(encoded, validate=True)
            if len(signature_bytes) != 64:
                continue
            public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
            public_key.verify(signature_bytes, signed_bytes)
        except (binascii.Error, ValueError, InvalidSignature):
            continue
        if isinstance(key_id, str):
            verified.append(key_id)

    result = tuple(sorted(set(verified)))
    if not result:
        raise SignatureVerificationError(
            "no Ed25519 signature verified against the explicit pinned key-id allowlist"
        )
    return result


def _secure_flags(*flags: int) -> int:
    value = 0
    for flag in flags:
        value |= flag
    value |= getattr(os, "O_CLOEXEC", 0)
    return value


def _assert_secure_directory(fd: int, display_path: Path) -> None:
    metadata = os.fstat(fd)
    if not stat.S_ISDIR(metadata.st_mode):
        raise StateSecurityError("state path is not a directory: {}".format(display_path))
    if metadata.st_uid != os.geteuid():
        raise StateSecurityError("state directory is not owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise StateSecurityError("state directory must not be group/world writable")


def _open_directory_without_symlinks(path: Path) -> int:
    """Open an absolute directory one component at a time without following links."""

    pure = PurePath(path)
    if not pure.is_absolute():
        raise StateSecurityError("state directory must be an absolute path")
    parts = pure.parts
    if any(part in {".", "..", ""} for part in parts[1:]):
        raise StateSecurityError("state directory must not contain traversal components")

    directory_flags = _secure_flags(os.O_RDONLY, getattr(os, "O_DIRECTORY", 0))
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise StateSecurityError("this platform does not provide O_NOFOLLOW")
    current_fd = os.open(parts[0], directory_flags)
    try:
        for component in parts[1:]:
            try:
                next_fd = os.open(
                    component,
                    directory_flags | nofollow,
                    dir_fd=current_fd,
                )
            except OSError as exc:
                raise StateSecurityError(
                    "cannot securely open state directory component {!r}: {}".format(
                        component, exc
                    )
                ) from exc
            os.close(current_fd)
            current_fd = next_fd
        _assert_secure_directory(current_fd, path)
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _assert_protected_regular_file(fd: int, label: str) -> None:
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode):
        raise StateSecurityError("{} must be a regular file".format(label))
    if metadata.st_uid != os.geteuid():
        raise StateSecurityError("{} is not owned by the current user".format(label))
    if metadata.st_nlink != 1:
        raise StateSecurityError("{} must not have hard links".format(label))
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise StateSecurityError("{} permissions must be no broader than 0600".format(label))


def _read_all(fd: int, maximum: int, label: str) -> bytes:
    chunks = []
    total = 0
    while True:
        chunk = os.read(fd, min(65536, maximum + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise StateCorruptionError("{} exceeds the protected size limit".format(label))


def _write_all(fd: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write while staging protected state")
        view = view[written:]


class StateStore:
    """Protected, inode-stable locked state store rooted at one fixed directory."""

    STATE_FILE = "edge-state-v3.json"
    PREVIOUS_STATE_FILE = "edge-state-v2.json"
    LEGACY_STATE_FILE = "accepted-state-v1.json"
    LOCK_FILE = "edge-state.lock"
    TEMP_PREFIX = ".edge-state-v3.tmp."

    def __init__(self, state_directory: Path):
        self.state_directory = Path(state_directory)

    @contextmanager
    def locked_directory(self) -> Iterator[int]:
        directory_fd = _open_directory_without_symlinks(self.state_directory)
        lock_fd: Optional[int] = None
        try:
            last_error: Optional[OSError] = None
            # APFS can transiently report ENOENT to one of two simultaneous
            # O_CREAT|O_NOFOLLOW openat calls. The fixed directory fd remains
            # valid, so a short bounded retry is safe and avoids weakening the
            # symlink policy.
            for _ in range(8):
                try:
                    lock_fd = os.open(
                        self.LOCK_FILE,
                        _secure_flags(os.O_RDWR, os.O_CREAT, os.O_NOFOLLOW),
                        0o600,
                        dir_fd=directory_fd,
                    )
                    break
                except OSError as exc:
                    last_error = exc
                    if exc.errno != errno.ENOENT:
                        break
            if lock_fd is None:
                raise StateSecurityError(
                    "cannot securely open state lock: {}".format(last_error)
                ) from last_error
            _assert_protected_regular_file(lock_fd, "state lock")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield directory_fd
        finally:
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)
            os.close(directory_fd)

    def load_locked(
        self, directory_fd: int, local_context: LocalContext
    ) -> Optional[Dict[str, Any]]:
        for previous_filename in (self.PREVIOUS_STATE_FILE, self.LEGACY_STATE_FILE):
            previous = self._read_named_state(
                directory_fd, previous_filename, required=False
            )
            if previous is not None:
                # Decode first so a real prior file produces the precise unsafe-format
                # explanation and corrupt legacy material is never silently ignored.
                self._decode_state(previous, local_context)
                raise StateVersionError(
                    "previous state filename is present; reviewed migration is required"
                )
        raw = self._read_named_state(directory_fd, self.STATE_FILE, required=False)
        if raw is None:
            return None
        return self._decode_state(raw, local_context)

    @staticmethod
    def _read_named_state(
        directory_fd: int,
        filename: str,
        *,
        required: bool,
    ) -> Optional[bytes]:
        try:
            state_fd = os.open(
                filename,
                _secure_flags(os.O_RDONLY, os.O_NOFOLLOW, getattr(os, "O_NONBLOCK", 0)),
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            if required:
                raise StateCorruptionError("required protected state is missing")
            return None
        except OSError as exc:
            raise StateSecurityError(
                "cannot securely open protected state: {}".format(exc)
            ) from exc

        try:
            _assert_protected_regular_file(state_fd, "protected state")
            raw = _read_all(state_fd, MAX_STATE_BYTES, "protected state")
        finally:
            os.close(state_fd)
        return raw

    def _decode_state(self, raw: bytes, local_context: LocalContext) -> Dict[str, Any]:
        if not raw:
            raise StateCorruptionError("protected state is empty")
        try:
            state_value = manifest_tool.parse_json_text(raw.decode("utf-8"))
        except (
            UnicodeError,
            json.JSONDecodeError,
            manifest_tool.DuplicateKeyError,
            RecursionError,
            ValueError,
        ) as exc:
            raise StateCorruptionError("protected state is invalid JSON: {}".format(exc)) from exc
        if not isinstance(state_value, dict):
            raise StateCorruptionError("protected state must be a JSON object")
        try:
            canonical = manifest_tool.canonical_json_bytes(state_value)
        except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
            raise StateCorruptionError("protected state is outside the canonical domain") from exc
        if raw != canonical:
            raise StateCorruptionError("protected state is not in canonical byte form")
        self._validate_state_value(state_value, local_context)
        return state_value

    @staticmethod
    def _validate_state_value(state_value: Dict[str, Any], local_context: LocalContext) -> None:
        version = state_value.get("formatVersion")
        if type(version) is not int:
            raise StateCorruptionError("unsupported protected state format version")
        if version == 1:
            raise StateVersionError(
                "protected state v1 conflates staged and active metadata; automatic "
                "migration is refused"
            )
        if version == 2:
            raise StateVersionError(
                "protected state v2 lacks a signed local-health plan binding; "
                "reviewed migration is required"
            )
        if version != STATE_FORMAT_VERSION:
            raise StateVersionError("unsupported protected state format version")
        required = {
            "activeLastKnownGood",
            "formatVersion",
            "highestSeenSequence",
            "identity",
            "lastAbortedCandidate",
            "pendingCandidate",
        }
        if set(state_value) != required:
            raise StateCorruptionError("protected state has missing or unknown members")
        identity = state_value.get("identity")
        expected_identity = local_context.identity_record()
        if (
            not isinstance(identity, dict)
            or manifest_tool.canonical_json_bytes(identity)
            != manifest_tool.canonical_json_bytes(expected_identity)
        ):
            raise StateSecurityError(
                "protected state identity does not match immutable local context"
            )
        highest_seen = state_value.get("highestSeenSequence")
        if (
            isinstance(highest_seen, bool)
            or not isinstance(highest_seen, int)
            or highest_seen < 1
        ):
            raise StateCorruptionError("protected highest-seen sequence is invalid")

        active = StateStore._validate_candidate_metadata(
            state_value.get("activeLastKnownGood"),
            "active last-known-good",
            local_context,
        )
        pending = StateStore._validate_candidate_metadata(
            state_value.get("pendingCandidate"),
            "pending candidate",
            local_context,
        )
        last_aborted = StateStore._validate_candidate_tombstone(
            state_value.get("lastAbortedCandidate"),
            "last aborted candidate",
        )
        if active is not None and active["sequence"] > highest_seen:
            raise StateCorruptionError("active sequence exceeds protected highest-seen")
        if last_aborted is not None:
            if last_aborted["sequence"] > highest_seen:
                raise StateCorruptionError(
                    "last aborted sequence exceeds protected highest-seen"
                )
            if active is not None and last_aborted["sequence"] == active["sequence"]:
                raise StateCorruptionError(
                    "one sequence cannot be both active and last aborted"
                )
        if pending is not None:
            if pending["sequence"] != highest_seen:
                raise StateCorruptionError(
                    "pending sequence must equal protected highest-seen"
                )
            if active is not None and pending["sequence"] <= active["sequence"]:
                raise StateCorruptionError("pending sequence must be above active LKG")
            if (
                last_aborted is not None
                and pending["sequence"] <= last_aborted["sequence"]
            ):
                raise StateCorruptionError(
                    "pending sequence must be above the last aborted candidate"
                )

        lifecycle_sequences = [
            candidate["sequence"]
            for candidate in (active, pending, last_aborted)
            if candidate is not None
        ]
        if not lifecycle_sequences or max(lifecycle_sequences) != highest_seen:
            raise StateCorruptionError(
                "protected highest-seen is not bound to active, pending, or aborted metadata"
            )

    @staticmethod
    def _validate_candidate_tombstone(
        value: Any,
        label: str,
    ) -> Optional[Dict[str, Any]]:
        if value is None:
            return None
        fields = {"manifestDigest", "sequence"}
        if not isinstance(value, dict) or set(value) != fields:
            raise StateCorruptionError(
                "{} tombstone has missing or unknown members".format(label)
            )
        if type(value.get("sequence")) is not int or value["sequence"] < 1:
            raise StateCorruptionError("{} sequence is invalid".format(label))
        if (
            not isinstance(value.get("manifestDigest"), str)
            or manifest_tool.DIGEST_RE.fullmatch(value["manifestDigest"]) is None
        ):
            raise StateCorruptionError(
                "{} manifest digest is invalid".format(label)
            )
        return value

    @staticmethod
    def _validate_candidate_metadata(
        value: Any,
        label: str,
        local_context: LocalContext,
    ) -> Optional[Dict[str, Any]]:
        if value is None:
            return None
        fields = {
            "artifactDigests",
            "expiresAt",
            "issuedAt",
            "localHealthGatePlanDigest",
            "manifestDigest",
            "manifestId",
            "sequence",
            "slot",
            "verifiedKeyIds",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise StateCorruptionError(
                "{} metadata has missing or unknown members".format(label)
            )
        if type(value.get("sequence")) is not int or value["sequence"] < 1:
            raise StateCorruptionError("{} sequence is invalid".format(label))
        if not _is_identifier(value.get("manifestId")):
            raise StateCorruptionError("{} manifestId is invalid".format(label))
        if (
            not isinstance(value.get("manifestDigest"), str)
            or manifest_tool.DIGEST_RE.fullmatch(value["manifestDigest"]) is None
        ):
            raise StateCorruptionError("{} digest is invalid".format(label))
        if (
            not isinstance(value.get("localHealthGatePlanDigest"), str)
            or manifest_tool.DIGEST_RE.fullmatch(
                value["localHealthGatePlanDigest"]
            )
            is None
        ):
            raise StateCorruptionError(
                "{} local health-gate plan digest is invalid".format(label)
            )
        if value.get("slot") != local_context.slot:
            raise StateCorruptionError("{} slot does not match local identity".format(label))
        timestamps = {}
        for field in ("issuedAt", "expiresAt"):
            errors = []
            parsed = manifest_tool.parse_utc_timestamp(value.get(field), field, errors)
            if parsed is None:
                raise StateCorruptionError("{} {} is invalid".format(label, field))
            timestamps[field] = parsed
        if timestamps["expiresAt"] <= timestamps["issuedAt"]:
            raise StateCorruptionError("{} expiry is not after issue time".format(label))
        for field, maximum, validator in (
            (
                "artifactDigests",
                64,
                lambda item: isinstance(item, str)
                and manifest_tool.DIGEST_RE.fullmatch(item),
            ),
            ("verifiedKeyIds", 4, _is_identifier),
        ):
            values = value.get(field)
            if (
                not isinstance(values, list)
                or not values
                or len(values) > maximum
                or any(not validator(item) for item in values)
                or values != sorted(set(values))
            ):
                raise StateCorruptionError(
                    "{} {} must be a non-empty sorted unique list".format(label, field)
                )
        return value

    def write_locked(self, directory_fd: int, state_value: Dict[str, Any]) -> None:
        content = manifest_tool.canonical_json_bytes(state_value)
        if len(content) > MAX_STATE_BYTES:
            raise StateCorruptionError("new protected state exceeds the size limit")
        temp_name = "{}{}.{}".format(
            self.TEMP_PREFIX,
            os.getpid(),
            secrets.token_hex(12),
        )
        temp_fd: Optional[int] = None
        renamed = False
        try:
            temp_fd = os.open(
                temp_name,
                _secure_flags(os.O_WRONLY, os.O_CREAT, os.O_EXCL, os.O_NOFOLLOW),
                0o600,
                dir_fd=directory_fd,
            )
            _assert_protected_regular_file(temp_fd, "temporary protected state")
            _write_all(temp_fd, content)
            os.fsync(temp_fd)
            os.close(temp_fd)
            temp_fd = None
            os.replace(
                temp_name,
                self.STATE_FILE,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            renamed = True
            os.fsync(directory_fd)
        finally:
            if temp_fd is not None:
                os.close(temp_fd)
            if not renamed:
                try:
                    os.unlink(temp_name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass


def _validation_context(
    local_context: LocalContext,
    accepted_sequence: int,
    accepted_digest: Optional[str],
    now: datetime,
) -> manifest_tool.ValidationContext:
    values: Dict[str, Any] = {
        "expected_cluster_id": local_context.cluster_id,
        "expected_node_id": local_context.node_id,
        "expected_generation": local_context.generation,
        "accepted_sequence": accepted_sequence,
        "accepted_digest": accepted_digest,
        "now": now,
        "expected_tenant_context_id": local_context.tenant_context_id,
        "expected_allocation_id": local_context.allocation_id,
        "expected_tenant_listener_port": local_context.tenant_listener_port,
        "expected_media_port_start": local_context.tenant_media_port_start,
        "expected_media_port_end": local_context.tenant_media_port_end,
        "expected_pbx_media_destination_port_start": (
            local_context.pbx_media_destination_port_start
        ),
        "expected_pbx_media_destination_port_end": (
            local_context.pbx_media_destination_port_end
        ),
        "expected_advertised_public_ip": local_context.expected_advertised_public_ip,
        "authorized_pbx_source_cidrs": local_context.authorized_pbx_source_cidrs,
        "authorized_microsoft_source_cidrs": (
            local_context.authorized_microsoft_source_cidrs
        ),
    }
    return manifest_tool.ValidationContext(**values)


def _enforce_exact_local_identity(envelope: Mapping[str, Any], local_context: LocalContext) -> None:
    manifest = envelope.get("manifest")
    target = manifest.get("target") if isinstance(manifest, dict) else None
    if not isinstance(target, dict):
        raise EnvelopeRejected("manifest target is missing")
    expected = local_context.target_identity_record()
    actual: Dict[str, Any] = {
        "clusterId": target.get("clusterId"),
        "generation": target.get("generation"),
        "nodeId": target.get("nodeId"),
        "scope": target.get("scope"),
        "slot": target.get("slot"),
    }
    if target.get("scope") == "TENANT":
        actual["tenant"] = target.get("tenant")
    if actual != expected:
        raise EnvelopeRejected("manifest target does not equal immutable local context")


def _enforce_local_network_allocation(
    envelope: Mapping[str, Any], local_context: LocalContext
) -> None:
    if local_context.scope != "TENANT":
        return
    manifest = envelope.get("manifest")
    if not isinstance(manifest, dict) or manifest.get("lifecycle") != "ACTIVE":
        return
    resource_set = manifest.get("resourceSet") if isinstance(manifest, dict) else None
    resources = resource_set.get("resources") if isinstance(resource_set, dict) else None
    if not isinstance(resources, list):
        raise EnvelopeRejected("tenant manifest has no resource inventory")

    listeners = [
        resource
        for resource in resources
        if isinstance(resource, dict) and resource.get("type") == "tenant.listener"
    ]
    media_resources = [
        resource
        for resource in resources
        if isinstance(resource, dict) and resource.get("type") == "tenant.media"
    ]
    connectors = [
        resource
        for resource in resources
        if isinstance(resource, dict) and resource.get("type") == "tenant.connector"
    ]
    if len(listeners) != 1:
        raise EnvelopeRejected("tenant manifest must contain exactly one authorized listener")
    if len(media_resources) != 1:
        raise EnvelopeRejected(
            "tenant manifest must contain exactly one authorized media allocation"
        )
    if len(connectors) != 1:
        raise EnvelopeRejected(
            "tenant manifest must contain exactly one authorized PBX connector"
        )

    listener_spec = listeners[0].get("spec")
    listener_port = listener_spec.get("port") if isinstance(listener_spec, dict) else None
    if listener_port == 5061:
        raise EnvelopeRejected("tenant manifest cannot claim shared Teams listener port 5061")
    if listener_port != local_context.tenant_listener_port:
        raise EnvelopeRejected("tenant listener port does not match local authorized allocation")

    media_spec = media_resources[0].get("spec")
    media_start = media_spec.get("portStart") if isinstance(media_spec, dict) else None
    media_end = media_spec.get("portEnd") if isinstance(media_spec, dict) else None
    if (
        media_start != local_context.tenant_media_port_start
        or media_end != local_context.tenant_media_port_end
    ):
        raise EnvelopeRejected("tenant media ports do not match local authorized allocation")
    if not (
        local_context.cluster_media_port_start
        <= media_start
        <= media_end
        <= local_context.cluster_media_port_end
    ):
        raise EnvelopeRejected("tenant media ports are outside the local cluster media pool")

    connector_spec = connectors[0].get("spec")
    pbx_media_start = (
        connector_spec.get("mediaDestinationPortStart")
        if isinstance(connector_spec, dict)
        else None
    )
    pbx_media_end = (
        connector_spec.get("mediaDestinationPortEnd")
        if isinstance(connector_spec, dict)
        else None
    )
    if (
        pbx_media_start != local_context.pbx_media_destination_port_start
        or pbx_media_end != local_context.pbx_media_destination_port_end
    ):
        raise EnvelopeRejected(
            "PBX media destination range does not match local authorized allocation"
        )


def _enforce_lkg_artifact_lineage(
    envelope: Mapping[str, Any], active_lkg: Optional[Mapping[str, Any]]
) -> None:
    if active_lkg is None:
        return
    manifest = envelope.get("manifest")
    rollback = manifest.get("rollbackTarget") if isinstance(manifest, dict) else None
    if not isinstance(rollback, dict):
        raise EnvelopeRejected("non-initial manifest must contain rollback metadata")
    actual = rollback.get("artifactDigests")
    expected = active_lkg["artifactDigests"]
    if not isinstance(actual, list) or sorted(actual) != expected:
        raise EnvelopeRejected(
            "rollback artifact digests do not match protected last-known-good metadata"
        )


def _candidate_for_envelope(
    envelope: Mapping[str, Any],
    verified_key_ids: Sequence[str],
) -> Dict[str, Any]:
    manifest = envelope["manifest"]
    target = manifest["target"]
    artifacts = manifest["resourceSet"]["artifacts"]
    local_health_plan = _build_local_health_gate_plan(envelope)
    return {
        "artifactDigests": sorted({artifact["sha256"] for artifact in artifacts}),
        "expiresAt": manifest["expiresAt"],
        "issuedAt": manifest["issuedAt"],
        "localHealthGatePlanDigest": _local_health_gate_plan_digest(
            local_health_plan
        ),
        "manifestDigest": envelope["manifestDigest"],
        "manifestId": manifest["manifestId"],
        "sequence": manifest["sequence"],
        "slot": target["slot"],
        "verifiedKeyIds": sorted(set(verified_key_ids)),
    }


def _state_with_pending(
    candidate: Dict[str, Any],
    local_context: LocalContext,
    prior_state: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    active = None if prior_state is None else prior_state["activeLastKnownGood"]
    last_aborted = None if prior_state is None else prior_state["lastAbortedCandidate"]
    return {
        "activeLastKnownGood": active,
        "formatVersion": STATE_FORMAT_VERSION,
        "highestSeenSequence": candidate["sequence"],
        "identity": local_context.identity_record(),
        "lastAbortedCandidate": last_aborted,
        "pendingCandidate": candidate,
    }


def _require_exact_pending(
    state_value: Mapping[str, Any],
    sequence: int,
    manifest_digest: str,
) -> Dict[str, Any]:
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise ValueError("sequence must be an integer >= 1")
    if (
        not isinstance(manifest_digest, str)
        or manifest_tool.DIGEST_RE.fullmatch(manifest_digest) is None
    ):
        raise ValueError("manifest_digest must be a lowercase sha256 digest")
    pending = state_value.get("pendingCandidate")
    if not isinstance(pending, dict):
        raise StateLifecycleError("there is no pending candidate")
    if pending["sequence"] != sequence or pending["manifestDigest"] != manifest_digest:
        raise StateLifecycleError(
            "requested sequence/digest does not identify the exact pending candidate"
        )
    return pending


def _candidate_status(value: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    if value is None:
        return None
    return {
        "manifestDigest": value["manifestDigest"],
        "sequence": value["sequence"],
    }


def inspect_protected_state(
    *,
    local_context: LocalContext,
    state_directory: Path,
) -> Dict[str, Any]:
    """Return a canonical, non-secret summary of fully validated protected state."""

    store = StateStore(state_directory)
    with store.locked_directory() as directory_fd:
        state_value = store.load_locked(directory_fd, local_context)
        if state_value is None:
            raise StateLifecycleError("protected state does not exist")
        return {
            "activeLastKnownGood": _candidate_status(
                state_value["activeLastKnownGood"]
            ),
            "apiVersion": AGENT_STATUS_API_VERSION,
            "highestSeenSequence": state_value["highestSeenSequence"],
            "kind": "EdgeAgentProtectedStateStatus",
            "lastAbortedCandidate": state_value["lastAbortedCandidate"],
            "pendingCandidate": _candidate_status(state_value["pendingCandidate"]),
        }


def verify_and_stage(
    envelope_bytes: bytes,
    *,
    local_context: LocalContext,
    keyring: PinnedKeyring,
    state_directory: Path,
    now: Optional[datetime] = None,
) -> StageResult:
    """Verify one envelope and atomically advance metadata under an exclusive lock."""

    envelope = parse_envelope_bytes(envelope_bytes)
    validate_structural_envelope(envelope)
    effective_now = now if now is not None else datetime.now(timezone.utc)
    if effective_now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    effective_now = effective_now.astimezone(timezone.utc)
    store = StateStore(state_directory)

    with store.locked_directory() as directory_fd:
        state_value = store.load_locked(directory_fd, local_context)
        if state_value is None:
            highest_seen = 0
            active_lkg = None
            pending = None
        else:
            highest_seen = state_value["highestSeenSequence"]
            active_lkg = state_value["activeLastKnownGood"]
            pending = state_value["pendingCandidate"]

        manifest = envelope.get("manifest")
        sequence = manifest.get("sequence") if isinstance(manifest, dict) else None
        if isinstance(sequence, int) and not isinstance(sequence, bool):
            if sequence <= highest_seen:
                raise EnvelopeRejected(
                    "replay/downgrade: {} is not above protected highest-seen {}".format(
                        sequence, highest_seen
                    )
                )
        if pending is not None:
            raise StateLifecycleError(
                "a pending candidate must be committed or aborted before another stage"
            )

        if active_lkg is None:
            accepted_sequence = 0
            accepted_digest = None
        else:
            accepted_sequence = active_lkg["sequence"]
            accepted_digest = active_lkg["manifestDigest"]

        try:
            manifest_tool.validate_envelope(
                envelope,
                _validation_context(
                    local_context,
                    accepted_sequence,
                    accepted_digest,
                    effective_now,
                ),
            )
        except manifest_tool.ContractError as exc:
            raise EnvelopeRejected("; ".join(exc.errors)) from exc
        except RecursionError as exc:
            raise EnvelopeRejected("manifest nesting exceeds the verifier limit") from exc
        if envelope["manifest"]["sequence"] <= highest_seen:
            raise EnvelopeRejected("manifest sequence does not exceed protected highest-seen")
        _enforce_exact_local_identity(envelope, local_context)
        _enforce_local_network_allocation(envelope, local_context)
        _enforce_lkg_artifact_lineage(envelope, active_lkg)
        verified_key_ids = verify_authorized_signatures(envelope, keyring)
        candidate = _candidate_for_envelope(envelope, verified_key_ids)
        new_state = _state_with_pending(candidate, local_context, state_value)
        store.write_locked(directory_fd, new_state)

    manifest = envelope["manifest"]
    return StageResult(
        manifest_digest=envelope["manifestDigest"],
        manifest_id=manifest["manifestId"],
        sequence=manifest["sequence"],
        local_health_gate_plan_digest=candidate[
            "localHealthGatePlanDigest"
        ],
        verified_key_ids=verified_key_ids,
    )


def _runtime_evidence_agent_gid() -> int:
    try:
        agent_gid = grp.getgrnam(RUNTIME_EVIDENCE_GROUP_NAME).gr_gid
    except KeyError as exc:
        raise StateSecurityError(
            "runtime evidence group {!r} does not exist".format(
                RUNTIME_EVIDENCE_GROUP_NAME
            )
        ) from exc
    if os.getegid() != agent_gid:
        raise StateSecurityError(
            "Agent process primary group does not own runtime evidence access"
        )
    return agent_gid


def _open_runtime_evidence_directory() -> Tuple[int, int]:
    """Open the one fixed evidence directory without following any symlink."""

    path = RUNTIME_EVIDENCE_DIRECTORY
    pure = PurePath(path)
    if not pure.is_absolute() or any(
        part in {".", "..", ""} for part in pure.parts[1:]
    ):
        raise StateSecurityError("fixed runtime evidence directory is invalid")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise StateSecurityError("this platform does not provide O_NOFOLLOW")
    directory_flags = _secure_flags(
        os.O_RDONLY, getattr(os, "O_DIRECTORY", 0)
    )
    current_fd = os.open(pure.parts[0], directory_flags)
    try:
        for component in pure.parts[1:]:
            try:
                next_fd = os.open(
                    component,
                    directory_flags | nofollow,
                    dir_fd=current_fd,
                )
            except OSError as exc:
                raise StateSecurityError(
                    "cannot securely open runtime evidence directory component "
                    "{!r}: {}".format(component, exc)
                ) from exc
            os.close(current_fd)
            current_fd = next_fd
        agent_gid = _runtime_evidence_agent_gid()
        metadata = os.fstat(current_fd)
        if not stat.S_ISDIR(metadata.st_mode):
            raise StateSecurityError("runtime evidence path is not a directory")
        if (
            metadata.st_uid != RUNTIME_EVIDENCE_ROOT_UID
            or metadata.st_gid != agent_gid
            or stat.S_IMODE(metadata.st_mode) != 0o750
        ):
            raise StateSecurityError(
                "runtime evidence directory must be root:vivolution-edge-agent 0750"
            )
        return current_fd, agent_gid
    except BaseException:
        os.close(current_fd)
        raise


def _runtime_evidence_filename(
    sequence: int, manifest_digest: str, runtime_evidence_digest: str
) -> str:
    if type(sequence) is not int or sequence < 1:
        raise ValueError("sequence must be an integer >= 1")
    for value, label in (
        (manifest_digest, "manifest_digest"),
        (runtime_evidence_digest, "runtime_evidence_digest"),
    ):
        if (
            not isinstance(value, str)
            or manifest_tool.DIGEST_RE.fullmatch(value) is None
        ):
            raise ValueError("{} must be a lowercase sha256 digest".format(label))
    return "{:016d}-{}-runtime-applied-healthy-{}.json".format(
        sequence,
        manifest_digest.split(":", 1)[1][:16],
        runtime_evidence_digest.split(":", 1)[1],
    )


def _read_runtime_evidence(
    *,
    sequence: int,
    manifest_digest: str,
    runtime_evidence_digest: str,
) -> bytes:
    filename = _runtime_evidence_filename(
        sequence, manifest_digest, runtime_evidence_digest
    )
    directory_fd, agent_gid = _open_runtime_evidence_directory()
    evidence_fd: Optional[int] = None
    try:
        evidence_fd = os.open(
            filename,
            _secure_flags(
                os.O_RDONLY,
                os.O_NOFOLLOW,
                getattr(os, "O_NONBLOCK", 0),
            ),
            dir_fd=directory_fd,
        )
        metadata = os.fstat(evidence_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise StateSecurityError("runtime evidence must be a regular file")
        if (
            metadata.st_uid != RUNTIME_EVIDENCE_ROOT_UID
            or metadata.st_gid != agent_gid
            or stat.S_IMODE(metadata.st_mode) != 0o440
        ):
            raise StateSecurityError(
                "runtime evidence must be root:vivolution-edge-agent 0440"
            )
        if metadata.st_nlink != 1:
            raise StateSecurityError("runtime evidence must have exactly one link")
        return _read_all(
            evidence_fd,
            MAX_RUNTIME_EVIDENCE_BYTES,
            "runtime evidence",
        )
    except FileNotFoundError as exc:
        raise StateLifecycleError(
            "the exact immutable runtime success evidence is unavailable"
        ) from exc
    except OSError as exc:
        raise StateSecurityError(
            "cannot securely open immutable runtime evidence: {}".format(exc)
        ) from exc
    finally:
        if evidence_fd is not None:
            os.close(evidence_fd)
        os.close(directory_fd)


def _validate_local_health_gate_plan(
    value: Any,
    *,
    local_context: LocalContext,
    expected_manifest_digest: str,
) -> Dict[str, Any]:
    if local_context.scope != "TENANT":
        raise StateLifecycleError(
            "signed local-health commit supports TENANT scope only"
        )
    fields = {"apiVersion", "healthGates", "kind", "manifestDigest"}
    if not isinstance(value, dict) or set(value) != fields:
        raise StateLifecycleError(
            "runtime local health-gate plan has missing or unknown members"
        )
    if (
        value["apiVersion"] != LOCAL_HEALTH_PLAN_API_VERSION
        or value["kind"] != LOCAL_HEALTH_PLAN_KIND
        or value["manifestDigest"] != expected_manifest_digest
    ):
        raise StateLifecycleError(
            "runtime local health-gate plan type or manifest identity is invalid"
        )
    raw_gates = value["healthGates"]
    if not isinstance(raw_gates, list) or len(raw_gates) != 3:
        raise StateLifecycleError(
            "runtime local health-gate plan must contain exactly three gates"
        )

    checked_gates = []
    seen_ids = set()
    seen_types = set()
    for raw_gate in raw_gates:
        if not isinstance(raw_gate, dict) or set(raw_gate) != LOCAL_HEALTH_GATE_FIELDS:
            raise StateLifecycleError(
                "runtime local health gate has missing or unknown members"
            )
        gate_id = raw_gate["gateId"]
        gate_type = raw_gate["type"]
        if not _is_identifier(gate_id) or gate_id in seen_ids:
            raise StateLifecycleError(
                "runtime local health gate id is invalid or duplicated"
            )
        if gate_type not in LOCAL_HEALTH_GATE_PARAMETERS or gate_type in seen_types:
            raise StateLifecycleError(
                "runtime local health gate type is forbidden or duplicated"
            )
        if (
            raw_gate["tenantContextId"] != local_context.tenant_context_id
            or raw_gate["allocationId"] != local_context.allocation_id
        ):
            raise StateLifecycleError(
                "runtime local health gate crosses immutable tenant identity"
            )
        refs = raw_gate["resourceRefs"]
        if (
            not isinstance(refs, list)
            or not refs
            or len(refs) > 64
            or any(not _is_identifier(ref) for ref in refs)
            or len(set(refs)) != len(refs)
        ):
            raise StateLifecycleError(
                "runtime local health gate resourceRefs are invalid"
            )
        expected_timeout, expected_attempts = LOCAL_HEALTH_GATE_PARAMETERS[gate_type]
        if (
            type(raw_gate["timeoutSeconds"]) is not int
            or raw_gate["timeoutSeconds"] != expected_timeout
            or type(raw_gate["maxAttempts"]) is not int
            or raw_gate["maxAttempts"] != expected_attempts
            or raw_gate["onFailure"] != "ROLLBACK_TO_TARGET"
        ):
            raise StateLifecycleError(
                "runtime local health gate parameters are unsupported"
            )
        seen_ids.add(gate_id)
        seen_types.add(gate_type)
        checked_gates.append(
            {
                "allocationId": raw_gate["allocationId"],
                "gateId": gate_id,
                "maxAttempts": expected_attempts,
                "onFailure": "ROLLBACK_TO_TARGET",
                "resourceRefs": list(refs),
                "tenantContextId": raw_gate["tenantContextId"],
                "timeoutSeconds": expected_timeout,
                "type": gate_type,
            }
        )
    if (
        seen_types != set(LOCAL_HEALTH_GATE_PARAMETERS)
        or tuple(gate["type"] for gate in checked_gates)
        != LOCAL_HEALTH_GATE_ORDER
    ):
        raise StateLifecycleError(
            "runtime local health-gate plan differs from the exact ordered local gate set"
        )
    return {
        "apiVersion": LOCAL_HEALTH_PLAN_API_VERSION,
        "healthGates": checked_gates,
        "kind": LOCAL_HEALTH_PLAN_KIND,
        "manifestDigest": expected_manifest_digest,
    }


def _validate_health_gate_results(
    value: Any, plan: Mapping[str, Any]
) -> Tuple[Mapping[str, Any], ...]:
    raw_gates = value
    plan_gates = plan["healthGates"]
    if not isinstance(raw_gates, list) or len(raw_gates) != len(plan_gates):
        raise StateLifecycleError(
            "runtime signed health-gate results differ from the signed plan"
        )
    checked = []
    result_fields = {"attemptsUsed", "gateId", "proofs", "status", "type"}
    proof_fields = {"name", "status"}
    for result, gate in zip(raw_gates, plan_gates):
        if not isinstance(result, dict) or set(result) != result_fields:
            raise StateLifecycleError(
                "runtime signed health-gate result has missing or unknown members"
            )
        if (
            result["gateId"] != gate["gateId"]
            or result["type"] != gate["type"]
            or result["status"] != "PASSED"
        ):
            raise StateLifecycleError(
                "runtime signed health-gate result does not match its signed gate"
            )
        attempts_used = result["attemptsUsed"]
        if (
            type(attempts_used) is not int
            or not 1 <= attempts_used <= gate["maxAttempts"]
        ):
            raise StateLifecycleError(
                "runtime signed health-gate attempts exceed the signed limit"
            )
        proofs = result["proofs"]
        expected_proofs = LOCAL_HEALTH_GATE_PROOFS[gate["type"]]
        if not isinstance(proofs, list) or len(proofs) != len(expected_proofs):
            raise StateLifecycleError(
                "runtime signed health-gate proof set is incomplete"
            )
        checked_proofs = []
        for proof, expected_name in zip(proofs, expected_proofs):
            if (
                not isinstance(proof, dict)
                or set(proof) != proof_fields
                or proof["name"] != expected_name
                or proof["status"] != "PASSED"
            ):
                raise StateLifecycleError(
                    "runtime signed health-gate proof set is not exact"
                )
            checked_proofs.append(
                {"name": expected_name, "status": "PASSED"}
            )
        checked.append(
            {
                "attemptsUsed": attempts_used,
                "gateId": gate["gateId"],
                "proofs": checked_proofs,
                "status": "PASSED",
                "type": gate["type"],
            }
        )
    return tuple(checked)


def _validate_runtime_checks(value: Any, profile: str) -> None:
    expected = RUNTIME_CHECKS_BY_PROFILE.get(profile)
    if expected is None or not isinstance(value, list) or len(value) != len(expected):
        raise StateLifecycleError("runtime check inventory is invalid")
    for check, expected_name in zip(value, expected):
        if (
            not isinstance(check, dict)
            or set(check) != {"name", "status"}
            or check["name"] != expected_name
            or check["status"] != "PASSED"
        ):
            raise StateLifecycleError(
                "runtime checks differ from the exact profile safety contract"
            )


def _validate_runtime_success_evidence(
    raw: bytes,
    *,
    pending: Mapping[str, Any],
    local_context: LocalContext,
    runtime_evidence_digest: str,
) -> Tuple[str, Tuple[Mapping[str, Any], ...]]:
    if not raw:
        raise StateLifecycleError("immutable runtime evidence is empty")
    try:
        evidence = manifest_tool.parse_json_text(raw.decode("utf-8"))
    except (
        UnicodeError,
        json.JSONDecodeError,
        manifest_tool.DuplicateKeyError,
        RecursionError,
        ValueError,
    ) as exc:
        raise StateLifecycleError(
            "immutable runtime evidence is invalid duplicate-safe UTF-8 JSON"
        ) from exc
    if not isinstance(evidence, dict):
        raise StateLifecycleError("immutable runtime evidence must be an object")
    try:
        canonical = manifest_tool.canonical_json_bytes(evidence)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise StateLifecycleError(
            "immutable runtime evidence is outside the canonical domain"
        ) from exc
    if raw != canonical + b"\n":
        raise StateLifecycleError(
            "immutable runtime evidence is not in canonical byte form"
        )

    fields = {
        "agentAction",
        "apiVersion",
        "evidenceDigest",
        "healthGates",
        "kind",
        "liveTeamsInteroperability",
        "localHealthGatePlan",
        "localHealthGatePlanDigest",
        "manifestDigest",
        "nodeId",
        "rollback",
        "rtpAdvertisedIpv4",
        "runtimeApplied",
        "runtimeChecks",
        "runtimeProfile",
        "runtimeReleaseDigest",
        "sequence",
        "status",
        "timestamp",
    }
    if set(evidence) != fields:
        raise StateLifecycleError(
            "runtime success evidence has missing or unknown members"
        )
    claimed_digest = evidence["evidenceDigest"]
    if claimed_digest != runtime_evidence_digest:
        raise StateLifecycleError(
            "runtime evidence digest does not equal the requested immutable evidence"
        )
    unsigned = dict(evidence)
    unsigned.pop("evidenceDigest")
    actual_digest = _sha256_digest(
        manifest_tool.canonical_json_bytes(unsigned)
    )
    if actual_digest != claimed_digest:
        raise StateLifecycleError("runtime evidence self-digest is invalid")

    if (
        evidence["apiVersion"] != RUNTIME_API_VERSION
        or evidence["kind"] != "EdgeRuntimeApplyEvidence"
        or evidence["status"] != RUNTIME_SUCCESS_STATUS
        or evidence["agentAction"] != "COMMIT_PENDING"
        or evidence["runtimeApplied"] is not True
        or evidence["liveTeamsInteroperability"] != "NOT_ASSERTED"
    ):
        raise StateLifecycleError(
            "runtime evidence does not assert exact local healthy apply semantics"
        )
    if (
        type(evidence["sequence"]) is not int
        or evidence["sequence"] != pending["sequence"]
        or evidence["manifestDigest"] != pending["manifestDigest"]
        or evidence["nodeId"] != local_context.node_id
    ):
        raise StateLifecycleError(
            "runtime evidence does not identify the exact pending candidate"
        )
    rollback = evidence["rollback"]
    if (
        not isinstance(rollback, dict)
        or set(rollback) != {"performed", "status", "targetReleaseDigest"}
        or rollback["performed"] is not False
        or rollback["status"] != "NOT_REQUIRED"
        or not isinstance(rollback["targetReleaseDigest"], str)
        or manifest_tool.DIGEST_RE.fullmatch(rollback["targetReleaseDigest"])
        is None
    ):
        raise StateLifecycleError(
            "runtime evidence rollback result is not exact NOT_REQUIRED evidence"
        )
    runtime_release_digest = evidence["runtimeReleaseDigest"]
    if (
        not isinstance(runtime_release_digest, str)
        or manifest_tool.DIGEST_RE.fullmatch(runtime_release_digest) is None
    ):
        raise StateLifecycleError("runtime release digest is invalid")

    errors = []
    if manifest_tool.parse_utc_timestamp(
        evidence["timestamp"], "runtime evidence timestamp", errors
    ) is None:
        raise StateLifecycleError("runtime evidence timestamp is invalid")
    profile = evidence["runtimeProfile"]
    advertised = evidence["rtpAdvertisedIpv4"]
    try:
        advertised_address = ipaddress.ip_address(advertised)
    except ValueError as exc:
        raise StateLifecycleError(
            "runtime evidence RTP advertised address is invalid"
        ) from exc
    if (
        not isinstance(advertised_address, ipaddress.IPv4Address)
        or str(advertised_address) != advertised
        or profile not in {"SYNTHETIC_PRIVATE", "DIRECT_ROUTING"}
        or (
            profile == "DIRECT_ROUTING"
            and advertised != local_context.expected_advertised_public_ip
        )
        or (profile == "SYNTHETIC_PRIVATE" and not advertised_address.is_private)
    ):
        raise StateLifecycleError(
            "runtime evidence profile and RTP advertised address are inconsistent"
        )
    _validate_runtime_checks(evidence["runtimeChecks"], profile)

    plan = _validate_local_health_gate_plan(
        evidence["localHealthGatePlan"],
        local_context=local_context,
        expected_manifest_digest=pending["manifestDigest"],
    )
    plan_digest = evidence["localHealthGatePlanDigest"]
    if (
        not isinstance(plan_digest, str)
        or manifest_tool.DIGEST_RE.fullmatch(plan_digest) is None
        or plan_digest != pending["localHealthGatePlanDigest"]
    ):
        raise StateLifecycleError(
            "runtime local health-gate plan digest differs from protected pending state"
        )
    try:
        computed_plan_digest = _local_health_gate_plan_digest(plan)
    except EnvelopeRejected as exc:
        raise StateLifecycleError(
            "runtime local health-gate plan cannot be canonicalized"
        ) from exc
    if computed_plan_digest != plan_digest:
        raise StateLifecycleError(
            "runtime local health-gate plan self-digest is invalid"
        )
    results = _validate_health_gate_results(evidence["healthGates"], plan)
    return runtime_release_digest, results


def commit_pending_after_health(
    *,
    local_context: LocalContext,
    state_directory: Path,
    sequence: int,
    manifest_digest: str,
    runtime_evidence_digest: str,
) -> CommitResult:
    """Promote one pending candidate only from immutable signed-gate evidence."""

    if (
        not isinstance(runtime_evidence_digest, str)
        or manifest_tool.DIGEST_RE.fullmatch(runtime_evidence_digest) is None
    ):
        raise ValueError("runtime_evidence_digest must be a lowercase sha256 digest")
    store = StateStore(state_directory)
    with store.locked_directory() as directory_fd:
        state_value = store.load_locked(directory_fd, local_context)
        if state_value is None:
            raise StateLifecycleError("protected state does not exist")
        pending = _require_exact_pending(state_value, sequence, manifest_digest)
        raw_evidence = _read_runtime_evidence(
            sequence=sequence,
            manifest_digest=manifest_digest,
            runtime_evidence_digest=runtime_evidence_digest,
        )
        runtime_release_digest, health_gates = _validate_runtime_success_evidence(
            raw_evidence,
            pending=pending,
            local_context=local_context,
            runtime_evidence_digest=runtime_evidence_digest,
        )
        new_state = dict(state_value)
        new_state["activeLastKnownGood"] = pending
        new_state["pendingCandidate"] = None
        store.write_locked(directory_fd, new_state)
    return CommitResult(
        manifest_digest=manifest_digest,
        sequence=sequence,
        local_health_gate_plan_digest=pending["localHealthGatePlanDigest"],
        runtime_evidence_digest=runtime_evidence_digest,
        runtime_release_digest=runtime_release_digest,
        health_gates=health_gates,
    )


def abort_pending(
    *,
    local_context: LocalContext,
    state_directory: Path,
    sequence: int,
    manifest_digest: str,
) -> AbortResult:
    """Discard one exact pending candidate without lowering the replay floor."""

    store = StateStore(state_directory)
    with store.locked_directory() as directory_fd:
        state_value = store.load_locked(directory_fd, local_context)
        if state_value is None:
            raise StateLifecycleError("protected state does not exist")
        pending = _require_exact_pending(state_value, sequence, manifest_digest)
        new_state = dict(state_value)
        new_state["lastAbortedCandidate"] = _candidate_status(pending)
        new_state["pendingCandidate"] = None
        store.write_locked(directory_fd, new_state)
    return AbortResult(manifest_digest=manifest_digest, sequence=sequence)
