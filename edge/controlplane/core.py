#!/usr/bin/env python3
"""Fail-closed CP1 materializer for the bounded first-tenant Edge POC.

The operator supplies desired tenant data and separately provisioned node facts.
This module binds the two, calls the reviewed deterministic compiler renderers,
content-addresses their exact bytes, validates the finished envelope, and only
then signs the canonical manifest with an explicitly named Ed25519 key.
"""

from __future__ import annotations

import base64
import copy
import errno
import hashlib
import ipaddress
import os
import re
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePath
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Tuple

from edge.agent import security_core as agent_security
from edge.compiler import core as compiler_core
from edge.compiler.core import NodeFacts, VerificationReceipt
from edge.schema import manifest_tool

PROFILE_API_VERSION = "edge.vivolution.ae/control-plane-profile/v0.1"
SYNTHETIC_PROFILE_KIND = "FirstTenantSyntheticFixtureProfile"
DIRECT_ROUTING_PROFILE_KIND = "FirstTenantDirectRoutingProfile"
DIRECT_ROUTING_PRIVATE_PBX_POC_PROFILE_KIND = (
    "FirstTenantDirectRoutingPrivatePbxPocProfile"
)
SYNTHETIC_DEPLOYMENT_MODE = "CP1_SYNTHETIC_NO_PSTN"
DIRECT_ROUTING_DEPLOYMENT_MODE = "DIRECT_ROUTING"
DIRECT_ROUTING_PRIVATE_PBX_POC_DEPLOYMENT_MODE = (
    "DIRECT_ROUTING_PRIVATE_PBX_POC"
)
# Backwards-compatible names retain the original bounded fixture contract.
PROFILE_KIND = SYNTHETIC_PROFILE_KIND
DEPLOYMENT_MODE = SYNTHETIC_DEPLOYMENT_MODE
MATERIALIZER_API_VERSION = "edge.vivolution.ae/control-plane-materializer/v0.1"

FIXTURE_PBX_HOST = "pbx-fixture.invalid"
FIXTURE_PBX_PORT = 16061
FIXTURE_PBX_SOURCE_CIDRS = ("10.20.1.4/32",)
FIXTURE_PBX_MEDIA_DESTINATION_PORT_START = 21000
FIXTURE_PBX_MEDIA_DESTINATION_PORT_END = 21127
PRIVATE_PBX_POC_HOST = "carrier.vivolution.ae"
PRIVATE_PBX_POC_PORT = 5061
PRIVATE_PBX_POC_SOURCE_CIDRS = ("10.20.1.4/32",)
PRIVATE_PBX_POC_MEDIA_DESTINATION_PORT_START = 30000
PRIVATE_PBX_POC_MEDIA_DESTINATION_PORT_END = 30127
MAX_DIRECT_PBX_MEDIA_DESTINATION_PORTS = 4096
_RESERVED_SIGNALING_AND_CONTROL_PORTS = frozenset(
    {
        compiler_core.TEAMS_TLS_PORT,
        compiler_core.PBX_TLS_LISTENER_PORT,
        compiler_core.RTPENGINE_NG_PORT,
        compiler_core.RTPENGINE_CLI_PORT,
    }
)
SUPPORTED_NODES = MappingProxyType({"sbc1": "A", "sbc2": "B"})

DIRECT_ROUTING_MICROSOFT_TARGETS = (
    MappingProxyType(
        {"fqdn": "sip.pstnhub.microsoft.com", "tlsPort": 5061, "transport": "TLS"}
    ),
    MappingProxyType(
        {"fqdn": "sip2.pstnhub.microsoft.com", "tlsPort": 5061, "transport": "TLS"}
    ),
    MappingProxyType(
        {"fqdn": "sip3.pstnhub.microsoft.com", "tlsPort": 5061, "transport": "TLS"}
    ),
)

SYNTHETIC_CONNECTOR_RESOURCE_ID = "connector-pbx-fixture"
SYNTHETIC_LISTENER_RESOURCE_ID = "listener-pbx-fixture"
DIRECT_ROUTING_CONNECTOR_RESOURCE_ID = "connector-pbx-direct-routing"
DIRECT_ROUTING_LISTENER_RESOURCE_ID = "listener-pbx-direct-routing"
DIRECT_ROUTING_PRIVATE_PBX_POC_CONNECTOR_RESOURCE_ID = (
    "connector-pbx-direct-private-poc"
)
DIRECT_ROUTING_PRIVATE_PBX_POC_LISTENER_RESOURCE_ID = (
    "listener-pbx-direct-private-poc"
)
SYNTHETIC_TEAMS_TO_PBX_ROUTE_ID = "route-teams-to-pbx"
SYNTHETIC_PBX_TO_TEAMS_ROUTE_ID = "route-pbx-to-teams"
DIRECT_ROUTING_TEAMS_TO_PBX_ROUTE_ID = "route-direct-teams-to-pbx"
DIRECT_ROUTING_PBX_TO_TEAMS_ROUTE_ID = "route-direct-pbx-to-teams"
DIRECT_ROUTING_PRIVATE_PBX_POC_TEAMS_TO_PBX_ROUTE_ID = (
    "route-direct-private-poc-teams-to-pbx"
)
DIRECT_ROUTING_PRIVATE_PBX_POC_PBX_TO_TEAMS_ROUTE_ID = (
    "route-direct-private-poc-pbx-to-teams"
)

_BASE_PROFILE_FIELDS = {
    "acceptedState",
    "activationTtlSeconds",
    "apiVersion",
    "capacity",
    "deploymentMode",
    "kind",
    "media",
    "pbxConnector",
    "routing",
    "secretReferences",
    "sequence",
    "targetAuthority",
}
_DIRECT_ROUTING_PROFILE_FIELDS = _BASE_PROFILE_FIELDS | {"microsoftTargets"}
_TARGET_FIELDS = {
    "allocationId",
    "clusterId",
    "customerAccountId",
    "m365TenantId",
    "serviceInstanceId",
    "tenantContextId",
}
_ACCEPTED_FIELDS = {"artifactDigests", "manifestDigest", "sequence"}
_DIRECT_ROUTING_ACCEPTED_FIELDS = _ACCEPTED_FIELDS | {"generation", "profileKind"}
_LIVE_DIRECT_PROFILE_KINDS = frozenset(
    {
        DIRECT_ROUTING_PROFILE_KIND,
        DIRECT_ROUTING_PRIVATE_PBX_POC_PROFILE_KIND,
    }
)
_PBX_FIELDS = {
    "mediaDestinationPortEnd",
    "mediaDestinationPortStart",
    "optionsIntervalSeconds",
    "remoteHost",
    "remotePort",
    "sourceIpv4Cidrs",
    "tlsServerName",
}
_ROUTING_FIELDS = {"calledNumberPrefix", "priority"}
_MEDIA_FIELDS = {"codecs", "maxSessions", "rtcpMux"}
_CAPACITY_FIELDS = {
    "maxBandwidthKbps",
    "maxCallsPerSecond",
    "maxConcurrentSessions",
    "reservedConcurrentSessions",
}
_SECRET_COLLECTION_FIELDS = {
    "pbxClientCa",
    "pbxClientIdentity",
    "pbxServerIdentity",
}
_SECRET_FIELDS = {"offlineValiditySeconds", "secretRefId", "version"}
_MICROSOFT_TARGET_FIELDS = {"fqdn", "tlsPort", "transport"}
_SECRET_PURPOSES = MappingProxyType(
    {
        "pbxClientIdentity": "PBX_CLIENT_MTLS_IDENTITY",
        "pbxServerIdentity": "PBX_SERVER_TLS_IDENTITY",
        "pbxClientCa": "PBX_CLIENT_CA_BUNDLE",
    }
)

_FQDN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_RESERVED_FQDN_SUFFIXES = (
    ".alt",
    ".arpa",
    ".example",
    ".invalid",
    ".local",
    ".localhost",
    ".onion",
    ".test",
)
_RESERVED_FQDN_NAMES = {
    "example.com",
    "example.net",
    "example.org",
    "localhost",
}
_PLACEHOLDER_FQDN_LABELS = {
    "changeme",
    "example",
    "placeholder",
    "replace",
    "replace-me",
    "todo",
}


class ControlPlaneError(ValueError):
    """Input or local security state cannot produce a trustworthy release."""


def _fail(message: str) -> None:
    raise ControlPlaneError(message)


def _exact_mapping(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail("{} must be a JSON object".format(label))
    actual = set(value)
    missing = sorted(fields - actual)
    extra = sorted(actual - fields)
    if missing or extra:
        _fail("{} members differ: missing={} extra={}".format(label, missing, extra))
    return value


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        _fail(
            "{} must be an integer from {} through {}".format(label, minimum, maximum)
        )
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or manifest_tool.ID_RE.fullmatch(value) is None:
        _fail("{} must be a lowercase v0.1 identifier".format(label))
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or manifest_tool.DIGEST_RE.fullmatch(value) is None:
        _fail("{} must be a lowercase sha256 digest".format(label))
    return value


def _canonical_digest(value: Any) -> str:
    return (
        "sha256:"
        + hashlib.sha256(manifest_tool.canonical_json_bytes(value)).hexdigest()
    )


def _content_digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _direct_routing_pbx_fqdn(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or value != value.lower()
        or value.endswith(".")
        or not 1 <= len(value) <= 253
    ):
        _fail("{} must be a canonical lowercase ASCII FQDN".format(label))
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        _fail("{} must be a canonical lowercase ASCII FQDN".format(label))
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        _fail("{} must be a DNS name, not an IP literal".format(label))
    labels = value.split(".")
    if len(labels) < 2 or any(
        _FQDN_LABEL_RE.fullmatch(item) is None for item in labels
    ):
        _fail("{} must be a canonical lowercase ASCII FQDN".format(label))
    if (
        value in _RESERVED_FQDN_NAMES
        or any(value.endswith(suffix) for suffix in _RESERVED_FQDN_SUFFIXES)
        or any(item in _PLACEHOLDER_FQDN_LABELS for item in labels)
        or value.endswith(".example.com")
        or value.endswith(".example.net")
        or value.endswith(".example.org")
    ):
        _fail("{} must be a real non-placeholder public DNS name".format(label))
    return value


def _direct_routing_pbx_cidrs(value: Any) -> Tuple[str, ...]:
    label = "direct-routing PBX sourceIpv4Cidrs"
    if not isinstance(value, list) or not 1 <= len(value) <= 8:
        _fail("{} must contain from one through eight canonical CIDRs".format(label))
    result = []
    seen = set()
    for item in value:
        if not isinstance(item, str):
            _fail("{} must contain only canonical IPv4 CIDRs".format(label))
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError:
            _fail("{} contains invalid or non-canonical CIDR {!r}".format(label, item))
        if not isinstance(network, ipaddress.IPv4Network) or str(network) != item:
            _fail("{} must contain only canonical IPv4 CIDRs".format(label))
        if network.prefixlen < 24:
            _fail("{} CIDR {} is broader than /24".format(label, item))
        if (
            not network.is_global
            or not network.network_address.is_global
            or not network.broadcast_address.is_global
        ):
            _fail("{} CIDR {} must be globally routable IPv4 space".format(label, item))
        if item in seen:
            _fail("{} contains duplicate CIDR {}".format(label, item))
        seen.add(item)
        result.append(item)
    canonical = tuple(
        sorted(
            result,
            key=lambda item: (
                int(ipaddress.ip_network(item).network_address),
                ipaddress.ip_network(item).prefixlen,
            ),
        )
    )
    if tuple(result) != canonical:
        _fail("{} must use unique canonical network order".format(label))
    return canonical


def _pbx_media_destination_range(
    start_value: Any,
    end_value: Any,
    *,
    remote_signaling_port: int,
    label: str,
) -> Tuple[int, int]:
    start = _integer(start_value, label + ".mediaDestinationPortStart", 1024, 65534)
    end = _integer(end_value, label + ".mediaDestinationPortEnd", 1025, 65535)
    if start % 2 != 0 or end % 2 != 1 or start > end:
        _fail(
            "{} media destination range must start even, end odd, and be ordered".format(
                label
            )
        )
    if end - start + 1 > MAX_DIRECT_PBX_MEDIA_DESTINATION_PORTS:
        _fail(
            "{} media destination range must contain no more than {} UDP ports".format(
                label, MAX_DIRECT_PBX_MEDIA_DESTINATION_PORTS
            )
        )
    reserved = _RESERVED_SIGNALING_AND_CONTROL_PORTS | {remote_signaling_port}
    collisions = sorted(port for port in reserved if start <= port <= end)
    if collisions:
        _fail(
            "{} media destination range collides with signaling/control ports {}".format(
                label, collisions
            )
        )
    return start, end


def _validate_direct_routing_microsoft_targets(value: Any) -> None:
    if not isinstance(value, list) or len(value) != len(
        DIRECT_ROUTING_MICROSOFT_TARGETS
    ):
        _fail(
            "microsoftTargets must contain the exact ordered Microsoft SIP target set"
        )
    normalized = []
    for index, item in enumerate(value):
        target = _exact_mapping(
            item,
            _MICROSOFT_TARGET_FIELDS,
            "microsoftTargets[{}]".format(index),
        )
        normalized.append(dict(target))
    expected = [dict(item) for item in DIRECT_ROUTING_MICROSOFT_TARGETS]
    if normalized != expected:
        _fail("microsoftTargets must equal the exact ordered Microsoft SIP target set")
    if expected[0]["fqdn"] != compiler_core.TEAMS_PRIMARY_UPSTREAM:
        _fail("control-plane and compiler Microsoft primary target differ")


@dataclass(frozen=True)
class FirstTenantProfile:
    """Validated, canonical desired input shared by the two node materializations."""

    _canonical: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, value: Any) -> "FirstTenantProfile":
        if not isinstance(value, Mapping):
            _fail("first-tenant profile must be a JSON object")
        kind = value.get("kind")
        if kind == SYNTHETIC_PROFILE_KIND:
            fields = _BASE_PROFILE_FIELDS
            expected_mode = SYNTHETIC_DEPLOYMENT_MODE
        elif kind == DIRECT_ROUTING_PROFILE_KIND:
            fields = _DIRECT_ROUTING_PROFILE_FIELDS
            expected_mode = DIRECT_ROUTING_DEPLOYMENT_MODE
        elif kind == DIRECT_ROUTING_PRIVATE_PBX_POC_PROFILE_KIND:
            fields = _DIRECT_ROUTING_PROFILE_FIELDS
            expected_mode = DIRECT_ROUTING_PRIVATE_PBX_POC_DEPLOYMENT_MODE
        else:
            _fail(
                "profile kind must be {}, {}, or {}".format(
                    SYNTHETIC_PROFILE_KIND,
                    DIRECT_ROUTING_PROFILE_KIND,
                    DIRECT_ROUTING_PRIVATE_PBX_POC_PROFILE_KIND,
                )
            )
        profile = _exact_mapping(value, fields, "first-tenant profile")
        if profile["apiVersion"] != PROFILE_API_VERSION:
            _fail("profile apiVersion must be {}".format(PROFILE_API_VERSION))
        if profile["deploymentMode"] != expected_mode:
            _fail(
                "deploymentMode must be {} for profile kind {}".format(
                    expected_mode, kind
                )
            )

        sequence = _integer(profile["sequence"], "profile sequence", 1, 2**31 - 1)
        _integer(profile["activationTtlSeconds"], "activationTtlSeconds", 300, 3600)

        target = _exact_mapping(
            profile["targetAuthority"], _TARGET_FIELDS, "targetAuthority"
        )
        for field in _TARGET_FIELDS - {"m365TenantId"}:
            _identifier(target[field], "targetAuthority.{}".format(field))
        m365 = target["m365TenantId"]
        if (
            not isinstance(m365, str)
            or manifest_tool.M365_TENANT_RE.fullmatch(m365) is None
        ):
            _fail("targetAuthority.m365TenantId must be a lowercase RFC 4122 UUID")

        accepted = profile["acceptedState"]
        if sequence == 1:
            if accepted is not None:
                _fail("acceptedState must be null for initial sequence 1")
        else:
            accepted_fields = (
                _DIRECT_ROUTING_ACCEPTED_FIELDS
                if kind in _LIVE_DIRECT_PROFILE_KINDS
                else _ACCEPTED_FIELDS
            )
            accepted = _exact_mapping(accepted, accepted_fields, "acceptedState")
            accepted_sequence = _integer(
                accepted["sequence"], "acceptedState.sequence", 1, sequence - 1
            )
            if accepted_sequence != sequence - 1:
                _fail("profile sequence must advance acceptedState by exactly one")
            _digest(accepted["manifestDigest"], "acceptedState.manifestDigest")
            artifact_digests = accepted["artifactDigests"]
            if not isinstance(artifact_digests, list) or len(artifact_digests) != 3:
                _fail(
                    "acceptedState.artifactDigests must contain exactly three digests"
                )
            normalized = tuple(
                _digest(item, "acceptedState.artifactDigests")
                for item in artifact_digests
            )
            if tuple(sorted(set(normalized))) != normalized:
                _fail("acceptedState.artifactDigests must be unique and sorted")
            if kind in _LIVE_DIRECT_PROFILE_KINDS:
                if accepted["profileKind"] != kind:
                    _fail(
                        "direct-routing acceptedState.profileKind must prove exact profile lineage"
                    )
                _integer(
                    accepted["generation"],
                    "direct-routing acceptedState.generation",
                    3
                    if kind == DIRECT_ROUTING_PRIVATE_PBX_POC_PROFILE_KIND
                    else 2,
                    2**31 - 1,
                )

        pbx = _exact_mapping(profile["pbxConnector"], _PBX_FIELDS, "pbxConnector")
        if kind == SYNTHETIC_PROFILE_KIND:
            if (
                pbx["remoteHost"] != FIXTURE_PBX_HOST
                or pbx["tlsServerName"] != FIXTURE_PBX_HOST
            ):
                _fail(
                    "fixture PBX remoteHost and tlsServerName must both be {}".format(
                        FIXTURE_PBX_HOST
                    )
                )
            if pbx["remotePort"] != FIXTURE_PBX_PORT or isinstance(
                pbx["remotePort"], bool
            ):
                _fail("fixture PBX remotePort must be {}".format(FIXTURE_PBX_PORT))
            sources = pbx["sourceIpv4Cidrs"]
            if (
                not isinstance(sources, list)
                or tuple(sources) != FIXTURE_PBX_SOURCE_CIDRS
            ):
                _fail(
                    "fixture PBX source authority must be exactly {}".format(
                        list(FIXTURE_PBX_SOURCE_CIDRS)
                    )
                )
            if (
                pbx["mediaDestinationPortStart"],
                pbx["mediaDestinationPortEnd"],
            ) != (
                FIXTURE_PBX_MEDIA_DESTINATION_PORT_START,
                FIXTURE_PBX_MEDIA_DESTINATION_PORT_END,
            ):
                _fail(
                    "fixture PBX media destination range must be exactly {}-{}".format(
                        FIXTURE_PBX_MEDIA_DESTINATION_PORT_START,
                        FIXTURE_PBX_MEDIA_DESTINATION_PORT_END,
                    )
                )
        elif kind == DIRECT_ROUTING_PROFILE_KIND:
            remote_host = _direct_routing_pbx_fqdn(
                pbx["remoteHost"], "direct-routing PBX remoteHost"
            )
            tls_server_name = _direct_routing_pbx_fqdn(
                pbx["tlsServerName"], "direct-routing PBX tlsServerName"
            )
            if remote_host != tls_server_name:
                _fail("direct-routing PBX remoteHost must exactly equal tlsServerName")
            if pbx["remotePort"] != 5061 or isinstance(pbx["remotePort"], bool):
                _fail(
                    "direct-routing PBX remotePort must be the reviewed TLS port 5061"
                )
            _direct_routing_pbx_cidrs(pbx["sourceIpv4Cidrs"])
            _pbx_media_destination_range(
                pbx["mediaDestinationPortStart"],
                pbx["mediaDestinationPortEnd"],
                remote_signaling_port=pbx["remotePort"],
                label="direct-routing PBX",
            )
            _validate_direct_routing_microsoft_targets(profile["microsoftTargets"])
        else:
            if (
                pbx["remoteHost"] != PRIVATE_PBX_POC_HOST
                or pbx["tlsServerName"] != PRIVATE_PBX_POC_HOST
            ):
                _fail(
                    "private-PBX Direct Routing POC remoteHost and tlsServerName "
                    "must both be {}".format(PRIVATE_PBX_POC_HOST)
                )
            if pbx["remotePort"] != PRIVATE_PBX_POC_PORT or isinstance(
                pbx["remotePort"], bool
            ):
                _fail(
                    "private-PBX Direct Routing POC remotePort must be {}".format(
                        PRIVATE_PBX_POC_PORT
                    )
                )
            if (
                not isinstance(pbx["sourceIpv4Cidrs"], list)
                or tuple(pbx["sourceIpv4Cidrs"]) != PRIVATE_PBX_POC_SOURCE_CIDRS
            ):
                _fail(
                    "private-PBX Direct Routing POC source authority must be exactly {}".format(
                        list(PRIVATE_PBX_POC_SOURCE_CIDRS)
                    )
                )
            if (
                pbx["mediaDestinationPortStart"],
                pbx["mediaDestinationPortEnd"],
            ) != (
                PRIVATE_PBX_POC_MEDIA_DESTINATION_PORT_START,
                PRIVATE_PBX_POC_MEDIA_DESTINATION_PORT_END,
            ):
                _fail(
                    "private-PBX Direct Routing POC media destination range must be "
                    "exactly {}-{}".format(
                        PRIVATE_PBX_POC_MEDIA_DESTINATION_PORT_START,
                        PRIVATE_PBX_POC_MEDIA_DESTINATION_PORT_END,
                    )
                )
            _validate_direct_routing_microsoft_targets(profile["microsoftTargets"])
        if pbx["optionsIntervalSeconds"] != 60 or isinstance(
            pbx["optionsIntervalSeconds"], bool
        ):
            _fail("PBX optionsIntervalSeconds must be the reviewed value 60")

        routing = _exact_mapping(profile["routing"], _ROUTING_FIELDS, "routing")
        prefix = routing["calledNumberPrefix"]
        if (
            not isinstance(prefix, str)
            or manifest_tool.E164_PREFIX_RE.fullmatch(prefix) is None
        ):
            _fail("routing.calledNumberPrefix must be an E.164 prefix")
        if kind in _LIVE_DIRECT_PROFILE_KINDS and prefix != "+971":
            _fail("direct-routing calledNumberPrefix must be exactly +971")
        if routing["priority"] != 100 or isinstance(routing["priority"], bool):
            _fail("routing.priority must be the reviewed POC value 100")

        media = _exact_mapping(profile["media"], _MEDIA_FIELDS, "media")
        if media["codecs"] != ["PCMA", "PCMU"]:
            _fail("media.codecs must be the reviewed ordered set ['PCMA', 'PCMU']")
        max_sessions = _integer(media["maxSessions"], "media.maxSessions", 1, 64)
        if media["rtcpMux"] is not False:
            _fail("media.rtcpMux must be false for the reviewed first-tenant profiles")
        if kind in _LIVE_DIRECT_PROFILE_KINDS:
            remote_media_ports = (
                pbx["mediaDestinationPortEnd"]
                - pbx["mediaDestinationPortStart"]
                + 1
            )
            if remote_media_ports < max_sessions * 2:
                _fail(
                    "direct-routing PBX media destination range must provide at least "
                    "two UDP ports per non-muxed session"
                )

        capacity = _exact_mapping(profile["capacity"], _CAPACITY_FIELDS, "capacity")
        reserved = _integer(
            capacity["reservedConcurrentSessions"],
            "capacity.reservedConcurrentSessions",
            1,
            64,
        )
        maximum = _integer(
            capacity["maxConcurrentSessions"],
            "capacity.maxConcurrentSessions",
            1,
            64,
        )
        if reserved > maximum:
            _fail("reservedConcurrentSessions must not exceed maxConcurrentSessions")
        if maximum != max_sessions:
            _fail("capacity.maxConcurrentSessions must equal media.maxSessions")
        _integer(capacity["maxCallsPerSecond"], "capacity.maxCallsPerSecond", 1, 100)
        _integer(capacity["maxBandwidthKbps"], "capacity.maxBandwidthKbps", 128, 100000)

        secret_collection = _exact_mapping(
            profile["secretReferences"],
            _SECRET_COLLECTION_FIELDS,
            "secretReferences",
        )
        seen_secret_ids = set()
        for role in sorted(_SECRET_COLLECTION_FIELDS):
            reference = _exact_mapping(
                secret_collection[role],
                _SECRET_FIELDS,
                "secretReferences.{}".format(role),
            )
            ref_id = _identifier(
                reference["secretRefId"], "{}.secretRefId".format(role)
            )
            if ref_id in seen_secret_ids:
                _fail("secret reference identifiers must be unique")
            seen_secret_ids.add(ref_id)
            version = _identifier(reference["version"], "{}.version".format(role))
            if kind in _LIVE_DIRECT_PROFILE_KINDS and (
                "fixture" in ref_id or "fixture" in version
            ):
                _fail(
                    "direct-routing secret metadata must not reference fixture material"
                )
            _integer(
                reference["offlineValiditySeconds"],
                "{}.offlineValiditySeconds".format(role),
                0,
                31536000,
            )

        # Canonical JSON round-tripping produces detached JSON primitives and
        # rejects floats/non-interoperable values before the value is retained.
        detached = manifest_tool.parse_json_text(
            manifest_tool.canonical_json_bytes(profile).decode("utf-8")
        )
        return cls(MappingProxyType(detached))

    def canonical_record(self) -> Dict[str, Any]:
        return copy.deepcopy(dict(self._canonical))

    @property
    def kind(self) -> str:
        return str(self._canonical["kind"])

    @property
    def deployment_mode(self) -> str:
        return str(self._canonical["deploymentMode"])

    @property
    def is_direct_routing(self) -> bool:
        return self.kind in _LIVE_DIRECT_PROFILE_KINDS


def _secure_flags(*flags: int) -> int:
    result = getattr(os, "O_CLOEXEC", 0)
    for flag in flags:
        result |= flag
    return result


def _open_private_parent(path: Path) -> Tuple[int, str]:
    """Open a key parent without following symlinks; require private ownership."""

    pure = PurePath(path)
    if not pure.is_absolute():
        _fail("private key path must be absolute")
    parts = pure.parts
    if len(parts) < 2 or any(part in {"", ".", ".."} for part in parts[1:]):
        _fail("private key path contains an unsafe component")
    name = parts[-1]
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory_flag:
        _fail("platform lacks required no-follow directory primitives")
    flags = _secure_flags(os.O_RDONLY, directory_flag)
    current_fd = os.open(parts[0], flags)
    try:
        for component in parts[1:-1]:
            try:
                next_fd = os.open(component, flags | nofollow, dir_fd=current_fd)
            except OSError as exc:
                _fail(
                    "cannot securely open private key parent component {!r}: {}".format(
                        component, exc
                    )
                )
            os.close(current_fd)
            current_fd = next_fd
        metadata = os.fstat(current_fd)
        mode = stat.S_IMODE(metadata.st_mode)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
            _fail("private key parent must be a directory owned by the current user")
        if mode & 0o077 or mode & 0o300 != 0o300:
            _fail("private key parent permissions must be private and owner-writable")
        return current_fd, name
    except BaseException:
        os.close(current_fd)
        raise


def _write_all(fd: int, content: bytes) -> None:
    pending = memoryview(content)
    while pending:
        count = os.write(fd, pending)
        if count <= 0:
            raise OSError("short write")
        pending = pending[count:]


def _public_key_bytes(seed: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        _fail("Ed25519 signing requires python3-cryptography")
    private = Ed25519PrivateKey.from_private_bytes(seed)
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _public_metadata(key_id: str, public_bytes: bytes) -> Dict[str, Any]:
    _identifier(key_id, "key id")
    return {
        "algorithm": "Ed25519",
        "apiVersion": MATERIALIZER_API_VERSION,
        "encoding": "base64-raw-32",
        "keyId": key_id,
        "kind": "SigningPublicKeyMetadata",
        "publicKeyBase64": base64.b64encode(public_bytes).decode("ascii"),
        "publicKeySha256": _content_digest(public_bytes),
        "signedBytesPrefixHex": agent_security.SIGNED_BYTES_PREFIX.hex(),
    }


def generate_private_seed(path: Path, *, key_id: str) -> Dict[str, Any]:
    """Atomically create one raw Ed25519 seed; return public metadata only."""

    _identifier(key_id, "key id")
    path = Path(path)
    parent_fd, name = _open_private_parent(path)
    temp_name = ".{}.new.{}".format(name, secrets.token_hex(12))
    temp_fd: Optional[int] = None
    linked = False
    try:
        try:
            temp_fd = os.open(
                temp_name,
                _secure_flags(os.O_WRONLY, os.O_CREAT, os.O_EXCL, os.O_NOFOLLOW),
                0o600,
                dir_fd=parent_fd,
            )
            os.fchmod(temp_fd, 0o600)
            seed = os.urandom(32)
            # Resolve the signing dependency and derive all public output
            # before atomically publishing the private destination.
            public_bytes = _public_key_bytes(seed)
            _write_all(temp_fd, seed)
            os.fsync(temp_fd)
            os.close(temp_fd)
            temp_fd = None
            # link(2) is an atomic no-replace publication within the same
            # directory. It fails for every existing file or symlink target.
            os.link(
                temp_name,
                name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
            linked = True
            os.unlink(temp_name, dir_fd=parent_fd)
            os.fsync(parent_fd)
            return _public_metadata(key_id, public_bytes)
        except FileExistsError:
            _fail("private key path already exists; refusing overwrite")
        except OSError as exc:
            if exc.errno in {errno.EEXIST, errno.ELOOP}:
                _fail(
                    "private key path already exists or is a symlink; refusing overwrite"
                )
            raise
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        try:
            os.unlink(temp_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        # The destination was created by this invocation; after temp cleanup
        # it has one link. Never remove it just because a later fsync failed.
        if linked:
            try:
                destination_fd = os.open(
                    name,
                    _secure_flags(os.O_RDONLY, os.O_NOFOLLOW),
                    dir_fd=parent_fd,
                )
                try:
                    if os.fstat(destination_fd).st_nlink != 1:
                        _fail("new private key unexpectedly has multiple hard links")
                finally:
                    os.close(destination_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def _read_private_seed(path: Path) -> bytes:
    parent_fd, name = _open_private_parent(Path(path))
    fd: Optional[int] = None
    try:
        try:
            fd = os.open(
                name,
                _secure_flags(os.O_RDONLY, os.O_NOFOLLOW),
                dir_fd=parent_fd,
            )
        except OSError as exc:
            _fail("cannot securely open private signing seed: {}".format(exc))
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            _fail(
                "private signing seed must be a regular file owned by the current user"
            )
        if metadata.st_nlink != 1:
            _fail("private signing seed must not have hard links")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            _fail("private signing seed permissions must be exactly 0600")
        content = b""
        while len(content) <= 32:
            chunk = os.read(fd, 33 - len(content))
            if not chunk:
                break
            content += chunk
        if len(content) != 32:
            _fail("private signing seed must contain exactly 32 raw bytes")
        return content
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        _fail("issued_at must be a timezone-aware datetime")
    normalized = value.astimezone(timezone.utc)
    if normalized.microsecond:
        _fail("issued_at must use whole seconds")
    return normalized.strftime("%Y-%m-%dT%H:%M:%SZ")


def _artifact_id(kind: str, node_id: str, sequence: int) -> str:
    label = {
        "OPENSIPS_TENANT_CONFIG": "opensips",
        "RTPENGINE_TENANT_CONFIG": "rtpengine",
        "NFTABLES_TENANT_POLICY": "nftables",
    }[kind]
    candidate = "artifact-{}-{}-{:06d}".format(label, node_id, sequence)
    if manifest_tool.ID_RE.fullmatch(candidate) is None:
        digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:20]
        candidate = "artifact-{}-{}".format(label, digest)
    return candidate


def _resource(
    resource_type: str,
    resource_id: str,
    tenant_context_id: str,
    allocation_id: str,
    artifact_ids: list[str],
    spec: Mapping[str, Any],
) -> Dict[str, Any]:
    return {
        "allocationId": allocation_id,
        "artifactIds": artifact_ids,
        "resourceId": resource_id,
        "spec": dict(spec),
        "tenantContextId": tenant_context_id,
        "type": resource_type,
    }


def _profile_resource_ids(profile: Mapping[str, Any]) -> Mapping[str, str]:
    if profile["kind"] == SYNTHETIC_PROFILE_KIND:
        return MappingProxyType(
            {
                "connector": SYNTHETIC_CONNECTOR_RESOURCE_ID,
                "listener": SYNTHETIC_LISTENER_RESOURCE_ID,
                "pbxToTeamsRoute": SYNTHETIC_PBX_TO_TEAMS_ROUTE_ID,
                "teamsToPbxRoute": SYNTHETIC_TEAMS_TO_PBX_ROUTE_ID,
            }
        )
    if profile["kind"] == DIRECT_ROUTING_PROFILE_KIND:
        return MappingProxyType(
            {
                "connector": DIRECT_ROUTING_CONNECTOR_RESOURCE_ID,
                "listener": DIRECT_ROUTING_LISTENER_RESOURCE_ID,
                "pbxToTeamsRoute": DIRECT_ROUTING_PBX_TO_TEAMS_ROUTE_ID,
                "teamsToPbxRoute": DIRECT_ROUTING_TEAMS_TO_PBX_ROUTE_ID,
            }
        )
    if profile["kind"] == DIRECT_ROUTING_PRIVATE_PBX_POC_PROFILE_KIND:
        return MappingProxyType(
            {
                "connector": DIRECT_ROUTING_PRIVATE_PBX_POC_CONNECTOR_RESOURCE_ID,
                "listener": DIRECT_ROUTING_PRIVATE_PBX_POC_LISTENER_RESOURCE_ID,
                "pbxToTeamsRoute": DIRECT_ROUTING_PRIVATE_PBX_POC_PBX_TO_TEAMS_ROUTE_ID,
                "teamsToPbxRoute": DIRECT_ROUTING_PRIVATE_PBX_POC_TEAMS_TO_PBX_ROUTE_ID,
            }
        )
    _fail("validated profile has an unknown kind")


def _build_health_gates(
    profile: Mapping[str, Any], tenant_context_id: str, allocation_id: str
) -> list[Dict[str, Any]]:
    resource_ids = _profile_resource_ids(profile)
    # These signed gates are deliberately limited to checks the node performs
    # during the transactional activation itself.  Peer OPTIONS, complete call
    # paths, and N-1 behavior require external participants and belong to the
    # separately sealed environment-acceptance evidence; putting them here
    # would let a local commit falsely assert that an external test had run.
    specifications = (
        (
            "gate-artifact-digests",
            "ARTIFACT_DIGESTS",
            [
                resource_ids["connector"],
                resource_ids["listener"],
                resource_ids["teamsToPbxRoute"],
                resource_ids["pbxToTeamsRoute"],
                "media-first-tenant",
                "capacity-first-tenant",
            ],
            30,
            1,
        ),
        (
            "gate-opensips-config",
            "OPENSIPS_CONFIG",
            [
                resource_ids["connector"],
                resource_ids["listener"],
                resource_ids["teamsToPbxRoute"],
                resource_ids["pbxToTeamsRoute"],
            ],
            30,
            1,
        ),
        ("gate-rtpengine-ready", "RTPENGINE_READY", ["media-first-tenant"], 30, 3),
    )
    return [
        {
            "allocationId": allocation_id,
            "gateId": gate_id,
            "maxAttempts": attempts,
            "onFailure": "ROLLBACK_TO_TARGET",
            "resourceRefs": refs,
            "tenantContextId": tenant_context_id,
            "timeoutSeconds": timeout,
            "type": gate_type,
        }
        for gate_id, gate_type, refs, timeout, attempts in specifications
    ]


def _build_manifest(
    profile: Mapping[str, Any], facts: NodeFacts, issued_at: datetime
) -> Dict[str, Any]:
    tenant = profile["targetAuthority"]
    tenant_context_id = tenant["tenantContextId"]
    allocation_id = tenant["allocationId"]
    sequence = profile["sequence"]
    pbx = profile["pbxConnector"]
    routing = profile["routing"]
    media = profile["media"]
    capacity = profile["capacity"]
    resource_ids = _profile_resource_ids(profile)

    artifact_ids = {
        kind: _artifact_id(kind, facts.node_id, sequence)
        for kind in compiler_core.ARTIFACT_MEDIA_TYPES
    }
    artifacts = []
    zero_digest = "sha256:" + "0" * 64
    for kind in sorted(
        artifact_ids, key=lambda item: compiler_core.ARTIFACT_APPLY_ORDER[item]
    ):
        artifacts.append(
            {
                "allocationId": allocation_id,
                "applyOrder": compiler_core.ARTIFACT_APPLY_ORDER[kind],
                "artifactId": artifact_ids[kind],
                "fetchPath": "/v0.1/artifacts/sha256/" + "0" * 64,
                "kind": kind,
                "mediaType": compiler_core.ARTIFACT_MEDIA_TYPES[kind],
                "scope": "TENANT",
                "sha256": zero_digest,
                "sizeBytes": 1,
                "tenantContextId": tenant_context_id,
            }
        )

    secret_references = []
    for role in ("pbxClientIdentity", "pbxServerIdentity", "pbxClientCa"):
        reference = profile["secretReferences"][role]
        secret_references.append(
            {
                "allocationId": allocation_id,
                "offlineValiditySeconds": reference["offlineValiditySeconds"],
                "purpose": _SECRET_PURPOSES[role],
                "requiredOnNode": True,
                "scope": "TENANT",
                "secretRefId": reference["secretRefId"],
                "tenantContextId": tenant_context_id,
                "version": reference["version"],
            }
        )

    connector_secret = profile["secretReferences"]["pbxClientIdentity"]["secretRefId"]
    server_secret = profile["secretReferences"]["pbxServerIdentity"]["secretRefId"]
    ca_secret = profile["secretReferences"]["pbxClientCa"]["secretRefId"]
    resources = [
        _resource(
            "tenant.connector",
            resource_ids["connector"],
            tenant_context_id,
            allocation_id,
            [artifact_ids["OPENSIPS_TENANT_CONFIG"]],
            {
                "authentication": "MTLS_AND_IP_ACL",
                "credentialSecretRef": connector_secret,
                "mediaDestinationPortEnd": pbx["mediaDestinationPortEnd"],
                "mediaDestinationPortStart": pbx["mediaDestinationPortStart"],
                "optionsIntervalSeconds": pbx["optionsIntervalSeconds"],
                "remoteHost": pbx["remoteHost"],
                "remotePort": pbx["remotePort"],
                "role": "PBX",
                "sourceCidrs": list(pbx["sourceIpv4Cidrs"]),
                "tlsServerName": pbx["tlsServerName"],
                "transport": "TLS",
            },
        ),
        _resource(
            "tenant.listener",
            resource_ids["listener"],
            tenant_context_id,
            allocation_id,
            [
                artifact_ids["OPENSIPS_TENANT_CONFIG"],
                artifact_ids["NFTABLES_TENANT_POLICY"],
            ],
            {
                "allowedSourceCidrs": list(pbx["sourceIpv4Cidrs"]),
                "bindAddress": "0.0.0.0",
                "certificateSecretRef": server_secret,
                "clientCaSecretRef": ca_secret,
                "mutualTls": True,
                "port": facts.tenant_listener_port,
                "role": "PBX",
                "transport": "TLS",
            },
        ),
        _resource(
            "tenant.route",
            resource_ids["teamsToPbxRoute"],
            tenant_context_id,
            allocation_id,
            [artifact_ids["OPENSIPS_TENANT_CONFIG"]],
            {
                "calledNumberPrefix": routing["calledNumberPrefix"],
                "connectorRef": resource_ids["connector"],
                "direction": "TEAMS_TO_PBX",
                "enabled": True,
                "priority": routing["priority"],
            },
        ),
        _resource(
            "tenant.route",
            resource_ids["pbxToTeamsRoute"],
            tenant_context_id,
            allocation_id,
            [artifact_ids["OPENSIPS_TENANT_CONFIG"]],
            {
                "calledNumberPrefix": routing["calledNumberPrefix"],
                "connectorRef": resource_ids["connector"],
                "direction": "PBX_TO_TEAMS",
                "enabled": True,
                "priority": routing["priority"],
            },
        ),
        _resource(
            "tenant.media",
            "media-first-tenant",
            tenant_context_id,
            allocation_id,
            [
                artifact_ids["RTPENGINE_TENANT_CONFIG"],
                artifact_ids["NFTABLES_TENANT_POLICY"],
            ],
            {
                "advertisedAddress": facts.public_ipv4,
                "codecs": list(media["codecs"]),
                "engine": "RTPENGINE",
                "maxSessions": media["maxSessions"],
                "portEnd": facts.tenant_media_port_end,
                "portStart": facts.tenant_media_port_start,
                "rtcpMux": media["rtcpMux"],
                "unitKey": "rtp-" + facts.tenant_context_id.removeprefix("tenant-"),
            },
        ),
        _resource(
            "tenant.capacity",
            "capacity-first-tenant",
            tenant_context_id,
            allocation_id,
            [
                artifact_ids["OPENSIPS_TENANT_CONFIG"],
                artifact_ids["RTPENGINE_TENANT_CONFIG"],
            ],
            dict(capacity),
        ),
    ]

    accepted = profile["acceptedState"]
    if accepted is None:
        previous_digest = None
        rollback = None
    else:
        previous_digest = accepted["manifestDigest"]
        rollback = {
            "allocationId": allocation_id,
            "artifactDigests": list(accepted["artifactDigests"]),
            "clusterId": facts.cluster_id,
            "generation": facts.generation,
            "manifestDigest": previous_digest,
            "nodeId": facts.node_id,
            "scope": "TENANT",
            "sequence": accepted["sequence"],
            "tenantContextId": tenant_context_id,
        }

    issued_text = _timestamp(issued_at)
    expires_text = _timestamp(
        issued_at.astimezone(timezone.utc)
        + timedelta(seconds=profile["activationTtlSeconds"])
    )
    return {
        "expiresAt": expires_text,
        "healthGates": _build_health_gates(profile, tenant_context_id, allocation_id),
        "issuedAt": issued_text,
        "lifecycle": "ACTIVE",
        "manifestId": (
            "manifest-direct-private-pbx-poc-{}-{:06d}".format(
                facts.node_id, sequence
            )
            if profile["kind"] == DIRECT_ROUTING_PRIVATE_PBX_POC_PROFILE_KIND
            else (
                "manifest-direct-{}-{:06d}".format(facts.node_id, sequence)
                if profile["kind"] == DIRECT_ROUTING_PROFILE_KIND
                else "manifest-{}-{:06d}".format(facts.node_id, sequence)
            )
        ),
        "previousDigest": previous_digest,
        "resourceSet": {
            "artifacts": artifacts,
            "cleanupIntent": None,
            "mode": "COMPLETE",
            "resources": resources,
            "secretReferences": secret_references,
        },
        "rollbackTarget": rollback,
        "sequence": sequence,
        "target": {
            "clusterId": facts.cluster_id,
            "generation": facts.generation,
            "nodeId": facts.node_id,
            "scope": "TENANT",
            "slot": facts.slot,
            "tenant": {
                "allocationId": facts.allocation_id,
                "customerAccountId": facts.customer_account_id,
                "m365TenantId": facts.m365_tenant_id,
                "serviceInstanceId": facts.service_instance_id,
                "tenantContextId": facts.tenant_context_id,
            },
        },
    }


def _validation_context(
    profile: Mapping[str, Any], facts: NodeFacts, issued_at: datetime
) -> manifest_tool.ValidationContext:
    accepted = profile["acceptedState"]
    return manifest_tool.ValidationContext(
        expected_cluster_id=facts.cluster_id,
        expected_node_id=facts.node_id,
        expected_generation=facts.generation,
        accepted_sequence=0 if accepted is None else accepted["sequence"],
        accepted_digest=None if accepted is None else accepted["manifestDigest"],
        now=issued_at,
        expected_tenant_context_id=facts.tenant_context_id,
        expected_allocation_id=facts.allocation_id,
        expected_tenant_listener_port=facts.tenant_listener_port,
        expected_media_port_start=facts.tenant_media_port_start,
        expected_media_port_end=facts.tenant_media_port_end,
        expected_pbx_media_destination_port_start=(
            facts.pbx_media_destination_port_start
        ),
        expected_pbx_media_destination_port_end=facts.pbx_media_destination_port_end,
        expected_advertised_public_ip=facts.public_ipv4,
        authorized_pbx_source_cidrs=facts.authorized_pbx_source_ipv4_cidrs,
        authorized_microsoft_source_cidrs=tuple(
            sorted(
                set(facts.teams_signaling_source_ipv4_cidrs)
                | set(facts.teams_media_source_ipv4_cidrs)
            )
        ),
    )


def _bind_profile_to_facts(profile: Mapping[str, Any], facts: NodeFacts) -> None:
    target = profile["targetAuthority"]
    expected = {
        "allocationId": facts.allocation_id,
        "clusterId": facts.cluster_id,
        "customerAccountId": facts.customer_account_id,
        "m365TenantId": facts.m365_tenant_id,
        "serviceInstanceId": facts.service_instance_id,
        "tenantContextId": facts.tenant_context_id,
    }
    if dict(target) != expected:
        _fail(
            "profile targetAuthority does not exactly match locally trusted node facts"
        )
    expected_slot = SUPPORTED_NODES.get(facts.node_id)
    if expected_slot is None or facts.slot != expected_slot:
        _fail("first-tenant POC supports only sbc1/A and sbc2/B node identities")
    if profile["kind"] == SYNTHETIC_PROFILE_KIND:
        if facts.authorized_pbx_source_ipv4_cidrs != FIXTURE_PBX_SOURCE_CIDRS:
            _fail("node facts PBX authority must be exactly the CP1 fixture host /32")
        if (
            facts.pbx_media_destination_port_start,
            facts.pbx_media_destination_port_end,
        ) != (
            FIXTURE_PBX_MEDIA_DESTINATION_PORT_START,
            FIXTURE_PBX_MEDIA_DESTINATION_PORT_END,
        ):
            _fail(
                "synthetic node facts PBX media destination must be the fixed CP1 "
                "fixture range {}-{}".format(
                    FIXTURE_PBX_MEDIA_DESTINATION_PORT_START,
                    FIXTURE_PBX_MEDIA_DESTINATION_PORT_END,
                )
            )
    elif profile["kind"] in _LIVE_DIRECT_PROFILE_KINDS:
        minimum_generation = (
            3
            if profile["kind"] == DIRECT_ROUTING_PRIVATE_PBX_POC_PROFILE_KIND
            else 2
        )
        if facts.generation < minimum_generation:
            _fail(
                "direct-routing materialization requires replacement node generation "
                "{} or later".format(minimum_generation)
            )
        expected_pbx_sources = tuple(profile["pbxConnector"]["sourceIpv4Cidrs"])
        if facts.authorized_pbx_source_ipv4_cidrs != expected_pbx_sources:
            _fail(
                "direct-routing profile PBX source authority must exactly match "
                "locally trusted node facts"
            )
        expected_pbx_media_destination = (
            profile["pbxConnector"]["mediaDestinationPortStart"],
            profile["pbxConnector"]["mediaDestinationPortEnd"],
        )
        if (
            facts.pbx_media_destination_port_start,
            facts.pbx_media_destination_port_end,
        ) != expected_pbx_media_destination:
            _fail(
                "direct-routing profile PBX media destination range must exactly "
                "match locally trusted node facts"
            )
        accepted = profile["acceptedState"]
        if accepted is not None and accepted["generation"] != facts.generation:
            _fail(
                "direct-routing acceptedState generation must equal the replacement node generation"
            )
        if profile["kind"] == DIRECT_ROUTING_PRIVATE_PBX_POC_PROFILE_KIND:
            if facts.node_fqdn != "{}.vivolution.ae".format(facts.node_id):
                _fail(
                    "private-PBX Direct Routing POC node facts require the exact root Microsoft gateway FQDN"
                )
            if expected_pbx_sources != PRIVATE_PBX_POC_SOURCE_CIDRS:
                _fail(
                    "private-PBX Direct Routing POC node facts must authorize only "
                    "10.20.1.4/32"
                )
            if expected_pbx_media_destination != (
                PRIVATE_PBX_POC_MEDIA_DESTINATION_PORT_START,
                PRIVATE_PBX_POC_MEDIA_DESTINATION_PORT_END,
            ):
                _fail(
                    "private-PBX Direct Routing POC node facts must retain only the "
                    "fixed 30000-30127 CP1 carrier media destination"
                )
    else:
        _fail("validated profile has an unknown kind")
    if facts.synthetic_teams_source_ipv4_cidrs:
        _fail(
            "synthetic Teams authority must not be encoded in tenant node facts; "
            "the fixed root runtime owns that CP1-only exception"
        )


def _sign_manifest(seed: bytes, manifest: Mapping[str, Any]) -> bytes:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        _fail("Ed25519 signing requires python3-cryptography")
    private = Ed25519PrivateKey.from_private_bytes(seed)
    signed_bytes = (
        agent_security.SIGNED_BYTES_PREFIX
        + manifest_tool.canonical_json_bytes(manifest)
    )
    return private.sign(signed_bytes)


@dataclass(frozen=True)
class MaterializedRelease:
    """Signed envelope, exact compiler bytes, and non-secret audit metadata."""

    _envelope_bytes: bytes
    artifacts: Mapping[str, bytes]
    compile_evidence: bytes
    _public_key_metadata: Mapping[str, Any]
    _evidence: Mapping[str, Any]

    @property
    def envelope(self) -> Dict[str, Any]:
        # Return a detached wire-equivalent object so callers cannot mutate the
        # already validated bytes later written by write_new_directory().
        parsed = manifest_tool.parse_json_text(self._envelope_bytes.decode("utf-8"))
        if not isinstance(parsed, dict):  # construction invariant
            _fail("stored signed envelope is not an object")
        return parsed

    @property
    def envelope_bytes(self) -> bytes:
        return bytes(self._envelope_bytes)

    @property
    def public_key_metadata(self) -> Dict[str, Any]:
        return copy.deepcopy(dict(self._public_key_metadata))

    @property
    def evidence(self) -> Dict[str, Any]:
        return copy.deepcopy(dict(self._evidence))

    def write_new_directory(self, output_dir: Path) -> None:
        output_dir = Path(output_dir)
        if output_dir.exists() or output_dir.is_symlink():
            _fail("output directory must not already exist")
        output_dir.mkdir(mode=0o700, parents=False)
        output_dir.chmod(0o700)
        artifacts_dir = output_dir / "artifacts"
        artifacts_dir.mkdir(mode=0o700)

        files: Dict[Path, bytes] = {
            output_dir / "signed-envelope.json": self.envelope_bytes,
            output_dir / "signing-public-key.json": manifest_tool.canonical_json_bytes(
                self.public_key_metadata
            ),
            output_dir
            / "materialization-evidence.json": manifest_tool.canonical_json_bytes(
                self.evidence
            ),
            artifacts_dir / "compile-evidence.json": self.compile_evidence,
        }
        for name, content in self.artifacts.items():
            files[artifacts_dir / name] = content
        for path, content in sorted(files.items(), key=lambda item: str(item[0])):
            with path.open("xb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            path.chmod(0o600)


def materialize_first_tenant(
    profile: FirstTenantProfile,
    node_facts: NodeFacts,
    *,
    private_seed_path: Path,
    key_id: str,
    issued_at: datetime,
) -> MaterializedRelease:
    """Build, validate, compile-check and sign one node-specific ACTIVE envelope."""

    if not isinstance(profile, FirstTenantProfile):
        _fail("profile must be a validated FirstTenantProfile")
    profile = FirstTenantProfile.from_mapping(profile.canonical_record())
    if not isinstance(node_facts, NodeFacts):
        _fail("node_facts must be validated NodeFacts")
    facts = NodeFacts.from_mapping(node_facts.canonical_record())
    _identifier(key_id, "key id")
    issued_text = _timestamp(issued_at)
    issued_at = datetime.strptime(issued_text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    record = profile.canonical_record()
    _bind_profile_to_facts(record, facts)

    seed = _read_private_seed(Path(private_seed_path))
    public_bytes = _public_key_bytes(seed)
    public_metadata = _public_metadata(key_id, public_bytes)

    manifest = _build_manifest(record, facts, issued_at)
    draft_envelope = {"manifest": manifest}
    effective = compiler_core._extract_effective(draft_envelope, facts)
    rendered_by_kind = compiler_core._render_artifacts(effective, facts)
    declarations = {
        declaration["kind"]: declaration
        for declaration in manifest["resourceSet"]["artifacts"]
    }
    for kind, content in rendered_by_kind.items():
        digest = _content_digest(content)
        declaration = declarations[kind]
        declaration["applyOrder"] = compiler_core.ARTIFACT_APPLY_ORDER[kind]
        declaration["mediaType"] = compiler_core.ARTIFACT_MEDIA_TYPES[kind]
        declaration["sha256"] = digest
        declaration["sizeBytes"] = len(content)
        declaration["fetchPath"] = "/v0.1/artifacts/sha256/" + digest.split(":", 1)[1]

    digest = manifest_tool.manifest_digest(manifest)
    signature = _sign_manifest(seed, manifest)
    envelope: Dict[str, Any] = {
        "apiVersion": manifest_tool.API_VERSION,
        "kind": manifest_tool.KIND,
        "manifest": manifest,
        "manifestDigest": digest,
        "signatures": [
            {
                "algorithm": "Ed25519",
                "createdAt": issued_text,
                "keyId": key_id,
                "value": base64.b64encode(signature).decode("ascii"),
            }
        ],
    }

    # Validate exactly what will be emitted using both the portable schema and
    # semantic contract, then verify the fresh signature through the Edge code.
    try:
        agent_security.validate_structural_envelope(envelope)
        manifest_tool.validate_envelope(
            envelope, _validation_context(record, facts, issued_at)
        )
        verified = agent_security.verify_authorized_signatures(
            envelope, agent_security.PinnedKeyring({key_id: public_bytes})
        )
    except Exception as exc:
        _fail("finished envelope failed local Edge validation: {}".format(exc))
    if verified != (key_id,):
        _fail("finished envelope did not verify with the explicit key id")

    _, local_health_gate_plan_digest = compiler_core.build_local_health_gate_plan(
        manifest
    )
    receipt = VerificationReceipt.from_mapping(
        {
            "localHealthGatePlanDigest": local_health_gate_plan_digest,
            "manifestDigest": digest,
            "manifestId": manifest["manifestId"],
            "sequence": manifest["sequence"],
            "status": compiler_core.VERIFIED_STATUS,
            "verifiedKeyIds": [key_id],
        }
    )
    compiled = compiler_core.compile_tenant_bundle(envelope, facts, receipt)
    expected_artifacts = {
        compiler_core.ARTIFACT_FILENAMES[kind]: content
        for kind, content in rendered_by_kind.items()
    }
    if dict(compiled.artifacts) != expected_artifacts:
        _fail("compiler revalidation returned bytes different from pre-sign rendering")

    artifact_metadata = {}
    for filename, content in sorted(compiled.artifacts.items()):
        content_digest = _content_digest(content)
        artifact_metadata[filename] = {
            "fetchPath": "/v0.1/artifacts/sha256/" + content_digest.split(":", 1)[1],
            "sha256": content_digest,
            "sizeBytes": len(content),
        }
    envelope_bytes = manifest_tool.canonical_json_bytes(envelope)
    direct_routing = record["kind"] in _LIVE_DIRECT_PROFILE_KINDS
    private_pbx_poc = (
        record["kind"] == DIRECT_ROUTING_PRIVATE_PBX_POC_PROFILE_KIND
    )
    readiness = {
        "callRateLimitEnforced": False,
        "codecPolicyEnforced": False,
        "liveTeamsInteroperability": (
            "REQUIRES_EXTERNAL_QUALIFICATION" if direct_routing else "NOT_ASSERTED"
        ),
        "pstnConnectivity": "NOT_ASSERTED" if direct_routing else "NOT_CONFIGURED",
        "runtimeApplied": False,
        "signedArtifactDeclarationsCompilerChecked": True,
        "syntheticFixtureAuthority": (
            "NOT_CONFIGURED" if direct_routing else "EXTERNAL_FIXED_ROOT_RUNTIME_POLICY"
        ),
    }
    evidence = {
        "apiVersion": MATERIALIZER_API_VERSION,
        "artifactFiles": artifact_metadata,
        "compilerEvidenceSha256": _content_digest(compiled.evidence),
        "envelopeSha256": _content_digest(envelope_bytes),
        "expiresAt": manifest["expiresAt"],
        "factsDigest": _canonical_digest(facts.canonical_record()),
        "issuedAt": issued_text,
        "keyId": key_id,
        "kind": "FirstTenantMaterializationEvidence",
        "manifestDigest": digest,
        "manifestId": manifest["manifestId"],
        "nodeId": facts.node_id,
        "profileDigest": _canonical_digest(record),
        "publicKeySha256": public_metadata["publicKeySha256"],
        "readiness": readiness,
        "sequence": manifest["sequence"],
        "status": "SIGNED_AND_LOCALLY_VALIDATED_NOT_APPLIED",
    }
    if direct_routing:
        evidence.update(
            {
                "deploymentMode": (
                    DIRECT_ROUTING_PRIVATE_PBX_POC_DEPLOYMENT_MODE
                    if private_pbx_poc
                    else DIRECT_ROUTING_DEPLOYMENT_MODE
                ),
                "microsoftTargets": copy.deepcopy(record["microsoftTargets"]),
                "pbxMediaDestinationPortRange": {
                    "end": facts.pbx_media_destination_port_end,
                    "start": facts.pbx_media_destination_port_start,
                },
                "profileKind": record["kind"],
            }
        )
        if private_pbx_poc:
            evidence["pocBoundary"] = (
                "PUBLIC_MICROSOFT_DIRECT_ROUTING_WITH_FIXED_PRIVATE_CP1_PBX_NO_PRODUCTION_CLAIM"
            )
    return MaterializedRelease(
        _envelope_bytes=envelope_bytes,
        artifacts=MappingProxyType(dict(compiled.artifacts)),
        compile_evidence=compiled.evidence,
        _public_key_metadata=MappingProxyType(public_metadata),
        _evidence=MappingProxyType(evidence),
    )
