#!/usr/bin/env python3
"""Fail-closed compiler for the bounded first-tenant Open Edge POC.

The compiler is deliberately not a signature verifier or an activation helper.
Its caller must supply the exact receipt returned by the trusted Edge verifier.
The receipt binds the immutable signed manifest bytes to this compilation, while
locally provisioned node facts remain authoritative for networking and target
identity.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, Iterable, Mapping, Sequence, Tuple

from edge.schema import manifest_tool


COMPILER_API_VERSION = "edge.vivolution.ae/compiler/v0.1"
LOCAL_HEALTH_PLAN_API_VERSION = "edge.vivolution.ae/local-health-plan/v0.1"
LOCAL_HEALTH_PLAN_KIND = "TenantLocalHealthGatePlan"
VERIFIED_STATUS = "VERIFIED_AND_STAGED_METADATA_ONLY"

TEAMS_TLS_PORT = 5061
PBX_TLS_LISTENER_PORT = 15061
OPTIONS_INTERVAL_SECONDS = 60
LOCAL_HEALTH_GATE_ORDER = (
    "ARTIFACT_DIGESTS",
    "OPENSIPS_CONFIG",
    "RTPENGINE_READY",
)
LOCAL_HEALTH_GATE_PARAMETERS = {
    "ARTIFACT_DIGESTS": (30, 1),
    "OPENSIPS_CONFIG": (30, 1),
    "RTPENGINE_READY": (30, 3),
}
MAX_PBX_MEDIA_DESTINATION_PORTS = 4096
CLUSTER_MEDIA_PORT_START = 20000
CLUSTER_MEDIA_PORT_END = 29999
TENANT_MEDIA_PORT_START = 20000
TENANT_MEDIA_PORT_END = 20255
RTPENGINE_NG_HOST = "127.0.0.1"
RTPENGINE_NG_PORT = 2223
RTPENGINE_CLI_PORT = 2224
TEAMS_PRIMARY_UPSTREAM = "sip.pstnhub.microsoft.com"
SYNTHETIC_CDR_MARKER = "VIVO_SYNTHETIC_CDR_V1"
SYNTHETIC_CDR_TEST_ID_REGEX = (
    "^[0-9]{8}T[0-9]{6}Z-sbc[12]-[0-9]{1,10}$"
)

ARTIFACT_MEDIA_TYPES = {
    "OPENSIPS_TENANT_CONFIG": "text/plain",
    "RTPENGINE_TENANT_CONFIG": "application/toml",
    "NFTABLES_TENANT_POLICY": "application/json",
}
ARTIFACT_APPLY_ORDER = {
    "OPENSIPS_TENANT_CONFIG": 10,
    "RTPENGINE_TENANT_CONFIG": 20,
    "NFTABLES_TENANT_POLICY": 30,
}
ARTIFACT_FILENAMES = {
    "OPENSIPS_TENANT_CONFIG": "opensips-tenant.cfg",
    "RTPENGINE_TENANT_CONFIG": "rtpengine-tenant.conf",
    "NFTABLES_TENANT_POLICY": "nftables-tenant-policy.json",
}

_FQDN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_RECEIPT_FIELDS = {
    "localHealthGatePlanDigest",
    "manifestDigest",
    "manifestId",
    "sequence",
    "status",
    "verifiedKeyIds",
}
_FACT_FIELDS = {
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


class CompileError(ValueError):
    """The candidate cannot be compiled without weakening a fixed invariant."""


def _fail(message: str) -> None:
    raise CompileError(message)


def _exact_mapping(value: Any, fields: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail("{} must be an object".format(name))
    actual = set(value)
    missing = sorted(fields - actual)
    extra = sorted(actual - fields)
    if missing or extra:
        _fail("{} members differ: missing={} extra={}".format(name, missing, extra))
    return value


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or manifest_tool.ID_RE.fullmatch(value) is None:
        _fail("{} must be a lowercase v0.1 identifier".format(name))
    return value


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        _fail("{} must be an integer from {} through {}".format(name, minimum, maximum))
    return value


def _fqdn(value: Any, name: str, node_id: str | None = None) -> str:
    if not isinstance(value, str) or value != value.lower() or not 1 <= len(value) <= 253:
        _fail("{} must be a canonical lowercase ASCII FQDN".format(name))
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        _fail("{} must be a canonical lowercase ASCII FQDN".format(name))
    labels = value.split(".")
    if len(labels) < 2 or any(_FQDN_LABEL_RE.fullmatch(label) is None for label in labels):
        _fail("{} must be a canonical lowercase ASCII FQDN".format(name))
    if value.endswith(".onmicrosoft.com"):
        _fail("{} cannot use an onmicrosoft.com Direct Routing identity".format(name))
    if node_id is not None and labels[0] != node_id:
        _fail("{} must be node-specific and begin with {}.".format(name, node_id))
    return value


def _ipv4(value: Any, name: str) -> ipaddress.IPv4Address:
    if not isinstance(value, str):
        _fail("{} must be a canonical IPv4 address".format(name))
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        _fail("{} must be a canonical IPv4 address".format(name))
    if not isinstance(parsed, ipaddress.IPv4Address) or str(parsed) != value:
        _fail("{} must be a canonical IPv4 address".format(name))
    return parsed


_RFC1918 = tuple(
    ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def _is_rfc1918(address: ipaddress.IPv4Address) -> bool:
    return any(address in network for network in _RFC1918)


def _cidr_tuple(
    value: Any,
    name: str,
    *,
    private: bool | None,
    minimum_prefix: int,
    maximum_items: int,
    allow_empty: bool = False,
) -> Tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        _fail("{} must be an array of canonical IPv4 CIDRs".format(name))
    if not value and not allow_empty:
        _fail("{} must contain at least one CIDR".format(name))
    if len(value) > maximum_items:
        _fail("{} contains too many CIDRs".format(name))
    result = []
    seen = set()
    for item in value:
        if not isinstance(item, str):
            _fail("{} must contain only canonical IPv4 CIDRs".format(name))
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError:
            _fail("{} contains invalid or non-canonical CIDR {!r}".format(name, item))
        if not isinstance(network, ipaddress.IPv4Network) or str(network) != item:
            _fail("{} must contain only canonical IPv4 CIDRs".format(name))
        if (
            network.is_loopback
            or network.is_link_local
            or network.is_multicast
            or network.network_address.is_unspecified
        ):
            _fail("{} CIDR {} is not an admissible peer network".format(name, item))
        if network.prefixlen < minimum_prefix:
            _fail("{} CIDR {} is broader than /{}".format(name, item, minimum_prefix))
        network_private = all(_is_rfc1918(address) for address in (network.network_address, network.broadcast_address))
        if private is True and not network_private:
            _fail("{} CIDR {} must be RFC1918 private space".format(name, item))
        if private is False and (network_private or not network.network_address.is_global):
            _fail("{} CIDR {} must be globally routable IPv4 space".format(name, item))
        if item in seen:
            _fail("{} contains duplicate CIDR {}".format(name, item))
        seen.add(item)
        result.append(item)
    return tuple(sorted(result, key=lambda item: (int(ipaddress.ip_network(item).network_address), ipaddress.ip_network(item).prefixlen)))


def _networks_overlap(first: Iterable[str], second: Iterable[str]) -> bool:
    left = [ipaddress.ip_network(value) for value in first]
    right = [ipaddress.ip_network(value) for value in second]
    return any(one.overlaps(two) for one in left for two in right)


@dataclass(frozen=True)
class VerificationReceipt:
    """Exact trusted verifier result for one immutable candidate."""

    manifest_digest: str
    manifest_id: str
    sequence: int
    local_health_gate_plan_digest: str
    verified_key_ids: Tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Any) -> "VerificationReceipt":
        record = _exact_mapping(value, _RECEIPT_FIELDS, "verification receipt")
        if record["status"] != VERIFIED_STATUS:
            _fail("verification receipt does not assert staged cryptographic verification")
        digest = record["manifestDigest"]
        if not isinstance(digest, str) or manifest_tool.DIGEST_RE.fullmatch(digest) is None:
            _fail("verification receipt manifestDigest is invalid")
        manifest_id = _identifier(record["manifestId"], "verification receipt manifestId")
        sequence = _integer(record["sequence"], "verification receipt sequence", 1, 2**63 - 1)
        plan_digest = record["localHealthGatePlanDigest"]
        if (
            not isinstance(plan_digest, str)
            or manifest_tool.DIGEST_RE.fullmatch(plan_digest) is None
        ):
            _fail("verification receipt localHealthGatePlanDigest is invalid")
        raw_keys = record["verifiedKeyIds"]
        if not isinstance(raw_keys, list) or not raw_keys:
            _fail("verification receipt must contain at least one verified key id")
        keys = tuple(_identifier(item, "verified key id") for item in raw_keys)
        if len(set(keys)) != len(keys) or tuple(sorted(keys)) != keys:
            _fail("verification receipt key ids must be unique and sorted")
        return cls(digest, manifest_id, sequence, plan_digest, keys)

    def canonical_record(self) -> Dict[str, Any]:
        return {
            "localHealthGatePlanDigest": self.local_health_gate_plan_digest,
            "manifestDigest": self.manifest_digest,
            "manifestId": self.manifest_id,
            "sequence": self.sequence,
            "status": VERIFIED_STATUS,
            "verifiedKeyIds": list(self.verified_key_ids),
        }


@dataclass(frozen=True)
class NodeFacts:
    """Locally trusted target and network facts; never populated from a manifest."""

    cluster_id: str
    node_id: str
    generation: int
    slot: str
    customer_account_id: str
    m365_tenant_id: str
    tenant_context_id: str
    service_instance_id: str
    allocation_id: str
    private_ipv4: str
    public_ipv4: str
    node_fqdn: str
    authorized_pbx_source_ipv4_cidrs: Tuple[str, ...]
    teams_signaling_source_ipv4_cidrs: Tuple[str, ...]
    teams_media_source_ipv4_cidrs: Tuple[str, ...]
    synthetic_teams_source_ipv4_cidrs: Tuple[str, ...]
    teams_tls_port: int
    tenant_listener_port: int
    tenant_media_port_start: int
    tenant_media_port_end: int
    pbx_media_destination_port_start: int
    pbx_media_destination_port_end: int
    cluster_media_port_start: int
    cluster_media_port_end: int
    rtpengine_ng_host: str
    rtpengine_ng_port: int

    @classmethod
    def from_mapping(cls, value: Any) -> "NodeFacts":
        record = _exact_mapping(value, _FACT_FIELDS, "node facts")
        cluster_id = _identifier(record["clusterId"], "node facts clusterId")
        node_id = _identifier(record["nodeId"], "node facts nodeId")
        generation = _integer(record["generation"], "node facts generation", 1, 2**31 - 1)
        slot = record["slot"]
        if slot not in {"A", "B"}:
            _fail("node facts slot must be A or B")
        customer = _identifier(record["customerAccountId"], "node facts customerAccountId")
        tenant_context = _identifier(record["tenantContextId"], "node facts tenantContextId")
        service = _identifier(record["serviceInstanceId"], "node facts serviceInstanceId")
        allocation = _identifier(record["allocationId"], "node facts allocationId")
        m365 = record["m365TenantId"]
        if not isinstance(m365, str) or manifest_tool.M365_TENANT_RE.fullmatch(m365) is None:
            _fail("node facts m365TenantId must be a lowercase RFC 4122 UUID")

        private = _ipv4(record["privateIpv4"], "node facts privateIpv4")
        public = _ipv4(record["publicIpv4"], "node facts publicIpv4")
        if not _is_rfc1918(private):
            _fail("node facts privateIpv4 must be RFC1918 space")
        if not public.is_global:
            _fail("node facts publicIpv4 must be globally routable")
        if private == public:
            _fail("node private and public addresses must differ")
        fqdn = _fqdn(record["nodeFqdn"], "node facts nodeFqdn", node_id)

        pbx_sources = _cidr_tuple(
            record["authorizedPbxSourceIpv4Cidrs"],
            "node facts authorizedPbxSourceIpv4Cidrs",
            private=None,
            minimum_prefix=24,
            maximum_items=16,
        )
        signaling = _cidr_tuple(
            record["teamsSignalingSourceIpv4Cidrs"],
            "node facts teamsSignalingSourceIpv4Cidrs",
            private=False,
            minimum_prefix=8,
            maximum_items=32,
        )
        media = _cidr_tuple(
            record["teamsMediaSourceIpv4Cidrs"],
            "node facts teamsMediaSourceIpv4Cidrs",
            private=False,
            minimum_prefix=8,
            maximum_items=32,
        )
        synthetic = _cidr_tuple(
            record["syntheticTeamsSourceIpv4Cidrs"],
            "node facts syntheticTeamsSourceIpv4Cidrs",
            private=True,
            minimum_prefix=24,
            maximum_items=8,
            allow_empty=True,
        )
        if _networks_overlap(pbx_sources, signaling + media):
            _fail("PBX source authority overlaps Microsoft source authority")
        if _networks_overlap(pbx_sources, synthetic):
            _fail("PBX source authority overlaps synthetic Teams source authority")

        teams_port = _integer(record["teamsTlsPort"], "node facts teamsTlsPort", 1, 65535)
        listener_port = _integer(record["tenantListenerPort"], "node facts tenantListenerPort", 1, 65535)
        tenant_start = _integer(record["tenantMediaPortStart"], "node facts tenantMediaPortStart", 1024, 65534)
        tenant_end = _integer(record["tenantMediaPortEnd"], "node facts tenantMediaPortEnd", 1025, 65535)
        pbx_media_start = _integer(
            record["pbxMediaDestinationPortStart"],
            "node facts pbxMediaDestinationPortStart",
            1024,
            65534,
        )
        pbx_media_end = _integer(
            record["pbxMediaDestinationPortEnd"],
            "node facts pbxMediaDestinationPortEnd",
            1025,
            65535,
        )
        cluster_start = _integer(record["clusterMediaPortStart"], "node facts clusterMediaPortStart", 1024, 65534)
        cluster_end = _integer(record["clusterMediaPortEnd"], "node facts clusterMediaPortEnd", 1025, 65535)
        ng_host = record["rtpengineNgHost"]
        ng_port = _integer(record["rtpengineNgPort"], "node facts rtpengineNgPort", 1024, 65535)

        fixed = (
            (teams_port, TEAMS_TLS_PORT, "teamsTlsPort"),
            (listener_port, PBX_TLS_LISTENER_PORT, "tenantListenerPort"),
            (tenant_start, TENANT_MEDIA_PORT_START, "tenantMediaPortStart"),
            (tenant_end, TENANT_MEDIA_PORT_END, "tenantMediaPortEnd"),
            (cluster_start, CLUSTER_MEDIA_PORT_START, "clusterMediaPortStart"),
            (cluster_end, CLUSTER_MEDIA_PORT_END, "clusterMediaPortEnd"),
            (ng_host, RTPENGINE_NG_HOST, "rtpengineNgHost"),
            (ng_port, RTPENGINE_NG_PORT, "rtpengineNgPort"),
        )
        for actual, expected, name in fixed:
            if actual != expected:
                _fail("node facts {} must equal fixed POC value {}".format(name, expected))
        occupied = {teams_port, listener_port, ng_port, RTPENGINE_CLI_PORT}
        if len(occupied) != 4:
            _fail("signaling and RTPengine control ports collide")
        if any(cluster_start <= port <= cluster_end for port in occupied):
            _fail("a signaling or control port collides with the cluster media pool")
        if tenant_start % 2 or tenant_end % 2 != 1 or not cluster_start <= tenant_start <= tenant_end <= cluster_end:
            _fail("tenant media allocation is invalid or outside the cluster pool")
        if (
            pbx_media_start % 2
            or pbx_media_end % 2 != 1
            or pbx_media_start > pbx_media_end
        ):
            _fail(
                "PBX media destination range must start even, end odd, and be ordered"
            )
        if pbx_media_end - pbx_media_start + 1 > MAX_PBX_MEDIA_DESTINATION_PORTS:
            _fail(
                "PBX media destination range exceeds {} UDP ports".format(
                    MAX_PBX_MEDIA_DESTINATION_PORTS
                )
            )
        pbx_media_collisions = sorted(
            port
            for port in occupied
            if pbx_media_start <= port <= pbx_media_end
        )
        if pbx_media_collisions:
            _fail(
                "PBX media destination range collides with signaling/control ports {}".format(
                    pbx_media_collisions
                )
            )

        return cls(
            cluster_id,
            node_id,
            generation,
            slot,
            customer,
            m365,
            tenant_context,
            service,
            allocation,
            str(private),
            str(public),
            fqdn,
            pbx_sources,
            signaling,
            media,
            synthetic,
            teams_port,
            listener_port,
            tenant_start,
            tenant_end,
            pbx_media_start,
            pbx_media_end,
            cluster_start,
            cluster_end,
            str(ng_host),
            ng_port,
        )

    def canonical_record(self) -> Dict[str, Any]:
        return {
            "allocationId": self.allocation_id,
            "authorizedPbxSourceIpv4Cidrs": list(self.authorized_pbx_source_ipv4_cidrs),
            "clusterId": self.cluster_id,
            "clusterMediaPortEnd": self.cluster_media_port_end,
            "clusterMediaPortStart": self.cluster_media_port_start,
            "customerAccountId": self.customer_account_id,
            "generation": self.generation,
            "m365TenantId": self.m365_tenant_id,
            "nodeFqdn": self.node_fqdn,
            "nodeId": self.node_id,
            "privateIpv4": self.private_ipv4,
            "publicIpv4": self.public_ipv4,
            "pbxMediaDestinationPortEnd": self.pbx_media_destination_port_end,
            "pbxMediaDestinationPortStart": self.pbx_media_destination_port_start,
            "rtpengineNgHost": self.rtpengine_ng_host,
            "rtpengineNgPort": self.rtpengine_ng_port,
            "serviceInstanceId": self.service_instance_id,
            "slot": self.slot,
            "syntheticTeamsSourceIpv4Cidrs": list(self.synthetic_teams_source_ipv4_cidrs),
            "teamsMediaSourceIpv4Cidrs": list(self.teams_media_source_ipv4_cidrs),
            "teamsSignalingSourceIpv4Cidrs": list(self.teams_signaling_source_ipv4_cidrs),
            "teamsTlsPort": self.teams_tls_port,
            "tenantContextId": self.tenant_context_id,
            "tenantListenerPort": self.tenant_listener_port,
            "tenantMediaPortEnd": self.tenant_media_port_end,
            "tenantMediaPortStart": self.tenant_media_port_start,
        }


@dataclass(frozen=True)
class _EffectiveTenant:
    tenant_context_id: str
    allocation_id: str
    connector_host: str
    connector_port: int
    connector_tls_server_name: str
    options_interval_seconds: int
    pbx_media_destination_port_start: int
    pbx_media_destination_port_end: int
    pbx_source_cidrs: Tuple[str, ...]
    called_number_prefix: str
    max_sessions: int
    max_calls_per_second: int
    max_bandwidth_kbps: int
    codecs: Tuple[str, ...]
    artifacts: Mapping[str, Mapping[str, Any]]


@dataclass(frozen=True)
class CompiledBundle:
    """Immutable deterministic artifact bytes and non-secret compile evidence."""

    artifacts: Mapping[str, bytes]
    evidence: bytes

    def all_files(self) -> Mapping[str, bytes]:
        files = dict(self.artifacts)
        files["compile-evidence.json"] = self.evidence
        return MappingProxyType(files)

    def write_new_directory(self, output_dir: Path) -> None:
        """Write to a brand-new directory; never merge with active state."""

        if output_dir.exists() or output_dir.is_symlink():
            _fail("output directory must not already exist")
        output_dir.mkdir(mode=0o700, parents=False)
        try:
            for name, content in sorted(self.all_files().items()):
                path = output_dir / name
                path.write_bytes(content)
                path.chmod(0o600)
        except Exception:
            # Leave the new, never-active directory for inspection; do not hide
            # a partial write or remove a path the caller may already be using.
            raise


def _parse_issued_at(manifest: Mapping[str, Any]) -> datetime:
    value = manifest.get("issuedAt")
    if not isinstance(value, str):
        _fail("manifest issuedAt is missing")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        _fail("manifest issuedAt is invalid")


def _revalidate_contract(envelope: Mapping[str, Any], facts: NodeFacts) -> None:
    manifest = envelope.get("manifest")
    if not isinstance(manifest, Mapping):
        _fail("signed envelope does not contain a manifest object")
    sequence = manifest.get("sequence")
    rollback = manifest.get("rollbackTarget")
    if sequence == 1:
        accepted_sequence = 0
        accepted_digest = None
    elif isinstance(rollback, Mapping):
        accepted_sequence = rollback.get("sequence")
        accepted_digest = rollback.get("manifestDigest")
    else:
        _fail("non-initial manifest lacks rollback lineage")
    if isinstance(accepted_sequence, bool) or not isinstance(accepted_sequence, int):
        _fail("rollback lineage sequence is invalid")
    context = manifest_tool.ValidationContext(
        expected_cluster_id=facts.cluster_id,
        expected_node_id=facts.node_id,
        expected_generation=facts.generation,
        accepted_sequence=accepted_sequence,
        accepted_digest=accepted_digest,
        now=_parse_issued_at(manifest),
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
    try:
        manifest_tool.validate_envelope(envelope, context)
    except manifest_tool.ContractError as exc:
        _fail("manifest contract rejected: {}".format("; ".join(exc.errors)))


def _resource_map(manifest: Mapping[str, Any]) -> Dict[str, list[Mapping[str, Any]]]:
    resources = manifest["resourceSet"]["resources"]
    grouped: Dict[str, list[Mapping[str, Any]]] = {}
    for resource in resources:
        grouped.setdefault(resource["type"], []).append(resource)
    return grouped


def _one(grouped: Mapping[str, Sequence[Mapping[str, Any]]], kind: str) -> Mapping[str, Any]:
    values = grouped.get(kind, ())
    if len(values) != 1:
        _fail("first-tenant compiler requires exactly one {} resource".format(kind))
    return values[0]


def _strict_host(value: Any, name: str, *, tls_name: bool = False) -> str:
    if isinstance(value, str):
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return _fqdn(value, name)
        if tls_name:
            _fail("{} must be a DNS name for TLS server-name validation".format(name))
        if isinstance(parsed, ipaddress.IPv4Address) and str(parsed) == value:
            return value
    _fail("{} must be a canonical lowercase FQDN or IPv4 address".format(name))


def _extract_effective(envelope: Mapping[str, Any], facts: NodeFacts) -> _EffectiveTenant:
    manifest = envelope["manifest"]
    if manifest.get("lifecycle") != "ACTIVE":
        _fail(
            "first-tenant compiler accepts lifecycle ACTIVE only; cleanup/decommission "
            "requires a separately reviewed compiler path"
        )
    target = manifest["target"]
    tenant = target["tenant"]
    expected_target = {
        "clusterId": facts.cluster_id,
        "nodeId": facts.node_id,
        "generation": facts.generation,
        "slot": facts.slot,
    }
    for field, expected in expected_target.items():
        if target.get(field) != expected:
            _fail("manifest target {} does not match local node facts".format(field))
    tenant_pairs = {
        "customerAccountId": facts.customer_account_id,
        "m365TenantId": facts.m365_tenant_id,
        "tenantContextId": facts.tenant_context_id,
        "serviceInstanceId": facts.service_instance_id,
        "allocationId": facts.allocation_id,
    }
    for field, expected in tenant_pairs.items():
        if tenant.get(field) != expected:
            _fail("manifest target tenant {} crosses local tenant authority".format(field))

    grouped = _resource_map(manifest)
    connector = _one(grouped, "tenant.connector")
    listener = _one(grouped, "tenant.listener")
    media = _one(grouped, "tenant.media")
    capacity = _one(grouped, "tenant.capacity")
    routes = grouped.get("tenant.route", ())
    if len(routes) != 2:
        _fail("first-tenant compiler requires exactly two directional routes")
    by_direction: Dict[str, Mapping[str, Any]] = {}
    for route in routes:
        spec = route["spec"]
        direction = spec["direction"]
        if direction in by_direction:
            _fail("duplicate route direction {}".format(direction))
        by_direction[direction] = route
    if set(by_direction) != {"TEAMS_TO_PBX", "PBX_TO_TEAMS"}:
        _fail("both TEAMS_TO_PBX and PBX_TO_TEAMS routes are required")
    for direction, route in by_direction.items():
        spec = route["spec"]
        if spec["enabled"] is not True:
            _fail("{} route must be enabled for the first-tenant POC".format(direction))
        if spec["connectorRef"] != connector["resourceId"]:
            _fail("{} route crosses its authorized connector".format(direction))
    prefixes = {route["spec"]["calledNumberPrefix"] for route in routes}
    if len(prefixes) != 1:
        _fail("both directional routes must use the same called-number prefix")
    prefix = next(iter(prefixes))

    connector_spec = connector["spec"]
    listener_spec = listener["spec"]
    media_spec = media["spec"]
    capacity_spec = capacity["spec"]
    pbx_connector_cidrs = _cidr_tuple(
        connector_spec["sourceCidrs"],
        "PBX connector sourceCidrs",
        private=None,
        minimum_prefix=24,
        maximum_items=16,
    )
    pbx_listener_cidrs = _cidr_tuple(
        listener_spec["allowedSourceCidrs"],
        "PBX listener allowedSourceCidrs",
        private=None,
        minimum_prefix=24,
        maximum_items=16,
    )
    if pbx_connector_cidrs != pbx_listener_cidrs:
        _fail("PBX connector and listener source CIDRs must match exactly")
    if pbx_listener_cidrs != facts.authorized_pbx_source_ipv4_cidrs:
        _fail("PBX source CIDRs must exactly match locally authorized node facts")
    if (
        connector_spec["mediaDestinationPortStart"],
        connector_spec["mediaDestinationPortEnd"],
    ) != (
        facts.pbx_media_destination_port_start,
        facts.pbx_media_destination_port_end,
    ):
        _fail(
            "PBX media destination range must exactly match locally authorized node facts"
        )
    teams_sources = facts.teams_signaling_source_ipv4_cidrs + facts.teams_media_source_ipv4_cidrs
    if _networks_overlap(pbx_listener_cidrs, teams_sources):
        _fail("PBX source CIDRs overlap Microsoft source authority")
    if _networks_overlap(pbx_listener_cidrs, facts.synthetic_teams_source_ipv4_cidrs):
        _fail("PBX source CIDRs overlap synthetic Teams source authority")

    if listener_spec["port"] != facts.tenant_listener_port:
        _fail("PBX listener does not match the fixed local allocation")
    if media_spec["advertisedAddress"] != facts.public_ipv4:
        _fail("manifest media advertisedAddress does not match local public IPv4")
    if (media_spec["portStart"], media_spec["portEnd"]) != (
        facts.tenant_media_port_start,
        facts.tenant_media_port_end,
    ):
        _fail("manifest media range does not match the fixed local allocation")
    if not facts.tenant_context_id.startswith("tenant-"):
        _fail("tenantContextId must use the tenant- namespace for fixed RTP identity")
    expected_unit_key = "rtp-" + facts.tenant_context_id.removeprefix("tenant-")
    if media_spec["unitKey"] != expected_unit_key or len(expected_unit_key) > 128:
        _fail("manifest RTPengine unitKey is not the fixed tenant-derived identity")
    max_sessions = media_spec["maxSessions"]
    available_sessions = (facts.tenant_media_port_end - facts.tenant_media_port_start + 1) // 4
    if max_sessions > available_sessions:
        _fail("manifest maxSessions exceeds four-port media allocation capacity")
    if capacity_spec["maxConcurrentSessions"] != max_sessions:
        _fail("tenant capacity and RTPengine maxSessions must match")
    if (
        facts.pbx_media_destination_port_end
        - facts.pbx_media_destination_port_start
        + 1
    ) // 2 < max_sessions:
        _fail(
            "PBX media destination range cannot serve all reviewed non-muxed sessions"
        )

    artifacts: Dict[str, Mapping[str, Any]] = {}
    for artifact in manifest["resourceSet"]["artifacts"]:
        kind = artifact["kind"]
        if kind in artifacts:
            _fail("first-tenant compiler requires exactly one artifact of kind {}".format(kind))
        artifacts[kind] = artifact
    if set(artifacts) != set(ARTIFACT_MEDIA_TYPES):
        _fail("first-tenant manifest must declare exactly the three compiler artifact kinds")

    connector_host = _strict_host(connector_spec["remoteHost"], "PBX remoteHost")
    connector_tls_name = _strict_host(
        connector_spec["tlsServerName"], "PBX tlsServerName", tls_name=True
    )
    if connector_host != connector_tls_name:
        _fail(
            "first-tenant POC requires PBX remoteHost to equal tlsServerName; "
            "separate resolution and SNI identities are not implemented"
        )
    options_interval_seconds = connector_spec["optionsIntervalSeconds"]
    if (
        isinstance(options_interval_seconds, bool)
        or options_interval_seconds != OPTIONS_INTERVAL_SECONDS
    ):
        _fail("PBX optionsIntervalSeconds must be the reviewed value 60")

    return _EffectiveTenant(
        tenant_context_id=facts.tenant_context_id,
        allocation_id=facts.allocation_id,
        connector_host=connector_host,
        connector_port=connector_spec["remotePort"],
        connector_tls_server_name=connector_tls_name,
        options_interval_seconds=options_interval_seconds,
        pbx_media_destination_port_start=facts.pbx_media_destination_port_start,
        pbx_media_destination_port_end=facts.pbx_media_destination_port_end,
        pbx_source_cidrs=pbx_listener_cidrs,
        called_number_prefix=prefix,
        max_sessions=max_sessions,
        max_calls_per_second=capacity_spec["maxCallsPerSecond"],
        max_bandwidth_kbps=capacity_spec["maxBandwidthKbps"],
        codecs=tuple(media_spec["codecs"]),
        artifacts=MappingProxyType(artifacts),
    )


def _tenant_token(effective: _EffectiveTenant, facts: NodeFacts) -> str:
    material = "{}\0{}\0{}".format(
        effective.tenant_context_id, effective.allocation_id, facts.node_id
    ).encode("ascii")
    return hashlib.sha256(material).hexdigest()[:12].upper()


def _synthetic_cdr_start(token: str, direction: str) -> str:
    """Render the optional, synthetic-only transaction accounting hook.

    The active privileged renderer defines ``VIVO_SYNTHETIC_CDR`` only for the
    ``SYNTHETIC_PRIVATE`` runtime profile.  Direct Routing therefore compiles
    the same signed tenant artifact but preprocesses every hook out before
    OpenSIPS parses the active configuration.
    """

    return f'''#!ifdef VIVO_SYNTHETIC_CDR
    if ($hdr(X-Vivolution-Fixture) == "no-pstn" &&
        ($hdr(X-Vivolution-Test-ID) =~ "{SYNTHETIC_CDR_TEST_ID_REGEX}")) {{
        $avp(vivo_synth_test_id) = $hdr(X-Vivolution-Test-ID);
        $avp(vivo_synth_direction) = "{direction}";
        $avp(vivo_synth_final_logged) = 0;
        xlog("L_NOTICE", "{SYNTHETIC_CDR_MARKER}|event=START|route={token}|direction=$avp(vivo_synth_direction)|test_id=$avp(vivo_synth_test_id)\\n");
    }}
#!endif'''


def _synthetic_cdr_final(token: str, result: str, indentation: str = "    ") -> str:
    return f'''#!ifdef VIVO_SYNTHETIC_CDR
{indentation}if ($avp(vivo_synth_test_id) != NULL &&
{indentation}    $avp(vivo_synth_final_logged) == 0) {{
{indentation}    xlog("L_NOTICE", "{SYNTHETIC_CDR_MARKER}|event=FINAL|route={token}|direction=$avp(vivo_synth_direction)|test_id=$avp(vivo_synth_test_id)|result={result}\\n");
{indentation}    $avp(vivo_synth_final_logged) = 1;
{indentation}}}
#!endif'''


def _render_opensips(effective: _EffectiveTenant, facts: NodeFacts, token: str) -> bytes:
    # E164 prefixes are already schema-constrained to '+' plus digits. A
    # character class avoids a configuration-parser/regex double-escape edge.
    prefix_regex = "^[+]{}[0-9]*$".format(effective.called_number_prefix[1:])
    pbx_uri = "sip:{}:{};transport=tls".format(
        effective.connector_host, effective.connector_port
    )
    teams_uri = "sip:{}:{};transport=tls".format(TEAMS_PRIMARY_UPSTREAM, TEAMS_TLS_PORT)
    text = f"""#### Vivolution generated tenant fragment v0.1
#### This file contains no certificate, key, password, token, path, unit, or package input.
#### It requires a reviewed shared dispatcher, TLS domains and the modules listed below.
#### Signed OPTIONS interval seconds: {effective.options_interval_seconds}
#### Signed PBX media destination UDP ports: {effective.pbx_media_destination_port_start}-{effective.pbx_media_destination_port_end}

modparam("rtpengine", "rtpengine_sock", "udp:{RTPENGINE_NG_HOST}:{RTPENGINE_NG_PORT}")

route[VIVO_{token}_TEAMS_TO_PBX] {{
    if ($Rp != {TEAMS_TLS_PORT}) {{
        send_reply(403, "Wrong ingress");
        exit;
    }}
    if (is_method("OPTIONS")) {{
        send_reply(200, "OK");
        exit;
    }}
    if (!is_method("INVITE")) {{
        send_reply(405, "Method not allowed");
        exit;
    }}
    if (!($rU =~ "{prefix_regex}")) {{
        send_reply(404, "No tenant route");
        exit;
    }}
{_synthetic_cdr_start(token, "TEAMS_FIXTURE_TO_PBX_FIXTURE")}
    $du = "{pbx_uri}";
    record_route();
    if (has_body("application/sdp")) {{
        if (!rtpengine_offer("replace-origin replace-session-connection ICE=remove")) {{
{_synthetic_cdr_final(token, "MEDIA_ANCHOR_FAILED", "            ")}
            send_reply(500, "Media anchoring failed");
            exit;
        }}
    }}
    t_on_reply("VIVO_{token}_MEDIA_REPLY");
    t_on_failure("VIVO_{token}_MEDIA_FAILURE");
    if (!t_relay()) {{
        rtpengine_delete();
{_synthetic_cdr_final(token, "RELAY_FAILED", "        ")}
        sl_reply_error();
    }}
    exit;
}}

route[VIVO_{token}_PBX_TO_TEAMS] {{
    if ($Rp != {PBX_TLS_LISTENER_PORT}) {{
        send_reply(403, "Wrong ingress");
        exit;
    }}
    if (is_method("OPTIONS")) {{
        send_reply(200, "OK");
        exit;
    }}
    if (!is_method("INVITE")) {{
        send_reply(405, "Method not allowed");
        exit;
    }}
    if (!($rU =~ "{prefix_regex}")) {{
        send_reply(404, "No tenant route");
        exit;
    }}
{_synthetic_cdr_start(token, "PBX_FIXTURE_TO_TEAMS_FIXTURE")}
    $du = "{teams_uri}";
    record_route();
    if (has_body("application/sdp")) {{
        if (!rtpengine_offer("replace-origin replace-session-connection ICE=remove")) {{
{_synthetic_cdr_final(token, "MEDIA_ANCHOR_FAILED", "            ")}
            send_reply(500, "Media anchoring failed");
            exit;
        }}
    }}
    t_on_reply("VIVO_{token}_MEDIA_REPLY");
    t_on_failure("VIVO_{token}_MEDIA_FAILURE");
    if (!t_relay()) {{
        rtpengine_delete();
{_synthetic_cdr_final(token, "RELAY_FAILED", "        ")}
        sl_reply_error();
    }}
    exit;
}}

onreply_route[VIVO_{token}_MEDIA_REPLY] {{
    if (t_check_status("[12][0-9][0-9]") && has_body("application/sdp")) {{
        if (!rtpengine_answer("replace-origin replace-session-connection ICE=remove")) {{
{_synthetic_cdr_final(token, "MEDIA_ANCHOR_FAILED", "            ")}
            drop;
        }}
    }}
    if (t_check_status("2[0-9][0-9]")) {{
{_synthetic_cdr_final(token, "ACCEPTED", "        ")}
    }}
}}

failure_route[VIVO_{token}_MEDIA_FAILURE] {{
{_synthetic_cdr_final(token, "SIP_FAILURE")}
    rtpengine_delete();
}}
"""
    return text.encode("ascii")


def _render_rtpengine(effective: _EffectiveTenant, facts: NodeFacts) -> bytes:
    text = f"""[rtpengine]
table = -1
interface = {facts.private_ipv4}!{facts.public_ipv4}
listen-ng = {RTPENGINE_NG_HOST}:{RTPENGINE_NG_PORT}
listen-cli = {RTPENGINE_NG_HOST}:{RTPENGINE_CLI_PORT}
port-min = {facts.tenant_media_port_start}
port-max = {facts.tenant_media_port_end}
timeout = 60
silent-timeout = 3600
final-timeout = 10800
tos = 184
num-threads = 2
media-num-threads = 2
max-sessions = {effective.max_sessions}
foreground = true
log-stderr = true
log-level = 5
no-log-timestamps = true
scheduling = default
priority = 0
idle-scheduling = default
idle-priority = 0
io-uring = false
"""
    return text.encode("ascii")


def _rule(
    rule_id: str,
    source_set: str,
    protocol: str,
    port_start: int,
    port_end: int | None = None,
    *,
    source_port_start: int | None = None,
    source_port_end: int | None = None,
) -> Dict[str, Any]:
    if port_end is None:
        port_end = port_start
    rule = {
        "action": "ACCEPT",
        "destinationPortRange": {"end": port_end, "start": port_start},
        "id": rule_id,
        "protocol": protocol,
        "sourceSet": source_set,
    }
    if protocol == "tcp":
        rule["connectionStates"] = ["new"]
    if source_port_start is not None or source_port_end is not None:
        if source_port_start is None or source_port_end is None:
            _fail("typed firewall source port range must provide both endpoints")
        rule["sourcePortRange"] = {
            "end": source_port_end,
            "start": source_port_start,
        }
    return rule


def _render_nftables(effective: _EffectiveTenant, facts: NodeFacts, token: str) -> bytes:
    suffix = token.lower()
    sets = [
        {
            "elements": list(effective.pbx_source_cidrs),
            "name": "pbx4_" + suffix,
            "type": "ipv4_addr",
        },
        {
            "elements": list(facts.teams_media_source_ipv4_cidrs),
            "name": "msmedia4_" + suffix,
            "type": "ipv4_addr",
        },
    ]
    owned_rules = [
        _rule("pbx-tls", "pbx4_" + suffix, "tcp", PBX_TLS_LISTENER_PORT),
        _rule(
            "pbx-media",
            "pbx4_" + suffix,
            "udp",
            facts.tenant_media_port_start,
            facts.tenant_media_port_end,
            source_port_start=facts.pbx_media_destination_port_start,
            source_port_end=facts.pbx_media_destination_port_end,
        ),
        _rule(
            "microsoft-media",
            "msmedia4_" + suffix,
            "udp",
            facts.tenant_media_port_start,
            facts.tenant_media_port_end,
        ),
    ]
    cluster_sets = [
        {
            "elements": list(facts.teams_signaling_source_ipv4_cidrs),
            "name": "mssignal4",
            "type": "ipv4_addr",
        }
    ]
    cluster_rules = [_rule("microsoft-tls", "mssignal4", "tcp", TEAMS_TLS_PORT)]
    if facts.synthetic_teams_source_ipv4_cidrs:
        sets.append(
            {
                "elements": list(facts.synthetic_teams_source_ipv4_cidrs),
                "name": "syntheticmedia4_" + suffix,
                "type": "ipv4_addr",
            }
        )
        owned_rules.append(
            _rule(
                "synthetic-media",
                "syntheticmedia4_" + suffix,
                "udp",
                facts.tenant_media_port_start,
                facts.tenant_media_port_end,
            )
        )
        cluster_sets.append(
            {
                "elements": list(facts.synthetic_teams_source_ipv4_cidrs),
                "name": "syntheticsignal4_" + suffix,
                "type": "ipv4_addr",
            }
        )
        cluster_rules.append(
            _rule(
                "synthetic-tls",
                "syntheticsignal4_" + suffix,
                "tcp",
                TEAMS_TLS_PORT,
            )
        )
    policy = {
        "apiVersion": COMPILER_API_VERSION,
        "clusterPrerequisites": {
            "chain": "input",
            "rules": cluster_rules,
            "sets": cluster_sets,
            "table": "vivolution_edge_filter",
        },
        "kind": "OwnedNftablesTenantPolicy",
        "mergeContract": {
            "defaultInputPolicy": "drop",
            "foreignTablesPreserved": True,
            "rawNftSyntaxAccepted": False,
            "replaceOwnedTenantOnly": True,
        },
        "nodeId": facts.node_id,
        "ownedTenantPolicy": {
            "allocationId": effective.allocation_id,
            "chain": "tenant_" + suffix,
            "rules": owned_rules,
            "sets": sets,
            "table": "vivolution_edge_filter",
            "tenantContextId": effective.tenant_context_id,
        },
    }
    return manifest_tool.canonical_json_bytes(policy) + b"\n"


def _render_artifacts(effective: _EffectiveTenant, facts: NodeFacts) -> Dict[str, bytes]:
    token = _tenant_token(effective, facts)
    return {
        "OPENSIPS_TENANT_CONFIG": _render_opensips(effective, facts, token),
        "RTPENGINE_TENANT_CONFIG": _render_rtpengine(effective, facts),
        "NFTABLES_TENANT_POLICY": _render_nftables(effective, facts, token),
    }


def _sha256(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def build_local_health_gate_plan(
    manifest: Mapping[str, Any],
) -> Tuple[Mapping[str, Any], str]:
    """Reconstruct the exact signed, ordered local-health execution plan.

    Health gates are part of the canonical signed manifest.  Array order is
    therefore semantic: neither the compiler nor runtime may sort or select a
    subset before binding the plan to the verifier receipt.
    """

    if not isinstance(manifest, Mapping):
        _fail("local health gate plan requires a manifest object")
    manifest_digest = manifest_tool.manifest_digest(manifest)
    health_gates = manifest.get("healthGates")
    if not isinstance(health_gates, list) or not health_gates:
        _fail("local health gate plan requires the full signed healthGates array")
    if tuple(
        gate.get("type") if isinstance(gate, Mapping) else None
        for gate in health_gates
    ) != LOCAL_HEALTH_GATE_ORDER:
        _fail("local health gates must use the exact supported execution order")
    for gate in health_gates:
        timeout, attempts = LOCAL_HEALTH_GATE_PARAMETERS[gate["type"]]
        if (
            type(gate.get("timeoutSeconds")) is not int
            or gate.get("timeoutSeconds") != timeout
            or type(gate.get("maxAttempts")) is not int
            or gate.get("maxAttempts") != attempts
            or gate.get("onFailure") != "ROLLBACK_TO_TARGET"
        ):
            _fail("local health gate parameters differ from the supported contract")
    plan_record = {
        "apiVersion": LOCAL_HEALTH_PLAN_API_VERSION,
        "healthGates": health_gates,
        "kind": LOCAL_HEALTH_PLAN_KIND,
        "manifestDigest": manifest_digest,
    }
    encoded = manifest_tool.canonical_json_bytes(plan_record)
    # Reparse canonical bytes to detach the evidence value from caller-owned
    # mutable lists and mappings while preserving signed array order exactly.
    plan = manifest_tool.parse_json_text(encoded.decode("utf-8"))
    if not isinstance(plan, Mapping):  # pragma: no cover - canonical object invariant
        _fail("local health gate plan canonicalization failed")
    return plan, _sha256(encoded)


def _match_declarations(effective: _EffectiveTenant, rendered: Mapping[str, bytes]) -> None:
    for kind, content in rendered.items():
        declaration = effective.artifacts[kind]
        expected_type = ARTIFACT_MEDIA_TYPES[kind]
        if declaration["mediaType"] != expected_type:
            _fail("{} artifact mediaType must be {}".format(kind, expected_type))
        if declaration["applyOrder"] != ARTIFACT_APPLY_ORDER[kind]:
            _fail("{} artifact applyOrder is not the fixed compiler order".format(kind))
        digest = _sha256(content)
        if declaration["sha256"] != digest:
            _fail("{} artifact digest does not match deterministic compiler output {}".format(kind, digest))
        if declaration["sizeBytes"] != len(content):
            _fail("{} artifact size does not match deterministic compiler output".format(kind))


def _check_receipt(
    envelope: Mapping[str, Any], receipt: VerificationReceipt
) -> Mapping[str, Any]:
    manifest = envelope.get("manifest")
    if not isinstance(manifest, Mapping):
        _fail("signed envelope does not contain a manifest")
    digest = manifest_tool.manifest_digest(manifest)
    if envelope.get("manifestDigest") != digest or receipt.manifest_digest != digest:
        _fail("verification receipt, envelope and canonical manifest digest do not match")
    if manifest.get("manifestId") != receipt.manifest_id or manifest.get("sequence") != receipt.sequence:
        _fail("verification receipt identifies a different manifest candidate")
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list):
        _fail("signed envelope signatures are missing")
    signed_key_ids = {item.get("keyId") for item in signatures if isinstance(item, Mapping)}
    if not set(receipt.verified_key_ids).issubset(signed_key_ids):
        _fail("verification receipt names a key absent from the signed envelope")
    return manifest


def _assert_no_secret_material(files: Mapping[str, bytes], envelope: Mapping[str, Any]) -> None:
    forbidden_literals = [b"-----BEGIN", b"PRIVATE KEY", b"password=", b"token="]
    secret_refs = envelope["manifest"]["resourceSet"]["secretReferences"]
    forbidden_literals.extend(
        item["secretRefId"].encode("ascii") for item in secret_refs if item.get("secretRefId")
    )
    signature_values = envelope.get("signatures", ())
    forbidden_literals.extend(
        item["value"].encode("ascii")
        for item in signature_values
        if isinstance(item, Mapping) and isinstance(item.get("value"), str)
    )
    for name, content in files.items():
        for literal in forbidden_literals:
            if literal and literal in content:
                _fail("compiler attempted to emit forbidden secret/signature material in {}".format(name))


def compile_tenant_bundle(
    envelope: Mapping[str, Any],
    facts: NodeFacts,
    receipt: VerificationReceipt,
) -> CompiledBundle:
    """Compile and declaration-check one verified first-tenant candidate."""

    if not isinstance(envelope, Mapping):
        _fail("signed envelope must be an object")
    if not isinstance(facts, NodeFacts):
        _fail("facts must be a validated NodeFacts value")
    # Dataclass constructors are public Python APIs. Re-validate their canonical
    # records here so direct construction cannot bypass from_mapping().
    facts = NodeFacts.from_mapping(facts.canonical_record())
    if not isinstance(receipt, VerificationReceipt):
        _fail("receipt must be a validated VerificationReceipt value")
    receipt = VerificationReceipt.from_mapping(receipt.canonical_record())
    manifest = _check_receipt(envelope, receipt)
    if manifest.get("lifecycle") != "ACTIVE":
        _fail(
            "first-tenant compiler accepts lifecycle ACTIVE only; cleanup/decommission "
            "requires a separately reviewed compiler path"
        )
    _revalidate_contract(envelope, facts)
    local_health_plan, local_health_plan_digest = build_local_health_gate_plan(
        manifest
    )
    if receipt.local_health_gate_plan_digest != local_health_plan_digest:
        _fail(
            "verification receipt localHealthGatePlanDigest does not match "
            "the canonical signed health gate plan"
        )
    effective = _extract_effective(envelope, facts)
    rendered_by_kind = _render_artifacts(effective, facts)
    _match_declarations(effective, rendered_by_kind)
    artifacts = {
        ARTIFACT_FILENAMES[kind]: content for kind, content in rendered_by_kind.items()
    }
    _assert_no_secret_material(artifacts, envelope)
    evidence_record = {
        "apiVersion": COMPILER_API_VERSION,
        "artifactDigests": {
            name: _sha256(content) for name, content in sorted(artifacts.items())
        },
        "factsDigest": _sha256(manifest_tool.canonical_json_bytes(facts.canonical_record())),
        "kind": "TenantCompileEvidence",
        "localHealthGatePlan": local_health_plan,
        "localHealthGatePlanDigest": local_health_plan_digest,
        "manifestDigest": receipt.manifest_digest,
        "manifestId": receipt.manifest_id,
        "nodeId": facts.node_id,
        "pbxMediaDestinationPortRange": {
            "end": facts.pbx_media_destination_port_end,
            "start": facts.pbx_media_destination_port_start,
        },
        "readiness": {
            "bandwidthQuotaEnforced": False,
            "callRateLimitEnforced": False,
            "codecPolicyEnforced": False,
            "compilerStage": "BOOTSTRAP_ARTIFACTS_READY",
            "liveTeamsInteroperability": "NOT_ASSERTED",
            "runtimeApplied": False,
            "syntheticTeamsInputConfigured": bool(facts.synthetic_teams_source_ipv4_cidrs),
        },
        "sequence": receipt.sequence,
    }
    evidence = manifest_tool.canonical_json_bytes(evidence_record) + b"\n"
    return CompiledBundle(MappingProxyType(dict(sorted(artifacts.items()))), evidence)
