#!/usr/bin/env python3
"""Strict contracts and deterministic renderers for the Edge root helper.

Nothing in this module executes a command or mutates a live system.  It turns
the verifier/compiler hand-off plus root-provisioned local authority into four
reviewable runtime files.  Raw paths, commands, service names and nft syntax
are never accepted from desired state.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence, Tuple

from edge.agent import security_core as agent_security
from edge.compiler import core as compiler_core
from edge.compiler.core import (
    LOCAL_HEALTH_PLAN_API_VERSION,
    LOCAL_HEALTH_PLAN_KIND,
    NodeFacts,
    VerificationReceipt,
)
from edge.schema import manifest_tool


RUNTIME_API_VERSION = "edge.vivolution.ae/runtime/v0.1"
RUNTIME_AUTHORITY_API_VERSION = "edge.vivolution.ae/runtime-authority/v0.1"
COMPILER_API_VERSION = "edge.vivolution.ae/compiler/v0.1"

OPENSIPS_VERSION = "3.6.8-1"
RTPENGINE_VERSION = "26.0.1.22-1~bpo13+1"
TEAMS_TLS_PORT = 5061
PBX_TLS_LISTENER_PORT = 15061
OPTIONS_INTERVAL_SECONDS = 60
SYNTHETIC_CDR_MARKER = "VIVO_SYNTHETIC_CDR_V1"
SYNTHETIC_CDR_TEST_ID_REGEX = (
    "^[0-9]{8}T[0-9]{6}Z-sbc[12]-[0-9]{1,10}$"
)
MICROSOFT_TLS12_CIPHER_LIST = (
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
)
# In TLS 1.2 the ECDSA token selects the remote server's authentication key;
# the Edge's independently required mutual-TLS client certificate may also be
# EC without broadening this exact fixture-server allowlist.
SYNTHETIC_FIXTURE_TLS12_CIPHER_LIST = (
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256"
)
MICROSOFT_MEDIA_PROCESSOR_REMOTE_PORT_SET = "{ 3478-3481, 49152-53247 }"
AZURE_IMDS_IPV4 = "169.254.169.254"
CONTROL_PLANE_IPV4_CIDRS = ("10.20.1.4/32",)
NTP_SERVER_IPV4_CIDRS = ("162.159.200.1/32", "162.159.200.123/32")
# SHA-1 is used only as Microsoft's published certificate identifier, never as
# a signature or integrity primitive. Reviewed against Microsoft Learn What's
# New for Direct Routing, 2025-12-12, and deliberately fail-closed.
MICROSOFT_SIP_ROOT_SHA1 = frozenset(
    {
        "A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436",  # DigiCert Global Root CA
        "DF3C24F9BFD666761B268073FE06D1CC8D4F82A4",  # DigiCert Global Root G2
        "7E04DE896A3E666D00E687D33FFAD93BE83D349E",  # DigiCert Global Root G3
        "17F3DE5E9F0F19E98EF61F32266E20C407AE30EE",  # DigiCert TLS ECC P384 Root G5
        "A78849DC5D7C758C8CDE399856B3AAD0B2A57135",  # DigiCert TLS RSA 4096 Root G5
        "999A64C37FF47D9FAB95F14769891460EEC4C3C5",  # Microsoft ECC Root CA 2017
        "73A5E64A3BFF8316FF0EDCCC618A906E4EAE4D74",  # Microsoft RSA Root CA 2017
    }
)
TEAMS_HUBS = (
    "sip.pstnhub.microsoft.com",
    "sip2.pstnhub.microsoft.com",
    "sip3.pstnhub.microsoft.com",
)

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
LOCAL_HEALTH_GATE_PARAMETERS = {
    "ARTIFACT_DIGESTS": (30, 1),
    "OPENSIPS_CONFIG": (30, 1),
    "RTPENGINE_READY": (30, 3),
}
LOCAL_HEALTH_GATE_ORDER = tuple(LOCAL_HEALTH_GATE_PARAMETERS)
LOCAL_HEALTH_GATE_PROOFS = {
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

_COMMON_SECRET_NAMES = frozenset(
    {
        "edgeCertificateChainPem",
        "edgePrivateKeyPem",
        "microsoftCaBundlePem",
        "pbxCaBundlePem",
        "publicCaBundlePem",
    }
)
_SYNTHETIC_SECRET_NAMES = _COMMON_SECRET_NAMES | {
    "fixtureCaCrt",
    "fixtureClientCrt",
    "fixtureClientKey",
}
_DIRECT_RESERVED_FQDN_SUFFIXES = (
    ".alt",
    ".arpa",
    ".example",
    ".invalid",
    ".local",
    ".localhost",
    ".onion",
    ".test",
    ".onmicrosoft.com",
)
_DIRECT_RESERVED_FQDN_NAMES = frozenset(
    {"example.com", "example.net", "example.org", "localhost"}
)
_DIRECT_PLACEHOLDER_FQDN_LABELS = frozenset(
    {"changeme", "example", "placeholder", "replace", "replace-me", "todo"}
)

ARTIFACT_FILENAMES = (
    "nftables-tenant-policy.json",
    "opensips-tenant.cfg",
    "rtpengine-tenant.conf",
)
HANDOFF_FILENAMES = set(ARTIFACT_FILENAMES) | {
    "compile-evidence.json",
    "signed-envelope.json",
    "verifier-receipt.json",
}
MAX_ARTIFACT_BYTES = 512 * 1024
MAX_JSON_BYTES = 256 * 1024
MAX_SIGNED_ENVELOPE_BYTES = agent_security.MAX_ENVELOPE_BYTES

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_FQDN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_TOKEN_RE = re.compile(r"^[0-9A-F]{12}$")
_SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")


class RuntimeContractError(ValueError):
    """A hand-off or local authority value is outside the reviewed contract."""


def _fail(message: str) -> None:
    raise RuntimeContractError(message)


def sha256_digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return manifest_tool.canonical_json_bytes(value) + b"\n"


def parse_json_bytes(raw: bytes, name: str, *, maximum: int = MAX_JSON_BYTES) -> Any:
    if not isinstance(raw, bytes) or not raw or len(raw) > maximum:
        _fail("{} is empty or exceeds its byte limit".format(name))
    try:
        return manifest_tool.parse_json_text(raw.decode("utf-8"))
    except (
        UnicodeError,
        json.JSONDecodeError,
        manifest_tool.DuplicateKeyError,
        RecursionError,
        ValueError,
    ) as exc:
        _fail("{} is not duplicate-safe UTF-8 JSON: {}".format(name, exc))


def _exact_mapping(value: Any, fields: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail("{} must be an object".format(name))
    missing = sorted(fields - set(value))
    extra = sorted(set(value) - fields)
    if missing or extra:
        _fail("{} members differ: missing={} extra={}".format(name, missing, extra))
    return value


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        _fail("{} must be an integer from {} through {}".format(name, minimum, maximum))
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        _fail("{} must be a canonical SHA-256 digest".format(name))
    return value


def _fqdn(value: Any, name: str) -> str:
    if not isinstance(value, str) or value != value.lower() or not 1 <= len(value) <= 253:
        _fail("{} must be a canonical lowercase ASCII FQDN".format(name))
    try:
        value.encode("ascii")
    except UnicodeError:
        _fail("{} must be a canonical lowercase ASCII FQDN".format(name))
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        _fail("{} must be a DNS name, not an IP literal".format(name))
    labels = value.split(".")
    if len(labels) < 2 or any(_FQDN_LABEL_RE.fullmatch(label) is None for label in labels):
        _fail("{} must be a canonical lowercase ASCII FQDN".format(name))
    return value


def _ipv4(value: Any, name: str, *, globally_routable: bool | None = None) -> str:
    if not isinstance(value, str):
        _fail("{} must be a canonical IPv4 address".format(name))
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        _fail("{} must be a canonical IPv4 address".format(name))
    if not isinstance(parsed, ipaddress.IPv4Address) or str(parsed) != value:
        _fail("{} must be a canonical IPv4 address".format(name))
    if globally_routable is True and not parsed.is_global:
        _fail("{} must be globally routable".format(name))
    if globally_routable is False and not parsed.is_private:
        _fail("{} must be private".format(name))
    return value


def _cidrs(
    value: Any,
    name: str,
    *,
    minimum_prefix: int,
    maximum_items: int,
    globally_routable: bool | None,
) -> Tuple[str, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= maximum_items:
        _fail("{} must contain one through {} CIDRs".format(name, maximum_items))
    result = []
    for item in value:
        if not isinstance(item, str):
            _fail("{} must contain canonical IPv4 CIDRs".format(name))
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError:
            _fail("{} contains an invalid or non-canonical CIDR".format(name))
        if (
            not isinstance(network, ipaddress.IPv4Network)
            or str(network) != item
            or network.prefixlen < minimum_prefix
        ):
            _fail("{} contains a non-canonical or overly broad CIDR".format(name))
        if globally_routable is True and not network.network_address.is_global:
            _fail("{} must contain globally routable CIDRs".format(name))
        if globally_routable is False and not network.network_address.is_private:
            _fail("{} must contain private CIDRs".format(name))
        result.append(item)
    if len(set(result)) != len(result):
        _fail("{} contains a duplicate CIDR".format(name))
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
        _fail("{} must be in canonical network order".format(name))
    return canonical


@dataclass(frozen=True)
class RuntimeAuthority:
    """Root-provisioned authority not controlled by a tenant manifest."""

    node_id: str
    generation: int
    slot: str
    profile: str
    administrator_source_ipv4_cidrs: Tuple[str, ...]
    azure_dhcp_server_ipv4: str
    secret_digests: Mapping[str, str]

    @classmethod
    def from_mapping(cls, value: Any) -> "RuntimeAuthority":
        record = _exact_mapping(
            value,
            {
                "administratorSourceIpv4Cidrs",
                "apiVersion",
                "azureDhcpServerIpv4",
                "generation",
                "nodeId",
                "profile",
                "secretDigests",
                "slot",
            },
            "runtime authority",
        )
        if record["apiVersion"] != RUNTIME_AUTHORITY_API_VERSION:
            _fail("runtime authority apiVersion is unsupported")
        node_id = record["nodeId"]
        if not isinstance(node_id, str) or manifest_tool.ID_RE.fullmatch(node_id) is None:
            _fail("runtime authority nodeId is invalid")
        generation = _integer(record["generation"], "runtime authority generation", 1, 2**31 - 1)
        slot = record["slot"]
        if slot not in {"A", "B"}:
            _fail("runtime authority slot must be A or B")
        profile = record["profile"]
        if profile not in {"SYNTHETIC_PRIVATE", "DIRECT_ROUTING"}:
            _fail("runtime authority profile is unsupported")
        administrators = _cidrs(
            record["administratorSourceIpv4Cidrs"],
            "administratorSourceIpv4Cidrs",
            minimum_prefix=24,
            maximum_items=8,
            globally_routable=True,
        )
        dhcp = _ipv4(record["azureDhcpServerIpv4"], "azureDhcpServerIpv4")
        if dhcp != "168.63.129.16":
            _fail("azureDhcpServerIpv4 must equal the fixed Azure WireServer address")
        required_secret_names = (
            _SYNTHETIC_SECRET_NAMES
            if profile == "SYNTHETIC_PRIVATE"
            else _COMMON_SECRET_NAMES
        )
        secrets = _exact_mapping(
            record["secretDigests"],
            set(required_secret_names),
            "runtime authority secretDigests for {}".format(profile),
        )
        checked = {name: _digest(value, "secret digest {}".format(name)) for name, value in secrets.items()}
        return cls(node_id, generation, slot, profile, administrators, dhcp, checked)

    def canonical_record(self) -> Dict[str, Any]:
        return {
            "administratorSourceIpv4Cidrs": list(self.administrator_source_ipv4_cidrs),
            "apiVersion": RUNTIME_AUTHORITY_API_VERSION,
            "azureDhcpServerIpv4": self.azure_dhcp_server_ipv4,
            "generation": self.generation,
            "nodeId": self.node_id,
            "profile": self.profile,
            "secretDigests": dict(sorted(self.secret_digests.items())),
            "slot": self.slot,
        }


@dataclass(frozen=True)
class SecretPaths:
    edge_certificate_chain_pem: Path
    edge_private_key_pem: Path
    fixture_ca_crt: Path
    fixture_client_crt: Path
    fixture_client_key: Path
    microsoft_ca_bundle_pem: Path
    pbx_ca_bundle_pem: Path
    public_ca_bundle_pem: Path

    def as_mapping(self, profile: str) -> Mapping[str, Path]:
        paths = {
            "edgeCertificateChainPem": self.edge_certificate_chain_pem,
            "edgePrivateKeyPem": self.edge_private_key_pem,
            "fixtureCaCrt": self.fixture_ca_crt,
            "fixtureClientCrt": self.fixture_client_crt,
            "fixtureClientKey": self.fixture_client_key,
            "microsoftCaBundlePem": self.microsoft_ca_bundle_pem,
            "pbxCaBundlePem": self.pbx_ca_bundle_pem,
            "publicCaBundlePem": self.public_ca_bundle_pem,
        }
        if profile == "SYNTHETIC_PRIVATE":
            return paths
        if profile == "DIRECT_ROUTING":
            return {
                name: path
                for name, path in paths.items()
                if name in _COMMON_SECRET_NAMES
            }
        _fail("secret path selection requires a supported runtime profile")


def validate_secret_material(
    facts: NodeFacts,
    authority: RuntimeAuthority,
    secret_bytes: Mapping[str, bytes],
    *,
    now: datetime | None = None,
) -> None:
    """Validate digest, PEM shape, key pairing, SAN and minimum validity."""

    expected_names = set(authority.secret_digests)
    if set(secret_bytes) != expected_names:
        _fail("secret material names do not match runtime authority")
    for name, content in secret_bytes.items():
        if not content or len(content) > 1024 * 1024:
            _fail("secret material {} is empty or oversized".format(name))
        if sha256_digest(content) != authority.secret_digests[name]:
            _fail("secret material {} does not match its immutable digest".format(name))

    try:
        from cryptography import x509
        from cryptography.x509.verification import DNSName, PolicyBuilder, Store
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID
    except ImportError as exc:
        _fail("python3-cryptography is required to validate TLS authority: {}".format(exc))

    certificate_bytes = secret_bytes["edgeCertificateChainPem"]
    try:
        certificates = x509.load_pem_x509_certificates(certificate_bytes)
        private_key = serialization.load_pem_private_key(
            secret_bytes["edgePrivateKeyPem"], password=None
        )
    except (TypeError, ValueError) as exc:
        _fail("edge certificate chain or private key is invalid PEM: {}".format(exc))
    if len(certificates) < 2:
        _fail("edge certificate full chain must contain a leaf and at least one issuer")
    leaf = certificates[0]
    leaf_public_key = leaf.public_key()
    if not isinstance(leaf_public_key, rsa.RSAPublicKey) or leaf_public_key.key_size != 2048:
        _fail("edge certificate leaf key must be exactly RSA-2048")
    if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size != 2048:
        _fail("edge certificate private key must be exactly RSA-2048")
    if leaf_public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ) != private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ):
        _fail("edge certificate and private key do not match")
    try:
        names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = names.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        _fail("edge certificate lacks Subject Alternative Name")
    expected_dns_names = {facts.node_fqdn, "*." + facts.node_fqdn}
    if set(dns_names) != expected_dns_names or len(dns_names) != 2 or len(names) != 2:
        _fail("edge certificate SANs must be exactly the node FQDN and its direct wildcard")
    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        _fail("edge certificate lacks Extended Key Usage")
    if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
        _fail("edge certificate lacks the Server Authentication EKU")

    check_time = now or datetime.now(timezone.utc)
    not_before = (
        leaf.not_valid_before_utc
        if hasattr(leaf, "not_valid_before_utc")
        else leaf.not_valid_before.replace(tzinfo=timezone.utc)
    )
    not_after = (
        leaf.not_valid_after_utc
        if hasattr(leaf, "not_valid_after_utc")
        else leaf.not_valid_after.replace(tzinfo=timezone.utc)
    )
    if not_before > check_time or not_after < check_time + timedelta(hours=24):
        _fail("edge certificate is not currently valid for at least 24 hours")
    try:
        public_roots = x509.load_pem_x509_certificates(secret_bytes["publicCaBundlePem"])
        if not public_roots:
            _fail("public CA bundle contains no certificates")
        public_verifier = (
            PolicyBuilder()
            .store(Store(public_roots))
            .time(check_time)
            .build_server_verifier(DNSName(facts.node_fqdn))
        )
        public_verifier.verify(leaf, certificates[1:])
    except Exception as exc:
        _fail("edge public certificate SAN/chain validation failed: {}".format(exc))

    if authority.profile == "SYNTHETIC_PRIVATE":
        try:
            fixture_certificates = x509.load_pem_x509_certificates(
                secret_bytes["fixtureClientCrt"]
            )
            fixture_private_key = serialization.load_pem_private_key(
                secret_bytes["fixtureClientKey"], password=None
            )
        except (TypeError, ValueError) as exc:
            _fail("fixture client certificate or key is invalid PEM: {}".format(exc))
        if not fixture_certificates:
            _fail("fixture client certificate file contains no certificate")
        fixture_leaf = fixture_certificates[0]
        if fixture_leaf.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ) != fixture_private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ):
            _fail("fixture client certificate and key do not match")
        fixture_not_before = (
            fixture_leaf.not_valid_before_utc
            if hasattr(fixture_leaf, "not_valid_before_utc")
            else fixture_leaf.not_valid_before.replace(tzinfo=timezone.utc)
        )
        fixture_not_after = (
            fixture_leaf.not_valid_after_utc
            if hasattr(fixture_leaf, "not_valid_after_utc")
            else fixture_leaf.not_valid_after.replace(tzinfo=timezone.utc)
        )
        if fixture_not_before > check_time or fixture_not_after < check_time + timedelta(hours=24):
            _fail("fixture client certificate is not currently valid for at least 24 hours")
        try:
            fixture_names = fixture_leaf.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            fixture_ips = fixture_names.get_values_for_type(x509.IPAddress)
        except x509.ExtensionNotFound:
            fixture_ips = []
        if ipaddress.ip_address(facts.private_ipv4) not in fixture_ips:
            _fail(
                "fixture client certificate IP SAN does not cover {}".format(
                    facts.private_ipv4
                )
            )
        try:
            fixture_roots = x509.load_pem_x509_certificates(secret_bytes["fixtureCaCrt"])
            fixture_verifier = (
                PolicyBuilder()
                .store(Store(fixture_roots))
                .time(check_time)
                .build_client_verifier()
            )
            fixture_verifier.verify(fixture_leaf, fixture_certificates[1:])
        except Exception as exc:
            _fail("fixture client certificate chain validation failed: {}".format(exc))

    ca_bundle_names = ["microsoftCaBundlePem", "pbxCaBundlePem", "publicCaBundlePem"]
    if authority.profile == "SYNTHETIC_PRIVATE":
        ca_bundle_names.insert(0, "fixtureCaCrt")
    for name in ca_bundle_names:
        try:
            ca_certificates = x509.load_pem_x509_certificates(secret_bytes[name])
        except ValueError as exc:
            _fail("{} is not a valid PEM certificate bundle: {}".format(name, exc))
        if not ca_certificates:
            _fail("{} contains no certificates".format(name))
        valid_ca_count = 0
        for certificate in ca_certificates:
            try:
                if not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                    _fail("{} contains a non-CA certificate".format(name))
            except x509.ExtensionNotFound:
                _fail("{} contains a certificate without Basic Constraints".format(name))
            ca_not_before = (
                certificate.not_valid_before_utc
                if hasattr(certificate, "not_valid_before_utc")
                else certificate.not_valid_before.replace(tzinfo=timezone.utc)
            )
            ca_not_after = (
                certificate.not_valid_after_utc
                if hasattr(certificate, "not_valid_after_utc")
                else certificate.not_valid_after.replace(tzinfo=timezone.utc)
            )
            if ca_not_before <= check_time < ca_not_after:
                valid_ca_count += 1
        if valid_ca_count == 0:
            _fail("{} contains no currently valid CA certificate".format(name))
        if name == "microsoftCaBundlePem":
            actual_thumbprints = {
                certificate.fingerprint(hashes.SHA1()).hex().upper()
                for certificate in ca_certificates
            }
            missing_thumbprints = sorted(MICROSOFT_SIP_ROOT_SHA1 - actual_thumbprints)
            if missing_thumbprints:
                _fail(
                    "microsoftCaBundlePem lacks current Microsoft SIP roots {}".format(
                        ",".join(missing_thumbprints)
                    )
                )


@dataclass(frozen=True)
class LocalHealthGatePlan:
    manifest_digest: str
    health_gates: Tuple[Mapping[str, Any], ...]

    def record(self) -> Dict[str, Any]:
        return {
            "apiVersion": LOCAL_HEALTH_PLAN_API_VERSION,
            "healthGates": [
                {
                    "allocationId": gate["allocationId"],
                    "gateId": gate["gateId"],
                    "maxAttempts": gate["maxAttempts"],
                    "onFailure": gate["onFailure"],
                    "resourceRefs": list(gate["resourceRefs"]),
                    "tenantContextId": gate["tenantContextId"],
                    "timeoutSeconds": gate["timeoutSeconds"],
                    "type": gate["type"],
                }
                for gate in self.health_gates
            ],
            "kind": LOCAL_HEALTH_PLAN_KIND,
            "manifestDigest": self.manifest_digest,
        }

    @property
    def digest(self) -> str:
        return sha256_digest(manifest_tool.canonical_json_bytes(self.record()))


def validate_local_health_gate_plan(
    value: Any,
    *,
    facts: NodeFacts,
    expected_manifest_digest: str,
) -> LocalHealthGatePlan:
    plan = _exact_mapping(
        value,
        {"apiVersion", "healthGates", "kind", "manifestDigest"},
        "local health gate plan",
    )
    if (
        plan["apiVersion"] != LOCAL_HEALTH_PLAN_API_VERSION
        or plan["kind"] != LOCAL_HEALTH_PLAN_KIND
        or plan["manifestDigest"] != expected_manifest_digest
    ):
        _fail("local health gate plan type or manifest identity is invalid")
    raw_gates = plan["healthGates"]
    if not isinstance(raw_gates, list) or len(raw_gates) != 3:
        _fail("local health gate plan must contain exactly three signed gates")
    checked = []
    seen_ids = set()
    seen_types = set()
    for raw_gate in raw_gates:
        gate = _exact_mapping(
            raw_gate, set(LOCAL_HEALTH_GATE_FIELDS), "local health gate"
        )
        gate_id = gate["gateId"]
        gate_type = gate["type"]
        if (
            not isinstance(gate_id, str)
            or manifest_tool.ID_RE.fullmatch(gate_id) is None
            or gate_id in seen_ids
        ):
            _fail("local health gate id is invalid or duplicated")
        if gate_type not in LOCAL_HEALTH_GATE_PARAMETERS or gate_type in seen_types:
            _fail("local health gate type is unsupported or duplicated")
        if (
            gate["tenantContextId"] != facts.tenant_context_id
            or gate["allocationId"] != facts.allocation_id
        ):
            _fail("local health gate crosses immutable tenant identity")
        refs = gate["resourceRefs"]
        if (
            not isinstance(refs, list)
            or not refs
            or len(refs) > 64
            or any(
                not isinstance(ref, str)
                or manifest_tool.ID_RE.fullmatch(ref) is None
                for ref in refs
            )
            or len(set(refs)) != len(refs)
        ):
            _fail("local health gate resourceRefs are invalid")
        timeout, attempts = LOCAL_HEALTH_GATE_PARAMETERS[gate_type]
        if (
            isinstance(gate["timeoutSeconds"], bool)
            or gate["timeoutSeconds"] != timeout
            or isinstance(gate["maxAttempts"], bool)
            or gate["maxAttempts"] != attempts
            or gate["onFailure"] != "ROLLBACK_TO_TARGET"
        ):
            _fail("local health gate parameters differ from the supported contract")
        seen_ids.add(gate_id)
        seen_types.add(gate_type)
        checked.append(
            {
                "allocationId": facts.allocation_id,
                "gateId": gate_id,
                "maxAttempts": attempts,
                "onFailure": "ROLLBACK_TO_TARGET",
                "resourceRefs": list(refs),
                "tenantContextId": facts.tenant_context_id,
                "timeoutSeconds": timeout,
                "type": gate_type,
            }
        )
    if (
        seen_types != set(LOCAL_HEALTH_GATE_PARAMETERS)
        or tuple(gate["type"] for gate in checked) != LOCAL_HEALTH_GATE_ORDER
    ):
        _fail("local health gate plan differs from the exact supported gate order")
    return LocalHealthGatePlan(expected_manifest_digest, tuple(checked))


def validate_local_health_gate_results(
    value: Any, plan: LocalHealthGatePlan
) -> Tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list) or len(value) != len(plan.health_gates):
        _fail("signed health gate results differ from the signed plan cardinality")
    checked = []
    for raw_result, gate in zip(value, plan.health_gates):
        result = _exact_mapping(
            raw_result,
            {"attemptsUsed", "gateId", "proofs", "status", "type"},
            "signed health gate result",
        )
        attempts = result["attemptsUsed"]
        if (
            result["gateId"] != gate["gateId"]
            or result["type"] != gate["type"]
            or result["status"] != "PASSED"
            or isinstance(attempts, bool)
            or not isinstance(attempts, int)
            or not 1 <= attempts <= gate["maxAttempts"]
        ):
            _fail("signed health gate result differs from its ordered signed gate")
        expected_proofs = LOCAL_HEALTH_GATE_PROOFS[gate["type"]]
        proofs = result["proofs"]
        if not isinstance(proofs, list) or len(proofs) != len(expected_proofs):
            _fail("signed health gate proof cardinality is invalid")
        checked_proofs = []
        for raw_proof, expected_name in zip(proofs, expected_proofs):
            proof = _exact_mapping(
                raw_proof, {"name", "status"}, "signed health gate proof"
            )
            if proof != {"name": expected_name, "status": "PASSED"}:
                _fail("signed health gate proof order or status is invalid")
            checked_proofs.append(dict(proof))
        checked.append(
            {
                "attemptsUsed": attempts,
                "gateId": gate["gateId"],
                "proofs": checked_proofs,
                "status": "PASSED",
                "type": gate["type"],
            }
        )
    return tuple(checked)


@dataclass(frozen=True)
class TenantRouteSpec:
    token: str
    pbx_host: str
    pbx_port: int
    called_number_prefix: str
    options_interval_seconds: int
    pbx_media_destination_port_start: int
    pbx_media_destination_port_end: int


@dataclass(frozen=True)
class RtpengineSpec:
    private_ipv4: str
    public_ipv4: str
    port_min: int
    port_max: int
    max_sessions: int


@dataclass(frozen=True)
class AcceptedRuntimeState:
    """Root-owned replay and rollback authority for envelope verification."""

    highest_seen_sequence: int
    active_sequence: int
    active_manifest_digest: str | None
    active_artifact_digests: Tuple[str, ...]

    def __post_init__(self) -> None:
        highest = _integer(
            self.highest_seen_sequence,
            "runtime highest-seen sequence",
            0,
            2**53 - 1,
        )
        active = _integer(
            self.active_sequence,
            "runtime active sequence",
            0,
            2**53 - 1,
        )
        if active > highest:
            _fail("runtime active sequence exceeds the root replay floor")
        if active == 0:
            if self.active_manifest_digest is not None or self.active_artifact_digests:
                _fail("bootstrap runtime state cannot assert manifest lineage")
            return
        _digest(self.active_manifest_digest, "runtime active manifest digest")
        digests = tuple(self.active_artifact_digests)
        if (
            not digests
            or len(digests) > 64
            or any(
                not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None
                for value in digests
            )
            or tuple(sorted(set(digests))) != digests
        ):
            _fail("runtime active artifact lineage is not canonical")

    @classmethod
    def bootstrap(cls) -> "AcceptedRuntimeState":
        return cls(0, 0, None, ())


@dataclass(frozen=True)
class ValidatedCandidate:
    manifest_digest: str
    manifest_id: str
    sequence: int
    facts: NodeFacts
    authority: RuntimeAuthority
    source_artifact_digests: Mapping[str, str]
    signed_envelope_digest: str
    verified_key_ids: Tuple[str, ...]
    compile_evidence_digest: str
    local_health_gate_plan: LocalHealthGatePlan
    local_health_gate_plan_digest: str
    route: TenantRouteSpec
    rtpengine: RtpengineSpec
    opensips_config: bytes
    rtpengine_config: bytes
    nftables_config: bytes

    def runtime_files(self) -> Mapping[str, bytes]:
        return {
            "nftables.conf": self.nftables_config,
            "opensips.cfg": self.opensips_config,
            "rtpengine.conf": self.rtpengine_config,
        }


def _tenant_token(facts: NodeFacts) -> str:
    material = "{}\0{}\0{}".format(
        facts.tenant_context_id, facts.allocation_id, facts.node_id
    ).encode("ascii")
    return hashlib.sha256(material).hexdigest()[:12].upper()


def _synthetic_cdr_start(token: str, direction: str) -> str:
    """Mirror the compiler's exact optional synthetic transaction hook."""

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


def _strict_host(value: str, name: str) -> str:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return _fqdn(value, name)
    if isinstance(parsed, ipaddress.IPv4Address) and str(parsed) == value:
        return value
    _fail("{} must be a canonical FQDN or IPv4 address".format(name))


def _compiler_fragment(route: TenantRouteSpec) -> bytes:
    if (
        isinstance(route.options_interval_seconds, bool)
        or route.options_interval_seconds != OPTIONS_INTERVAL_SECONDS
    ):
        _fail("compiled OPTIONS interval must be the reviewed value 60")
    if (
        route.pbx_media_destination_port_start % 2 != 0
        or route.pbx_media_destination_port_end % 2 != 1
        or route.pbx_media_destination_port_start
        > route.pbx_media_destination_port_end
    ):
        _fail("compiled PBX media destination range is invalid")
    prefix_regex = "^[+]{}[0-9]*$".format(route.called_number_prefix[1:])
    pbx_uri = "sip:{}:{};transport=tls".format(route.pbx_host, route.pbx_port)
    teams_uri = "sip:{}:5061;transport=tls".format(TEAMS_HUBS[0])
    text = f"""#### Vivolution generated tenant fragment v0.1
#### This file contains no certificate, key, password, token, path, unit, or package input.
#### It requires a reviewed shared dispatcher, TLS domains and the modules listed below.
#### Signed OPTIONS interval seconds: {route.options_interval_seconds}
#### Signed PBX media destination UDP ports: {route.pbx_media_destination_port_start}-{route.pbx_media_destination_port_end}

modparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:2223")

route[VIVO_{route.token}_TEAMS_TO_PBX] {{
    if ($socket_in(port) != 5061) {{
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
{_synthetic_cdr_start(route.token, "TEAMS_FIXTURE_TO_PBX_FIXTURE")}
    $du = "{pbx_uri}";
    record_route();
    if (has_body("application/sdp")) {{
        if (!rtpengine_offer("replace-origin replace-session-connection ICE=remove")) {{
{_synthetic_cdr_final(route.token, "MEDIA_ANCHOR_FAILED", "            ")}
            send_reply(500, "Media anchoring failed");
            exit;
        }}
    }}
    t_on_reply("VIVO_{route.token}_MEDIA_REPLY");
    t_on_failure("VIVO_{route.token}_MEDIA_FAILURE");
    if (!t_relay()) {{
        rtpengine_delete();
{_synthetic_cdr_final(route.token, "RELAY_FAILED", "        ")}
        sl_reply_error();
    }}
    exit;
}}

route[VIVO_{route.token}_PBX_TO_TEAMS] {{
    if ($socket_in(port) != 15061) {{
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
{_synthetic_cdr_start(route.token, "PBX_FIXTURE_TO_TEAMS_FIXTURE")}
    $du = "{teams_uri}";
    record_route();
    if (has_body("application/sdp")) {{
        if (!rtpengine_offer("replace-origin replace-session-connection ICE=remove")) {{
{_synthetic_cdr_final(route.token, "MEDIA_ANCHOR_FAILED", "            ")}
            send_reply(500, "Media anchoring failed");
            exit;
        }}
    }}
    t_on_reply("VIVO_{route.token}_MEDIA_REPLY");
    t_on_failure("VIVO_{route.token}_MEDIA_FAILURE");
    if (!t_relay()) {{
        rtpengine_delete();
{_synthetic_cdr_final(route.token, "RELAY_FAILED", "        ")}
        sl_reply_error();
    }}
    exit;
}}

onreply_route[VIVO_{route.token}_MEDIA_REPLY] {{
    if (t_check_status("[12][0-9][0-9]") && has_body("application/sdp")) {{
        if (!rtpengine_answer("replace-origin replace-session-connection ICE=remove")) {{
{_synthetic_cdr_final(route.token, "MEDIA_ANCHOR_FAILED", "            ")}
            drop;
        }}
    }}
    if (t_check_status("2[0-9][0-9]")) {{
{_synthetic_cdr_final(route.token, "ACCEPTED", "        ")}
    }}
}}

failure_route[VIVO_{route.token}_MEDIA_FAILURE] {{
{_synthetic_cdr_final(route.token, "SIP_FAILURE")}
    rtpengine_delete();
}}
"""
    return text.encode("ascii")


def parse_compiler_fragment(raw: bytes, facts: NodeFacts) -> TenantRouteSpec:
    if len(raw) > MAX_ARTIFACT_BYTES:
        _fail("OpenSIPS tenant fragment exceeds its byte limit")
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        _fail("OpenSIPS tenant fragment must be ASCII")
    expected_token = _tenant_token(facts)
    if _TOKEN_RE.fullmatch(expected_token) is None:
        _fail("derived tenant route token is invalid")
    pbx_matches = re.findall(
        r'^    \$du = "sip:([^";]+):([0-9]{1,5});transport=tls";$', text, re.MULTILINE
    )
    pbx_matches = [item for item in pbx_matches if item[0] not in TEAMS_HUBS]
    if len(pbx_matches) != 1:
        _fail("OpenSIPS tenant fragment has no unique typed PBX destination")
    host = _strict_host(pbx_matches[0][0], "compiled PBX host")
    port = _integer(int(pbx_matches[0][1]), "compiled PBX port", 1024, 65535)
    prefixes = re.findall(
        r'^    if \(!\(\$rU =~ "\^\[\+\]([0-9]{1,15})\[0-9\]\*\$"\)\) \{$',
        text,
        re.MULTILINE,
    )
    if len(prefixes) != 2 or len(set(prefixes)) != 1:
        _fail("OpenSIPS tenant fragment has no unique typed E.164 prefix")
    intervals = re.findall(
        r"^#### Signed OPTIONS interval seconds: ([0-9]{1,3})$", text, re.MULTILINE
    )
    if len(intervals) != 1:
        _fail("OpenSIPS tenant fragment has no unique signed OPTIONS interval")
    interval = _integer(
        int(intervals[0]),
        "compiled OPTIONS interval",
        OPTIONS_INTERVAL_SECONDS,
        OPTIONS_INTERVAL_SECONDS,
    )
    media_ranges = re.findall(
        r"^#### Signed PBX media destination UDP ports: ([0-9]{4,5})-([0-9]{4,5})$",
        text,
        re.MULTILINE,
    )
    if len(media_ranges) != 1:
        _fail(
            "OpenSIPS tenant fragment has no unique signed PBX media destination range"
        )
    media_start = _integer(
        int(media_ranges[0][0]), "compiled PBX media destination start", 1024, 65534
    )
    media_end = _integer(
        int(media_ranges[0][1]), "compiled PBX media destination end", 1025, 65535
    )
    if (media_start, media_end) != (
        facts.pbx_media_destination_port_start,
        facts.pbx_media_destination_port_end,
    ):
        _fail(
            "compiled PBX media destination range differs from immutable node facts"
        )
    route = TenantRouteSpec(
        expected_token,
        host,
        port,
        "+" + prefixes[0],
        interval,
        media_start,
        media_end,
    )
    if raw != _compiler_fragment(route):
        _fail("OpenSIPS tenant fragment differs from the reviewed compiler v0.1 grammar")
    return route


_RTP_FIXED = {
    "table": "-1",
    "listen-ng": "127.0.0.1:2223",
    "listen-cli": "127.0.0.1:2224",
    "timeout": "60",
    "silent-timeout": "3600",
    "final-timeout": "10800",
    "tos": "184",
    "num-threads": "2",
    "media-num-threads": "2",
    "foreground": "true",
    "log-stderr": "true",
    "log-level": "5",
    "no-log-timestamps": "true",
    "scheduling": "default",
    "priority": "0",
    "idle-scheduling": "default",
    "idle-priority": "0",
    "io-uring": "false",
}


def parse_rtpengine_artifact(raw: bytes, facts: NodeFacts) -> RtpengineSpec:
    if len(raw) > 64 * 1024:
        _fail("RTPengine artifact exceeds its byte limit")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError:
        _fail("RTPengine artifact must be ASCII")
    if not lines or lines[0] != "[rtpengine]":
        _fail("RTPengine artifact has an invalid section")
    values: Dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        match = re.fullmatch(r"([a-z][a-z0-9-]*) = ([A-Za-z0-9.!:~-]+)", line)
        if match is None or match.group(1) in values:
            _fail("RTPengine artifact contains raw, duplicate or invalid syntax")
        values[match.group(1)] = match.group(2)
    expected_keys = set(_RTP_FIXED) | {"interface", "port-min", "port-max", "max-sessions"}
    if set(values) != expected_keys:
        _fail("RTPengine artifact keys differ from the fixed userspace grammar")
    for key, expected in _RTP_FIXED.items():
        if values[key] != expected:
            _fail("RTPengine artifact {} differs from its fixed value".format(key))
    expected_interface = "{}!{}".format(facts.private_ipv4, facts.public_ipv4)
    if values["interface"] != expected_interface:
        _fail("RTPengine interface does not match immutable node facts")
    port_min = _integer(int(values["port-min"]), "RTPengine port-min", 1024, 65534)
    port_max = _integer(int(values["port-max"]), "RTPengine port-max", 1025, 65535)
    if (port_min, port_max) != (facts.tenant_media_port_start, facts.tenant_media_port_end):
        _fail("RTPengine media range does not match immutable node facts")
    max_sessions = _integer(int(values["max-sessions"]), "RTPengine max-sessions", 1, 64)
    spec = RtpengineSpec(facts.private_ipv4, facts.public_ipv4, port_min, port_max, max_sessions)
    if raw != render_rtpengine(spec):
        _fail("RTPengine artifact is not byte-canonical")
    return spec


def render_rtpengine(spec: RtpengineSpec) -> bytes:
    return f"""[rtpengine]
table = -1
interface = {spec.private_ipv4}!{spec.public_ipv4}
listen-ng = 127.0.0.1:2223
listen-cli = 127.0.0.1:2224
port-min = {spec.port_min}
port-max = {spec.port_max}
timeout = 60
silent-timeout = 3600
final-timeout = 10800
tos = 184
num-threads = 2
media-num-threads = 2
max-sessions = {spec.max_sessions}
foreground = true
log-stderr = true
log-level = 5
no-log-timestamps = true
scheduling = default
priority = 0
idle-scheduling = default
idle-priority = 0
io-uring = false
""".encode("ascii")


def render_runtime_rtpengine(
    facts: NodeFacts,
    authority: RuntimeAuthority,
    compiler_spec: RtpengineSpec,
) -> bytes:
    """Apply only the locally trusted profile to a strict compiler artifact.

    The compiler artifact remains byte-canonical and bound to immutable node
    facts as ``private!public``.  The root runtime may narrow only the live SDP
    advertisement: the isolated fixture uses the private address, while real
    Direct Routing retains the public address.
    """

    if (
        compiler_spec.private_ipv4,
        compiler_spec.public_ipv4,
        compiler_spec.port_min,
        compiler_spec.port_max,
    ) != (
        facts.private_ipv4,
        facts.public_ipv4,
        facts.tenant_media_port_start,
        facts.tenant_media_port_end,
    ):
        _fail("RTPengine compiler spec differs from immutable node facts")
    compiler_config = render_rtpengine(compiler_spec)
    compiler_interface = "interface = {}!{}\n".format(
        facts.private_ipv4, facts.public_ipv4
    ).encode("ascii")
    if compiler_config.count(compiler_interface) != 1:
        _fail("RTPengine compiler interface transformation is ambiguous")
    if authority.profile == "SYNTHETIC_PRIVATE":
        advertised_ipv4 = facts.private_ipv4
    elif authority.profile == "DIRECT_ROUTING":
        advertised_ipv4 = facts.public_ipv4
    else:
        _fail("runtime authority profile cannot select an RTP advertisement")
    runtime_spec = RtpengineSpec(
        facts.private_ipv4,
        advertised_ipv4,
        compiler_spec.port_min,
        compiler_spec.port_max,
        compiler_spec.max_sessions,
    )
    runtime_interface = "interface = {}!{}\n".format(
        facts.private_ipv4, advertised_ipv4
    ).encode("ascii")
    transformed = compiler_config.replace(compiler_interface, runtime_interface, 1)
    if transformed != render_rtpengine(runtime_spec):
        _fail("RTPengine profile transformation differs from the fixed runtime grammar")
    return transformed


def _nft_rule(
    rule_id: str,
    source_set: str,
    protocol: str,
    start: int,
    end: int | None = None,
    *,
    source_start: int | None = None,
    source_end: int | None = None,
) -> Dict[str, Any]:
    if end is None:
        end = start
    rule: Dict[str, Any] = {
        "action": "ACCEPT",
        "destinationPortRange": {"end": end, "start": start},
        "id": rule_id,
        "protocol": protocol,
        "sourceSet": source_set,
    }
    if protocol == "tcp":
        rule["connectionStates"] = ["new"]
    if source_start is not None or source_end is not None:
        if source_start is None or source_end is None:
            _fail("typed nft source range requires both endpoints")
        rule["sourcePortRange"] = {"end": source_end, "start": source_start}
    return rule


def expected_nft_policy(facts: NodeFacts) -> Dict[str, Any]:
    suffix = _tenant_token(facts).lower()
    tenant_sets = [
        {
            "elements": list(facts.authorized_pbx_source_ipv4_cidrs),
            "name": "pbx4_" + suffix,
            "type": "ipv4_addr",
        },
        {
            "elements": list(facts.teams_media_source_ipv4_cidrs),
            "name": "msmedia4_" + suffix,
            "type": "ipv4_addr",
        },
    ]
    tenant_rules = [
        _nft_rule("pbx-tls", "pbx4_" + suffix, "tcp", 15061),
        _nft_rule(
            "pbx-media",
            "pbx4_" + suffix,
            "udp",
            facts.tenant_media_port_start,
            facts.tenant_media_port_end,
            source_start=facts.pbx_media_destination_port_start,
            source_end=facts.pbx_media_destination_port_end,
        ),
        _nft_rule("microsoft-media", "msmedia4_" + suffix, "udp", facts.tenant_media_port_start, facts.tenant_media_port_end),
    ]
    cluster_sets = [
        {
            "elements": list(facts.teams_signaling_source_ipv4_cidrs),
            "name": "mssignal4",
            "type": "ipv4_addr",
        }
    ]
    cluster_rules = [_nft_rule("microsoft-tls", "mssignal4", "tcp", 5061)]
    if facts.synthetic_teams_source_ipv4_cidrs:
        tenant_sets.append(
            {
                "elements": list(facts.synthetic_teams_source_ipv4_cidrs),
                "name": "syntheticmedia4_" + suffix,
                "type": "ipv4_addr",
            }
        )
        tenant_rules.append(
            _nft_rule(
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
        cluster_rules.append(_nft_rule("synthetic-tls", "syntheticsignal4_" + suffix, "tcp", 5061))
    return {
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
            "allocationId": facts.allocation_id,
            "chain": "tenant_" + suffix,
            "rules": tenant_rules,
            "sets": tenant_sets,
            "table": "vivolution_edge_filter",
            "tenantContextId": facts.tenant_context_id,
        },
    }


def validate_nft_artifact(raw: bytes, facts: NodeFacts) -> None:
    policy = parse_json_bytes(raw, "nftables tenant policy")
    if not isinstance(policy, Mapping) or policy != expected_nft_policy(facts):
        _fail("nftables tenant policy differs from the complete typed compiler v0.1 policy")
    if raw != canonical_bytes(expected_nft_policy(facts)):
        _fail("nftables tenant policy is not byte-canonical")


def _nft_elements(cidrs: Sequence[str]) -> str:
    return ", ".join(cidrs)


def render_nftables(
    facts: NodeFacts,
    authority: RuntimeAuthority,
    route: TenantRouteSpec,
) -> bytes:
    synthetic_sets = ""
    synthetic_rules = ""
    if authority.profile == "SYNTHETIC_PRIVATE":
        synthetic_sets = f"""
    set synthetic_teams_source_ipv4 {{
        type ipv4_addr
        flags interval
        auto-merge
        elements = {{ {_nft_elements(facts.authorized_pbx_source_ipv4_cidrs)} }}
    }}
"""
        synthetic_rules = f"""
        ip saddr @synthetic_teams_source_ipv4 tcp dport 5061 ct state new accept
        ip saddr @synthetic_teams_source_ipv4 udp dport {facts.tenant_media_port_start}-{facts.tenant_media_port_end} accept
"""
    microsoft_rules = ""
    profile_output_rules = ""
    if authority.profile == "DIRECT_ROUTING":
        microsoft_rules = f"""        ip saddr @microsoft_signaling_source_ipv4 tcp dport 5061 ct state new accept
        ip saddr @microsoft_media_source_ipv4 udp sport {MICROSOFT_MEDIA_PROCESSOR_REMOTE_PORT_SET} udp dport {facts.tenant_media_port_start}-{facts.tenant_media_port_end} accept
"""
        profile_output_rules = f"""
        ip daddr @microsoft_signaling_source_ipv4 tcp dport 5061 ct state new accept
        ip daddr @microsoft_media_source_ipv4 udp sport {facts.tenant_media_port_start}-{facts.tenant_media_port_end} udp dport {MICROSOFT_MEDIA_PROCESSOR_REMOTE_PORT_SET} accept
        ip daddr @pbx_source_ipv4 tcp dport {route.pbx_port} ct state new accept
        ip daddr @pbx_source_ipv4 udp sport {facts.tenant_media_port_start}-{facts.tenant_media_port_end} udp dport {facts.pbx_media_destination_port_start}-{facts.pbx_media_destination_port_end} accept
"""
    else:
        profile_output_rules = f"""
        ip daddr @control_plane_ipv4 tcp dport {{ 16061, 25061 }} ct state new accept
        ip daddr @control_plane_ipv4 udp sport {facts.tenant_media_port_start}-{facts.tenant_media_port_end} udp dport {{ 21000-21127, 22000-22063 }} accept
"""
    text = f"""#!/usr/sbin/nft -f
# Vivolution runtime-owned table v0.1. Foreign tables are preserved.
destroy table inet vivolution_edge_filter

table inet vivolution_edge_filter {{
    set administrator_source_ipv4 {{
        type ipv4_addr
        flags interval
        auto-merge
        elements = {{ {_nft_elements(authority.administrator_source_ipv4_cidrs)} }}
    }}

    set microsoft_signaling_source_ipv4 {{
        type ipv4_addr
        flags interval
        auto-merge
        elements = {{ {_nft_elements(facts.teams_signaling_source_ipv4_cidrs)} }}
    }}

    set microsoft_media_source_ipv4 {{
        type ipv4_addr
        flags interval
        auto-merge
        elements = {{ {_nft_elements(facts.teams_media_source_ipv4_cidrs)} }}
    }}
{synthetic_sets}
    set pbx_source_ipv4 {{
        type ipv4_addr
        flags interval
        auto-merge
        elements = {{ {_nft_elements(facts.authorized_pbx_source_ipv4_cidrs)} }}
    }}

    set control_plane_ipv4 {{
        type ipv4_addr
        flags interval
        auto-merge
        elements = {{ {_nft_elements(CONTROL_PLANE_IPV4_CIDRS)} }}
    }}

    set ntp_server_ipv4 {{
        type ipv4_addr
        flags interval
        auto-merge
        elements = {{ {_nft_elements(NTP_SERVER_IPV4_CIDRS)} }}
    }}

    chain input {{
        type filter hook input priority filter; policy drop;

        iifname "lo" accept
        ct state invalid drop
        ct state established,related accept
        ip protocol icmp accept
        ip6 nexthdr ipv6-icmp accept
        ip saddr {authority.azure_dhcp_server_ipv4} udp sport 67 udp dport 68 accept
        ip saddr @administrator_source_ipv4 tcp dport 22 ct state new accept
{microsoft_rules}
{synthetic_rules}        ip saddr @pbx_source_ipv4 tcp dport 15061 ct state new accept
        ip saddr @pbx_source_ipv4 udp sport {facts.pbx_media_destination_port_start}-{facts.pbx_media_destination_port_end} udp dport {facts.tenant_media_port_start}-{facts.tenant_media_port_end} accept
    }}

    chain forward {{
        type filter hook forward priority filter; policy drop;
    }}

    chain output {{
        type filter hook output priority filter; policy drop;

        oifname "lo" accept
        ct state invalid drop
        ct state established,related accept
        ip daddr {authority.azure_dhcp_server_ipv4} udp sport 68 udp dport 67 accept
        ip daddr {authority.azure_dhcp_server_ipv4} udp dport 53 accept
        ip daddr {authority.azure_dhcp_server_ipv4} tcp dport 53 ct state new accept
        ip daddr {authority.azure_dhcp_server_ipv4} tcp dport {{ 80, 32526 }} ct state new accept
        ip daddr {AZURE_IMDS_IPV4} tcp dport 80 ct state new accept
        ip daddr @ntp_server_ipv4 udp dport 123 accept
        ip daddr @control_plane_ipv4 tcp dport 443 ct state new accept
        meta nfproto ipv4 tcp dport {{ 80, 443 }} ct state new accept
{profile_output_rules}
    }}
}}
"""
    if "flush ruleset" in text or "destroy table" not in text:
        _fail("internal nft renderer violated the owned-table contract")
    return text.encode("ascii")


def _source_match(cidrs: Sequence[str]) -> str:
    return " || ".join("$(si{{ip.matches,{}}}) == 1".format(cidr) for cidr in cidrs)


def _tls_domain(
    kind: str,
    name: str,
    match_address: str,
    match_domain: str,
    certificate: Path,
    private_key: Path,
    ca_bundle: Path,
    cipher_list: str,
) -> str:
    for path in (certificate, private_key, ca_bundle):
        if _SAFE_PATH_RE.fullmatch(str(path)) is None:
            _fail("fixed TLS path contains unsafe characters")
    if cipher_list not in {
        MICROSOFT_TLS12_CIPHER_LIST,
        SYNTHETIC_FIXTURE_TLS12_CIPHER_LIST,
    }:
        _fail("fixed TLS domain selected an unreviewed cipher list")
    return f"""modparam("tls_mgm", "{kind}_domain", "{name}")
modparam("tls_mgm", "match_ip_address", "[{name}]{match_address}")
modparam("tls_mgm", "match_sip_domain", "[{name}]{match_domain}")
modparam("tls_mgm", "certificate", "[{name}]{certificate}")
modparam("tls_mgm", "private_key", "[{name}]{private_key}")
modparam("tls_mgm", "ca_list", "[{name}]{ca_bundle}")
modparam("tls_mgm", "tls_method", "[{name}]TLSv1_2")
modparam("tls_mgm", "ciphers_list", "[{name}]{cipher_list}")
modparam("tls_mgm", "verify_cert", "[{name}]1")
modparam("tls_mgm", "require_cert", "[{name}]1")
"""


def _egress_identity(facts: NodeFacts, port: int, indentation: str = "    ") -> str:
    return (
        f'{indentation}force_send_socket("tls:{facts.private_ipv4}:{port}");\n'
        f'{indentation}set_advertised_address("{facts.node_fqdn}");\n'
        f'{indentation}set_advertised_port("{port}");'
    )


def _direct_options_routes(route: TenantRouteSpec, facts: NodeFacts) -> str:
    # OpenSIPS 3.6.8's TM module runs ``local_route`` for each request created
    # by ``t_new_request``.  Assigning the TLS client-domain AVP and forced
    # socket there is important: TM reselects that socket and rebuilds Via
    # after the local route, so the generated request cannot inherit whichever
    # listener happened to be declared first in the base configuration.
    teams_from = f"sip:{facts.node_fqdn}:{TEAMS_TLS_PORT}"
    pbx_from = f"sip:{facts.node_fqdn}:{PBX_TLS_LISTENER_PORT}"
    local_targets = []
    timer_requests = []
    for hub in TEAMS_HUBS:
        ruri = f"sip:{hub}:{TEAMS_TLS_PORT};transport=tls"
        local_targets.append(
            f'''    if ($ru == "{ruri}") {{
        $avp(tls_sip_dom) = "{hub}";
{_egress_identity(facts, TEAMS_TLS_PORT, "        ")}
        append_hf("Contact: <{teams_from};transport=tls>\\r\\n");
        exit;
    }}'''
        )
        timer_requests.append(
            f'    t_new_request("OPTIONS", "{ruri}", "{teams_from}", '
            f'"sip:{hub}:{TEAMS_TLS_PORT}");'
        )

    pbx_ruri = f"sip:{route.pbx_host}:{route.pbx_port};transport=tls"
    local_targets.append(
        f'''    if ($ru == "{pbx_ruri}") {{
        $avp(tls_sip_dom) = "{route.pbx_host}";
{_egress_identity(facts, PBX_TLS_LISTENER_PORT, "        ")}
        append_hf("Contact: <{pbx_from};transport=tls>\\r\\n");
        exit;
    }}'''
    )
    timer_requests.append(
        f'    t_new_request("OPTIONS", "{pbx_ruri}", "{pbx_from}", '
        f'"sip:{route.pbx_host}:{route.pbx_port}");'
    )
    local_target_text = "\n".join(local_targets)
    timer_request_text = "\n".join(timer_requests)

    return f'''#### Direct Routing OPTIONS generation; peer responses are an external acceptance gate.
local_route {{
    if (!is_method("OPTIONS")) {{
        exit;
    }}
{local_target_text}
    exit;
}}

timer_route[VIVO_{route.token}_DIRECT_OPTIONS, {route.options_interval_seconds}] {{
{timer_request_text}
}}
'''


def _runtime_tenant_fragment(
    route: TenantRouteSpec, authority: RuntimeAuthority, facts: NodeFacts
) -> str:
    source = _compiler_fragment(route).decode("ascii")
    pbx_du = f'    $du = "sip:{route.pbx_host}:{route.pbx_port};transport=tls";'
    pbx_target = (
        '    $du = "sip:10.20.1.4:16061;transport=tls";'
        if authority.profile == "SYNTHETIC_PRIVATE"
        else pbx_du
    )
    pbx_runtime = (
        f'    $avp(tls_sip_dom) = "{route.pbx_host}";\n'
        f"{pbx_target}\n"
        f"{_egress_identity(facts, PBX_TLS_LISTENER_PORT)}"
    )
    if source.count(pbx_du) != 1:
        _fail("internal PBX destination transformation is ambiguous")
    source = source.replace(pbx_du, pbx_runtime, 1)

    teams_du = f'    $du = "sip:{TEAMS_HUBS[0]}:5061;transport=tls";'
    if authority.profile == "SYNTHETIC_PRIVATE":
        teams_runtime = (
            '    $avp(tls_sip_dom) = "10.20.1.4";\n'
            '    $du = "sip:10.20.1.4:25061;transport=tls";\n'
            f"{_egress_identity(facts, TEAMS_TLS_PORT)}"
        )
    else:
        teams_runtime = (
            "    $avp(vivo_teams_hub) = 1;\n"
            f'    $avp(tls_sip_dom) = "{TEAMS_HUBS[0]}";\n'
            f"{teams_du}\n"
            f"{_egress_identity(facts, TEAMS_TLS_PORT)}"
        )
    if source.count(teams_du) != 1:
        _fail("internal Teams destination transformation is ambiguous")
    source = source.replace(teams_du, teams_runtime, 1)

    failure_hook = f'    t_on_failure("VIVO_{route.token}_MEDIA_FAILURE");'
    first = source.find(failure_hook)
    second = source.find(failure_hook, first + 1)
    if first < 0 or second < 0 or source.find(failure_hook, second + 1) >= 0:
        _fail("internal failure-route transformation is ambiguous")
    failover_hook = (
        f'    t_on_failure("VIVO_{route.token}_MEDIA_FAILURE");'
        if authority.profile == "SYNTHETIC_PRIVATE"
        else f'    t_on_failure("VIVO_{route.token}_TEAMS_FAILOVER");'
    )
    source = source[:second] + failover_hook + source[second + len(failure_hook) :]

    old_tail = f"""failure_route[VIVO_{route.token}_MEDIA_FAILURE] {{
{_synthetic_cdr_final(route.token, "SIP_FAILURE")}
    rtpengine_delete();
}}
"""
    new_tail = old_tail
    if authority.profile == "DIRECT_ROUTING":
        new_tail += f"""
failure_route[VIVO_{route.token}_TEAMS_FAILOVER] {{
    if (t_was_cancelled()) {{
        rtpengine_delete();
        exit;
    }}
    if ($avp(vivo_teams_hub) == 1) {{
        $avp(vivo_teams_hub) = 2;
        $avp(tls_sip_dom) = "{TEAMS_HUBS[1]}";
        $du = "sip:{TEAMS_HUBS[1]}:5061;transport=tls";
{_egress_identity(facts, TEAMS_TLS_PORT, "        ")}
        t_on_failure("VIVO_{route.token}_TEAMS_FAILOVER");
        if (t_relay()) exit;
    }}
    if ($avp(vivo_teams_hub) == 2) {{
        $avp(vivo_teams_hub) = 3;
        $avp(tls_sip_dom) = "{TEAMS_HUBS[2]}";
        $du = "sip:{TEAMS_HUBS[2]}:5061;transport=tls";
{_egress_identity(facts, TEAMS_TLS_PORT, "        ")}
        t_on_failure("VIVO_{route.token}_TEAMS_FAILOVER");
        if (t_relay()) exit;
    }}
    rtpengine_delete();
}}
"""
        new_tail += "\n" + _direct_options_routes(route, facts)
    if source.count(old_tail) != 1:
        _fail("internal failure-route tail transformation is ambiguous")
    return source.replace(old_tail, new_tail, 1)


def render_opensips(
    facts: NodeFacts,
    route: TenantRouteSpec,
    authority: RuntimeAuthority,
    secrets: SecretPaths,
) -> bytes:
    peer_ca = (
        secrets.fixture_ca_crt
        if authority.profile == "SYNTHETIC_PRIVATE"
        else secrets.microsoft_ca_bundle_pem
    )
    teams_server = _tls_domain(
        "server",
        "teams-inbound",
        "{}:5061".format(facts.private_ipv4),
        facts.node_fqdn,
        secrets.edge_certificate_chain_pem,
        secrets.edge_private_key_pem,
        peer_ca,
        MICROSOFT_TLS12_CIPHER_LIST,
    )
    pbx_server = _tls_domain(
        "server",
        "pbx-inbound",
        "{}:15061".format(facts.private_ipv4),
        facts.node_fqdn,
        secrets.edge_certificate_chain_pem,
        secrets.edge_private_key_pem,
        secrets.fixture_ca_crt if authority.profile == "SYNTHETIC_PRIVATE" else secrets.pbx_ca_bundle_pem,
        MICROSOFT_TLS12_CIPHER_LIST,
    )
    if authority.profile == "SYNTHETIC_PRIVATE":
        teams_clients = _tls_domain(
            "client",
            "teams-fixture-outbound",
            "10.20.1.4:25061",
            "10.20.1.4",
            secrets.fixture_client_crt,
            secrets.fixture_client_key,
            secrets.fixture_ca_crt,
            SYNTHETIC_FIXTURE_TLS12_CIPHER_LIST,
        )
    else:
        teams_clients = "\n".join(
            _tls_domain(
                "client",
                "teams-outbound-{}".format(index),
                "*",
                hub,
                secrets.edge_certificate_chain_pem,
                secrets.edge_private_key_pem,
                secrets.microsoft_ca_bundle_pem,
                MICROSOFT_TLS12_CIPHER_LIST,
            )
            for index, hub in enumerate(TEAMS_HUBS, 1)
        )
    pbx_client = _tls_domain(
        "client",
        "pbx-outbound",
        "10.20.1.4:16061" if authority.profile == "SYNTHETIC_PRIVATE" else "*",
        route.pbx_host,
        secrets.fixture_client_crt if authority.profile == "SYNTHETIC_PRIVATE" else secrets.edge_certificate_chain_pem,
        secrets.fixture_client_key if authority.profile == "SYNTHETIC_PRIVATE" else secrets.edge_private_key_pem,
        secrets.fixture_ca_crt if authority.profile == "SYNTHETIC_PRIVATE" else secrets.pbx_ca_bundle_pem,
        SYNTHETIC_FIXTURE_TLS12_CIPHER_LIST
        if authority.profile == "SYNTHETIC_PRIVATE"
        else MICROSOFT_TLS12_CIPHER_LIST,
    )
    microsoft_sources = (
        facts.authorized_pbx_source_ipv4_cidrs
        if authority.profile == "SYNTHETIC_PRIVATE"
        else facts.teams_signaling_source_ipv4_cidrs
    )
    if not microsoft_sources:
        _fail("Teams ingress must have at least one local source authority")
    synthetic_cdr_runtime = (
        "#!define VIVO_SYNTHETIC_CDR\n"
        'modparam("tm", "onreply_avp_mode", 1)\n'
        if authority.profile == "SYNTHETIC_PRIVATE"
        else ""
    )
    text = f"""#### Vivolution Open Edge runtime configuration v0.1
#### Complete, locally compiled configuration. Do not hand-edit.

log_level=3
xlog_level=3
stderror_enabled=no
syslog_enabled=yes
syslog_facility=LOG_LOCAL0
tcp_workers=4
tcp_connection_lifetime=3600
advertised_address="{facts.node_fqdn}"
socket=tls:{facts.private_ipv4}:5061
socket=tls:{facts.private_ipv4}:15061
alias=tls:{facts.node_fqdn}:5061
alias=tls:{facts.node_fqdn}:15061
mpath="/usr/lib/x86_64-linux-gnu/opensips/modules/"

loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "tm.so"
loadmodule "rr.so"
loadmodule "maxfwd.so"
loadmodule "proto_tls.so"
loadmodule "tls_openssl.so"
loadmodule "tls_mgm.so"
loadmodule "sipmsgops.so"
loadmodule "textops.so"
loadmodule "rtpengine.so"
{synthetic_cdr_runtime}

modparam("tm", "fr_timeout", 5)
modparam("tm", "fr_inv_timeout", 60)
modparam("rr", "append_fromtag", 1)
modparam("tls_mgm", "client_sip_domain_avp", "tls_sip_dom")
{teams_server}
{pbx_server}
{teams_clients}
{pbx_client}
route {{
    if (!mf_process_maxfwd_header(10)) {{
        send_reply(483, "Too Many Hops");
        exit;
    }}
    if (is_method("CANCEL")) {{
        if (t_check_trans()) t_relay();
        exit;
    }}
    if (has_totag()) {{
        if (loose_route()) {{
            if (is_method("BYE")) rtpengine_delete();
            route(VIVO_RELAY);
        }}
        if (is_method("ACK") && t_check_trans()) t_relay();
        send_reply(404, "Not here");
        exit;
    }}
    if (!is_peer_verified()) {{
        send_reply(403, "Verified mutual TLS required");
        exit;
    }}
    if ($socket_in(port) == 5061) {{
        if (!({_source_match(microsoft_sources)})) {{
            send_reply(403, "Unauthorized Teams source");
            exit;
        }}
        route(VIVO_{route.token}_TEAMS_TO_PBX);
    }}
    if ($socket_in(port) == 15061) {{
        if (!({_source_match(facts.authorized_pbx_source_ipv4_cidrs)})) {{
            send_reply(403, "Unauthorized PBX source");
            exit;
        }}
        route(VIVO_{route.token}_PBX_TO_TEAMS);
    }}
    send_reply(403, "Unknown ingress");
    exit;
}}

route[VIVO_RELAY] {{
    if (!t_relay()) sl_reply_error();
    exit;
}}

{_runtime_tenant_fragment(route, authority, facts)}"""
    return text.encode("ascii")


def _validate_compile_evidence(
    raw: bytes,
    facts: NodeFacts,
    artifacts: Mapping[str, bytes],
    receipt: VerificationReceipt,
) -> Tuple[Mapping[str, str], LocalHealthGatePlan, str]:
    evidence = _exact_mapping(
        parse_json_bytes(raw, "compile evidence"),
        {
            "apiVersion",
            "artifactDigests",
            "factsDigest",
            "kind",
            "localHealthGatePlan",
            "localHealthGatePlanDigest",
            "manifestDigest",
            "manifestId",
            "nodeId",
            "pbxMediaDestinationPortRange",
            "readiness",
            "sequence",
        },
        "compile evidence",
    )
    if evidence["apiVersion"] != COMPILER_API_VERSION or evidence["kind"] != "TenantCompileEvidence":
        _fail("compile evidence type is unsupported")
    if raw != canonical_bytes(evidence):
        _fail("compile evidence is not in canonical newline-terminated byte form")
    expected_identity = {
        "manifestDigest": receipt.manifest_digest,
        "manifestId": receipt.manifest_id,
        "sequence": receipt.sequence,
        "nodeId": facts.node_id,
    }
    for field, expected in expected_identity.items():
        if evidence[field] != expected:
            _fail("compile evidence {} does not match verifier/local authority".format(field))
    facts_digest = sha256_digest(manifest_tool.canonical_json_bytes(facts.canonical_record()))
    if evidence["factsDigest"] != facts_digest:
        _fail("compile evidence factsDigest does not match immutable node facts")
    if evidence["pbxMediaDestinationPortRange"] != {
        "end": facts.pbx_media_destination_port_end,
        "start": facts.pbx_media_destination_port_start,
    }:
        _fail(
            "compile evidence PBX media destination range differs from immutable node facts"
        )
    readiness = _exact_mapping(
        evidence["readiness"],
        {
            "bandwidthQuotaEnforced",
            "callRateLimitEnforced",
            "codecPolicyEnforced",
            "compilerStage",
            "liveTeamsInteroperability",
            "runtimeApplied",
            "syntheticTeamsInputConfigured",
        },
        "compile evidence readiness",
    )
    expected_readiness = {
        "bandwidthQuotaEnforced": False,
        "callRateLimitEnforced": False,
        "codecPolicyEnforced": False,
        "compilerStage": "BOOTSTRAP_ARTIFACTS_READY",
        "liveTeamsInteroperability": "NOT_ASSERTED",
        "runtimeApplied": False,
        "syntheticTeamsInputConfigured": bool(facts.synthetic_teams_source_ipv4_cidrs),
    }
    if dict(readiness) != expected_readiness:
        _fail("compile evidence readiness differs from the reviewed compiler boundary")
    plan = validate_local_health_gate_plan(
        evidence["localHealthGatePlan"],
        facts=facts,
        expected_manifest_digest=receipt.manifest_digest,
    )
    plan_digest = _digest(
        evidence["localHealthGatePlanDigest"],
        "compile evidence local health gate plan digest",
    )
    if (
        plan_digest != plan.digest
        or plan_digest != receipt.local_health_gate_plan_digest
    ):
        _fail(
            "compile evidence, verifier receipt and canonical local health gate "
            "plan digests do not match"
        )
    digests = _exact_mapping(
        evidence["artifactDigests"], set(ARTIFACT_FILENAMES), "compile evidence artifactDigests"
    )
    result = {}
    for name in ARTIFACT_FILENAMES:
        digest = _digest(digests[name], "compile evidence artifact digest")
        if digest != sha256_digest(artifacts[name]):
            _fail("compiled artifact {} does not match compile evidence".format(name))
        result[name] = digest
    return result, plan, sha256_digest(raw)


def _local_agent_context(facts: NodeFacts) -> agent_security.LocalContext:
    """Reconstruct the same immutable TENANT context under root authority."""

    try:
        return agent_security.LocalContext(
            scope="TENANT",
            cluster_id=facts.cluster_id,
            node_id=facts.node_id,
            generation=facts.generation,
            slot=facts.slot,
            customer_account_id=facts.customer_account_id,
            m365_tenant_id=facts.m365_tenant_id,
            tenant_context_id=facts.tenant_context_id,
            service_instance_id=facts.service_instance_id,
            allocation_id=facts.allocation_id,
            tenant_listener_port=facts.tenant_listener_port,
            tenant_media_port_start=facts.tenant_media_port_start,
            tenant_media_port_end=facts.tenant_media_port_end,
            pbx_media_destination_port_start=(
                facts.pbx_media_destination_port_start
            ),
            pbx_media_destination_port_end=facts.pbx_media_destination_port_end,
            cluster_media_port_start=facts.cluster_media_port_start,
            cluster_media_port_end=facts.cluster_media_port_end,
            expected_advertised_public_ip=facts.public_ipv4,
            authorized_pbx_source_cidrs=(
                facts.authorized_pbx_source_ipv4_cidrs
            ),
        )
    except (TypeError, ValueError) as exc:
        _fail("immutable node facts cannot form Agent verification context: {}".format(exc))


def _pinned_keyring(raw: bytes) -> agent_security.PinnedKeyring:
    record = _exact_mapping(
        parse_json_bytes(raw, "root-pinned signing public key", maximum=4096),
        {"keyId", "publicKeyBase64"},
        "root-pinned signing public key",
    )
    canonical = manifest_tool.canonical_json_bytes(record)
    if raw not in {canonical, canonical + b"\n"}:
        _fail("root-pinned signing public key is not canonical JSON")
    key_id = record["keyId"]
    if not isinstance(key_id, str) or manifest_tool.ID_RE.fullmatch(key_id) is None:
        _fail("root-pinned signing key id is invalid")
    encoded = record["publicKeyBase64"]
    if not isinstance(encoded, str):
        _fail("root-pinned signing public key is invalid")
    try:
        public_key = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        _fail("root-pinned signing public key is not canonical base64: {}".format(exc))
    if len(public_key) != 32 or base64.b64encode(public_key).decode("ascii") != encoded:
        _fail("root-pinned signing public key must be one canonical Ed25519 key")
    try:
        return agent_security.PinnedKeyring({key_id: public_key})
    except ValueError as exc:
        _fail("root-pinned signing key is invalid: {}".format(exc))


def _verify_root_signed_envelope(
    raw: bytes,
    pinned_key_raw: bytes,
    facts: NodeFacts,
    accepted_runtime: AcceptedRuntimeState,
    *,
    expected_sequence: int,
    expected_manifest_digest: str,
    now: datetime,
) -> Tuple[Mapping[str, Any], Tuple[str, ...], str, Mapping[str, str], LocalHealthGatePlan]:
    """Independently verify signed authority inside the privileged boundary."""

    if not isinstance(accepted_runtime, AcceptedRuntimeState):
        _fail("root runtime acceptance state is required")
    # Re-run dataclass validation even if a caller used an unusual construction path.
    accepted_runtime = AcceptedRuntimeState(
        accepted_runtime.highest_seen_sequence,
        accepted_runtime.active_sequence,
        accepted_runtime.active_manifest_digest,
        tuple(accepted_runtime.active_artifact_digests),
    )
    if now.tzinfo is None:
        _fail("root envelope verification time must be timezone-aware")
    effective_now = now.astimezone(timezone.utc)
    keyring = _pinned_keyring(pinned_key_raw)
    try:
        envelope = agent_security.parse_envelope_bytes(raw)
        agent_security.validate_structural_envelope(envelope)
    except agent_security.AgentError as exc:
        _fail("root signed-envelope structural verification failed: {}".format(exc))
    canonical_envelope = manifest_tool.canonical_json_bytes(envelope)
    if raw not in {canonical_envelope, canonical_envelope + b"\n"}:
        _fail("root signed envelope is not canonical JSON")

    local_context = _local_agent_context(facts)
    active_lkg: Mapping[str, Any] | None
    if accepted_runtime.active_sequence == 0:
        active_lkg = None
    else:
        active_lkg = {
            "artifactDigests": list(accepted_runtime.active_artifact_digests),
            "manifestDigest": accepted_runtime.active_manifest_digest,
            "sequence": accepted_runtime.active_sequence,
        }
    try:
        manifest_tool.validate_envelope(
            envelope,
            agent_security._validation_context(
                local_context,
                accepted_runtime.active_sequence,
                accepted_runtime.active_manifest_digest,
                effective_now,
            ),
        )
        manifest = envelope["manifest"]
        if manifest["sequence"] <= accepted_runtime.highest_seen_sequence:
            raise agent_security.EnvelopeRejected(
                "manifest sequence does not exceed the root-protected replay floor"
            )
        agent_security._enforce_exact_local_identity(envelope, local_context)
        agent_security._enforce_local_network_allocation(envelope, local_context)
        agent_security._enforce_lkg_artifact_lineage(envelope, active_lkg)
        verified_key_ids = agent_security.verify_authorized_signatures(
            envelope, keyring
        )
        agent_candidate = agent_security._candidate_for_envelope(
            envelope, verified_key_ids
        )
    except manifest_tool.ContractError as exc:
        _fail("root signed-envelope semantic verification failed: {}".format("; ".join(exc.errors)))
    except (agent_security.AgentError, KeyError, TypeError, ValueError) as exc:
        _fail("root signed-envelope verification failed: {}".format(exc))

    if (
        envelope["manifestDigest"] != expected_manifest_digest
        or manifest["sequence"] != expected_sequence
    ):
        _fail("root signed envelope differs from the CLI candidate identity")
    if agent_candidate["manifestDigest"] != expected_manifest_digest:
        _fail("root Agent verification result differs from the signed manifest")

    signed_plan = validate_local_health_gate_plan(
        {
            "apiVersion": LOCAL_HEALTH_PLAN_API_VERSION,
            "healthGates": manifest["healthGates"],
            "kind": LOCAL_HEALTH_PLAN_KIND,
            "manifestDigest": expected_manifest_digest,
        },
        facts=facts,
        expected_manifest_digest=expected_manifest_digest,
    )
    if agent_candidate["localHealthGatePlanDigest"] != signed_plan.digest:
        _fail("root Agent and runtime signed health-plan digests differ")

    declarations = manifest["resourceSet"]["artifacts"]
    by_kind = {
        declaration["kind"]: declaration
        for declaration in declarations
        if isinstance(declaration, Mapping)
    }
    if set(by_kind) != set(compiler_core.ARTIFACT_FILENAMES):
        _fail("signed manifest artifact declarations differ from the fixed compiler set")
    signed_artifact_digests: Dict[str, str] = {}
    for kind, filename in compiler_core.ARTIFACT_FILENAMES.items():
        declaration = by_kind[kind]
        digest = _digest(declaration.get("sha256"), "signed artifact declaration")
        signed_artifact_digests[filename] = digest
    if sorted(signed_artifact_digests.values()) != agent_candidate["artifactDigests"]:
        _fail("root Agent and runtime signed artifact declarations differ")

    return (
        envelope,
        tuple(verified_key_ids),
        sha256_digest(raw),
        dict(sorted(signed_artifact_digests.items())),
        signed_plan,
    )


def validate_candidate(
    handoff: Mapping[str, bytes],
    node_facts_raw: bytes,
    runtime_authority_raw: bytes,
    pinned_key_raw: bytes,
    secret_bytes: Mapping[str, bytes],
    secret_paths: SecretPaths,
    *,
    expected_sequence: int,
    expected_manifest_digest: str,
    accepted_runtime: AcceptedRuntimeState,
    now: datetime | None = None,
) -> ValidatedCandidate:
    """Validate and render one verifier-approved, compiler-produced candidate."""

    if set(handoff) != HANDOFF_FILENAMES:
        _fail("candidate hand-off file set differs from the fixed contract")
    for name, content in handoff.items():
        maximum = (
            MAX_SIGNED_ENVELOPE_BYTES
            if name == "signed-envelope.json"
            else MAX_JSON_BYTES
            if name.endswith(".json")
            else MAX_ARTIFACT_BYTES
        )
        if not isinstance(content, bytes) or not content or len(content) > maximum:
            _fail("candidate hand-off {} is empty or oversized".format(name))
    expected_sequence = _integer(expected_sequence, "expected sequence", 1, 2**53 - 1)
    expected_manifest_digest = _digest(expected_manifest_digest, "expected manifest digest")

    facts_record = parse_json_bytes(node_facts_raw, "immutable node facts")
    try:
        facts = NodeFacts.from_mapping(facts_record)
    except Exception as exc:
        _fail("immutable node facts rejected: {}".format(exc))
    authority = RuntimeAuthority.from_mapping(
        parse_json_bytes(runtime_authority_raw, "runtime authority")
    )
    if (authority.node_id, authority.generation, authority.slot) != (
        facts.node_id,
        facts.generation,
        facts.slot,
    ):
        _fail("runtime authority crosses immutable node identity")

    effective_now = now if now is not None else datetime.now(timezone.utc)
    if effective_now.tzinfo is None:
        _fail("runtime validation time must be timezone-aware")
    (
        signed_envelope,
        verified_key_ids,
        signed_envelope_digest,
        signed_artifact_digests,
        signed_health_plan,
    ) = _verify_root_signed_envelope(
        handoff["signed-envelope.json"],
        pinned_key_raw,
        facts,
        accepted_runtime,
        expected_sequence=expected_sequence,
        expected_manifest_digest=expected_manifest_digest,
        now=effective_now,
    )

    receipt_mapping = parse_json_bytes(handoff["verifier-receipt.json"], "verifier receipt")
    try:
        receipt = VerificationReceipt.from_mapping(receipt_mapping)
    except Exception as exc:
        _fail("verifier receipt rejected: {}".format(exc))
    if receipt.sequence != expected_sequence or receipt.manifest_digest != expected_manifest_digest:
        _fail("CLI candidate identity differs from the verifier receipt")
    if handoff["verifier-receipt.json"] != canonical_bytes(receipt.canonical_record()):
        _fail("verifier receipt is not canonical newline-terminated JSON")
    if (
        receipt.manifest_id != signed_envelope["manifest"]["manifestId"]
        or receipt.verified_key_ids != verified_key_ids
    ):
        _fail("verifier receipt differs from independent root signature verification")

    artifacts = {name: handoff[name] for name in ARTIFACT_FILENAMES}
    artifact_digests, local_health_plan, compile_evidence_digest = _validate_compile_evidence(
        handoff["compile-evidence.json"], facts, artifacts, receipt
    )
    if artifact_digests != signed_artifact_digests:
        _fail("compiled artifacts differ from signed manifest declarations")
    if local_health_plan.record() != signed_health_plan.record():
        _fail("compiler health plan differs from the independently verified signed plan")
    validate_secret_material(facts, authority, secret_bytes, now=effective_now)
    route = parse_compiler_fragment(artifacts["opensips-tenant.cfg"], facts)
    if authority.profile == "SYNTHETIC_PRIVATE":
        if facts.synthetic_teams_source_ipv4_cidrs:
            _fail(
                "synthetic runtime profile keeps compiler synthetic source authority empty; "
                "the fixed root profile authorizes CP1 on the separate Teams listener"
            )
        if facts.authorized_pbx_source_ipv4_cidrs != ("10.20.1.4/32",):
            _fail("synthetic runtime profile requires only fixed CP1 PBX source 10.20.1.4/32")
        if (
            facts.pbx_media_destination_port_start,
            facts.pbx_media_destination_port_end,
        ) != (21000, 21127):
            _fail(
                "synthetic runtime profile requires fixed CP1 PBX media destination 21000-21127"
            )
        if (route.pbx_host, route.pbx_port) != ("pbx-fixture.invalid", 16061):
            _fail(
                "synthetic runtime profile requires typed PBX TLS identity "
                "pbx-fixture.invalid:16061; runtime pins its address to 10.20.1.4"
            )
    else:
        if authority.generation < 2:
            _fail("Direct Routing requires a replacement/new-generation node identity")
        if facts.synthetic_teams_source_ipv4_cidrs:
            _fail("Direct Routing profile refuses synthetic Teams source authority")
        direct_pbx_sources = _cidrs(
            list(facts.authorized_pbx_source_ipv4_cidrs),
            "Direct Routing PBX source authority",
            minimum_prefix=24,
            maximum_items=8,
            globally_routable=True,
        )
        if any(
            not (
                ipaddress.ip_network(value).network_address.is_global
                and ipaddress.ip_network(value).broadcast_address.is_global
            )
            for value in direct_pbx_sources
        ):
            _fail("Direct Routing PBX source authority must be wholly globally routable")
        if direct_pbx_sources != facts.authorized_pbx_source_ipv4_cidrs:
            _fail("Direct Routing PBX source authority is not canonical")
        direct_pbx_host = _fqdn(route.pbx_host, "Direct Routing PBX TLS identity")
        direct_pbx_labels = direct_pbx_host.split(".")
        if (
            direct_pbx_host in _DIRECT_RESERVED_FQDN_NAMES
            or direct_pbx_host.endswith(_DIRECT_RESERVED_FQDN_SUFFIXES)
            or direct_pbx_host.endswith((".example.com", ".example.net", ".example.org"))
            or any(
                label in _DIRECT_PLACEHOLDER_FQDN_LABELS
                for label in direct_pbx_labels
            )
        ):
            _fail("Direct Routing PBX TLS identity is reserved or a placeholder")
        if route.pbx_port != 5061:
            _fail("Direct Routing PBX TLS port must be the reviewed value 5061")
        if (
            route.pbx_media_destination_port_start,
            route.pbx_media_destination_port_end,
        ) == (21000, 21127):
            _fail(
                "Direct Routing PBX media destination must not retain the synthetic fixture range"
            )
        if (
            route.pbx_media_destination_port_end
            - route.pbx_media_destination_port_start
            + 1
            < 100
        ):
            _fail(
                "Direct Routing PBX media destination range cannot serve 50 non-muxed sessions"
            )
        if route.called_number_prefix != "+971":
            _fail("Direct Routing called-number prefix must be exactly +971")
    rtpengine = parse_rtpengine_artifact(artifacts["rtpengine-tenant.conf"], facts)
    validate_nft_artifact(artifacts["nftables-tenant-policy.json"], facts)

    opensips = render_opensips(facts, route, authority, secret_paths)
    nftables = render_nftables(facts, authority, route)
    rtpengine_config = render_runtime_rtpengine(facts, authority, rtpengine)
    forbidden = (b"flush ruleset", b"include ", b"exec ", b"system(")
    for name, content in {
        "opensips.cfg": opensips,
        "rtpengine.conf": rtpengine_config,
        "nftables.conf": nftables,
    }.items():
        for token in forbidden:
            if token in content:
                _fail("runtime renderer emitted forbidden token in {}".format(name))
    return ValidatedCandidate(
        receipt.manifest_digest,
        receipt.manifest_id,
        receipt.sequence,
        facts,
        authority,
        dict(sorted(artifact_digests.items())),
        signed_envelope_digest,
        verified_key_ids,
        compile_evidence_digest,
        local_health_plan,
        local_health_plan.digest,
        route,
        rtpengine,
        opensips,
        rtpengine_config,
        nftables,
    )
