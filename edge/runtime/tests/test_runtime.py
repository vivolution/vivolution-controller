from __future__ import annotations

import copy
import base64
import hashlib
import ipaddress
import json
import os
import shutil
import socket
import stat
import tempfile
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from edge.compiler import core as compiler
from edge.agent import security_core as agent_security
from edge.compiler.core import NodeFacts, VerificationReceipt, compile_tenant_bundle
from edge.runtime import contracts
from edge.runtime.contracts import RuntimeContractError, SecretPaths, canonical_bytes, sha256_digest
from edge.runtime.core import (
    ApplyFailed,
    CommandResult,
    CommandRunner,
    RuntimeIdentity,
    RuntimeLayout,
    RuntimeManager,
    RuntimeApplyError,
    RuntimeSecurityError,
)
from edge.schema import manifest_tool


ROOT = Path(__file__).resolve().parents[3]
EXAMPLE = ROOT / "edge/schema/examples/v0.1-one-tenant-pbx-relay.json"
NOW = datetime(2026, 8, 30, 8, 0, tzinfo=timezone.utc)
SIGNING_KEY_ID = "edge-signing-key-2026-01"
SIGNING_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(b"\x42" * 32)
SIGNING_PUBLIC_KEY = SIGNING_PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw,
)


def pinned_key_bytes() -> bytes:
    return canonical_bytes(
        {
            "keyId": SIGNING_KEY_ID,
            "publicKeyBase64": base64.b64encode(SIGNING_PUBLIC_KEY).decode("ascii"),
        }
    )


def sign_envelope(envelope: dict) -> bytes:
    manifest = envelope["manifest"]
    envelope["manifestDigest"] = manifest_tool.manifest_digest(manifest)
    signature = SIGNING_PRIVATE_KEY.sign(
        agent_security.SIGNED_BYTES_PREFIX
        + manifest_tool.canonical_json_bytes(manifest)
    )
    envelope["signatures"] = [
        {
            "algorithm": "Ed25519",
            "createdAt": manifest["issuedAt"],
            "keyId": SIGNING_KEY_ID,
            "value": base64.b64encode(signature).decode("ascii"),
        }
    ]
    return manifest_tool.canonical_json_bytes(envelope)


def facts_record() -> dict:
    return {
        "allocationId": "allocation-vivolution-uaen-poc",
        "authorizedPbxSourceIpv4Cidrs": ["10.20.1.4/32"],
        "clusterId": "cluster-uaen-poc-01",
        "clusterMediaPortEnd": 29999,
        "clusterMediaPortStart": 20000,
        "customerAccountId": "vivolution-technologies-llc",
        "generation": 1,
        "m365TenantId": "9b7a1c2d-3e4f-4a5b-8c6d-7e8f9012abcd",
        "nodeFqdn": "sbc1.voice.vivolution.ae",
        "nodeId": "sbc1",
        "privateIpv4": "10.20.2.4",
        "publicIpv4": "20.74.155.72",
        "pbxMediaDestinationPortEnd": 21127,
        "pbxMediaDestinationPortStart": 21000,
        "rtpengineNgHost": "127.0.0.1",
        "rtpengineNgPort": 2223,
        "serviceInstanceId": "service-vivolution-pbx-relay",
        "slot": "A",
        "syntheticTeamsSourceIpv4Cidrs": [],
        "teamsMediaSourceIpv4Cidrs": ["52.112.0.0/14", "52.120.0.0/14"],
        "teamsSignalingSourceIpv4Cidrs": ["52.112.0.0/14", "52.120.0.0/14"],
        "teamsTlsPort": 5061,
        "tenantContextId": "tenant-vivolution-poc",
        "tenantListenerPort": 15061,
        "tenantMediaPortEnd": 20255,
        "tenantMediaPortStart": 20000,
    }


def _resource(envelope: dict, kind: str) -> dict:
    return next(item for item in envelope["manifest"]["resourceSet"]["resources"] if item["type"] == kind)


def compiled_handoff(*, direct: bool = False) -> tuple[dict[str, bytes], dict]:
    envelope = copy.deepcopy(manifest_tool.load_json(EXAMPLE))
    manifest = envelope["manifest"]
    manifest.setdefault("lifecycle", "ACTIVE")
    manifest["resourceSet"].setdefault("cleanupIntent", None)
    manifest["sequence"] = 1
    manifest["manifestId"] = "manifest-vivolution-sbc1-000001"
    manifest["previousDigest"] = None
    manifest["rollbackTarget"] = None
    manifest["issuedAt"] = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest["expiresAt"] = (NOW + timedelta(hours=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    raw_facts = facts_record()
    if direct:
        # Use a globally routed test value without ever contacting it.
        raw_facts["authorizedPbxSourceIpv4Cidrs"] = ["8.8.8.8/32"]
        raw_facts["generation"] = 2
        raw_facts["pbxMediaDestinationPortStart"] = 30000
        raw_facts["pbxMediaDestinationPortEnd"] = 30127
        manifest["target"]["generation"] = 2
    facts = NodeFacts.from_mapping(raw_facts)
    connector = _resource(envelope, "tenant.connector")
    connector["spec"].update(
        {
            "remoteHost": "pbx.voice.vivolution.ae" if direct else "pbx-fixture.invalid",
            "remotePort": 5061 if direct else 16061,
            "mediaDestinationPortStart": facts.pbx_media_destination_port_start,
            "mediaDestinationPortEnd": facts.pbx_media_destination_port_end,
            "tlsServerName": "pbx.voice.vivolution.ae" if direct else "pbx-fixture.invalid",
            "sourceCidrs": list(facts.authorized_pbx_source_ipv4_cidrs),
        }
    )
    listener = _resource(envelope, "tenant.listener")
    listener["spec"]["allowedSourceCidrs"] = list(
        facts.authorized_pbx_source_ipv4_cidrs
    )
    for resource in manifest["resourceSet"]["resources"]:
        if resource["type"] == "tenant.media":
            resource["spec"]["advertisedAddress"] = facts.public_ipv4
        if resource["type"] == "tenant.route":
            resource["spec"]["calledNumberPrefix"] = "+971" if direct else "+999"
    effective = compiler._extract_effective(envelope, facts)
    rendered = compiler._render_artifacts(effective, facts)
    for declaration in manifest["resourceSet"]["artifacts"]:
        kind = declaration["kind"]
        content = rendered[kind]
        digest = sha256_digest(content)
        declaration.update(
            {
                "mediaType": compiler.ARTIFACT_MEDIA_TYPES[kind],
                "applyOrder": compiler.ARTIFACT_APPLY_ORDER[kind],
                "sizeBytes": len(content),
                "sha256": digest,
                "fetchPath": "/v0.1/artifacts/sha256/" + digest.split(":", 1)[1],
            }
        )
    signed_envelope = sign_envelope(envelope)
    _, plan_digest = compiler.build_local_health_gate_plan(manifest)
    receipt = VerificationReceipt.from_mapping(
        {
            "localHealthGatePlanDigest": plan_digest,
            "manifestDigest": envelope["manifestDigest"],
            "manifestId": manifest["manifestId"],
            "sequence": manifest["sequence"],
            "status": "VERIFIED_AND_STAGED_METADATA_ONLY",
            "verifiedKeyIds": [SIGNING_KEY_ID],
        }
    )
    bundle = compile_tenant_bundle(envelope, facts, receipt)
    handoff = dict(bundle.all_files())
    handoff["signed-envelope.json"] = signed_envelope
    handoff["verifier-receipt.json"] = canonical_bytes(receipt.canonical_record())
    return handoff, facts.canonical_record()


def reidentify_handoff(handoff: dict[str, bytes], sequence: int, digit: str) -> tuple[dict[str, bytes], str]:
    cloned = dict(handoff)
    del digit
    prior_envelope = json.loads(cloned["signed-envelope.json"])
    prior_manifest = prior_envelope["manifest"]
    prior_digest = prior_envelope["manifestDigest"]
    prior_sequence = prior_manifest["sequence"]
    envelope = copy.deepcopy(prior_envelope)
    manifest = envelope["manifest"]
    manifest["sequence"] = sequence
    manifest["manifestId"] = "manifest-vivolution-sbc1-{:06d}".format(sequence)
    manifest["previousDigest"] = prior_digest
    manifest["rollbackTarget"] = {
        "allocationId": manifest["target"]["tenant"]["allocationId"],
        "artifactDigests": sorted(
            declaration["sha256"]
            for declaration in prior_manifest["resourceSet"]["artifacts"]
        ),
        "clusterId": manifest["target"]["clusterId"],
        "generation": manifest["target"]["generation"],
        "manifestDigest": prior_digest,
        "nodeId": manifest["target"]["nodeId"],
        "scope": "TENANT",
        "sequence": prior_sequence,
        "tenantContextId": manifest["target"]["tenant"]["tenantContextId"],
    }
    cloned["signed-envelope.json"] = sign_envelope(envelope)
    digest = envelope["manifestDigest"]
    receipt = json.loads(cloned["verifier-receipt.json"])
    receipt["sequence"] = sequence
    receipt["manifestDigest"] = digest
    receipt["manifestId"] = manifest["manifestId"]
    evidence = json.loads(cloned["compile-evidence.json"])
    evidence["sequence"] = sequence
    evidence["manifestDigest"] = digest
    evidence["manifestId"] = receipt["manifestId"]
    evidence["localHealthGatePlan"]["manifestDigest"] = digest
    plan_digest = sha256_digest(
        manifest_tool.canonical_json_bytes(evidence["localHealthGatePlan"])
    )
    evidence["localHealthGatePlanDigest"] = plan_digest
    receipt["localHealthGatePlanDigest"] = plan_digest
    cloned["verifier-receipt.json"] = canonical_bytes(receipt)
    cloned["compile-evidence.json"] = canonical_bytes(evidence)
    return cloned, digest


def update_artifact_evidence(handoff: dict[str, bytes], name: str) -> None:
    evidence = json.loads(handoff["compile-evidence.json"])
    evidence["artifactDigests"][name] = sha256_digest(handoff[name])
    handoff["compile-evidence.json"] = canonical_bytes(evidence)


def _ca(common_name: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _leaf(
    ca_key: rsa.RSAPrivateKey,
    ca_certificate: x509.Certificate,
    common_name: str,
    *,
    dns: str | list[str] | None,
    ip: str | None,
    eku: x509.ObjectIdentifier,
    rsa_key: bool = True,
) -> tuple[bytes, bytes]:
    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if rsa_key
        else ec.generate_private_key(ec.SECP256R1())
    )
    names: list[x509.GeneralName] = []
    if dns is not None:
        names.extend(
            x509.DNSName(value)
            for value in ([dns] if isinstance(dns, str) else dns)
        )
    if ip is not None:
        names.append(x509.IPAddress(ipaddress.ip_address(ip)))
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(hours=1))
        .not_valid_after(NOW + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def secret_material() -> dict[str, bytes]:
    public_key, public_ca = _ca("POC public root")
    fixture_key, fixture_ca = _ca("Vivolution fixture root")
    edge_cert, edge_key = _leaf(
        public_key,
        public_ca,
        "sbc1.voice.vivolution.ae",
        dns=["sbc1.voice.vivolution.ae", "*.sbc1.voice.vivolution.ae"],
        ip=None,
        eku=ExtendedKeyUsageOID.SERVER_AUTH,
    )
    fixture_cert, fixture_client_key = _leaf(
        fixture_key,
        fixture_ca,
        "sbc1-fixture.invalid",
        dns="sbc1-fixture.invalid",
        ip="10.20.2.4",
        eku=ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    public_pem = public_ca.public_bytes(serialization.Encoding.PEM)
    fixture_pem = fixture_ca.public_bytes(serialization.Encoding.PEM)
    return {
        "edgeCertificateChainPem": edge_cert + public_pem,
        "edgePrivateKeyPem": edge_key,
        "fixtureCaCrt": fixture_pem,
        "fixtureClientCrt": fixture_cert,
        "fixtureClientKey": fixture_client_key,
        "microsoftCaBundlePem": public_pem,
        "pbxCaBundlePem": public_pem,
        "publicCaBundlePem": public_pem,
    }


class InjectedCrash(BaseException):
    pass


class FakeDatagramSocket:
    def __init__(
        self,
        response: bytes,
        peer: tuple[str, int],
        *,
        recv_error: OSError | None = None,
    ) -> None:
        self.response = response
        self.peer = peer
        self.recv_error = recv_error
        self.timeout: float | None = None
        self.request: tuple[bytes, tuple[str, int]] | None = None
        self.recv_size: int | None = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        return None

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def sendto(self, request: bytes, peer: tuple[str, int]) -> None:
        self.request = (request, peer)

    def recvfrom(self, size: int) -> tuple[bytes, tuple[str, int]]:
        self.recv_size = size
        if self.recv_error is not None:
            raise self.recv_error
        return self.response, self.peer


class FakeRunner(CommandRunner):
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.fail_offline_parse_once = False
        self.fail_start_opensips_once = False
        self.crash_checkpoint: str | None = None
        self.runtime_layout: RuntimeLayout | None = None
        self.socket_inventory_override: str | None = None

    def run(self, argv, *, timeout=30):
        command = tuple(argv)
        self.commands.append(command)
        if command[:4] == ("/usr/bin/dpkg-query", "-W", "-f=${Version}", "opensips"):
            return CommandResult(0, contracts.OPENSIPS_VERSION + "\n")
        if command[:4] == ("/usr/bin/dpkg-query", "-W", "-f=${Version}", "rtpengine-daemon"):
            return CommandResult(0, contracts.RTPENGINE_VERSION + "\n")
        if (
            command[:3] == ("/usr/sbin/opensips", "-C", "-f")
            and self.fail_offline_parse_once
        ):
            self.fail_offline_parse_once = False
            return CommandResult(1, "", "injected offline parse failure")
        if command == ("/usr/bin/systemctl", "start", "opensips.service") and self.fail_start_opensips_once:
            self.fail_start_opensips_once = False
            return CommandResult(1, "", "injected start failure")
        if command[:2] == ("/usr/bin/systemctl", "is-active"):
            return CommandResult(0, "active\n")
        if command == ("/usr/bin/ss", "-H", "-lntup"):
            if self.socket_inventory_override is not None:
                return CommandResult(0, self.socket_inventory_override)
            active = None
            if self.runtime_layout is not None and self.runtime_layout.active_link.is_symlink():
                active = os.readlink(self.runtime_layout.active_link)
            if active == "bootstrap":
                voice_listener = "udp UNCONN 0 0 127.0.0.1:5060 0.0.0.0:*\n"
            else:
                voice_listener = (
                    "tcp LISTEN 0 128 10.20.2.4:5061 0.0.0.0:*\n"
                    "tcp LISTEN 0 128 10.20.2.4:15061 0.0.0.0:*\n"
                )
            return CommandResult(
                0,
                voice_listener
                + "udp UNCONN 0 0 127.0.0.1:2223 0.0.0.0:*\n"
                + "tcp LISTEN 0 128 127.0.0.1:2224 0.0.0.0:*\n",
            )
        if command[:5] == ("/usr/sbin/nft", "list", "table", "inet", "vivolution_edge_filter"):
            return CommandResult(
                0,
                "table inet vivolution_edge_filter {\n"
                " chain input { type filter hook input priority filter; policy drop;\n"
                " tcp dport 5061 accept\n tcp dport 15061 accept\n"
                " ip saddr @pbx_source_ipv4 udp sport 21000-21127 udp dport 20000-20255 accept\n"
                " ip saddr @pbx_source_ipv4 udp sport 30000-30127 udp dport 20000-20255 accept\n }\n"
                " chain output { type filter hook output priority filter; policy drop;\n"
                " ip daddr 168.63.129.16 udp sport 68 udp dport 67 accept\n"
                " ip daddr @ntp_server_ipv4 udp dport 123 accept\n"
                " ip daddr @control_plane_ipv4 tcp dport { 16061, 25061 } ct state new accept\n"
                " ip daddr @control_plane_ipv4 udp sport 20000-20255 udp dport { 21000-21127, 22000-22063 } accept\n"
                " ip daddr @microsoft_signaling_source_ipv4 tcp dport 5061 ct state new accept\n"
                " ip daddr @microsoft_media_source_ipv4 udp sport 20000-20255 udp dport { 3478-3481, 49152-53247 } accept\n"
                " ip daddr @pbx_source_ipv4 tcp dport 5061 ct state new accept\n"
                " ip daddr @pbx_source_ipv4 udp sport 20000-20255 udp dport 30000-30127 accept\n"
                " }\n}\n",
            )
        return CommandResult(0, "")

    def rtpengine_ping(self, *, timeout=2.0):
        return True

    def checkpoint(self, name):
        if self.crash_checkpoint == name:
            self.crash_checkpoint = None
            raise InjectedCrash(name)


class RuntimeHarness:
    def __init__(self, case: unittest.TestCase) -> None:
        self.case = case
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.uid = os.getuid()
        self.gid = os.getgid()
        self.identity = RuntimeIdentity(
            self.uid, self.gid, self.gid, self.gid, self.gid
        )
        etc = self.base / "etc"
        tls = etc / "vivolution-edge" / "tls"
        opensips = etc / "opensips"
        rtpengine = etc / "rtpengine"
        for directory in (tls, opensips, rtpengine):
            directory.mkdir(parents=True, mode=0o755)
        secrets = SecretPaths(
            tls / "teams-fullchain.pem",
            tls / "teams-key.pem",
            tls / "fixture-ca.crt",
            tls / "fixture-client.crt",
            tls / "fixture-client.key",
            tls / "microsoft-ca-bundle.pem",
            tls / "pbx-ca-bundle.pem",
            tls / "public-ca-bundle.pem",
        )
        self.layout = RuntimeLayout(
            self.base / "runtime",
            self.base / "inbox",
            etc / "vivolution-edge" / "node-facts.json",
            etc / "vivolution-edge" / "runtime-authority.json",
            etc / "vivolution-edge" / "signing-public-key.json",
            secrets,
            opensips / "opensips.cfg",
            rtpengine / "rtpengine.conf",
            etc / "nftables.conf",
        )
        self.layout.inbox_root.mkdir(mode=0o700)
        self.layout.live_opensips.write_text(
            'socket=udp:127.0.0.1:5060\nroute { send_reply(503, "bootstrap"); }\n', encoding="ascii"
        )
        self.layout.live_rtpengine.write_text(
            "[rtpengine]\ntable = -1\nlisten-ng = 127.0.0.1:2223\n", encoding="ascii"
        )
        self.layout.live_nftables.write_text(
            "destroy table inet vivolution_edge_filter\n"
            "table inet vivolution_edge_filter { chain input { type filter hook input priority filter; policy drop; } }\n",
            encoding="ascii",
        )
        for path in (self.layout.live_opensips, self.layout.live_rtpengine, self.layout.live_nftables):
            path.chmod(0o644)
        self.handoff, self.facts = compiled_handoff()
        self.digest = json.loads(self.handoff["verifier-receipt.json"])["manifestDigest"]
        self.sequence = json.loads(self.handoff["verifier-receipt.json"])["sequence"]
        self.secrets = secret_material()
        self._write_local_authority()
        self.write_handoff(self.handoff, self.sequence, self.digest)

    def _write_local_authority(self) -> None:
        self.layout.node_facts.write_bytes(canonical_bytes(self.facts))
        self.layout.node_facts.chmod(0o600)
        authority = {
            "administratorSourceIpv4Cidrs": ["83.110.90.142/32"],
            "apiVersion": contracts.RUNTIME_AUTHORITY_API_VERSION,
            "azureDhcpServerIpv4": "168.63.129.16",
            "generation": 1,
            "nodeId": "sbc1",
            "profile": "SYNTHETIC_PRIVATE",
            "secretDigests": {name: sha256_digest(content) for name, content in sorted(self.secrets.items())},
            "slot": "A",
        }
        self.layout.runtime_authority.write_bytes(canonical_bytes(authority))
        self.layout.runtime_authority.chmod(0o600)
        self.layout.signing_public_key.write_bytes(pinned_key_bytes())
        self.layout.signing_public_key.chmod(0o444)
        for name, path in self.layout.secrets.as_mapping("SYNTHETIC_PRIVATE").items():
            path.write_bytes(self.secrets[name])
            path.chmod(0o440)

    def write_handoff(self, handoff: dict[str, bytes], sequence: int, digest: str) -> Path:
        path = self.layout.candidate_dir(sequence, digest)
        path.mkdir(mode=0o700)
        for name, content in handoff.items():
            target = path / name
            target.write_bytes(content)
            target.chmod(0o600)
        return path

    def manager(
        self, runner: FakeRunner | None = None, *, monotonic_clock=None
    ) -> tuple[RuntimeManager, FakeRunner]:
        runner = runner or FakeRunner()
        runner.runtime_layout = self.layout
        keywords = {"clock": lambda: NOW}
        if monotonic_clock is not None:
            keywords["monotonic_clock"] = monotonic_clock
        return RuntimeManager(self.layout, self.identity, runner, **keywords), runner

    def close(self) -> None:
        self.temporary.cleanup()


class RuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = RuntimeHarness(self)
        self.official_microsoft_sip_roots = contracts.MICROSOFT_SIP_ROOT_SHA1
        fake_root = x509.load_pem_x509_certificates(
            self.harness.secrets["microsoftCaBundlePem"]
        )[0]
        contracts.MICROSOFT_SIP_ROOT_SHA1 = frozenset(
            {fake_root.fingerprint(hashes.SHA1()).hex().upper()}
        )

    def tearDown(self) -> None:
        contracts.MICROSOFT_SIP_ROOT_SHA1 = self.official_microsoft_sip_roots
        self.harness.close()

    def test_rtpengine_ping_accepts_only_exact_pinned_pong_response(self) -> None:
        cookie = b"vivo-runtime-ping"
        exact_response = cookie + b" d6:result4:ponge"
        cases = (
            ("exact", exact_response, ("127.0.0.1", 2223), True),
            ("generic-ok", cookie + b" d6:result2:oke", ("127.0.0.1", 2223), False),
            ("wrong-cookie", b"other d6:result4:ponge", ("127.0.0.1", 2223), False),
            ("trailing-data", exact_response + b"x", ("127.0.0.1", 2223), False),
            ("wrong-peer-ip", exact_response, ("10.20.2.4", 2223), False),
            ("wrong-peer", exact_response, ("127.0.0.1", 2224), False),
        )
        for name, response, peer, expected in cases:
            with self.subTest(name=name):
                client = FakeDatagramSocket(response, peer)
                with mock.patch("edge.runtime.core.socket.socket", return_value=client):
                    actual = CommandRunner().rtpengine_ping(timeout=1.25)
                self.assertEqual(actual, expected)
                self.assertEqual(client.timeout, 1.25)
                self.assertEqual(
                    client.request,
                    (cookie + b" d7:command4:pinge", ("127.0.0.1", 2223)),
                )
                self.assertEqual(client.recv_size, 4096)

    def test_rtpengine_ping_rejects_receive_timeout(self) -> None:
        client = FakeDatagramSocket(
            b"",
            ("127.0.0.1", 2223),
            recv_error=socket.timeout("timed out"),
        )
        with mock.patch("edge.runtime.core.socket.socket", return_value=client):
            self.assertFalse(CommandRunner().rtpengine_ping(timeout=0.5))
        self.assertEqual(client.timeout, 0.5)
        self.assertEqual(
            client.request,
            (
                b"vivo-runtime-ping d7:command4:pinge",
                ("127.0.0.1", 2223),
            ),
        )
        self.assertEqual(client.recv_size, 4096)

    def validate_with_edge_certificate(
        self,
        chain: bytes,
        private_key: bytes,
        trust_root: bytes,
    ) -> None:
        secrets = dict(self.harness.secrets)
        secrets.update(
            {
                "edgeCertificateChainPem": chain,
                "edgePrivateKeyPem": private_key,
                "publicCaBundlePem": trust_root,
            }
        )
        authority = json.loads(self.harness.layout.runtime_authority.read_bytes())
        for name in ("edgeCertificateChainPem", "edgePrivateKeyPem", "publicCaBundlePem"):
            authority["secretDigests"][name] = sha256_digest(secrets[name])
        contracts.validate_candidate(
            self.harness.handoff,
            canonical_bytes(self.harness.facts),
            canonical_bytes(authority),
            pinned_key_bytes(),
            secrets,
            self.harness.layout.secrets,
            expected_sequence=self.harness.sequence,
            expected_manifest_digest=self.harness.digest,
            accepted_runtime=contracts.AcceptedRuntimeState.bootstrap(),
            now=NOW,
        )

    def test_successful_activation_uses_public_server_leaf_and_fixture_client_only_outbound(self) -> None:
        manager, _ = self.harness.manager()
        evidence = manager.activate(self.harness.sequence, self.harness.digest)
        self.assertEqual(evidence["status"], "RUNTIME_APPLIED_HEALTHY")
        self.assertEqual(evidence["agentAction"], "COMMIT_PENDING")
        self.assertFalse(evidence["rollback"]["performed"])
        self.assertEqual(evidence["runtimeProfile"], "SYNTHETIC_PRIVATE")
        self.assertEqual(evidence["rtpAdvertisedIpv4"], "10.20.2.4")
        self.assertEqual(
            [result["type"] for result in evidence["healthGates"]],
            list(contracts.LOCAL_HEALTH_GATE_ORDER),
        )
        for result in evidence["healthGates"]:
            self.assertEqual(result["status"], "PASSED")
            self.assertEqual(result["attemptsUsed"], 1)
            self.assertEqual(
                [proof["name"] for proof in result["proofs"]],
                list(contracts.LOCAL_HEALTH_GATE_PROOFS[result["type"]]),
            )
            self.assertEqual(
                {proof["status"] for proof in result["proofs"]}, {"PASSED"}
            )
        self.assertEqual(
            evidence["localHealthGatePlanDigest"],
            sha256_digest(
                manifest_tool.canonical_json_bytes(
                    evidence["localHealthGatePlan"]
                )
            ),
        )
        unsigned = dict(evidence)
        evidence_digest = unsigned.pop("evidenceDigest")
        self.assertEqual(
            evidence_digest,
            sha256_digest(manifest_tool.canonical_json_bytes(unsigned)),
        )
        self.assertIn(
            "rtpengine-synthetic-private-advertisement",
            {check["name"] for check in evidence["runtimeChecks"]},
        )
        self.assertIn(
            b"interface = 10.20.2.4!20.74.155.72\n",
            self.harness.handoff["rtpengine-tenant.conf"],
        )
        rtpengine = self.harness.layout.live_rtpengine.read_text(encoding="ascii")
        self.assertIn("interface = 10.20.2.4!10.20.2.4\n", rtpengine)
        self.assertNotIn("interface = 10.20.2.4!20.74.155.72\n", rtpengine)
        config = self.harness.layout.live_opensips.read_text(encoding="ascii")
        self.assertIn("10.20.1.4:16061", config)
        self.assertIn("10.20.1.4:25061", config)
        self.assertIn("[teams-inbound]" + str(self.harness.layout.secrets.edge_certificate_chain_pem), config)
        self.assertIn("[pbx-inbound]" + str(self.harness.layout.secrets.edge_certificate_chain_pem), config)
        self.assertNotIn("[teams-inbound]" + str(self.harness.layout.secrets.fixture_client_crt), config)
        self.assertNotIn("[pbx-inbound]" + str(self.harness.layout.secrets.fixture_client_crt), config)
        self.assertIn("[teams-fixture-outbound]" + str(self.harness.layout.secrets.fixture_client_crt), config)
        self.assertIn("[pbx-outbound]" + str(self.harness.layout.secrets.fixture_client_crt), config)
        self.assertEqual(config.count(contracts.MICROSOFT_TLS12_CIPHER_LIST), 4)
        evidence_files = list(self.harness.layout.evidence_dir.iterdir())
        self.assertEqual(len(evidence_files), 1)
        evidence_stat = evidence_files[0].stat()
        self.assertEqual(stat.S_IMODE(evidence_stat.st_mode), 0o440)
        self.assertEqual(evidence_stat.st_gid, self.harness.identity.agent_gid)
        evidence_dir_stat = self.harness.layout.evidence_dir.stat()
        self.assertEqual(stat.S_IMODE(evidence_dir_stat.st_mode), 0o750)
        self.assertEqual(
            evidence_dir_stat.st_gid, self.harness.identity.agent_gid
        )
        active_release = self.harness.layout.runtime_root / os.readlink(
            self.harness.layout.active_link
        )
        metadata = json.loads((active_release / "release-meta.json").read_bytes())
        self.assertEqual(
            metadata["compileEvidenceDigest"],
            sha256_digest(self.harness.handoff["compile-evidence.json"]),
        )
        self.assertEqual(
            metadata["localHealthGatePlan"], evidence["localHealthGatePlan"]
        )
        self.assertEqual(
            metadata["localHealthGatePlanDigest"],
            evidence["localHealthGatePlanDigest"],
        )
        self.assertEqual(
            metadata["signedEnvelopeDigest"],
            sha256_digest(self.harness.handoff["signed-envelope.json"]),
        )
        self.assertEqual(metadata["verifiedKeyIds"], [SIGNING_KEY_ID])
        nft = self.harness.layout.live_nftables.read_text(encoding="ascii")
        self.assertNotIn("flush ruleset", nft)
        self.assertIn("destroy table inet vivolution_edge_filter", nft)
        self.assertIn("hook output priority filter; policy drop;", nft)
        self.assertIn("meta nfproto ipv4 tcp dport { 80, 443 }", nft)
        self.assertIn(
            "ip daddr @control_plane_ipv4 udp sport 20000-20255 "
            "udp dport { 21000-21127, 22000-22063 } accept",
            nft,
        )
        self.assertNotIn("ip daddr @microsoft_media_source_ipv4 udp sport", nft)
        self.assertNotIn("0.0.0.0/0", nft)
        self.assertEqual(os.readlink(self.harness.layout.active_link).split("/")[1], "A")

    def test_root_inbox_is_exact_six_file_signed_boundary(self) -> None:
        self.assertEqual(set(self.harness.handoff), contracts.HANDOFF_FILENAMES)
        candidate = self.harness.layout.candidate_dir(
            self.harness.sequence, self.harness.digest
        )
        extra = candidate / "unsigned-override.json"
        extra.write_bytes(b"{}")
        extra.chmod(0o600)
        manager, _ = self.harness.manager()
        with self.assertRaisesRegex(RuntimeSecurityError, "unexpected file set"):
            manager.activate(self.harness.sequence, self.harness.digest)

    def test_root_runtime_rejects_altered_envelope_signature(self) -> None:
        candidate = self.harness.layout.candidate_dir(
            self.harness.sequence, self.harness.digest
        )
        envelope = json.loads((candidate / "signed-envelope.json").read_bytes())
        signature = envelope["signatures"][0]["value"]
        envelope["signatures"][0]["value"] = (
            ("A" if signature[0] != "A" else "B") + signature[1:]
        )
        (candidate / "signed-envelope.json").write_bytes(
            manifest_tool.canonical_json_bytes(envelope)
        )
        manager, _ = self.harness.manager()
        with self.assertRaisesRegex(RuntimeContractError, "signature"):
            manager.activate(self.harness.sequence, self.harness.digest)

    def test_root_runtime_rejects_wrong_root_pinned_key(self) -> None:
        wrong_pin = canonical_bytes(
            {
                "keyId": SIGNING_KEY_ID,
                "publicKeyBase64": base64.b64encode(b"\x24" * 32).decode("ascii"),
            }
        )
        self.harness.layout.signing_public_key.chmod(0o600)
        self.harness.layout.signing_public_key.write_bytes(wrong_pin)
        self.harness.layout.signing_public_key.chmod(0o444)
        manager, _ = self.harness.manager()
        with self.assertRaisesRegex(RuntimeContractError, "signature"):
            manager.activate(self.harness.sequence, self.harness.digest)

    def test_root_runtime_rejects_forged_receipt_key_identity(self) -> None:
        candidate = self.harness.layout.candidate_dir(
            self.harness.sequence, self.harness.digest
        )
        receipt = json.loads((candidate / "verifier-receipt.json").read_bytes())
        receipt["verifiedKeyIds"] = ["forged-signing-key"]
        (candidate / "verifier-receipt.json").write_bytes(canonical_bytes(receipt))
        manager, _ = self.harness.manager()
        with self.assertRaisesRegex(
            RuntimeContractError, "independent root signature verification"
        ):
            manager.activate(self.harness.sequence, self.harness.digest)

    def test_root_runtime_rejects_validly_signed_wrong_lkg_artifact_lineage(self) -> None:
        manager, _ = self.harness.manager()
        manager.activate(self.harness.sequence, self.harness.digest)
        second, _ = reidentify_handoff(
            self.harness.handoff, self.harness.sequence + 1, "8"
        )
        envelope = json.loads(second["signed-envelope.json"])
        envelope["manifest"]["rollbackTarget"]["artifactDigests"][0] = (
            "sha256:" + "0" * 64
        )
        second["signed-envelope.json"] = sign_envelope(envelope)
        second_digest = envelope["manifestDigest"]
        evidence = json.loads(second["compile-evidence.json"])
        evidence["manifestDigest"] = second_digest
        evidence["localHealthGatePlan"]["manifestDigest"] = second_digest
        plan_digest = sha256_digest(
            manifest_tool.canonical_json_bytes(evidence["localHealthGatePlan"])
        )
        evidence["localHealthGatePlanDigest"] = plan_digest
        second["compile-evidence.json"] = canonical_bytes(evidence)
        receipt = json.loads(second["verifier-receipt.json"])
        receipt["manifestDigest"] = second_digest
        receipt["localHealthGatePlanDigest"] = plan_digest
        second["verifier-receipt.json"] = canonical_bytes(receipt)
        self.harness.write_handoff(
            second, self.harness.sequence + 1, second_digest
        )
        with self.assertRaisesRegex(RuntimeContractError, "artifact digests"):
            manager.activate(self.harness.sequence + 1, second_digest)

    def test_official_microsoft_sip_root_contract_is_exact_and_bundle_is_pinned(self) -> None:
        self.assertEqual(
            self.official_microsoft_sip_roots,
            {
                "A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436",
                "DF3C24F9BFD666761B268073FE06D1CC8D4F82A4",
                "7E04DE896A3E666D00E687D33FFAD93BE83D349E",
                "17F3DE5E9F0F19E98EF61F32266E20C407AE30EE",
                "A78849DC5D7C758C8CDE399856B3AAD0B2A57135",
                "999A64C37FF47D9FAB95F14769891460EEC4C3C5",
                "73A5E64A3BFF8316FF0EDCCC618A906E4EAE4D74",
            },
        )
        contracts.MICROSOFT_SIP_ROOT_SHA1 = self.official_microsoft_sip_roots
        try:
            with self.assertRaisesRegex(RuntimeContractError, "lacks current Microsoft SIP roots"):
                contracts.validate_candidate(
                    self.harness.handoff,
                    canonical_bytes(self.harness.facts),
                    self.harness.layout.runtime_authority.read_bytes(),
                    pinned_key_bytes(),
                    self.harness.secrets,
                    self.harness.layout.secrets,
                    expected_sequence=self.harness.sequence,
                    expected_manifest_digest=self.harness.digest,
                    accepted_runtime=contracts.AcceptedRuntimeState.bootstrap(),
                    now=NOW,
                )
        finally:
            fake_root = x509.load_pem_x509_certificates(
                self.harness.secrets["microsoftCaBundlePem"]
            )[0]
            contracts.MICROSOFT_SIP_ROOT_SHA1 = frozenset(
                {fake_root.fingerprint(hashes.SHA1()).hex().upper()}
            )

    def test_opensips_injection_is_rejected_even_if_compile_evidence_hash_is_rewritten(self) -> None:
        handoff = dict(self.harness.handoff)
        handoff["opensips-tenant.cfg"] += b'include "/tmp/owned.cfg"\n'
        update_artifact_evidence(handoff, "opensips-tenant.cfg")
        with self.assertRaisesRegex(RuntimeContractError, "signed manifest declarations"):
            contracts.validate_candidate(
                handoff,
                canonical_bytes(self.harness.facts),
                self.harness.layout.runtime_authority.read_bytes(),
                pinned_key_bytes(),
                self.harness.secrets,
                self.harness.layout.secrets,
                expected_sequence=self.harness.sequence,
                expected_manifest_digest=self.harness.digest,
                accepted_runtime=contracts.AcceptedRuntimeState.bootstrap(),
                now=NOW,
            )

    def test_runtime_rejects_self_consistent_unsupported_signed_health_plan(self) -> None:
        handoff = dict(self.harness.handoff)
        evidence = json.loads(handoff["compile-evidence.json"])
        evidence["localHealthGatePlan"]["healthGates"][2]["maxAttempts"] = 4
        plan_digest = sha256_digest(
            manifest_tool.canonical_json_bytes(evidence["localHealthGatePlan"])
        )
        evidence["localHealthGatePlanDigest"] = plan_digest
        receipt = json.loads(handoff["verifier-receipt.json"])
        receipt["localHealthGatePlanDigest"] = plan_digest
        handoff["compile-evidence.json"] = canonical_bytes(evidence)
        handoff["verifier-receipt.json"] = canonical_bytes(receipt)
        with self.assertRaisesRegex(
            RuntimeContractError, "parameters differ from the supported contract"
        ):
            contracts.validate_candidate(
                handoff,
                canonical_bytes(self.harness.facts),
                self.harness.layout.runtime_authority.read_bytes(),
                pinned_key_bytes(),
                self.harness.secrets,
                self.harness.layout.secrets,
                expected_sequence=self.harness.sequence,
                expected_manifest_digest=self.harness.digest,
                accepted_runtime=contracts.AcceptedRuntimeState.bootstrap(),
                now=NOW,
            )

    def test_nft_flush_injection_is_rejected_as_non_typed_policy(self) -> None:
        handoff = dict(self.harness.handoff)
        policy = json.loads(handoff["nftables-tenant-policy.json"])
        policy["raw"] = "flush ruleset"
        handoff["nftables-tenant-policy.json"] = canonical_bytes(policy)
        update_artifact_evidence(handoff, "nftables-tenant-policy.json")
        with self.assertRaisesRegex(RuntimeContractError, "signed manifest declarations"):
            contracts.validate_candidate(
                handoff,
                canonical_bytes(self.harness.facts),
                self.harness.layout.runtime_authority.read_bytes(),
                pinned_key_bytes(),
                self.harness.secrets,
                self.harness.layout.secrets,
                expected_sequence=self.harness.sequence,
                expected_manifest_digest=self.harness.digest,
                accepted_runtime=contracts.AcceptedRuntimeState.bootstrap(),
                now=NOW,
            )

    def test_rtpengine_extra_command_key_is_rejected(self) -> None:
        handoff = dict(self.harness.handoff)
        handoff["rtpengine-tenant.conf"] += b"exec = owned\n"
        update_artifact_evidence(handoff, "rtpengine-tenant.conf")
        with self.assertRaisesRegex(RuntimeContractError, "signed manifest declarations"):
            contracts.validate_candidate(
                handoff,
                canonical_bytes(self.harness.facts),
                self.harness.layout.runtime_authority.read_bytes(),
                pinned_key_bytes(),
                self.harness.secrets,
                self.harness.layout.secrets,
                expected_sequence=self.harness.sequence,
                expected_manifest_digest=self.harness.digest,
                accepted_runtime=contracts.AcceptedRuntimeState.bootstrap(),
                now=NOW,
            )

    def test_synthetic_profile_cannot_weaken_the_compiler_interface_contract(self) -> None:
        handoff = dict(self.harness.handoff)
        handoff["rtpengine-tenant.conf"] = handoff["rtpengine-tenant.conf"].replace(
            b"interface = 10.20.2.4!20.74.155.72\n",
            b"interface = 10.20.2.4!10.20.2.4\n",
        )
        update_artifact_evidence(handoff, "rtpengine-tenant.conf")
        with self.assertRaisesRegex(
            RuntimeContractError,
            "signed manifest declarations",
        ):
            contracts.validate_candidate(
                handoff,
                canonical_bytes(self.harness.facts),
                self.harness.layout.runtime_authority.read_bytes(),
                pinned_key_bytes(),
                self.harness.secrets,
                self.harness.layout.secrets,
                expected_sequence=self.harness.sequence,
                expected_manifest_digest=self.harness.digest,
                accepted_runtime=contracts.AcceptedRuntimeState.bootstrap(),
                now=NOW,
            )

    def test_symlink_handoff_file_is_rejected(self) -> None:
        candidate = self.harness.layout.candidate_dir(self.harness.sequence, self.harness.digest)
        artifact = candidate / "opensips-tenant.cfg"
        original = candidate / "original"
        artifact.rename(original)
        artifact.symlink_to(original)
        original.unlink()
        manager, _ = self.harness.manager()
        with self.assertRaises(RuntimeSecurityError):
            manager.activate(self.harness.sequence, self.harness.digest)

    def test_world_writable_handoff_file_is_rejected(self) -> None:
        candidate = self.harness.layout.candidate_dir(self.harness.sequence, self.harness.digest)
        (candidate / "compile-evidence.json").chmod(0o666)
        manager, _ = self.harness.manager()
        with self.assertRaisesRegex(RuntimeSecurityError, "owner or mode"):
            manager.activate(self.harness.sequence, self.harness.digest)

    def test_hardlinked_handoff_file_is_rejected(self) -> None:
        candidate = self.harness.layout.candidate_dir(self.harness.sequence, self.harness.digest)
        os.link(candidate / "compile-evidence.json", self.harness.base / "second-link")
        manager, _ = self.harness.manager()
        with self.assertRaisesRegex(RuntimeSecurityError, "single-link"):
            manager.activate(self.harness.sequence, self.harness.digest)

    def test_mismatched_fixture_private_key_is_rejected(self) -> None:
        wrong = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        secrets = dict(self.harness.secrets)
        secrets["fixtureClientKey"] = wrong
        authority = json.loads(self.harness.layout.runtime_authority.read_bytes())
        authority["secretDigests"]["fixtureClientKey"] = sha256_digest(wrong)
        with self.assertRaisesRegex(RuntimeContractError, "do not match"):
            contracts.validate_candidate(
                self.harness.handoff,
                canonical_bytes(self.harness.facts),
                canonical_bytes(authority),
                pinned_key_bytes(),
                secrets,
                self.harness.layout.secrets,
                expected_sequence=self.harness.sequence,
                expected_manifest_digest=self.harness.digest,
                accepted_runtime=contracts.AcceptedRuntimeState.bootstrap(),
                now=NOW,
            )

    def test_edge_public_certificate_requires_rsa_exact_sans_server_auth_and_full_chain(self) -> None:
        ca_key, ca_certificate = _ca("alternate public root")
        ca_pem = ca_certificate.public_bytes(serialization.Encoding.PEM)
        cases = []
        leaf, key = _leaf(
            ca_key,
            ca_certificate,
            "sbc1.voice.vivolution.ae",
            dns="sbc1.voice.vivolution.ae",
            ip=None,
            eku=ExtendedKeyUsageOID.SERVER_AUTH,
        )
        cases.append(("SANs must be exactly", leaf + ca_pem, key, ca_pem))
        leaf, key = _leaf(
            ca_key,
            ca_certificate,
            "sbc1.voice.vivolution.ae",
            dns=["sbc1.voice.vivolution.ae", "*.sbc1.voice.vivolution.ae"],
            ip=None,
            eku=ExtendedKeyUsageOID.CLIENT_AUTH,
        )
        cases.append(("Server Authentication EKU", leaf + ca_pem, key, ca_pem))
        leaf, key = _leaf(
            ca_key,
            ca_certificate,
            "sbc1.voice.vivolution.ae",
            dns=["sbc1.voice.vivolution.ae", "*.sbc1.voice.vivolution.ae"],
            ip=None,
            eku=ExtendedKeyUsageOID.SERVER_AUTH,
            rsa_key=False,
        )
        cases.append(("RSA-2048", leaf + ca_pem, key, ca_pem))
        leaf, key = _leaf(
            ca_key,
            ca_certificate,
            "sbc1.voice.vivolution.ae",
            dns=["sbc1.voice.vivolution.ae", "*.sbc1.voice.vivolution.ae"],
            ip=None,
            eku=ExtendedKeyUsageOID.SERVER_AUTH,
        )
        cases.append(("full chain", leaf, key, ca_pem))
        for message, chain, private_key, trust_root in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(RuntimeContractError, message):
                    self.validate_with_edge_certificate(chain, private_key, trust_root)

    def test_service_start_failure_rolls_back_to_bootstrap_and_burns_sequence(self) -> None:
        runner = FakeRunner()
        runner.fail_start_opensips_once = True
        manager, _ = self.harness.manager(runner)
        with self.assertRaises(ApplyFailed) as caught:
            manager.activate(self.harness.sequence, self.harness.digest)
        evidence = caught.exception.evidence
        self.assertEqual(evidence["status"], "RUNTIME_APPLY_FAILED_ROLLED_BACK")
        self.assertEqual(evidence["agentAction"], "ABORT_PENDING")
        self.assertEqual(evidence["rollback"]["status"], "HEALTHY")
        self.assertIn("start OpenSIPS failed", evidence["failure"])
        self.assertEqual(os.readlink(self.harness.layout.active_link), "bootstrap")
        state = json.loads(self.harness.layout.state_file.read_bytes())
        self.assertEqual(state["highestSeenSequence"], self.harness.sequence)
        self.assertEqual(state["active"]["kind"], "BOOTSTRAP")
        self.assertFalse(self.harness.layout.journal_file.exists())

    def test_signed_rtpengine_gate_retries_whole_gate_within_max_attempts(self) -> None:
        class FlakyRtpRunner(FakeRunner):
            def __init__(self):
                super().__init__()
                self.ping_calls = 0

            def rtpengine_ping(self, *, timeout=2.0):
                self.ping_calls += 1
                # Baseline succeeds; the first two signed-gate attempts fail.
                return self.ping_calls not in {2, 3}

        runner = FlakyRtpRunner()
        manager, _ = self.harness.manager(runner)
        evidence = manager.activate(self.harness.sequence, self.harness.digest)
        rtp_result = next(
            gate
            for gate in evidence["healthGates"]
            if gate["type"] == "RTPENGINE_READY"
        )
        self.assertEqual(rtp_result["attemptsUsed"], 3)
        self.assertEqual(runner.ping_calls, 4)

    def test_signed_gate_monotonic_timeout_rolls_back_without_false_results(self) -> None:
        values = iter((0.0, 31.0))

        def monotonic_clock():
            return next(values)

        manager, _ = self.harness.manager(
            FakeRunner(), monotonic_clock=monotonic_clock
        )
        with self.assertRaises(ApplyFailed) as caught:
            manager.activate(self.harness.sequence, self.harness.digest)
        evidence = caught.exception.evidence
        self.assertEqual(evidence["status"], "RUNTIME_APPLY_FAILED_ROLLED_BACK")
        self.assertEqual(evidence["healthGates"], [])
        self.assertIn("exhausted its timeout", evidence["failure"])
        self.assertEqual(os.readlink(self.harness.layout.active_link), "bootstrap")

    def test_offline_preflight_failure_is_canonical_abort_and_burns_sequence(self) -> None:
        runner = FakeRunner()
        runner.fail_offline_parse_once = True
        manager, _ = self.harness.manager(runner)
        with self.assertRaises(ApplyFailed) as caught:
            manager.activate(self.harness.sequence, self.harness.digest)
        self.assertEqual(
            caught.exception.evidence["status"],
            "RUNTIME_PREFLIGHT_FAILED_NO_LIVE_CHANGE",
        )
        self.assertEqual(caught.exception.evidence["agentAction"], "ABORT_PENDING")
        self.assertEqual(caught.exception.evidence["healthGates"], [])
        state = json.loads(self.harness.layout.state_file.read_bytes())
        self.assertEqual(state["highestSeenSequence"], self.harness.sequence)
        self.assertEqual(state["active"]["kind"], "BOOTSTRAP")
        release_directories = list((self.harness.layout.runtime_root / "slots" / "A").iterdir())
        self.assertEqual(len(release_directories), 1)
        with self.assertRaisesRegex(RuntimeSecurityError, "replay floor"):
            manager.activate(self.harness.sequence, self.harness.digest)

    def test_crash_after_atomic_pointer_swap_is_recovered_to_prior_lkg(self) -> None:
        runner = FakeRunner()
        runner.crash_checkpoint = "pointer-activated"
        manager, _ = self.harness.manager(runner)
        with self.assertRaises(InjectedCrash):
            manager.activate(self.harness.sequence, self.harness.digest)
        self.assertTrue(self.harness.layout.journal_file.exists())
        self.assertNotEqual(os.readlink(self.harness.layout.active_link), "bootstrap")
        recovery, _ = self.harness.manager(FakeRunner())
        evidence = recovery.recover()
        self.assertEqual(evidence["status"], "CRASH_RECOVERED_TO_PRIOR_LKG")
        self.assertEqual(evidence["agentAction"], "ABORT_PENDING")
        self.assertEqual(os.readlink(self.harness.layout.active_link), "bootstrap")
        self.assertFalse(self.harness.layout.journal_file.exists())

    def test_staged_journal_recovery_validates_bootstrap_prior(self) -> None:
        class StopCrashRunner(FakeRunner):
            def __init__(self) -> None:
                super().__init__()
                self.crash_once = True

            def run(self, argv, *, timeout=30):
                command = tuple(argv)
                if (
                    self.crash_once
                    and command
                    == ("/usr/bin/systemctl", "stop", "opensips.service")
                ):
                    self.crash_once = False
                    raise InjectedCrash("first-service-stop")
                return super().run(argv, timeout=timeout)

        manager, _ = self.harness.manager(StopCrashRunner())
        with self.assertRaises(InjectedCrash):
            manager.activate(self.harness.sequence, self.harness.digest)
        journal = json.loads(self.harness.layout.journal_file.read_bytes())
        self.assertEqual(journal["phase"], "STAGED")
        self.assertEqual(os.readlink(self.harness.layout.active_link), "bootstrap")

        recovery, _ = self.harness.manager(FakeRunner())
        evidence = recovery.recover()
        self.assertEqual(evidence["status"], "CRASH_RECOVERED_TO_PRIOR_LKG")
        state = json.loads(self.harness.layout.state_file.read_bytes())
        self.assertEqual(state["active"]["kind"], "BOOTSTRAP")
        self.assertEqual(os.readlink(self.harness.layout.active_link), "bootstrap")
        self.assertFalse(self.harness.layout.journal_file.exists())

    def test_health_reports_exact_protected_active_identity_and_baseline_gates(self) -> None:
        manager, _ = self.harness.manager()
        result = manager.health()
        self.assertEqual(
            set(result),
            {
                "active",
                "apiVersion",
                "runtimeChecks",
                "highestSeenSequence",
                "kind",
            },
        )
        self.assertEqual(result["apiVersion"], contracts.RUNTIME_API_VERSION)
        self.assertEqual(result["kind"], "EdgeRuntimeHealth")
        self.assertEqual(result["active"]["kind"], "BOOTSTRAP")
        self.assertEqual(result["highestSeenSequence"], 0)
        self.assertEqual(
            {check["status"] for check in result["runtimeChecks"]}, {"PASSED"}
        )
        self.assertEqual(
            {check["name"] for check in result["runtimeChecks"]},
            {
                "systemd-nftables",
                "systemd-rtpengine-daemon",
                "systemd-opensips",
                "opensips-active-parse",
                "listeners-exact",
                "nft-owned-default-deny",
                "rtpengine-ng-ping",
                "rtpengine-control-loopback",
            },
        )

    def test_bootstrap_health_rejects_candidate_signaling_listeners(self) -> None:
        runner = FakeRunner()
        runner.socket_inventory_override = (
            "udp UNCONN 0 0 127.0.0.1:5060 0.0.0.0:*\n"
            "tcp LISTEN 0 128 10.20.2.4:5061 0.0.0.0:*\n"
            "tcp LISTEN 0 128 10.20.2.4:15061 0.0.0.0:*\n"
            "udp UNCONN 0 0 127.0.0.1:2223 0.0.0.0:*\n"
            "tcp LISTEN 0 128 127.0.0.1:2224 0.0.0.0:*\n"
        )
        manager, _ = self.harness.manager(runner)
        with self.assertRaisesRegex(
            RuntimeApplyError,
            "managed listener inventory is not exact for the BOOTSTRAP release",
        ):
            manager.health()

    def test_bootstrap_health_rejects_control_listener_on_wrong_address(self) -> None:
        runner = FakeRunner()
        runner.socket_inventory_override = (
            "udp UNCONN 0 0 127.0.0.1:5060 0.0.0.0:*\n"
            "udp UNCONN 0 0 10.20.2.4:2223 0.0.0.0:*\n"
            "tcp LISTEN 0 128 127.0.0.1:2224 0.0.0.0:*\n"
        )
        manager, _ = self.harness.manager(runner)
        with self.assertRaisesRegex(
            RuntimeApplyError,
            "managed listener inventory is not exact for the BOOTSTRAP release",
        ):
            manager.health()

    def test_bootstrap_health_rejects_wrong_protocol_wildcard_and_duplicate(self) -> None:
        exact_controls = (
            "udp UNCONN 0 0 127.0.0.1:2223 0.0.0.0:*\n"
            "tcp LISTEN 0 128 127.0.0.1:2224 0.0.0.0:*\n"
        )
        cases = {
            "wrong-protocol": (
                "tcp LISTEN 0 128 127.0.0.1:5060 0.0.0.0:*\n"
                + exact_controls
            ),
            "wildcard": (
                "udp UNCONN 0 0 0.0.0.0:5060 0.0.0.0:*\n"
                + exact_controls
            ),
            "duplicate": (
                "udp UNCONN 0 0 127.0.0.1:5060 0.0.0.0:*\n"
                "udp UNCONN 0 0 127.0.0.1:5060 0.0.0.0:*\n"
                + exact_controls
            ),
        }
        for name, inventory in cases.items():
            with self.subTest(name=name):
                runner = FakeRunner()
                runner.socket_inventory_override = inventory
                manager, _ = self.harness.manager(runner)
                with self.assertRaisesRegex(
                    RuntimeApplyError,
                    "managed listener inventory is not exact for the BOOTSTRAP release",
                ):
                    manager.health()

    def test_candidate_health_requires_candidate_signaling_listeners(self) -> None:
        runner = FakeRunner()
        runner.socket_inventory_override = (
            "udp UNCONN 0 0 127.0.0.1:5060 0.0.0.0:*\n"
            "udp UNCONN 0 0 127.0.0.1:2223 0.0.0.0:*\n"
            "tcp LISTEN 0 128 127.0.0.1:2224 0.0.0.0:*\n"
        )
        manager, _ = self.harness.manager(runner)
        with self.assertRaises(ApplyFailed) as caught:
            manager.activate(self.harness.sequence, self.harness.digest)
        self.assertIn(
            "managed listener inventory is not exact for the CANDIDATE release",
            caught.exception.evidence["failure"],
        )
        self.assertEqual(os.readlink(self.harness.layout.active_link), "bootstrap")

    def test_health_refuses_and_preserves_an_interrupted_transaction_journal(self) -> None:
        runner = FakeRunner()
        runner.crash_checkpoint = "pointer-activated"
        manager, _ = self.harness.manager(runner)
        with self.assertRaises(InjectedCrash):
            manager.activate(self.harness.sequence, self.harness.digest)
        journal = self.harness.layout.journal_file.read_bytes()

        health, _ = self.harness.manager(FakeRunner())
        with self.assertRaisesRegex(RuntimeSecurityError, "transaction journal exists"):
            health.health()
        self.assertEqual(self.harness.layout.journal_file.read_bytes(), journal)

    def test_crash_after_committed_state_preserves_healthy_candidate(self) -> None:
        runner = FakeRunner()
        runner.crash_checkpoint = "state-committed"
        manager, _ = self.harness.manager(runner)
        with self.assertRaises(InjectedCrash):
            manager.activate(self.harness.sequence, self.harness.digest)
        committed_target = os.readlink(self.harness.layout.active_link)
        self.assertNotEqual(committed_target, "bootstrap")
        self.assertTrue(self.harness.layout.journal_file.exists())
        state = json.loads(self.harness.layout.state_file.read_bytes())
        self.assertEqual(state["active"]["relativePath"], committed_target)

        recovery, _ = self.harness.manager(FakeRunner())
        result = recovery.recover()
        self.assertEqual(result["status"], "COMMITTED_TRANSACTION_RECOVERY_FINALIZED")
        self.assertEqual(result["agentAction"], "COMMIT_PENDING")
        self.assertEqual(
            [gate["type"] for gate in result["healthGates"]],
            list(contracts.LOCAL_HEALTH_GATE_ORDER),
        )
        self.assertEqual(
            result["localHealthGatePlanDigest"],
            sha256_digest(
                manifest_tool.canonical_json_bytes(
                    result["localHealthGatePlan"]
                )
            ),
        )
        self.assertIn(
            "nft-owned-default-deny",
            {check["name"] for check in result["runtimeChecks"]},
        )
        self.assertEqual(os.readlink(self.harness.layout.active_link), committed_target)
        self.assertFalse(self.harness.layout.journal_file.exists())

    def test_committed_recovery_rejects_tampered_original_success_evidence(self) -> None:
        runner = FakeRunner()
        runner.crash_checkpoint = "state-committed"
        manager, _ = self.harness.manager(runner)
        with self.assertRaises(InjectedCrash):
            manager.activate(self.harness.sequence, self.harness.digest)
        evidence_files = list(
            self.harness.layout.evidence_dir.glob("*runtime-applied-healthy*.json")
        )
        self.assertEqual(len(evidence_files), 1)
        evidence_path = evidence_files[0]
        tampered = json.loads(evidence_path.read_bytes())
        tampered["healthGates"][0]["attemptsUsed"] = 2
        evidence_path.chmod(0o640)
        evidence_path.write_bytes(canonical_bytes(tampered))
        evidence_path.chmod(0o440)

        recovery, _ = self.harness.manager(FakeRunner())
        with self.assertRaisesRegex(RuntimeSecurityError, "self-digest"):
            recovery.recover()
        self.assertTrue(self.harness.layout.journal_file.exists())

    def test_two_releases_alternate_slots_and_manual_rollback_requires_exact_previous(self) -> None:
        manager, _ = self.harness.manager()
        first = manager.activate(self.harness.sequence, self.harness.digest)
        second_handoff, second_digest = reidentify_handoff(self.harness.handoff, self.harness.sequence + 1, "8")
        self.harness.write_handoff(second_handoff, self.harness.sequence + 1, second_digest)
        second = manager.activate(self.harness.sequence + 1, second_digest)
        self.assertNotEqual(first["runtimeReleaseDigest"], second["runtimeReleaseDigest"])
        self.assertIn("slots/B/", os.readlink(self.harness.layout.active_link))
        with self.assertRaises(RuntimeSecurityError):
            manager.rollback(self.harness.sequence, "sha256:" + "f" * 64)
        rollback = manager.rollback(self.harness.sequence, self.harness.digest)
        self.assertEqual(
            rollback["status"], "RUNTIME_ROLLED_BACK_HEALTHY_REQUIRES_AGENT_RECONCILIATION"
        )
        self.assertIn("slots/A/", os.readlink(self.harness.layout.active_link))

    def test_crash_after_manual_rollback_state_preserves_rollback_target(self) -> None:
        runner = FakeRunner()
        manager, _ = self.harness.manager(runner)
        manager.activate(self.harness.sequence, self.harness.digest)
        second_handoff, second_digest = reidentify_handoff(
            self.harness.handoff, self.harness.sequence + 1, "8"
        )
        self.harness.write_handoff(
            second_handoff, self.harness.sequence + 1, second_digest
        )
        manager.activate(self.harness.sequence + 1, second_digest)
        runner.crash_checkpoint = "rollback-state-committed"

        with self.assertRaises(InjectedCrash):
            manager.rollback(self.harness.sequence, self.harness.digest)
        committed_target = os.readlink(self.harness.layout.active_link)
        self.assertIn("slots/A/", committed_target)
        recovery, _ = self.harness.manager(FakeRunner())
        result = recovery.recover()
        self.assertEqual(result["status"], "COMMITTED_TRANSACTION_RECOVERY_FINALIZED")
        self.assertEqual(result["agentAction"], "RECONCILE_PROTECTED_STATE")
        self.assertEqual(os.readlink(self.harness.layout.active_link), committed_target)
        self.assertFalse(self.harness.layout.journal_file.exists())

    def test_signed_options_generation_and_socket_identity_are_profile_bounded(self) -> None:
        synthetic_facts = NodeFacts.from_mapping(self.harness.facts)
        synthetic_route = contracts.parse_compiler_fragment(
            self.harness.handoff["opensips-tenant.cfg"], synthetic_facts
        )
        synthetic_authority = contracts.RuntimeAuthority.from_mapping(
            json.loads(self.harness.layout.runtime_authority.read_bytes())
        )
        synthetic = contracts.render_opensips(
            synthetic_facts,
            synthetic_route,
            synthetic_authority,
            self.harness.layout.secrets,
        ).decode("ascii")
        self.assertIn("#!define VIVO_SYNTHETIC_CDR", synthetic)
        self.assertNotIn('loadmodule "xlog.so"', synthetic)
        self.assertEqual(synthetic.count("VIVO_SYNTHETIC_CDR_V1"), 9)
        self.assertIn("TEAMS_FIXTURE_TO_PBX_FIXTURE", synthetic)
        self.assertIn("PBX_FIXTURE_TO_TEAMS_FIXTURE", synthetic)
        self.assertNotIn("$hdr(Call-ID)", synthetic)
        self.assertNotIn("$hdr(From)", synthetic)
        self.assertNotIn("timer_route[", synthetic)
        self.assertNotIn('t_new_request("OPTIONS"', synthetic)
        self.assertIn(
            '    $du = "sip:10.20.1.4:16061;transport=tls";\n'
            '    force_send_socket("tls:10.20.2.4:15061");\n'
            '    set_advertised_address("sbc1.voice.vivolution.ae");\n'
            '    set_advertised_port("15061");\n'
            "    record_route();",
            synthetic,
        )
        self.assertIn(
            '    $du = "sip:10.20.1.4:25061;transport=tls";\n'
            '    force_send_socket("tls:10.20.2.4:5061");\n'
            '    set_advertised_address("sbc1.voice.vivolution.ae");\n'
            '    set_advertised_port("5061");\n'
            "    record_route();",
            synthetic,
        )

        direct_handoff, direct_facts_record = compiled_handoff(direct=True)
        direct_facts = NodeFacts.from_mapping(direct_facts_record)
        direct_route = contracts.parse_compiler_fragment(
            direct_handoff["opensips-tenant.cfg"], direct_facts
        )
        authority_record = json.loads(self.harness.layout.runtime_authority.read_bytes())
        authority_record["profile"] = "DIRECT_ROUTING"
        authority_record["generation"] = 2
        authority_record["secretDigests"] = {
            name: digest
            for name, digest in authority_record["secretDigests"].items()
            if not name.startswith("fixture")
        }
        direct_authority = contracts.RuntimeAuthority.from_mapping(authority_record)
        direct = contracts.render_opensips(
            direct_facts,
            direct_route,
            direct_authority,
            self.harness.layout.secrets,
        ).decode("ascii")

        self.assertNotIn("#!define VIVO_SYNTHETIC_CDR", direct)
        self.assertNotIn('loadmodule "xlog.so"', direct)
        self.assertIn("#!ifdef VIVO_SYNTHETIC_CDR", direct)

        self.assertEqual(direct_route.options_interval_seconds, 60)
        self.assertEqual(
            direct.count(
                f"timer_route[VIVO_{direct_route.token}_DIRECT_OPTIONS, 60] {{"
            ),
            1,
        )
        self.assertEqual(direct.count("local_route {"), 1)
        self.assertEqual(direct.count('t_new_request("OPTIONS"'), 4)
        for hub in contracts.TEAMS_HUBS:
            ruri = f"sip:{hub}:5061;transport=tls"
            self.assertEqual(
                direct.count(
                    f'    t_new_request("OPTIONS", "{ruri}", '
                    f'"sip:sbc1.voice.vivolution.ae:5061", "sip:{hub}:5061");'
                ),
                1,
            )
            self.assertIn(
                f'    if ($ru == "{ruri}") {{\n'
                f'        $avp(tls_sip_dom) = "{hub}";\n'
                '        force_send_socket("tls:10.20.2.4:5061");\n'
                '        set_advertised_address("sbc1.voice.vivolution.ae");\n'
                '        set_advertised_port("5061");',
                direct,
            )
        pbx_ruri = "sip:pbx.voice.vivolution.ae:5061;transport=tls"
        self.assertEqual(
            direct.count(
                f'    t_new_request("OPTIONS", "{pbx_ruri}", '
                '"sip:sbc1.voice.vivolution.ae:15061", '
                '"sip:pbx.voice.vivolution.ae:5061");'
            ),
            1,
        )
        self.assertIn(
            f'    if ($ru == "{pbx_ruri}") {{\n'
            '        $avp(tls_sip_dom) = "pbx.voice.vivolution.ae";\n'
            '        force_send_socket("tls:10.20.2.4:15061");\n'
            '        set_advertised_address("sbc1.voice.vivolution.ae");\n'
            '        set_advertised_port("15061");',
            direct,
        )
        self.assertEqual(
            direct.count(
                'append_hf("Contact: <sip:sbc1.voice.vivolution.ae:5061;'
                'transport=tls>\\r\\n");'
            ),
            3,
        )
        self.assertEqual(
            direct.count(
                'append_hf("Contact: <sip:sbc1.voice.vivolution.ae:15061;'
                'transport=tls>\\r\\n");'
            ),
            1,
        )
        self.assertIn(
            f'    $du = "{pbx_ruri}";\n'
            '    force_send_socket("tls:10.20.2.4:15061");\n'
            '    set_advertised_address("sbc1.voice.vivolution.ae");\n'
            '    set_advertised_port("15061");\n'
            "    record_route();",
            direct,
        )
        primary_ruri = "sip:sip.pstnhub.microsoft.com:5061;transport=tls"
        self.assertIn(
            f'    $du = "{primary_ruri}";\n'
            '    force_send_socket("tls:10.20.2.4:5061");\n'
            '    set_advertised_address("sbc1.voice.vivolution.ae");\n'
            '    set_advertised_port("5061");\n'
            "    record_route();",
            direct,
        )
        for hub in contracts.TEAMS_HUBS[1:]:
            self.assertIn(
                f'        $du = "sip:{hub}:5061;transport=tls";\n'
                '        force_send_socket("tls:10.20.2.4:5061");\n'
                '        set_advertised_address("sbc1.voice.vivolution.ae");\n'
                '        set_advertised_port("5061");',
                direct,
            )

        tampered = self.harness.handoff["opensips-tenant.cfg"].replace(
            b"#### Signed OPTIONS interval seconds: 60\n",
            b"#### Signed OPTIONS interval seconds: 61\n",
        )
        with self.assertRaisesRegex(RuntimeContractError, "compiled OPTIONS interval"):
            contracts.parse_compiler_fragment(tampered, synthetic_facts)

        tampered_cdr = self.harness.handoff["opensips-tenant.cfg"].replace(
            b"VIVO_SYNTHETIC_CDR_V1", b"VIVO_FORGED_CDR_V1", 1
        )
        with self.assertRaisesRegex(RuntimeContractError, "reviewed compiler v0.1 grammar"):
            contracts.parse_compiler_fragment(tampered_cdr, synthetic_facts)

    def test_direct_routing_renderer_has_all_three_hubs_and_never_fixture_leaf_on_server(self) -> None:
        direct_handoff, direct_facts_record = compiled_handoff(direct=True)
        direct_receipt = json.loads(direct_handoff["verifier-receipt.json"])
        direct_sequence = direct_receipt["sequence"]
        direct_digest = direct_receipt["manifestDigest"]
        facts = NodeFacts.from_mapping(direct_facts_record)
        authority_record = json.loads(self.harness.layout.runtime_authority.read_bytes())
        authority_record["profile"] = "DIRECT_ROUTING"
        authority_record["generation"] = 2
        authority_record["secretDigests"] = {
            name: digest
            for name, digest in authority_record["secretDigests"].items()
            if not name.startswith("fixture")
        }
        authority = contracts.RuntimeAuthority.from_mapping(authority_record)
        route = contracts.parse_compiler_fragment(
            direct_handoff["opensips-tenant.cfg"], facts
        )
        config = contracts.render_opensips(facts, route, authority, self.harness.layout.secrets).decode("ascii")
        for hub in contracts.TEAMS_HUBS:
            self.assertIn(hub, config)
        self.assertIn("TEAMS_FAILOVER", config)
        self.assertNotIn("[teams-inbound]" + str(self.harness.layout.secrets.fixture_client_crt), config)
        self.assertEqual(config.count(contracts.MICROSOFT_TLS12_CIPHER_LIST), 6)
        self.assertNotIn("ECDHE-ECDSA", config)
        nft = contracts.render_nftables(facts, authority, route).decode("ascii")
        self.assertIn(
            "udp sport { 3478-3481, 49152-53247 } udp dport 20000-20255 accept",
            nft,
        )
        self.assertIn("hook output priority filter; policy drop;", nft)
        self.assertIn(
            "ip daddr @microsoft_media_source_ipv4 udp sport 20000-20255 "
            "udp dport { 3478-3481, 49152-53247 } accept",
            nft,
        )
        self.assertIn(
            "ip daddr @pbx_source_ipv4 udp sport 20000-20255 "
            "udp dport 30000-30127 accept",
            nft,
        )
        self.assertIn(
            "ip saddr @pbx_source_ipv4 udp sport 30000-30127 "
            "udp dport 20000-20255 accept",
            nft,
        )
        self.assertNotIn("udp sport 20000-20255 udp dport 0-65535", nft)
        self.assertNotIn("0.0.0.0/0", nft)
        direct_secrets = {
            name: content
            for name, content in self.harness.secrets.items()
            if not name.startswith("fixture")
        }
        candidate = contracts.validate_candidate(
            direct_handoff,
            canonical_bytes(direct_facts_record),
            canonical_bytes(authority.canonical_record()),
            pinned_key_bytes(),
            direct_secrets,
            self.harness.layout.secrets,
            expected_sequence=direct_sequence,
            expected_manifest_digest=direct_digest,
            accepted_runtime=contracts.AcceptedRuntimeState.bootstrap(),
            now=NOW,
        )
        self.assertIn(
            b"interface = 10.20.2.4!20.74.155.72\n",
            candidate.rtpengine_config,
        )
        self.assertNotIn(
            b"interface = 10.20.2.4!10.20.2.4\n",
            candidate.rtpengine_config,
        )
        self.harness.layout.runtime_authority.write_bytes(
            canonical_bytes(authority.canonical_record())
        )
        self.harness.layout.node_facts.write_bytes(canonical_bytes(direct_facts_record))
        for name, path in self.harness.layout.secrets.as_mapping("SYNTHETIC_PRIVATE").items():
            if name.startswith("fixture"):
                path.unlink()
        self.harness.write_handoff(direct_handoff, direct_sequence, direct_digest)
        manager, _ = self.harness.manager()
        evidence = manager.activate(direct_sequence, direct_digest)
        self.assertEqual(evidence["runtimeProfile"], "DIRECT_ROUTING")
        self.assertEqual(evidence["rtpAdvertisedIpv4"], "20.74.155.72")
        self.assertIn(
            "rtpengine-direct-public-advertisement",
            {check["name"] for check in evidence["runtimeChecks"]},
        )
        self.assertIn(
            "interface = 10.20.2.4!20.74.155.72\n",
            self.harness.layout.live_rtpengine.read_text(encoding="ascii"),
        )

    def test_direct_routing_authority_rejects_synthetic_secret_digests(self) -> None:
        authority_record = json.loads(self.harness.layout.runtime_authority.read_bytes())
        authority_record["profile"] = "DIRECT_ROUTING"
        authority_record["generation"] = 2
        with self.assertRaisesRegex(
            RuntimeContractError, "extra=.*fixtureCaCrt"
        ):
            contracts.RuntimeAuthority.from_mapping(authority_record)

        authority_record["secretDigests"] = {
            name: digest
            for name, digest in authority_record["secretDigests"].items()
            if not name.startswith("fixture")
        }
        authority = contracts.RuntimeAuthority.from_mapping(authority_record)
        self.assertEqual(
            set(self.harness.layout.secrets.as_mapping(authority.profile)),
            set(authority.secret_digests),
        )

    def test_duplicate_runtime_authority_member_is_rejected(self) -> None:
        raw = self.harness.layout.runtime_authority.read_text(encoding="utf-8")
        duplicate = raw.replace('{"administratorSourceIpv4Cidrs"', '{"nodeId":"sbc2","administratorSourceIpv4Cidrs"')
        with self.assertRaises(RuntimeContractError):
            contracts.parse_json_bytes(duplicate.encode("utf-8"), "runtime authority")


if __name__ == "__main__":
    unittest.main()
