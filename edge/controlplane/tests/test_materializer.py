from __future__ import annotations

import base64
import copy
import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from edge.agent import security_core
from edge.compiler.core import NodeFacts, VerificationReceipt, compile_tenant_bundle
from edge.controlplane.core import (
    DIRECT_ROUTING_CONNECTOR_RESOURCE_ID,
    DIRECT_ROUTING_DEPLOYMENT_MODE,
    DIRECT_ROUTING_LISTENER_RESOURCE_ID,
    DIRECT_ROUTING_MICROSOFT_TARGETS,
    DIRECT_ROUTING_PBX_TO_TEAMS_ROUTE_ID,
    DIRECT_ROUTING_PRIVATE_PBX_POC_CONNECTOR_RESOURCE_ID,
    DIRECT_ROUTING_PRIVATE_PBX_POC_DEPLOYMENT_MODE,
    DIRECT_ROUTING_PRIVATE_PBX_POC_LISTENER_RESOURCE_ID,
    DIRECT_ROUTING_PRIVATE_PBX_POC_PBX_TO_TEAMS_ROUTE_ID,
    DIRECT_ROUTING_PRIVATE_PBX_POC_PROFILE_KIND,
    DIRECT_ROUTING_PRIVATE_PBX_POC_TEAMS_TO_PBX_ROUTE_ID,
    DIRECT_ROUTING_PROFILE_KIND,
    DIRECT_ROUTING_TEAMS_TO_PBX_ROUTE_ID,
    SYNTHETIC_PROFILE_KIND,
    ControlPlaneError,
    FirstTenantProfile,
    generate_private_seed,
    materialize_first_tenant,
)
from edge.schema import manifest_tool

KEY_ID = "edge-signing-key-2026-01"
ISSUED = datetime(2026, 8, 30, 4, 30, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[3]
PROFILE_EXAMPLE = ROOT / "edge/controlplane/first-tenant-profile.example.json"
DIRECT_PROFILE_TEMPLATE = (
    ROOT / "edge/controlplane/first-tenant-direct-routing-profile.template.json"
)
PRIVATE_PBX_POC_PROFILE_TEMPLATE = (
    ROOT
    / "edge/controlplane/first-tenant-direct-routing-private-pbx-poc-profile.template.json"
)


def profile_record() -> dict:
    return {
        "acceptedState": None,
        "activationTtlSeconds": 1800,
        "apiVersion": "edge.vivolution.ae/control-plane-profile/v0.1",
        "capacity": {
            "maxBandwidthKbps": 6400,
            "maxCallsPerSecond": 5,
            "maxConcurrentSessions": 50,
            "reservedConcurrentSessions": 25,
        },
        "deploymentMode": "CP1_SYNTHETIC_NO_PSTN",
        "kind": "FirstTenantSyntheticFixtureProfile",
        "media": {"codecs": ["PCMA", "PCMU"], "maxSessions": 50, "rtcpMux": False},
        "pbxConnector": {
            "mediaDestinationPortEnd": 21127,
            "mediaDestinationPortStart": 21000,
            "optionsIntervalSeconds": 60,
            "remoteHost": "pbx-fixture.invalid",
            "remotePort": 16061,
            "sourceIpv4Cidrs": ["10.20.1.4/32"],
            "tlsServerName": "pbx-fixture.invalid",
        },
        "routing": {"calledNumberPrefix": "+971", "priority": 100},
        "secretReferences": {
            "pbxClientCa": {
                "offlineValiditySeconds": 604800,
                "secretRefId": "secret-pbx-client-ca",
                "version": "version-2026-08-30-01",
            },
            "pbxClientIdentity": {
                "offlineValiditySeconds": 604800,
                "secretRefId": "secret-pbx-client-identity",
                "version": "version-2026-08-30-01",
            },
            "pbxServerIdentity": {
                "offlineValiditySeconds": 604800,
                "secretRefId": "secret-pbx-server-identity",
                "version": "version-2026-08-30-01",
            },
        },
        "sequence": 1,
        "targetAuthority": {
            "allocationId": "allocation-vivolution-uaen-poc",
            "clusterId": "cluster-uaen-poc-01",
            "customerAccountId": "vivolution-technologies-llc",
            "m365TenantId": "9b7a1c2d-3e4f-4a5b-8c6d-7e8f9012abcd",
            "serviceInstanceId": "service-vivolution-pbx-relay",
            "tenantContextId": "tenant-vivolution-poc",
        },
    }


def direct_profile_record() -> dict:
    record = profile_record()
    record["deploymentMode"] = DIRECT_ROUTING_DEPLOYMENT_MODE
    record["kind"] = DIRECT_ROUTING_PROFILE_KIND
    record["microsoftTargets"] = [
        dict(item) for item in DIRECT_ROUTING_MICROSOFT_TARGETS
    ]
    record["pbxConnector"] = {
        "mediaDestinationPortEnd": 30127,
        "mediaDestinationPortStart": 30000,
        "optionsIntervalSeconds": 60,
        "remoteHost": "pbx.voice.vivolution.ae",
        "remotePort": 5061,
        "sourceIpv4Cidrs": ["20.74.155.71/32"],
        "tlsServerName": "pbx.voice.vivolution.ae",
    }
    record["secretReferences"] = {
        "pbxClientCa": {
            "offlineValiditySeconds": 31536000,
            "secretRefId": "secret-direct-pbx-ca-bundle",
            "version": "version-direct-2026-08-30-01",
        },
        "pbxClientIdentity": {
            "offlineValiditySeconds": 31536000,
            "secretRefId": "secret-direct-edge-pbx-client-identity",
            "version": "version-direct-2026-08-30-01",
        },
        "pbxServerIdentity": {
            "offlineValiditySeconds": 31536000,
            "secretRefId": "secret-direct-edge-pbx-server-identity",
            "version": "version-direct-2026-08-30-01",
        },
    }
    return record


def private_pbx_poc_profile_record() -> dict:
    record = direct_profile_record()
    record["deploymentMode"] = DIRECT_ROUTING_PRIVATE_PBX_POC_DEPLOYMENT_MODE
    record["kind"] = DIRECT_ROUTING_PRIVATE_PBX_POC_PROFILE_KIND
    record["pbxConnector"] = {
        "mediaDestinationPortEnd": 30127,
        "mediaDestinationPortStart": 30000,
        "optionsIntervalSeconds": 60,
        "remoteHost": "carrier.vivolution.ae",
        "remotePort": 5061,
        "sourceIpv4Cidrs": ["10.20.1.4/32"],
        "tlsServerName": "carrier.vivolution.ae",
    }
    record["secretReferences"] = {
        "pbxClientCa": {
            "offlineValiditySeconds": 31536000,
            "secretRefId": "secret-private-pbx-poc-client-ca",
            "version": "version-private-pbx-poc-ca",
        },
        "pbxClientIdentity": {
            "offlineValiditySeconds": 31536000,
            "secretRefId": "secret-private-pbx-poc-client-identity",
            "version": "version-private-pbx-poc-client",
        },
        "pbxServerIdentity": {
            "offlineValiditySeconds": 31536000,
            "secretRefId": "secret-private-pbx-poc-server-identity",
            "version": "version-private-pbx-poc-server",
        },
    }
    return record


def private_pbx_poc_facts_record(node_id: str = "sbc1") -> dict:
    record = facts_record(node_id, direct_routing=True)
    record["authorizedPbxSourceIpv4Cidrs"] = ["10.20.1.4/32"]
    record["generation"] = 3
    record["nodeFqdn"] = "{}.vivolution.ae".format(node_id)
    return record


def facts_record(node_id: str = "sbc1", *, direct_routing: bool = False) -> dict:
    second = node_id == "sbc2"
    return {
        "allocationId": "allocation-vivolution-uaen-poc",
        "authorizedPbxSourceIpv4Cidrs": (
            ["20.74.155.71/32"] if direct_routing else ["10.20.1.4/32"]
        ),
        "clusterId": "cluster-uaen-poc-01",
        "clusterMediaPortEnd": 29999,
        "clusterMediaPortStart": 20000,
        "customerAccountId": "vivolution-technologies-llc",
        "generation": 2 if direct_routing else 1,
        "m365TenantId": "9b7a1c2d-3e4f-4a5b-8c6d-7e8f9012abcd",
        "nodeFqdn": "{}.voice.vivolution.ae".format(node_id),
        "nodeId": node_id,
        "privateIpv4": "10.20.2.5" if second else "10.20.2.4",
        "publicIpv4": "20.74.155.73" if second else "20.74.155.72",
        "pbxMediaDestinationPortEnd": 30127 if direct_routing else 21127,
        "pbxMediaDestinationPortStart": 30000 if direct_routing else 21000,
        "rtpengineNgHost": "127.0.0.1",
        "rtpengineNgPort": 2223,
        "serviceInstanceId": "service-vivolution-pbx-relay",
        "slot": "B" if second else "A",
        "syntheticTeamsSourceIpv4Cidrs": [],
        "teamsMediaSourceIpv4Cidrs": ["52.112.0.0/14", "52.120.0.0/14"],
        "teamsSignalingSourceIpv4Cidrs": ["52.112.0.0/14", "52.120.0.0/14"],
        "teamsTlsPort": 5061,
        "tenantContextId": "tenant-vivolution-poc",
        "tenantListenerPort": 15061,
        "tenantMediaPortEnd": 20255,
        "tenantMediaPortStart": 20000,
    }


def local_context(facts: NodeFacts) -> security_core.LocalContext:
    return security_core.LocalContext(
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
        pbx_media_destination_port_start=facts.pbx_media_destination_port_start,
        pbx_media_destination_port_end=facts.pbx_media_destination_port_end,
        cluster_media_port_start=facts.cluster_media_port_start,
        cluster_media_port_end=facts.cluster_media_port_end,
        expected_advertised_public_ip=facts.public_ipv4,
        authorized_pbx_source_cidrs=facts.authorized_pbx_source_ipv4_cidrs,
    )


class MaterializerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.key = self.root / "signing.seed"
        self.public_metadata = generate_private_seed(self.key, key_id=KEY_ID)
        self.profile = FirstTenantProfile.from_mapping(profile_record())
        self.facts = NodeFacts.from_mapping(facts_record())

    def tearDown(self) -> None:
        self.temp.cleanup()

    def materialize(self, *, issued: datetime = ISSUED, profile=None, facts=None):
        return materialize_first_tenant(
            self.profile if profile is None else profile,
            self.facts if facts is None else facts,
            private_seed_path=self.key,
            key_id=KEY_ID,
            issued_at=issued,
        )

    def test_checked_in_profile_example_is_the_reviewed_fixture_profile(self) -> None:
        loaded = manifest_tool.load_json(PROFILE_EXAMPLE)
        self.assertEqual(loaded, profile_record())
        self.assertEqual(
            FirstTenantProfile.from_mapping(loaded).canonical_record(), profile_record()
        )

    def test_checked_in_direct_template_is_deliberately_fail_closed(self) -> None:
        loaded = manifest_tool.load_json(DIRECT_PROFILE_TEMPLATE)
        self.assertEqual(
            loaded["microsoftTargets"],
            [dict(item) for item in DIRECT_ROUTING_MICROSOFT_TARGETS],
        )
        with self.assertRaises(ControlPlaneError):
            FirstTenantProfile.from_mapping(loaded)

    def test_checked_in_private_pbx_poc_template_is_exact_and_explicit(self) -> None:
        loaded = manifest_tool.load_json(PRIVATE_PBX_POC_PROFILE_TEMPLATE)
        self.assertEqual(
            loaded["deploymentMode"], DIRECT_ROUTING_PRIVATE_PBX_POC_DEPLOYMENT_MODE
        )
        self.assertEqual(loaded["kind"], DIRECT_ROUTING_PRIVATE_PBX_POC_PROFILE_KIND)
        self.assertEqual(
            loaded["pbxConnector"],
            {
                "mediaDestinationPortEnd": 30127,
                "mediaDestinationPortStart": 30000,
                "optionsIntervalSeconds": 60,
                "remoteHost": "carrier.vivolution.ae",
                "remotePort": 5061,
                "sourceIpv4Cidrs": ["10.20.1.4/32"],
                "tlsServerName": "carrier.vivolution.ae",
            },
        )
        with self.assertRaisesRegex(ControlPlaneError, "m365TenantId"):
            FirstTenantProfile.from_mapping(loaded)

    def test_signature_agent_stage_and_compiler_are_compatible(self) -> None:
        release = self.materialize()
        # Exercise the emitted wire form, not the in-memory read-only wrapper.
        envelope = manifest_tool.parse_json_text(release.envelope_bytes.decode("utf-8"))
        public_bytes = base64.b64decode(
            release.public_key_metadata["publicKeyBase64"], validate=True
        )
        signature = base64.b64decode(envelope["signatures"][0]["value"], validate=True)
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(
            signature,
            security_core.SIGNED_BYTES_PREFIX
            + manifest_tool.canonical_json_bytes(envelope["manifest"]),
        )

        state_directory = self.root / "agent-state"
        state_directory.mkdir(mode=0o700)
        staged = security_core.verify_and_stage(
            release.envelope_bytes,
            local_context=local_context(self.facts),
            keyring=security_core.PinnedKeyring({KEY_ID: public_bytes}),
            state_directory=state_directory,
            now=ISSUED,
        )
        self.assertEqual(staged.verified_key_ids, (KEY_ID,))
        receipt = VerificationReceipt.from_mapping(staged.evidence())
        compiled = compile_tenant_bundle(envelope, self.facts, receipt)
        self.assertEqual(dict(compiled.artifacts), dict(release.artifacts))
        self.assertEqual(
            json.loads(compiled.evidence)["readiness"]["liveTeamsInteroperability"],
            "NOT_ASSERTED",
        )
        self.assertEqual(
            release.evidence["readiness"]["syntheticFixtureAuthority"],
            "EXTERNAL_FIXED_ROOT_RUNTIME_POLICY",
        )
        self.assertFalse(release.evidence["readiness"]["runtimeApplied"])

    def test_synthetic_replacement_generation_materializes_signed_node_release(self) -> None:
        replacement_record = facts_record()
        replacement_record["generation"] = 2
        replacement_facts = NodeFacts.from_mapping(replacement_record)
        release = self.materialize(facts=replacement_facts)
        target = release.envelope["manifest"]["target"]
        self.assertEqual(target["generation"], 2)
        self.assertEqual(target["nodeId"], "sbc1")
        self.assertEqual(
            release.evidence["readiness"]["syntheticFixtureAuthority"],
            "EXTERNAL_FIXED_ROOT_RUNTIME_POLICY",
        )
        public_bytes = base64.b64decode(
            release.public_key_metadata["publicKeyBase64"], validate=True
        )
        state_directory = self.root / "synthetic-generation-2-agent-state"
        state_directory.mkdir(mode=0o700)
        staged = security_core.verify_and_stage(
            release.envelope_bytes,
            local_context=local_context(replacement_facts),
            keyring=security_core.PinnedKeyring({KEY_ID: public_bytes}),
            state_directory=state_directory,
            now=ISSUED,
        )
        compiled = compile_tenant_bundle(
            release.envelope,
            replacement_facts,
            VerificationReceipt.from_mapping(staged.evidence()),
        )
        self.assertEqual(dict(compiled.artifacts), dict(release.artifacts))

    def test_direct_routing_profile_materializes_signed_node_release(self) -> None:
        profile = FirstTenantProfile.from_mapping(direct_profile_record())
        facts = NodeFacts.from_mapping(facts_record(direct_routing=True))
        release = self.materialize(profile=profile, facts=facts)
        envelope = release.envelope

        self.assertTrue(profile.is_direct_routing)
        self.assertEqual(profile.kind, DIRECT_ROUTING_PROFILE_KIND)
        self.assertEqual(profile.deployment_mode, DIRECT_ROUTING_DEPLOYMENT_MODE)
        self.assertEqual(
            envelope["manifest"]["manifestId"], "manifest-direct-sbc1-000001"
        )
        resource_ids = {
            resource["resourceId"]
            for resource in envelope["manifest"]["resourceSet"]["resources"]
        }
        self.assertTrue(
            {
                DIRECT_ROUTING_CONNECTOR_RESOURCE_ID,
                DIRECT_ROUTING_LISTENER_RESOURCE_ID,
                DIRECT_ROUTING_TEAMS_TO_PBX_ROUTE_ID,
                DIRECT_ROUTING_PBX_TO_TEAMS_ROUTE_ID,
            }.issubset(resource_ids)
        )
        self.assertNotIn("fixture", release.envelope_bytes.decode("utf-8"))
        opensips = release.artifacts["opensips-tenant.cfg"].decode("ascii")
        self.assertIn("sip:pbx.voice.vivolution.ae:5061;transport=tls", opensips)
        self.assertIn("sip:sip.pstnhub.microsoft.com:5061;transport=tls", opensips)
        self.assertEqual(
            release.evidence["microsoftTargets"],
            [dict(item) for item in DIRECT_ROUTING_MICROSOFT_TARGETS],
        )
        self.assertEqual(
            release.evidence["readiness"]["liveTeamsInteroperability"],
            "REQUIRES_EXTERNAL_QUALIFICATION",
        )
        self.assertEqual(
            release.evidence["readiness"]["syntheticFixtureAuthority"],
            "NOT_CONFIGURED",
        )

        public_bytes = base64.b64decode(
            release.public_key_metadata["publicKeyBase64"], validate=True
        )
        state_directory = self.root / "direct-agent-state"
        state_directory.mkdir(mode=0o700)
        staged = security_core.verify_and_stage(
            release.envelope_bytes,
            local_context=local_context(facts),
            keyring=security_core.PinnedKeyring({KEY_ID: public_bytes}),
            state_directory=state_directory,
            now=ISSUED,
        )
        compiled = compile_tenant_bundle(
            envelope,
            facts,
            VerificationReceipt.from_mapping(staged.evidence()),
        )
        self.assertEqual(dict(compiled.artifacts), dict(release.artifacts))

    def test_private_pbx_poc_materializes_distinct_signed_generation_three_release(self) -> None:
        profile = FirstTenantProfile.from_mapping(private_pbx_poc_profile_record())
        facts = NodeFacts.from_mapping(private_pbx_poc_facts_record())
        release = self.materialize(profile=profile, facts=facts)
        manifest = release.envelope["manifest"]

        self.assertEqual(profile.kind, DIRECT_ROUTING_PRIVATE_PBX_POC_PROFILE_KIND)
        self.assertEqual(
            profile.deployment_mode, DIRECT_ROUTING_PRIVATE_PBX_POC_DEPLOYMENT_MODE
        )
        self.assertEqual(
            manifest["manifestId"], "manifest-direct-private-pbx-poc-sbc1-000001"
        )
        resources = {
            item["resourceId"]: item
            for item in manifest["resourceSet"]["resources"]
        }
        self.assertTrue(
            {
                DIRECT_ROUTING_PRIVATE_PBX_POC_CONNECTOR_RESOURCE_ID,
                DIRECT_ROUTING_PRIVATE_PBX_POC_LISTENER_RESOURCE_ID,
                DIRECT_ROUTING_PRIVATE_PBX_POC_TEAMS_TO_PBX_ROUTE_ID,
                DIRECT_ROUTING_PRIVATE_PBX_POC_PBX_TO_TEAMS_ROUTE_ID,
            }.issubset(resources)
        )
        self.assertEqual(manifest["target"]["generation"], 3)
        opensips = release.artifacts["opensips-tenant.cfg"].decode("ascii")
        self.assertIn("sip:carrier.vivolution.ae:5061;transport=tls", opensips)
        self.assertIn("sip:sip.pstnhub.microsoft.com:5061;transport=tls", opensips)
        self.assertNotIn("fixture", release.envelope_bytes.decode("utf-8"))
        self.assertEqual(
            release.evidence["pocBoundary"],
            "PUBLIC_MICROSOFT_DIRECT_ROUTING_WITH_FIXED_PRIVATE_CP1_PBX_NO_PRODUCTION_CLAIM",
        )
        self.assertEqual(
            release.evidence["profileKind"],
            DIRECT_ROUTING_PRIVATE_PBX_POC_PROFILE_KIND,
        )

        public_bytes = base64.b64decode(
            release.public_key_metadata["publicKeyBase64"], validate=True
        )
        state_directory = self.root / "private-pbx-poc-agent-state"
        state_directory.mkdir(mode=0o700)
        staged = security_core.verify_and_stage(
            release.envelope_bytes,
            local_context=local_context(facts),
            keyring=security_core.PinnedKeyring({KEY_ID: public_bytes}),
            state_directory=state_directory,
            now=ISSUED,
        )
        compiled = compile_tenant_bundle(
            release.envelope,
            facts,
            VerificationReceipt.from_mapping(staged.evidence()),
        )
        self.assertEqual(dict(compiled.artifacts), dict(release.artifacts))

    def test_private_pbx_poc_rejects_every_cross_profile_or_generation_input(self) -> None:
        for field, candidate in (
            ("remoteHost", "pbx-fixture.invalid"),
            ("tlsServerName", "pbx-fixture.invalid"),
            ("remotePort", 16061),
            ("sourceIpv4Cidrs", ["8.8.8.8/32"]),
            ("mediaDestinationPortStart", 21000),
            ("mediaDestinationPortEnd", 21127),
        ):
            with self.subTest(field=field):
                record = private_pbx_poc_profile_record()
                record["pbxConnector"][field] = candidate
                with self.assertRaises(ControlPlaneError):
                    FirstTenantProfile.from_mapping(record)

        fixture_secret = private_pbx_poc_profile_record()
        fixture_secret["secretReferences"]["pbxClientIdentity"]["version"] = (
            "version-fixture-client"
        )
        with self.assertRaisesRegex(ControlPlaneError, "must not reference fixture"):
            FirstTenantProfile.from_mapping(fixture_secret)

        generation_two = private_pbx_poc_facts_record()
        generation_two["generation"] = 2
        with self.assertRaisesRegex(ControlPlaneError, "generation 3 or later"):
            self.materialize(
                profile=FirstTenantProfile.from_mapping(
                    private_pbx_poc_profile_record()
                ),
                facts=NodeFacts.from_mapping(generation_two),
            )

        legacy_gateway = private_pbx_poc_facts_record()
        legacy_gateway["nodeFqdn"] = "sbc1.voice.vivolution.ae"
        with self.assertRaisesRegex(ControlPlaneError, "root Microsoft gateway FQDN"):
            self.materialize(
                profile=FirstTenantProfile.from_mapping(
                    private_pbx_poc_profile_record()
                ),
                facts=NodeFacts.from_mapping(legacy_gateway),
            )

    def test_direct_routing_rejects_non_real_or_ambiguous_pbx_names(self) -> None:
        bad_names = (
            "192.0.2.10",
            "*.voice.vivolution.ae",
            "PBX.voice.vivolution.ae",
            "pbx.voice.vivolution.ae.",
            "pbx.invalid",
            "pbx.example.com",
            "replace-me.voice.vivolution.ae",
        )
        for name in bad_names:
            with self.subTest(name=name):
                record = direct_profile_record()
                record["pbxConnector"]["remoteHost"] = name
                record["pbxConnector"]["tlsServerName"] = name
                with self.assertRaises(ControlPlaneError):
                    FirstTenantProfile.from_mapping(record)

        mismatched = direct_profile_record()
        mismatched["pbxConnector"]["tlsServerName"] = "pbx2.voice.vivolution.ae"
        with self.assertRaisesRegex(ControlPlaneError, "exactly equal"):
            FirstTenantProfile.from_mapping(mismatched)

    def test_direct_routing_rejects_unsafe_pbx_source_authority(self) -> None:
        bad_sources = (
            ["10.20.1.4/32"],
            ["203.0.113.0/24"],
            ["8.8.0.0/16"],
            ["8.8.8.8/24"],
            ["20.74.155.71/32", "20.74.155.71/32"],
            ["20.74.155.71/32", "1.1.1.1/32"],
        )
        for sources in bad_sources:
            with self.subTest(sources=sources):
                record = direct_profile_record()
                record["pbxConnector"]["sourceIpv4Cidrs"] = sources
                with self.assertRaises(ControlPlaneError):
                    FirstTenantProfile.from_mapping(record)

        profile = FirstTenantProfile.from_mapping(direct_profile_record())
        wrong_facts = facts_record(direct_routing=True)
        wrong_facts["authorizedPbxSourceIpv4Cidrs"] = ["1.1.1.1/32"]
        with self.assertRaisesRegex(ControlPlaneError, "exactly match"):
            self.materialize(profile=profile, facts=NodeFacts.from_mapping(wrong_facts))

        generation_one = facts_record(direct_routing=True)
        generation_one["generation"] = 1
        with self.assertRaisesRegex(ControlPlaneError, "generation 2 or later"):
            self.materialize(
                profile=profile, facts=NodeFacts.from_mapping(generation_one)
            )

    def test_direct_routing_requires_reviewed_port_route_and_microsoft_targets(
        self,
    ) -> None:
        bad_port = direct_profile_record()
        bad_port["pbxConnector"]["remotePort"] = 5062
        with self.assertRaisesRegex(ControlPlaneError, "5061"):
            FirstTenantProfile.from_mapping(bad_port)

        bad_prefix = direct_profile_record()
        bad_prefix["routing"]["calledNumberPrefix"] = "+1"
        with self.assertRaisesRegex(ControlPlaneError, r"exactly \+971"):
            FirstTenantProfile.from_mapping(bad_prefix)

        missing_targets = direct_profile_record()
        del missing_targets["microsoftTargets"]
        with self.assertRaisesRegex(ControlPlaneError, "missing"):
            FirstTenantProfile.from_mapping(missing_targets)

        bad_target_sets = []
        reordered = direct_profile_record()
        reordered["microsoftTargets"].reverse()
        bad_target_sets.append(reordered)
        wrong_host = direct_profile_record()
        wrong_host["microsoftTargets"][0]["fqdn"] = "sip4.pstnhub.microsoft.com"
        bad_target_sets.append(wrong_host)
        wrong_port = direct_profile_record()
        wrong_port["microsoftTargets"][0]["tlsPort"] = 5062
        bad_target_sets.append(wrong_port)
        wrong_transport = direct_profile_record()
        wrong_transport["microsoftTargets"][0]["transport"] = "TCP"
        bad_target_sets.append(wrong_transport)
        for index, record in enumerate(bad_target_sets):
            with self.subTest(index=index):
                with self.assertRaisesRegex(ControlPlaneError, "exact ordered"):
                    FirstTenantProfile.from_mapping(record)

        synthetic_with_targets = profile_record()
        synthetic_with_targets["microsoftTargets"] = [
            dict(item) for item in DIRECT_ROUTING_MICROSOFT_TARGETS
        ]
        with self.assertRaisesRegex(ControlPlaneError, "extra"):
            FirstTenantProfile.from_mapping(synthetic_with_targets)

        fixture_secret = direct_profile_record()
        fixture_secret["secretReferences"]["pbxClientIdentity"]["secretRefId"] = (
            "secret-fixture-client-identity"
        )
        with self.assertRaisesRegex(ControlPlaneError, "must not reference fixture"):
            FirstTenantProfile.from_mapping(fixture_secret)

    def test_direct_profile_carries_only_exact_signed_direct_lineage(self) -> None:
        direct_facts = NodeFacts.from_mapping(facts_record(direct_routing=True))
        first = self.materialize(
            profile=FirstTenantProfile.from_mapping(direct_profile_record()),
            facts=direct_facts,
        )
        record = direct_profile_record()
        record["sequence"] = 2
        record["acceptedState"] = {
            "artifactDigests": sorted(
                declaration["sha256"]
                for declaration in first.envelope["manifest"]["resourceSet"][
                    "artifacts"
                ]
            ),
            "manifestDigest": first.envelope["manifestDigest"],
            "sequence": 1,
            "generation": 2,
            "profileKind": DIRECT_ROUTING_PROFILE_KIND,
        }
        second = self.materialize(
            issued=ISSUED + timedelta(seconds=60),
            profile=FirstTenantProfile.from_mapping(record),
            facts=direct_facts,
        )
        self.assertEqual(
            second.envelope["manifest"]["previousDigest"],
            first.envelope["manifestDigest"],
        )
        self.assertEqual(second.envelope["manifest"]["rollbackTarget"]["sequence"], 1)
        self.assertTrue(
            second.envelope["manifest"]["manifestId"].startswith("manifest-direct-")
        )

        missing_direct_lineage = copy.deepcopy(record)
        del missing_direct_lineage["acceptedState"]["profileKind"]
        with self.assertRaisesRegex(ControlPlaneError, "missing=.*profileKind"):
            FirstTenantProfile.from_mapping(missing_direct_lineage)

        synthetic_lineage = copy.deepcopy(record)
        synthetic_lineage["acceptedState"]["profileKind"] = SYNTHETIC_PROFILE_KIND
        with self.assertRaisesRegex(ControlPlaneError, "prove exact profile lineage"):
            FirstTenantProfile.from_mapping(synthetic_lineage)

    def test_rendering_and_signing_are_deterministic_apart_from_timestamps(
        self,
    ) -> None:
        first = self.materialize()
        repeated = self.materialize()
        later = self.materialize(issued=ISSUED + timedelta(seconds=30))
        self.assertEqual(first.envelope_bytes, repeated.envelope_bytes)
        self.assertEqual(dict(first.artifacts), dict(later.artifacts))

        first_manifest = copy.deepcopy(dict(first.envelope)["manifest"])
        later_manifest = copy.deepcopy(dict(later.envelope)["manifest"])
        for record in (first_manifest, later_manifest):
            del record["issuedAt"]
            del record["expiresAt"]
        self.assertEqual(first_manifest, later_manifest)
        self.assertNotEqual(
            first.envelope["manifestDigest"], later.envelope["manifestDigest"]
        )

    def test_two_node_profile_produces_exact_node_targets(self) -> None:
        first = self.materialize()
        second_facts = NodeFacts.from_mapping(facts_record("sbc2"))
        second = self.materialize(facts=second_facts)
        self.assertEqual(first.envelope["manifest"]["target"]["nodeId"], "sbc1")
        self.assertEqual(first.envelope["manifest"]["target"]["slot"], "A")
        self.assertEqual(second.envelope["manifest"]["target"]["nodeId"], "sbc2")
        self.assertEqual(second.envelope["manifest"]["target"]["slot"], "B")
        self.assertNotEqual(
            first.envelope["manifestDigest"], second.envelope["manifestDigest"]
        )

    def test_profile_is_exact_and_rejects_broad_fixture_authority(self) -> None:
        unknown = profile_record()
        unknown["operatorNote"] = "not signed"
        with self.assertRaisesRegex(ControlPlaneError, "extra"):
            FirstTenantProfile.from_mapping(unknown)

        broad = profile_record()
        broad["pbxConnector"]["sourceIpv4Cidrs"] = ["10.20.1.0/24"]
        with self.assertRaisesRegex(ControlPlaneError, "exactly"):
            FirstTenantProfile.from_mapping(broad)

        bad_port = profile_record()
        bad_port["pbxConnector"]["remotePort"] = 5061
        with self.assertRaisesRegex(ControlPlaneError, "16061"):
            FirstTenantProfile.from_mapping(bad_port)

        bool_sequence = profile_record()
        bool_sequence["sequence"] = True
        with self.assertRaises(ControlPlaneError):
            FirstTenantProfile.from_mapping(bool_sequence)

    def test_profile_identity_and_local_authority_mismatches_fail_closed(self) -> None:
        wrong_tenant = profile_record()
        wrong_tenant["targetAuthority"]["tenantContextId"] = "tenant-other"
        with self.assertRaisesRegex(ControlPlaneError, "does not exactly match"):
            self.materialize(profile=FirstTenantProfile.from_mapping(wrong_tenant))

        broad_facts = facts_record()
        broad_facts["authorizedPbxSourceIpv4Cidrs"] = ["10.20.1.0/24"]
        with self.assertRaisesRegex(ControlPlaneError, "CP1 fixture host"):
            self.materialize(facts=NodeFacts.from_mapping(broad_facts))

        synthetic_in_tenant_facts = facts_record()
        synthetic_in_tenant_facts["syntheticTeamsSourceIpv4Cidrs"] = ["10.20.1.5/32"]
        with self.assertRaisesRegex(ControlPlaneError, "root runtime"):
            self.materialize(facts=NodeFacts.from_mapping(synthetic_in_tenant_facts))

        wrong_slot = facts_record()
        wrong_slot["slot"] = "B"
        with self.assertRaisesRegex(ControlPlaneError, "sbc1/A"):
            self.materialize(facts=NodeFacts.from_mapping(wrong_slot))

    def test_secure_key_creation_refuses_existing_symlinks_and_public_parent(
        self,
    ) -> None:
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o600)
        self.assertEqual(self.key.stat().st_size, 32)
        self.assertNotIn("private", json.dumps(self.public_metadata).lower())
        with self.assertRaisesRegex(ControlPlaneError, "exists"):
            generate_private_seed(self.key, key_id=KEY_ID)

        symlink_path = self.root / "linked.seed"
        symlink_path.symlink_to(self.root / "missing.seed")
        with self.assertRaisesRegex(ControlPlaneError, "exists|symlink"):
            generate_private_seed(symlink_path, key_id=KEY_ID)

        public_parent = self.root / "public-parent"
        public_parent.mkdir(mode=0o755)
        public_parent.chmod(0o755)
        with self.assertRaisesRegex(ControlPlaneError, "permissions"):
            generate_private_seed(public_parent / "key.seed", key_id=KEY_ID)

        real_parent = self.root / "real-private-parent"
        real_parent.mkdir(mode=0o700)
        linked_parent = self.root / "linked-private-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaisesRegex(ControlPlaneError, "securely open"):
            generate_private_seed(linked_parent / "key.seed", key_id=KEY_ID)

    def test_key_read_rejects_bad_permissions_symlink_and_hardlink(self) -> None:
        self.key.chmod(0o644)
        with self.assertRaisesRegex(ControlPlaneError, "exactly 0600"):
            self.materialize()
        self.key.chmod(0o600)

        alias = self.root / "alias.seed"
        alias.symlink_to(self.key)
        with self.assertRaisesRegex(ControlPlaneError, "securely open"):
            materialize_first_tenant(
                self.profile,
                self.facts,
                private_seed_path=alias,
                key_id=KEY_ID,
                issued_at=ISSUED,
            )

        hardlink = self.root / "hardlink.seed"
        os.link(self.key, hardlink)
        with self.assertRaisesRegex(ControlPlaneError, "hard links"):
            self.materialize()

    def test_output_is_canonical_private_and_never_overwritten(self) -> None:
        release = self.materialize()
        output = self.root / "release"
        release.write_new_directory(output)
        self.assertEqual(
            (output / "signed-envelope.json").read_bytes(), release.envelope_bytes
        )
        self.assertEqual(
            manifest_tool.canonical_json_bytes(
                manifest_tool.load_json(output / "signed-envelope.json")
            ),
            (output / "signed-envelope.json").read_bytes(),
        )
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        for path in output.rglob("*"):
            if path.is_file():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        original = (output / "signed-envelope.json").read_bytes()
        with self.assertRaisesRegex(ControlPlaneError, "already exist"):
            release.write_new_directory(output)
        self.assertEqual((output / "signed-envelope.json").read_bytes(), original)

    def test_non_initial_lineage_is_complete_and_compiler_valid(self) -> None:
        first = self.materialize()
        second_record = profile_record()
        second_record["sequence"] = 2
        second_record["acceptedState"] = {
            "artifactDigests": sorted(
                declaration["sha256"]
                for declaration in first.envelope["manifest"]["resourceSet"][
                    "artifacts"
                ]
            ),
            "manifestDigest": first.envelope["manifestDigest"],
            "sequence": 1,
        }
        second = self.materialize(
            issued=ISSUED + timedelta(seconds=60),
            profile=FirstTenantProfile.from_mapping(second_record),
        )
        rollback = second.envelope["manifest"]["rollbackTarget"]
        self.assertEqual(rollback["manifestDigest"], first.envelope["manifestDigest"])
        self.assertEqual(rollback["sequence"], 1)
        self.assertEqual(
            second.envelope["manifest"]["previousDigest"],
            first.envelope["manifestDigest"],
        )


if __name__ == "__main__":
    unittest.main()
