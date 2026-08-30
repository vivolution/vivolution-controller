from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from edge.compiler import core
from edge.compiler.core import (
    CompileError,
    NodeFacts,
    VerificationReceipt,
    compile_tenant_bundle,
)
from edge.schema import manifest_tool


ROOT = Path(__file__).resolve().parents[3]
EXAMPLE = ROOT / "edge/schema/examples/v0.1-one-tenant-pbx-relay.json"


def facts_record() -> dict:
    return {
        "allocationId": "allocation-vivolution-uaen-poc",
        "authorizedPbxSourceIpv4Cidrs": ["203.0.113.10/32"],
        "clusterId": "cluster-uaen-poc-01",
        "clusterMediaPortEnd": 29999,
        "clusterMediaPortStart": 20000,
        "customerAccountId": "vivolution-technologies-llc",
        "generation": 1,
        "m365TenantId": "9b7a1c2d-3e4f-4a5b-8c6d-7e8f9012abcd",
        "nodeFqdn": "sbc1.voice.vivolution.ae",
        "nodeId": "sbc1",
        "privateIpv4": "10.30.2.4",
        "publicIpv4": "20.74.155.72",
        "pbxMediaDestinationPortEnd": 30127,
        "pbxMediaDestinationPortStart": 30000,
        "rtpengineNgHost": "127.0.0.1",
        "rtpengineNgPort": 2223,
        "serviceInstanceId": "service-vivolution-pbx-relay",
        "slot": "A",
        "syntheticTeamsSourceIpv4Cidrs": ["10.30.1.4/32"],
        "teamsMediaSourceIpv4Cidrs": ["52.120.0.0/14", "52.112.0.0/14"],
        "teamsSignalingSourceIpv4Cidrs": ["52.112.0.0/14", "52.120.0.0/14"],
        "teamsTlsPort": 5061,
        "tenantContextId": "tenant-vivolution-poc",
        "tenantListenerPort": 15061,
        "tenantMediaPortEnd": 20255,
        "tenantMediaPortStart": 20000,
    }


def refresh_digest(envelope: dict) -> None:
    envelope["manifestDigest"] = manifest_tool.manifest_digest(envelope["manifest"])


def receipt_for(envelope: dict) -> VerificationReceipt:
    manifest = envelope["manifest"]
    _, plan_digest = core.build_local_health_gate_plan(manifest)
    return VerificationReceipt.from_mapping(
        {
            "localHealthGatePlanDigest": plan_digest,
            "manifestDigest": envelope["manifestDigest"],
            "manifestId": manifest["manifestId"],
            "sequence": manifest["sequence"],
            "status": "VERIFIED_AND_STAGED_METADATA_ONLY",
            "verifiedKeyIds": [envelope["signatures"][0]["keyId"]],
        }
    )


def active_example() -> tuple[dict, NodeFacts, VerificationReceipt]:
    # The shared schema fixture owns its own digest. These additions make the
    # helper resilient while the lifecycle schema/example land in either order.
    envelope = copy.deepcopy(manifest_tool.load_json(EXAMPLE))
    manifest = envelope["manifest"]
    manifest.setdefault("lifecycle", "ACTIVE")
    manifest["resourceSet"].setdefault("cleanupIntent", None)
    facts = NodeFacts.from_mapping(facts_record())
    for resource in manifest["resourceSet"]["resources"]:
        if resource["type"] == "tenant.media":
            resource["spec"]["advertisedAddress"] = facts.public_ipv4

    # Rendered bytes exclude declaration metadata, so CP1 can first render a
    # draft, then content-address and sign it without a digest cycle.
    effective = core._extract_effective(envelope, facts)
    rendered = core._render_artifacts(effective, facts)
    for declaration in manifest["resourceSet"]["artifacts"]:
        kind = declaration["kind"]
        content = rendered[kind]
        digest = "sha256:" + hashlib.sha256(content).hexdigest()
        declaration["mediaType"] = core.ARTIFACT_MEDIA_TYPES[kind]
        declaration["applyOrder"] = core.ARTIFACT_APPLY_ORDER[kind]
        declaration["sizeBytes"] = len(content)
        declaration["sha256"] = digest
        declaration["fetchPath"] = "/v0.1/artifacts/sha256/" + digest.split(":", 1)[1]
    refresh_digest(envelope)
    return envelope, facts, receipt_for(envelope)


def resource(envelope: dict, resource_type: str) -> dict:
    return next(
        item
        for item in envelope["manifest"]["resourceSet"]["resources"]
        if item["type"] == resource_type
    )


class CompilerTests(unittest.TestCase):
    def compile(self):
        envelope, facts, receipt = active_example()
        return compile_tenant_bundle(envelope, facts, receipt)

    def test_active_candidate_compiles_with_explicit_readiness_boundary(self) -> None:
        envelope, facts, receipt = active_example()
        bundle = compile_tenant_bundle(envelope, facts, receipt)
        self.assertEqual(
            set(bundle.artifacts),
            {
                "nftables-tenant-policy.json",
                "opensips-tenant.cfg",
                "rtpengine-tenant.conf",
            },
        )
        evidence = json.loads(bundle.evidence)
        self.assertEqual(evidence["readiness"]["compilerStage"], "BOOTSTRAP_ARTIFACTS_READY")
        self.assertEqual(evidence["readiness"]["liveTeamsInteroperability"], "NOT_ASSERTED")
        self.assertFalse(evidence["readiness"]["runtimeApplied"])
        self.assertTrue(evidence["readiness"]["syntheticTeamsInputConfigured"])
        expected_plan, expected_plan_digest = core.build_local_health_gate_plan(
            envelope["manifest"]
        )
        self.assertEqual(evidence["localHealthGatePlan"], expected_plan)
        self.assertEqual(
            evidence["localHealthGatePlanDigest"], expected_plan_digest
        )
        self.assertEqual(
            evidence["localHealthGatePlan"]["healthGates"],
            envelope["manifest"]["healthGates"],
        )
        self.assertEqual(
            evidence["pbxMediaDestinationPortRange"],
            {"end": 30127, "start": 30000},
        )

    def test_golden_artifact_digests_and_fixed_contract(self) -> None:
        bundle = self.compile()
        digests = {
            name: hashlib.sha256(content).hexdigest()
            for name, content in bundle.artifacts.items()
        }
        self.assertEqual(
            digests,
            {
                # Filled from the reviewed deterministic renderer. Changes are
                # deliberate review points, never fixture digest inheritance.
                "nftables-tenant-policy.json": "bb28b3faacacdb0692c684cf7510163d6f83791e24b44f18e07e0adfe8644075",
                "opensips-tenant.cfg": "40898421b0b8b69b52321f4c420c85a3d289b1ef423a40bfedaca07326ba3a13",
                "rtpengine-tenant.conf": "c83e0cf4baf62d9b6800eac8cdb131d623502ff1ee978c6fc030957d20e5a7ea",
            },
        )
        opensips = bundle.artifacts["opensips-tenant.cfg"].decode("ascii")
        self.assertIn('"udp:127.0.0.1:2223"', opensips)
        self.assertIn("$socket_in(port) != 5061", opensips)
        self.assertIn("$socket_in(port) != 15061", opensips)
        self.assertNotIn("$Rp", opensips)
        self.assertEqual(opensips.count("#### Signed OPTIONS interval seconds: 60\n"), 1)
        self.assertIn("sip:sip.pstnhub.microsoft.com:5061;transport=tls", opensips)
        self.assertEqual(opensips.count("VIVO_SYNTHETIC_CDR_V1"), 9)
        self.assertEqual(opensips.count("#!ifdef VIVO_SYNTHETIC_CDR"), 9)
        self.assertNotIn("#!define VIVO_SYNTHETIC_CDR", opensips)
        self.assertIn("TEAMS_FIXTURE_TO_PBX_FIXTURE", opensips)
        self.assertIn("PBX_FIXTURE_TO_TEAMS_FIXTURE", opensips)
        self.assertIn("|result=ACCEPTED", opensips)
        self.assertNotIn("Call-ID", opensips)
        self.assertNotIn("$fU", opensips)
        rtpengine = bundle.artifacts["rtpengine-tenant.conf"].decode("ascii")
        self.assertIn("table = -1\n", rtpengine)
        self.assertIn("interface = 10.30.2.4!20.74.155.72\n", rtpengine)
        self.assertIn("port-min = 20000\nport-max = 20255\n", rtpengine)
        policy = json.loads(bundle.artifacts["nftables-tenant-policy.json"])
        self.assertEqual(policy["mergeContract"]["defaultInputPolicy"], "drop")
        self.assertFalse(policy["mergeContract"]["rawNftSyntaxAccepted"])
        pbx_media = next(
            rule
            for rule in policy["ownedTenantPolicy"]["rules"]
            if rule["id"] == "pbx-media"
        )
        self.assertEqual(
            pbx_media["sourcePortRange"], {"end": 30127, "start": 30000}
        )

    def test_compilation_is_byte_deterministic(self) -> None:
        first = self.compile().all_files()
        second = self.compile().all_files()
        self.assertEqual(dict(first), dict(second))

    def test_synthetic_cdr_hook_is_digest_bound_and_rejects_header_injection(self) -> None:
        envelope, facts, receipt = active_example()
        artifact = next(
            item
            for item in envelope["manifest"]["resourceSet"]["artifacts"]
            if item["kind"] == "OPENSIPS_TENANT_CONFIG"
        )
        artifact["sha256"] = "sha256:" + "f" * 64
        artifact["fetchPath"] = "/v0.1/artifacts/sha256/" + "f" * 64
        refresh_digest(envelope)
        with self.assertRaisesRegex(CompileError, "artifact digest does not match"):
            compile_tenant_bundle(envelope, facts, receipt_for(envelope))

        opensips = self.compile().artifacts["opensips-tenant.cfg"].decode("ascii")
        self.assertIn(
            '($hdr(X-Vivolution-Test-ID) =~ "^[0-9]{8}T[0-9]{6}Z-sbc[12]-[0-9]{1,10}$")',
            opensips,
        )
        self.assertNotIn("$hdr(From)", opensips)
        self.assertNotIn("$hdr(P-Asserted-Identity)", opensips)

    def test_signed_options_interval_is_consumed_and_fixed_to_sixty_seconds(self) -> None:
        envelope, facts, _ = active_example()
        resource(envelope, "tenant.connector")["spec"]["optionsIntervalSeconds"] = 61
        refresh_digest(envelope)
        with self.assertRaisesRegex(
            CompileError, "optionsIntervalSeconds must be the reviewed value 60"
        ):
            compile_tenant_bundle(envelope, facts, receipt_for(envelope))

    def test_declared_digest_mismatch_fails_closed(self) -> None:
        envelope, facts, _ = active_example()
        envelope["manifest"]["resourceSet"]["artifacts"][0]["sha256"] = "sha256:" + "f" * 64
        envelope["manifest"]["resourceSet"]["artifacts"][0]["fetchPath"] = "/v0.1/artifacts/sha256/" + "f" * 64
        refresh_digest(envelope)
        with self.assertRaisesRegex(CompileError, "artifact digest does not match"):
            compile_tenant_bundle(envelope, facts, receipt_for(envelope))

    def test_receipt_cannot_be_rebound_to_mutated_manifest(self) -> None:
        envelope, facts, receipt = active_example()
        resource(envelope, "tenant.capacity")["spec"]["maxCallsPerSecond"] = 4
        refresh_digest(envelope)
        with self.assertRaisesRegex(CompileError, "digest do not match"):
            compile_tenant_bundle(envelope, facts, receipt)

    def test_receipt_cannot_substitute_or_reorder_the_signed_health_plan(self) -> None:
        envelope, facts, receipt = active_example()
        forged = replace(
            receipt,
            local_health_gate_plan_digest="sha256:" + "f" * 64,
        )
        with self.assertRaisesRegex(
            CompileError, "localHealthGatePlanDigest does not match"
        ):
            compile_tenant_bundle(envelope, facts, forged)

        envelope["manifest"]["healthGates"] = list(
            reversed(envelope["manifest"]["healthGates"])
        )
        refresh_digest(envelope)
        with self.assertRaisesRegex(CompileError, "exact supported execution order"):
            receipt_for(envelope)

    def test_manifest_string_injection_is_rejected(self) -> None:
        envelope, facts, _ = active_example()
        resource(envelope, "tenant.connector")["spec"]["remoteHost"] = 'pbx.invalid";\nroute[OWNED] {'
        refresh_digest(envelope)
        with self.assertRaises(CompileError):
            compile_tenant_bundle(envelope, facts, receipt_for(envelope))

    def test_locally_supplied_fqdn_injection_is_rejected(self) -> None:
        record = facts_record()
        record["nodeFqdn"] = 'sbc1.voice.vivolution.ae";drop'
        with self.assertRaisesRegex(CompileError, "FQDN"):
            NodeFacts.from_mapping(record)

    def test_invalid_private_public_ip_and_cidr_are_rejected(self) -> None:
        mutations = (
            ("privateIpv4", "20.1.1.1"),
            ("publicIpv4", "10.1.1.1"),
            ("teamsSignalingSourceIpv4Cidrs", ["52.112.0.1/14"]),
            ("syntheticTeamsSourceIpv4Cidrs", ["52.112.1.1/32"]),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                record = facts_record()
                record[field] = value
                with self.assertRaises(CompileError):
                    NodeFacts.from_mapping(record)

    def test_wrong_or_colliding_allocations_are_rejected(self) -> None:
        for field, value in (
            ("tenantListenerPort", 5061),
            ("tenantListenerPort", 20000),
            ("tenantMediaPortStart", 20002),
            ("clusterMediaPortStart", 15000),
            ("rtpengineNgPort", 15061),
        ):
            with self.subTest(field=field):
                record = facts_record()
                record[field] = value
                with self.assertRaises(CompileError):
                    NodeFacts.from_mapping(record)

    def test_direct_dataclass_construction_cannot_bypass_fact_validation(self) -> None:
        envelope, facts, receipt = active_example()
        forged = replace(facts, tenant_listener_port=5061)
        with self.assertRaises(CompileError):
            compile_tenant_bundle(envelope, forged, receipt)

    def test_missing_directional_route_is_rejected(self) -> None:
        envelope, facts, _ = active_example()
        resources = envelope["manifest"]["resourceSet"]["resources"]
        envelope["manifest"]["resourceSet"]["resources"] = [
            item
            for item in resources
            if not (
                item["type"] == "tenant.route"
                and item["spec"]["direction"] == "PBX_TO_TEAMS"
            )
        ]
        refresh_digest(envelope)
        with self.assertRaises(CompileError):
            compile_tenant_bundle(envelope, facts, receipt_for(envelope))

    def test_cross_tenant_resource_identity_is_rejected(self) -> None:
        envelope, facts, _ = active_example()
        resource(envelope, "tenant.connector")["tenantContextId"] = "tenant-other"
        refresh_digest(envelope)
        with self.assertRaises(CompileError):
            compile_tenant_bundle(envelope, facts, receipt_for(envelope))

    def test_cross_connector_reference_is_rejected(self) -> None:
        envelope, facts, _ = active_example()
        route = next(
            item
            for item in envelope["manifest"]["resourceSet"]["resources"]
            if item["type"] == "tenant.route"
        )
        route["spec"]["connectorRef"] = "connector-other-tenant"
        refresh_digest(envelope)
        with self.assertRaises(CompileError):
            compile_tenant_bundle(envelope, facts, receipt_for(envelope))

    def test_pbx_and_teams_source_authorities_must_not_overlap(self) -> None:
        record = facts_record()
        record["authorizedPbxSourceIpv4Cidrs"] = ["52.112.1.1/32"]
        with self.assertRaisesRegex(CompileError, "overlaps Microsoft"):
            NodeFacts.from_mapping(record)

    def test_non_active_lifecycle_is_explicitly_rejected(self) -> None:
        envelope, facts, _ = active_example()
        envelope["manifest"]["lifecycle"] = "ABSENT"
        refresh_digest(envelope)
        with self.assertRaisesRegex(CompileError, "lifecycle ACTIVE only"):
            compile_tenant_bundle(envelope, facts, receipt_for(envelope))

    def test_arbitrary_unit_identity_is_not_accepted(self) -> None:
        envelope, facts, _ = active_example()
        resource(envelope, "tenant.media")["spec"]["unitKey"] = "rtp-another-tenant"
        refresh_digest(envelope)
        with self.assertRaises(CompileError):
            compile_tenant_bundle(envelope, facts, receipt_for(envelope))

    def test_no_secret_reference_signature_or_private_material_is_emitted(self) -> None:
        envelope, facts, receipt = active_example()
        output = b"\n".join(compile_tenant_bundle(envelope, facts, receipt).all_files().values())
        for secret in envelope["manifest"]["resourceSet"]["secretReferences"]:
            self.assertNotIn(secret["secretRefId"].encode("ascii"), output)
        self.assertNotIn(envelope["signatures"][0]["value"].encode("ascii"), output)
        self.assertNotIn(b"PRIVATE KEY", output)

    def test_output_writer_refuses_existing_path(self) -> None:
        bundle = self.compile()
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(CompileError, "must not already exist"):
                bundle.write_new_directory(Path(temporary))

    def test_node_facts_reject_unknown_injection_fields(self) -> None:
        record = facts_record()
        record["script"] = "/tmp/run-me"
        with self.assertRaisesRegex(CompileError, r"extra=\['script'\]"):
            NodeFacts.from_mapping(record)


if __name__ == "__main__":
    unittest.main()
