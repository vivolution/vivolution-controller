#!/usr/bin/env python3
"""Focused stdlib tests for the Edge desired-state v0.1 contract."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


EDGE_DIR = Path(__file__).resolve().parents[1]
SCHEMA_DIR = EDGE_DIR / "schema"
EXAMPLE = SCHEMA_DIR / "examples" / "v0.1-one-tenant-pbx-relay.json"
SIDECAR = SCHEMA_DIR / "examples" / "v0.1-one-tenant-pbx-relay.sha256"
TOOL = SCHEMA_DIR / "manifest_tool.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

sys.path.insert(0, str(SCHEMA_DIR))
import manifest_tool  # noqa: E402


PREVIOUS_DIGEST = "sha256:" + "1" * 64


def load_json(path: Path) -> Any:
    return manifest_tool.load_json(path)


def run_draft_2020_12_validator(document: Any) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as instance_file:
        json.dump(document, instance_file, ensure_ascii=False)
        instance_file.flush()
        return subprocess.run(
            ["node", str(Path(__file__).resolve().parent / "schema_validate_202012.cjs"),
             str(SCHEMA_DIR / "edge-desired-state-v0.1.schema.json"), instance_file.name],
            check=False, capture_output=True, text=True,
        )


def valid_context(**overrides: Any) -> manifest_tool.ValidationContext:
    values: Dict[str, Any] = {
        "expected_cluster_id": "cluster-uaen-poc-01",
        "expected_node_id": "sbc1",
        "expected_generation": 1,
        "expected_tenant_context_id": "tenant-vivolution-poc",
        "expected_allocation_id": "allocation-vivolution-uaen-poc",
        "expected_tenant_listener_port": 15061,
        "expected_media_port_start": 20000,
        "expected_media_port_end": 20255,
        "expected_pbx_media_destination_port_start": 30000,
        "expected_pbx_media_destination_port_end": 30127,
        "expected_advertised_public_ip": "198.51.100.20",
        "authorized_pbx_source_cidrs": ("203.0.113.10/32",),
        "accepted_sequence": 6,
        "accepted_digest": PREVIOUS_DIGEST,
        "now": datetime(2026, 8, 30, 4, 45, tzinfo=timezone.utc),
    }
    values.update(overrides)
    return manifest_tool.ValidationContext(**values)


def set_json_pointer(document: Any, pointer: str, value: Any) -> None:
    if not pointer.startswith("/"):
        raise ValueError("fixture pointer must be absolute")
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]
    target = document
    for part in parts[:-1]:
        target = target[int(part)] if isinstance(target, list) else target[part]
    final = parts[-1]
    if isinstance(target, list):
        target[int(final)] = value
    else:
        target[final] = value


def load_negative_scenario(name: str):
    scenario_path = FIXTURES / name
    scenario = load_json(scenario_path)
    base_path = (scenario_path.parent / scenario["baseEnvelope"]).resolve()
    envelope = copy.deepcopy(load_json(base_path))
    for mutation in scenario["mutations"]:
        set_json_pointer(envelope, mutation["pointer"], mutation["value"])
    envelope["manifestDigest"] = manifest_tool.manifest_digest(envelope["manifest"])
    raw_context = scenario["context"]
    context = manifest_tool.ValidationContext(
        expected_cluster_id=raw_context["expectedClusterId"],
        expected_node_id=raw_context["expectedNodeId"],
        expected_generation=raw_context["expectedGeneration"],
        expected_tenant_context_id=raw_context["expectedTenantContextId"],
        expected_allocation_id=raw_context["expectedAllocationId"],
        expected_tenant_listener_port=15061,
        expected_media_port_start=20000,
        expected_media_port_end=20255,
        expected_pbx_media_destination_port_start=30000,
        expected_pbx_media_destination_port_end=30127,
        expected_advertised_public_ip="198.51.100.20",
        authorized_pbx_source_cidrs=("203.0.113.10/32",),
        accepted_sequence=raw_context["acceptedSequence"],
        accepted_digest=raw_context["acceptedDigest"],
        now=datetime.strptime(raw_context["now"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        ),
    )
    return scenario, envelope, context


class DesiredStateContractTests(unittest.TestCase):
    def test_schema_is_draft_2020_12_and_closed_at_envelope(self) -> None:
        schema = load_json(SCHEMA_DIR / "edge-desired-state-v0.1.schema.json")
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("tenant.connector", schema["$defs"]["tenantResource"]["properties"]["type"]["enum"])
        self.assertIn("cluster.shared-listener", schema["$defs"]["clusterResource"]["properties"]["type"]["enum"])

    def test_one_tenant_example_passes_preflight(self) -> None:
        manifest_tool.validate_envelope(load_json(EXAMPLE), valid_context())

    def test_example_passes_real_draft_2020_12_validator(self) -> None:
        result = run_draft_2020_12_validator(load_json(EXAMPLE))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "DRAFT_2020_12_VALID")

    def test_canonical_digest_matches_envelope_and_evidence_sidecar(self) -> None:
        envelope = load_json(EXAMPLE)
        calculated = manifest_tool.manifest_digest(envelope["manifest"])
        self.assertEqual(calculated, envelope["manifestDigest"])
        self.assertEqual(calculated, SIDECAR.read_text(encoding="ascii").strip())

    def test_canonical_json_is_independent_of_object_order_and_whitespace(self) -> None:
        envelope = load_json(EXAMPLE)
        manifest = envelope["manifest"]
        reversed_manifest = {key: manifest[key] for key in reversed(list(manifest))}
        reparsed = json.loads(json.dumps(reversed_manifest, indent=7))
        self.assertEqual(
            manifest_tool.canonical_json_bytes(manifest),
            manifest_tool.canonical_json_bytes(reparsed),
        )
        self.assertEqual(
            manifest_tool.manifest_digest(manifest),
            manifest_tool.manifest_digest(reparsed),
        )

    def test_cross_language_ed25519_signature_vector(self) -> None:
        vector_path = SCHEMA_DIR / "vectors" / "ed25519-v0.1-example.json"
        vector = load_json(vector_path)
        canonical = manifest_tool.canonical_json_bytes(load_json(EXAMPLE)["manifest"])
        domain = vector["domainSeparatorUtf8"].encode("utf-8")
        self.assertEqual(len(canonical), vector["canonicalManifestLength"])
        self.assertEqual(
            "sha256:" + hashlib.sha256(canonical).hexdigest(),
            "sha256:" + vector["canonicalManifestSha256"],
        )
        self.assertEqual(len(domain + canonical), vector["signingInputLength"])
        self.assertEqual(
            hashlib.sha256(domain + canonical).hexdigest(),
            vector["signingInputSha256"],
        )
        with tempfile.NamedTemporaryFile() as canonical_file:
            canonical_file.write(canonical)
            canonical_file.flush()
            result = subprocess.run(
                ["node", str(Path(__file__).resolve().parent / "verify_signature_vector.cjs"),
                 str(vector_path), canonical_file.name, domain.hex()],
                check=False, capture_output=True, text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "ED25519_VECTOR_VALID")

    def test_duplicate_json_members_are_rejected_before_digesting(self) -> None:
        with self.assertRaises(manifest_tool.DuplicateKeyError):
            manifest_tool.parse_json_text('{"sequence":7,"sequence":8}')

    def test_floating_point_values_are_outside_canonical_domain(self) -> None:
        envelope = load_json(EXAMPLE)
        envelope["manifest"]["sequence"] = 7.0
        with self.assertRaises(ValueError):
            manifest_tool.manifest_digest(envelope["manifest"])

    def test_negative_scenario_fixtures(self) -> None:
        for filename in (
            "invalid-cross-scope.json",
            "invalid-replay.json",
            "invalid-wrong-node.json",
        ):
            with self.subTest(fixture=filename):
                scenario, envelope, context = load_negative_scenario(filename)
                with self.assertRaises(manifest_tool.ContractError) as caught:
                    manifest_tool.validate_envelope(envelope, context)
                self.assertIn(scenario["expectedError"], "\n".join(caught.exception.errors))

    def test_expired_activation_is_rejected(self) -> None:
        envelope = load_json(EXAMPLE)
        with self.assertRaises(manifest_tool.ContractError) as caught:
            manifest_tool.validate_envelope(
                envelope,
                valid_context(now=datetime(2026, 8, 30, 5, 0, tzinfo=timezone.utc)),
            )
        self.assertIn("activation has expired", str(caught.exception))

    def test_secret_value_member_is_rejected_even_if_digest_is_recomputed(self) -> None:
        envelope = copy.deepcopy(load_json(EXAMPLE))
        envelope["manifest"]["resourceSet"]["secretReferences"][0]["secretValue"] = "do-not-accept"
        envelope["manifestDigest"] = manifest_tool.manifest_digest(envelope["manifest"])
        with self.assertRaises(manifest_tool.ContractError) as caught:
            manifest_tool.validate_envelope(envelope, valid_context())
        self.assertIn("secret values are forbidden", str(caught.exception))

    def test_rollback_must_name_accepted_last_known_good(self) -> None:
        envelope = copy.deepcopy(load_json(EXAMPLE))
        envelope["manifest"]["rollbackTarget"]["sequence"] = 5
        envelope["manifestDigest"] = manifest_tool.manifest_digest(envelope["manifest"])
        with self.assertRaises(manifest_tool.ContractError) as caught:
            manifest_tool.validate_envelope(envelope, valid_context())
        self.assertIn("must equal accepted high-water sequence", str(caught.exception))

    def test_tenant_listener_must_match_local_allocation(self) -> None:
        envelope = copy.deepcopy(load_json(EXAMPLE))
        envelope["manifest"]["resourceSet"]["resources"][1]["spec"]["port"] = 15062
        envelope["manifestDigest"] = manifest_tool.manifest_digest(envelope["manifest"])
        with self.assertRaises(manifest_tool.ContractError) as caught:
            manifest_tool.validate_envelope(envelope, valid_context())
        self.assertIn("locally authorized port 15061", str(caught.exception))

    def test_tenant_listener_must_not_collide_with_teams(self) -> None:
        envelope = copy.deepcopy(load_json(EXAMPLE))
        envelope["manifest"]["resourceSet"]["resources"][1]["spec"]["port"] = 5061
        envelope["manifestDigest"] = manifest_tool.manifest_digest(envelope["manifest"])
        with self.assertRaises(manifest_tool.ContractError) as caught:
            manifest_tool.validate_envelope(envelope, valid_context())
        self.assertIn("must not collide with shared Teams port 5061", str(caught.exception))

    def test_tenant_media_must_match_local_allocation(self) -> None:
        envelope = copy.deepcopy(load_json(EXAMPLE))
        envelope["manifest"]["resourceSet"]["resources"][4]["spec"]["portStart"] = 20256
        envelope["manifest"]["resourceSet"]["resources"][4]["spec"]["portEnd"] = 20511
        envelope["manifestDigest"] = manifest_tool.manifest_digest(envelope["manifest"])
        with self.assertRaises(manifest_tool.ContractError) as caught:
            manifest_tool.validate_envelope(envelope, valid_context())
        self.assertIn("locally authorized ports 20000-20255", str(caught.exception))

    def test_absent_tenant_is_empty_and_bound_to_exact_cleanup_identity(self) -> None:
        envelope = copy.deepcopy(load_json(EXAMPLE))
        manifest = envelope["manifest"]
        manifest["lifecycle"] = "ABSENT"
        manifest["resourceSet"] = {
            "mode": "COMPLETE",
            "cleanupIntent": {
                "type": "TENANT_RESOURCES_ABSENT",
                "tenantContextId": "tenant-vivolution-poc",
                "allocationId": "allocation-vivolution-uaen-poc",
            },
            "artifacts": [],
            "secretReferences": [],
            "resources": [],
        }
        manifest["healthGates"] = [{
            "gateId": "gate-tenant-resources-absent",
            "type": "TENANT_RESOURCES_ABSENT",
            "tenantContextId": "tenant-vivolution-poc",
            "allocationId": "allocation-vivolution-uaen-poc",
            "resourceRefs": [],
            "timeoutSeconds": 30,
            "maxAttempts": 1,
            "onFailure": "ROLLBACK_TO_TARGET",
        }]
        envelope["manifestDigest"] = manifest_tool.manifest_digest(manifest)
        manifest_tool.validate_envelope(envelope, valid_context())
        schema_result = run_draft_2020_12_validator(envelope)
        self.assertEqual(schema_result.returncode, 0, schema_result.stderr)

        envelope["manifest"]["resourceSet"]["cleanupIntent"]["allocationId"] = "allocation-other"
        envelope["manifestDigest"] = manifest_tool.manifest_digest(envelope["manifest"])
        with self.assertRaises(manifest_tool.ContractError) as caught:
            manifest_tool.validate_envelope(envelope, valid_context())
        self.assertIn("cross-scope cleanup identity", str(caught.exception))

    def test_absent_tenant_rejects_any_active_resource(self) -> None:
        envelope = copy.deepcopy(load_json(EXAMPLE))
        envelope["manifest"]["lifecycle"] = "ABSENT"
        envelope["manifest"]["resourceSet"]["cleanupIntent"] = {
            "type": "TENANT_RESOURCES_ABSENT",
            "tenantContextId": "tenant-vivolution-poc",
            "allocationId": "allocation-vivolution-uaen-poc",
        }
        envelope["manifestDigest"] = manifest_tool.manifest_digest(envelope["manifest"])
        with self.assertRaises(manifest_tool.ContractError) as caught:
            manifest_tool.validate_envelope(envelope, valid_context())
        self.assertIn("must be empty for ABSENT lifecycle", str(caught.exception))

    def test_cluster_absent_lifecycle_is_fail_closed(self) -> None:
        envelope = copy.deepcopy(load_json(EXAMPLE))
        envelope["manifest"]["target"] = {
            "scope": "CLUSTER", "clusterId": "cluster-uaen-poc-01",
            "nodeId": "sbc1", "slot": "A", "generation": 1,
        }
        envelope["manifest"]["lifecycle"] = "ABSENT"
        envelope["manifestDigest"] = manifest_tool.manifest_digest(envelope["manifest"])
        with self.assertRaises(manifest_tool.ContractError) as caught:
            manifest_tool.validate_envelope(envelope, valid_context())
        self.assertIn("not allowed for CLUSTER scope", str(caught.exception))

    def test_cluster_decommission_is_exact_node_scoped_and_empty(self) -> None:
        envelope = copy.deepcopy(load_json(EXAMPLE))
        manifest = envelope["manifest"]
        manifest.update({
            "target": {
                "scope": "CLUSTER", "clusterId": "cluster-uaen-poc-01",
                "nodeId": "sbc1", "slot": "A", "generation": 1,
            },
            "lifecycle": "DECOMMISSION",
            "sequence": 1,
            "previousDigest": None,
            "rollbackTarget": None,
            "resourceSet": {
                "mode": "COMPLETE",
                "cleanupIntent": {
                    "type": "NODE_DECOMMISSION",
                    "clusterId": "cluster-uaen-poc-01",
                    "nodeId": "sbc1",
                    "generation": 1,
                },
                "artifacts": [], "secretReferences": [], "resources": [],
            },
            "healthGates": [{
                "gateId": "gate-node-decommissioned",
                "type": "NODE_DECOMMISSIONED",
                "resourceRefs": [],
                "timeoutSeconds": 30,
                "maxAttempts": 1,
                "onFailure": "ROLLBACK_TO_TARGET",
            }],
        })
        envelope["manifestDigest"] = manifest_tool.manifest_digest(manifest)
        context = valid_context(
            accepted_sequence=0,
            accepted_digest=None,
            expected_tenant_context_id=None,
            expected_allocation_id=None,
        )
        manifest_tool.validate_envelope(envelope, context)
        schema_result = run_draft_2020_12_validator(envelope)
        self.assertEqual(schema_result.returncode, 0, schema_result.stderr)

        manifest["resourceSet"]["cleanupIntent"]["nodeId"] = "sbc2"
        envelope["manifestDigest"] = manifest_tool.manifest_digest(manifest)
        with self.assertRaises(manifest_tool.ContractError) as caught:
            manifest_tool.validate_envelope(envelope, context)
        self.assertIn("must equal the exact node target", str(caught.exception))

    def test_secret_purpose_and_node_presence_are_bound_to_consumer(self) -> None:
        for field, value, expected in (
            ("purpose", "PBX_SERVER_TLS_IDENTITY", "does not match consuming field purpose"),
            ("requiredOnNode", False, "must set requiredOnNode=true"),
        ):
            with self.subTest(field=field):
                envelope = copy.deepcopy(load_json(EXAMPLE))
                envelope["manifest"]["resourceSet"]["secretReferences"][0][field] = value
                envelope["manifestDigest"] = manifest_tool.manifest_digest(envelope["manifest"])
                with self.assertRaises(manifest_tool.ContractError) as caught:
                    manifest_tool.validate_envelope(envelope, valid_context())
                self.assertIn(expected, str(caught.exception))

    def test_health_gate_type_has_exact_relevant_resource_set(self) -> None:
        envelope = copy.deepcopy(load_json(EXAMPLE))
        envelope["manifest"]["healthGates"][2]["resourceRefs"] = ["connector-vivolution-pbx"]
        envelope["manifestDigest"] = manifest_tool.manifest_digest(envelope["manifest"])
        with self.assertRaises(manifest_tool.ContractError) as caught:
            manifest_tool.validate_envelope(envelope, valid_context())
        self.assertIn("RTPENGINE_READY must reference exactly", str(caught.exception))

    def test_external_acceptance_checks_cannot_be_claimed_as_local_activation_gates(self) -> None:
        for gate_type in (
            "SIP_OPTIONS",
            "SYNTHETIC_CALL",
            "PEER_N_MINUS_ONE_CAPACITY",
        ):
            with self.subTest(gate_type=gate_type):
                envelope = copy.deepcopy(load_json(EXAMPLE))
                gate = copy.deepcopy(envelope["manifest"]["healthGates"][0])
                gate["gateId"] = "gate-forbidden-external-" + gate_type.lower().replace("_", "-")
                gate["type"] = gate_type
                envelope["manifest"]["healthGates"].append(gate)
                envelope["manifestDigest"] = manifest_tool.manifest_digest(
                    envelope["manifest"]
                )
                with self.assertRaises(manifest_tool.ContractError) as caught:
                    manifest_tool.validate_envelope(envelope, valid_context())
                self.assertIn("is not allowed for TENANT scope", str(caught.exception))

    def test_broad_and_locally_unauthorized_source_networks_are_rejected(self) -> None:
        for cidr, expected in (
            ("0.0.0.0/0", "must not authorize an all-addresses /0 network"),
            ("203.0.113.11/32", "outside the locally authorized source CIDR set"),
        ):
            with self.subTest(cidr=cidr):
                envelope = copy.deepcopy(load_json(EXAMPLE))
                envelope["manifest"]["resourceSet"]["resources"][0]["spec"]["sourceCidrs"] = [cidr]
                envelope["manifestDigest"] = manifest_tool.manifest_digest(envelope["manifest"])
                with self.assertRaises(manifest_tool.ContractError) as caught:
                    manifest_tool.validate_envelope(envelope, valid_context())
                self.assertIn(expected, str(caught.exception))

    def test_media_advertised_ip_is_local_trust_not_signed_self_assertion(self) -> None:
        envelope = copy.deepcopy(load_json(EXAMPLE))
        envelope["manifest"]["resourceSet"]["resources"][4]["spec"]["advertisedAddress"] = "198.51.100.21"
        envelope["manifestDigest"] = manifest_tool.manifest_digest(envelope["manifest"])
        with self.assertRaises(manifest_tool.ContractError) as caught:
            manifest_tool.validate_envelope(envelope, valid_context())
        self.assertIn("must exactly equal locally trusted public IP", str(caught.exception))

    def test_integer_lexical_and_interoperable_bounds_are_enforced(self) -> None:
        with self.assertRaisesRegex(ValueError, "exponent JSON number"):
            manifest_tool.parse_json_text('{"sequence":1e1}')
        with self.assertRaisesRegex(ValueError, "exceeds the interoperable"):
            manifest_tool.parse_json_text('{"sequence":9007199254740992}')
        with self.assertRaisesRegex(ValueError, "integer exceeds the interoperable"):
            manifest_tool.canonical_json_bytes({"sequence": 9007199254740992})

    def test_activation_ttl_and_clock_skew_are_bounded(self) -> None:
        envelope = copy.deepcopy(load_json(EXAMPLE))
        envelope["manifest"]["expiresAt"] = "2026-08-30T06:30:01Z"
        envelope["manifestDigest"] = manifest_tool.manifest_digest(envelope["manifest"])
        with self.assertRaises(manifest_tool.ContractError) as caught:
            manifest_tool.validate_envelope(envelope, valid_context())
        self.assertIn("activation TTL must not exceed 3600 seconds", str(caught.exception))

        envelope = copy.deepcopy(load_json(EXAMPLE))
        envelope["manifest"]["issuedAt"] = "2026-08-30T04:50:01Z"
        envelope["manifest"]["expiresAt"] = "2026-08-30T05:20:01Z"
        envelope["signatures"][0]["createdAt"] = "2026-08-30T04:50:01Z"
        envelope["manifestDigest"] = manifest_tool.manifest_digest(envelope["manifest"])
        with self.assertRaises(manifest_tool.ContractError) as caught:
            manifest_tool.validate_envelope(envelope, valid_context())
        self.assertIn("future clock skew", str(caught.exception))

    def test_cli_validate_emits_explicit_signature_caveat(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "validate",
                str(EXAMPLE),
                "--expected-cluster-id",
                "cluster-uaen-poc-01",
                "--expected-node-id",
                "sbc1",
                "--expected-generation",
                "1",
                "--expected-tenant-context-id",
                "tenant-vivolution-poc",
                "--expected-allocation-id",
                "allocation-vivolution-uaen-poc",
                "--expected-tenant-listener-port",
                "15061",
                "--expected-media-port-start",
                "20000",
                "--expected-media-port-end",
                "20255",
                "--expected-pbx-media-destination-port-start",
                "30000",
                "--expected-pbx-media-destination-port-end",
                "30127",
                "--expected-advertised-public-ip",
                "198.51.100.20",
                "--authorized-pbx-source-cidr",
                "203.0.113.10/32",
                "--accepted-sequence",
                "6",
                "--accepted-digest",
                PREVIOUS_DIGEST,
                "--now",
                "2026-08-30T04:45:00Z",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual(evidence["status"], "PREFLIGHT_VALID")
        self.assertEqual(evidence["signatureCryptography"], "NOT_VERIFIED")


if __name__ == "__main__":
    unittest.main()
