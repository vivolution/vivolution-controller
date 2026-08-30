#!/usr/bin/env python3
"""Security-focused tests for verify-and-stage metadata behavior."""

from __future__ import annotations

import base64
import copy
import io
import json
import multiprocessing
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from edge.agent import cli as agent_cli
from edge.agent import security_core
from edge.schema import manifest_tool

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


REPOSITORY = Path(__file__).resolve().parents[3]
EXAMPLE = REPOSITORY / "edge" / "schema" / "examples" / "v0.1-one-tenant-pbx-relay.json"
NOW = datetime(2026, 8, 30, 4, 45, tzinfo=timezone.utc)
KEY_ID = "cp1-signing-2026-01"


def local_context(node_id: str = "sbc1") -> security_core.LocalContext:
    return security_core.LocalContext(
        scope="TENANT",
        cluster_id="cluster-uaen-poc-01",
        node_id=node_id,
        generation=1,
        slot="A",
        customer_account_id="vivolution-technologies-llc",
        m365_tenant_id="9b7a1c2d-3e4f-4a5b-8c6d-7e8f9012abcd",
        tenant_context_id="tenant-vivolution-poc",
        service_instance_id="service-vivolution-pbx-relay",
        allocation_id="allocation-vivolution-uaen-poc",
        tenant_listener_port=15061,
        tenant_media_port_start=20000,
        tenant_media_port_end=20255,
        pbx_media_destination_port_start=30000,
        pbx_media_destination_port_end=30127,
        cluster_media_port_start=20000,
        cluster_media_port_end=29999,
        expected_advertised_public_ip="20.74.155.72",
        authorized_pbx_source_cidrs=("203.0.113.10/32",),
    )


def cluster_context(node_id: str = "sbc1") -> security_core.LocalContext:
    return security_core.LocalContext(
        scope="CLUSTER",
        cluster_id="cluster-uaen-poc-01",
        node_id=node_id,
        generation=1,
        slot="A",
        authorized_microsoft_source_cidrs=(
            "52.112.0.0/14",
            "52.120.0.0/14",
        ),
    )


def public_bytes(private_key) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def make_envelope(
    private_key,
    *,
    sequence: int = 1,
    previous_envelope=None,
    key_id: str = KEY_ID,
    node_id: str = "sbc1",
) -> dict:
    envelope = copy.deepcopy(manifest_tool.load_json(EXAMPLE))
    manifest = envelope["manifest"]
    manifest["manifestId"] = "manifest-vivolution-sbc1-{:06d}".format(sequence)
    manifest["target"]["nodeId"] = node_id
    for resource in manifest["resourceSet"]["resources"]:
        if resource["type"] == "tenant.media":
            resource["spec"]["advertisedAddress"] = "20.74.155.72"
    manifest["sequence"] = sequence
    manifest["issuedAt"] = "2026-08-30T04:30:00Z"
    manifest["expiresAt"] = "2026-08-30T05:00:00Z"
    if previous_envelope is None:
        manifest["previousDigest"] = None
        manifest["rollbackTarget"] = None
    else:
        previous_manifest = previous_envelope["manifest"]
        previous_digest = previous_envelope["manifestDigest"]
        manifest["previousDigest"] = previous_digest
        manifest["rollbackTarget"] = {
            "allocationId": manifest["target"]["tenant"]["allocationId"],
            "artifactDigests": sorted(
                artifact["sha256"]
                for artifact in previous_manifest["resourceSet"]["artifacts"]
            ),
            "clusterId": manifest["target"]["clusterId"],
            "generation": manifest["target"]["generation"],
            "manifestDigest": previous_digest,
            "nodeId": node_id,
            "scope": "TENANT",
            "sequence": previous_manifest["sequence"],
            "tenantContextId": manifest["target"]["tenant"]["tenantContextId"],
        }
    envelope["manifestDigest"] = manifest_tool.manifest_digest(manifest)
    signed = security_core.SIGNED_BYTES_PREFIX + manifest_tool.canonical_json_bytes(manifest)
    envelope["signatures"] = [
        {
            "algorithm": "Ed25519",
            "createdAt": "2026-08-30T04:30:00Z",
            "keyId": key_id,
            "value": base64.b64encode(private_key.sign(signed)).decode("ascii"),
        }
    ]
    return envelope


def envelope_bytes(envelope: dict) -> bytes:
    return manifest_tool.canonical_json_bytes(envelope)


def runtime_success_evidence(envelope: dict) -> dict:
    plan = security_core._build_local_health_gate_plan(envelope)
    results = []
    for gate in plan["healthGates"]:
        results.append(
            {
                "attemptsUsed": 1,
                "gateId": gate["gateId"],
                "proofs": [
                    {"name": name, "status": "PASSED"}
                    for name in security_core.LOCAL_HEALTH_GATE_PROOFS[gate["type"]]
                ],
                "status": "PASSED",
                "type": gate["type"],
            }
        )
    unsigned = {
        "agentAction": "COMMIT_PENDING",
        "apiVersion": security_core.RUNTIME_API_VERSION,
        "healthGates": results,
        "kind": "EdgeRuntimeApplyEvidence",
        "liveTeamsInteroperability": "NOT_ASSERTED",
        "localHealthGatePlan": plan,
        "localHealthGatePlanDigest": security_core._local_health_gate_plan_digest(
            plan
        ),
        "manifestDigest": envelope["manifestDigest"],
        "nodeId": envelope["manifest"]["target"]["nodeId"],
        "rollback": {
            "performed": False,
            "status": "NOT_REQUIRED",
            "targetReleaseDigest": "sha256:" + "1" * 64,
        },
        "rtpAdvertisedIpv4": "20.74.155.72",
        "runtimeApplied": True,
        "runtimeChecks": [
            {"name": name, "status": "PASSED"}
            for name in security_core.RUNTIME_CHECKS_BY_PROFILE["DIRECT_ROUTING"]
        ],
        "runtimeProfile": "DIRECT_ROUTING",
        "runtimeReleaseDigest": "sha256:" + "2" * 64,
        "sequence": envelope["manifest"]["sequence"],
        "status": security_core.RUNTIME_SUCCESS_STATUS,
        "timestamp": "2026-08-30T04:46:00Z",
    }
    complete = dict(unsigned)
    complete["evidenceDigest"] = security_core._sha256_digest(
        manifest_tool.canonical_json_bytes(unsigned)
    )
    return complete


def reseal_runtime_evidence(evidence: dict) -> dict:
    resealed = copy.deepcopy(evidence)
    resealed.pop("evidenceDigest", None)
    digest = security_core._sha256_digest(
        manifest_tool.canonical_json_bytes(resealed)
    )
    resealed["evidenceDigest"] = digest
    return resealed


def _concurrent_worker(
    state_directory: str,
    raw_envelope: bytes,
    raw_public_key: bytes,
    barrier,
    result_queue,
) -> None:
    try:
        barrier.wait(timeout=10)
        result = security_core.verify_and_stage(
            raw_envelope,
            local_context=local_context(),
            keyring=security_core.PinnedKeyring({KEY_ID: raw_public_key}),
            state_directory=Path(state_directory),
            now=NOW,
        )
        result_queue.put(("ok", result.sequence))
    except BaseException as exc:  # child reports an exact terminal outcome to parent
        result_queue.put(("error", type(exc).__name__))


@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE, "python3-cryptography is required")
class SecurityCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.private_key = Ed25519PrivateKey.generate()
        cls.public_key_bytes = public_bytes(cls.private_key)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name).resolve()
        self.state_directory = base / "state"
        self.state_directory.mkdir(mode=0o700)
        os.chmod(self.state_directory, 0o700)
        self.runtime_evidence_directory = base / "runtime-evidence"
        self.runtime_evidence_directory.mkdir(mode=0o750)
        os.chmod(self.runtime_evidence_directory, 0o750)
        self.keyring = security_core.PinnedKeyring({KEY_ID: self.public_key_bytes})

    def stage(self, envelope: dict, **overrides):
        values = {
            "local_context": local_context(),
            "keyring": self.keyring,
            "state_directory": self.state_directory,
            "now": NOW,
        }
        values.update(overrides)
        return security_core.verify_and_stage(envelope_bytes(envelope), **values)

    def write_runtime_evidence(self, evidence: dict) -> Path:
        digest = evidence["evidenceDigest"]
        path = self.runtime_evidence_directory / security_core._runtime_evidence_filename(
            evidence["sequence"], evidence["manifestDigest"], digest
        )
        encoded = manifest_tool.canonical_json_bytes(evidence) + b"\n"
        if path.exists():
            os.chmod(path, 0o600)
        path.write_bytes(encoded)
        os.chmod(path, 0o440)
        return path

    def runtime_evidence_patches(self):
        return (
            mock.patch.object(
                security_core,
                "RUNTIME_EVIDENCE_DIRECTORY",
                self.runtime_evidence_directory,
            ),
            mock.patch.object(
                security_core,
                "RUNTIME_EVIDENCE_ROOT_UID",
                os.geteuid(),
            ),
            mock.patch.object(
                security_core,
                "_runtime_evidence_agent_gid",
                return_value=os.getegid(),
            ),
        )

    def commit(self, envelope: dict, **overrides):
        evidence = overrides.pop("evidence", runtime_success_evidence(envelope))
        self.write_runtime_evidence(evidence)
        values = {
            "local_context": local_context(),
            "state_directory": self.state_directory,
            "sequence": envelope["manifest"]["sequence"],
            "manifest_digest": envelope["manifestDigest"],
            "runtime_evidence_digest": evidence["evidenceDigest"],
        }
        values.update(overrides)
        return self.commit_with_values(values)

    def commit_with_values(self, values):
        first, second, third = self.runtime_evidence_patches()
        with first, second, third:
            return security_core.commit_pending_after_health(**values)

    def abort(self, envelope: dict, **overrides):
        values = {
            "local_context": local_context(),
            "state_directory": self.state_directory,
            "sequence": envelope["manifest"]["sequence"],
            "manifest_digest": envelope["manifestDigest"],
        }
        values.update(overrides)
        return security_core.abort_pending(**values)

    def load_state(self):
        store = security_core.StateStore(self.state_directory)
        with store.locked_directory() as directory_fd:
            return store.load_locked(directory_fd, local_context())

    def test_valid_signature_stages_canonical_owner_only_metadata(self) -> None:
        envelope = make_envelope(self.private_key)
        result = self.stage(envelope)
        self.assertEqual(result.sequence, 1)
        self.assertEqual(result.verified_key_ids, (KEY_ID,))
        expected_plan_digest = security_core._local_health_gate_plan_digest(
            security_core._build_local_health_gate_plan(envelope)
        )
        self.assertEqual(result.local_health_gate_plan_digest, expected_plan_digest)
        self.assertEqual(
            result.evidence()["localHealthGatePlanDigest"], expected_plan_digest
        )

        state_path = self.state_directory / security_core.StateStore.STATE_FILE
        raw_state = state_path.read_bytes()
        state = manifest_tool.parse_json_text(raw_state.decode("utf-8"))
        self.assertEqual(raw_state, manifest_tool.canonical_json_bytes(state))
        self.assertEqual(state["highestSeenSequence"], 1)
        self.assertIsNone(state["activeLastKnownGood"])
        self.assertIsNone(state["lastAbortedCandidate"])
        self.assertEqual(
            state["pendingCandidate"]["manifestDigest"], envelope["manifestDigest"]
        )
        self.assertEqual(
            state["pendingCandidate"]["localHealthGatePlanDigest"],
            expected_plan_digest,
        )
        self.assertEqual(state["identity"], local_context().identity_record())
        self.assertEqual(stat.S_IMODE(state_path.stat().st_mode), 0o600)

    def test_stage_commit_abort_lifecycle_preserves_active_lkg_and_replay_floor(self) -> None:
        first = make_envelope(self.private_key)
        self.stage(first)
        with self.assertRaises(ValueError):
            security_core.commit_pending_after_health(
                local_context=local_context(),
                state_directory=self.state_directory,
                sequence=1,
                manifest_digest=first["manifestDigest"],
                runtime_evidence_digest="not-a-digest",
            )
        committed_result = self.commit(first)
        self.assertEqual(
            committed_result.evidence()["status"],
            "PENDING_COMMITTED_AFTER_SIGNED_LOCAL_HEALTH",
        )
        self.assertEqual(len(committed_result.health_gates), 3)
        committed = self.load_state()
        self.assertEqual(
            committed["activeLastKnownGood"]["manifestDigest"],
            first["manifestDigest"],
        )
        self.assertIsNone(committed["pendingCandidate"])
        self.assertIsNone(committed["lastAbortedCandidate"])

        second = make_envelope(self.private_key, sequence=2, previous_envelope=first)
        self.stage(second)
        staged = self.load_state()
        self.assertEqual(
            staged["activeLastKnownGood"]["manifestDigest"],
            first["manifestDigest"],
        )
        self.assertEqual(
            staged["pendingCandidate"]["manifestDigest"],
            second["manifestDigest"],
        )
        self.assertEqual(staged["highestSeenSequence"], 2)

        with self.assertRaises(security_core.StateLifecycleError):
            security_core.abort_pending(
                local_context=local_context(),
                state_directory=self.state_directory,
                sequence=2,
                manifest_digest="sha256:" + "0" * 64,
            )
        self.abort(second)
        aborted = self.load_state()
        self.assertEqual(
            aborted["activeLastKnownGood"]["manifestDigest"],
            first["manifestDigest"],
        )
        self.assertIsNone(aborted["pendingCandidate"])
        self.assertEqual(aborted["highestSeenSequence"], 2)
        self.assertEqual(
            aborted["lastAbortedCandidate"],
            {"manifestDigest": second["manifestDigest"], "sequence": 2},
        )
        with self.assertRaises(security_core.EnvelopeRejected) as replay:
            self.stage(second)
        self.assertIn("highest-seen", str(replay.exception))

        third = make_envelope(self.private_key, sequence=3, previous_envelope=first)
        self.stage(third)
        self.assertEqual(self.load_state()["pendingCandidate"]["sequence"], 3)
        self.assertEqual(
            self.load_state()["lastAbortedCandidate"],
            {"manifestDigest": second["manifestDigest"], "sequence": 2},
        )
        self.commit(third)
        committed_after_abort = self.load_state()
        self.assertEqual(committed_after_abort["activeLastKnownGood"]["sequence"], 3)
        self.assertEqual(
            committed_after_abort["lastAbortedCandidate"],
            {"manifestDigest": second["manifestDigest"], "sequence": 2},
        )

    def test_canonical_local_health_plan_binds_every_signed_member_and_order(self) -> None:
        envelope = make_envelope(self.private_key)
        plan = security_core._build_local_health_gate_plan(envelope)
        digest = security_core._local_health_gate_plan_digest(plan)
        self.assertEqual(
            [gate["type"] for gate in plan["healthGates"]],
            list(security_core.LOCAL_HEALTH_GATE_ORDER),
        )
        mutations = []
        changed_timeout = copy.deepcopy(plan)
        changed_timeout["healthGates"][0]["timeoutSeconds"] += 1
        mutations.append(changed_timeout)
        changed_refs = copy.deepcopy(plan)
        changed_refs["healthGates"][0]["resourceRefs"] = list(
            reversed(changed_refs["healthGates"][0]["resourceRefs"])
        )
        mutations.append(changed_refs)
        changed_order = copy.deepcopy(plan)
        changed_order["healthGates"][0], changed_order["healthGates"][1] = (
            changed_order["healthGates"][1],
            changed_order["healthGates"][0],
        )
        mutations.append(changed_order)
        changed_manifest = copy.deepcopy(plan)
        changed_manifest["manifestDigest"] = "sha256:" + "f" * 64
        mutations.append(changed_manifest)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertNotEqual(
                    security_core._local_health_gate_plan_digest(mutation), digest
                )

    def test_commit_rejects_semantically_forged_runtime_success_evidence(self) -> None:
        envelope = make_envelope(self.private_key)
        self.stage(envelope)
        original = runtime_success_evidence(envelope)

        mutations = []
        wrong_status = copy.deepcopy(original)
        wrong_status["status"] = "RUNTIME_APPLY_FAILED_ROLLED_BACK"
        mutations.append(("status", wrong_status))
        wrong_rollback = copy.deepcopy(original)
        wrong_rollback["rollback"]["performed"] = True
        mutations.append(("rollback", wrong_rollback))
        unsupported_parameter = copy.deepcopy(original)
        unsupported_parameter["localHealthGatePlan"]["healthGates"][0][
            "timeoutSeconds"
        ] = 31
        unsupported_parameter["localHealthGatePlanDigest"] = (
            security_core._local_health_gate_plan_digest(
                unsupported_parameter["localHealthGatePlan"]
            )
        )
        mutations.append(("parameter", unsupported_parameter))
        wrong_order = copy.deepcopy(original)
        wrong_order["healthGates"][0], wrong_order["healthGates"][1] = (
            wrong_order["healthGates"][1],
            wrong_order["healthGates"][0],
        )
        mutations.append(("result-order", wrong_order))
        wrong_plan_order = copy.deepcopy(original)
        wrong_plan_order["localHealthGatePlan"]["healthGates"][0], wrong_plan_order[
            "localHealthGatePlan"
        ]["healthGates"][1] = (
            wrong_plan_order["localHealthGatePlan"]["healthGates"][1],
            wrong_plan_order["localHealthGatePlan"]["healthGates"][0],
        )
        wrong_plan_order["healthGates"][0], wrong_plan_order["healthGates"][1] = (
            wrong_plan_order["healthGates"][1],
            wrong_plan_order["healthGates"][0],
        )
        wrong_plan_order["localHealthGatePlanDigest"] = (
            security_core._local_health_gate_plan_digest(
                wrong_plan_order["localHealthGatePlan"]
            )
        )
        mutations.append(("plan-order", wrong_plan_order))
        wrong_proof = copy.deepcopy(original)
        wrong_proof["healthGates"][0]["proofs"][0]["name"] = "sip-options"
        mutations.append(("proof", wrong_proof))
        excess_attempts = copy.deepcopy(original)
        excess_attempts["healthGates"][0]["attemptsUsed"] = 2
        mutations.append(("attempts", excess_attempts))
        external_gate = copy.deepcopy(original)
        external_gate["localHealthGatePlan"]["healthGates"][0]["type"] = (
            "SIP_OPTIONS"
        )
        external_gate["localHealthGatePlanDigest"] = (
            security_core._local_health_gate_plan_digest(
                external_gate["localHealthGatePlan"]
            )
        )
        external_gate["healthGates"][0]["type"] = "SIP_OPTIONS"
        mutations.append(("external-gate", external_gate))
        arbitrary_runtime_check = copy.deepcopy(original)
        arbitrary_runtime_check["runtimeChecks"] = [
            {"name": "arbitrary-check", "status": "PASSED"}
        ]
        mutations.append(("runtime-checks", arbitrary_runtime_check))

        for name, mutation in mutations:
            with self.subTest(case=name):
                evidence = reseal_runtime_evidence(mutation)
                self.write_runtime_evidence(evidence)
                with self.assertRaises(security_core.StateLifecycleError):
                    self.commit_with_values(
                        {
                            "local_context": local_context(),
                            "state_directory": self.state_directory,
                            "sequence": 1,
                            "manifest_digest": envelope["manifestDigest"],
                            "runtime_evidence_digest": evidence["evidenceDigest"],
                        }
                    )
                self.assertIsNotNone(self.load_state()["pendingCandidate"])

        self.commit(envelope)

    def test_commit_requires_exact_immutable_runtime_evidence_file(self) -> None:
        envelope = make_envelope(self.private_key)
        self.stage(envelope)
        evidence = runtime_success_evidence(envelope)
        values = {
            "local_context": local_context(),
            "state_directory": self.state_directory,
            "sequence": 1,
            "manifest_digest": envelope["manifestDigest"],
            "runtime_evidence_digest": evidence["evidenceDigest"],
        }

        with self.assertRaises(security_core.StateLifecycleError):
            self.commit_with_values(values)

        evidence_directory_link = (
            self.runtime_evidence_directory.parent / "runtime-evidence-link"
        )
        evidence_directory_link.symlink_to(
            self.runtime_evidence_directory, target_is_directory=True
        )
        with mock.patch.object(
            security_core,
            "RUNTIME_EVIDENCE_DIRECTORY",
            evidence_directory_link,
        ), mock.patch.object(
            security_core,
            "RUNTIME_EVIDENCE_ROOT_UID",
            os.geteuid(),
        ), mock.patch.object(
            security_core,
            "_runtime_evidence_agent_gid",
            return_value=os.getegid(),
        ):
            with self.assertRaises(security_core.StateSecurityError):
                security_core.commit_pending_after_health(**values)
        evidence_directory_link.unlink()

        tampered = copy.deepcopy(evidence)
        tampered["timestamp"] = "2026-08-30T04:47:00Z"
        self.write_runtime_evidence(tampered)
        with self.assertRaisesRegex(
            security_core.StateLifecycleError, "self-digest"
        ):
            self.commit_with_values(values)

        evidence_path = self.write_runtime_evidence(evidence)
        os.chmod(self.runtime_evidence_directory, 0o755)
        with self.assertRaises(security_core.StateSecurityError):
            self.commit_with_values(values)
        os.chmod(self.runtime_evidence_directory, 0o750)

        with mock.patch.object(
            security_core,
            "RUNTIME_EVIDENCE_DIRECTORY",
            self.runtime_evidence_directory,
        ), mock.patch.object(
            security_core,
            "RUNTIME_EVIDENCE_ROOT_UID",
            os.geteuid() + 1,
        ), mock.patch.object(
            security_core,
            "_runtime_evidence_agent_gid",
            return_value=os.getegid(),
        ):
            with self.assertRaises(security_core.StateSecurityError):
                security_core.commit_pending_after_health(**values)

        second_link = self.runtime_evidence_directory / "second-link"
        os.link(evidence_path, second_link)
        with self.assertRaises(security_core.StateSecurityError):
            self.commit_with_values(values)
        second_link.unlink()

        os.chmod(evidence_path, 0o640)
        with self.assertRaises(security_core.StateSecurityError):
            self.commit_with_values(values)
        os.chmod(evidence_path, 0o440)

        original = evidence_path.read_bytes()
        os.chmod(evidence_path, 0o600)
        evidence_path.write_bytes(original.rstrip(b"\n"))
        os.chmod(evidence_path, 0o440)
        with self.assertRaisesRegex(
            security_core.StateLifecycleError, "canonical byte form"
        ):
            self.commit_with_values(values)
        os.chmod(evidence_path, 0o600)
        evidence_path.write_bytes(original)
        os.chmod(evidence_path, 0o440)

        external = self.runtime_evidence_directory.parent / "external-evidence"
        external.write_bytes(original)
        os.chmod(external, 0o440)
        evidence_path.unlink()
        evidence_path.symlink_to(external)
        with self.assertRaises(security_core.StateSecurityError):
            self.commit_with_values(values)
        evidence_path.unlink()
        external.unlink()

        self.write_runtime_evidence(evidence)
        result = self.commit_with_values(values)
        self.assertEqual(result.runtime_evidence_digest, evidence["evidenceDigest"])

    def test_commit_output_links_exact_plan_runtime_release_and_gate_results(self) -> None:
        envelope = make_envelope(self.private_key)
        staged = self.stage(envelope)
        evidence = runtime_success_evidence(envelope)
        result = self.commit(envelope, evidence=evidence).evidence()
        self.assertEqual(
            set(result),
            {
                "activeManifestDigest",
                "activeSequence",
                "healthGates",
                "localHealthGatePlanDigest",
                "runtimeEvidenceDigest",
                "runtimeReleaseDigest",
                "status",
            },
        )
        self.assertEqual(
            result["localHealthGatePlanDigest"],
            staged.local_health_gate_plan_digest,
        )
        self.assertEqual(result["runtimeEvidenceDigest"], evidence["evidenceDigest"])
        self.assertEqual(
            result["runtimeReleaseDigest"], evidence["runtimeReleaseDigest"]
        )
        self.assertEqual(result["healthGates"], evidence["healthGates"])
        self.assertNotIn("OPTIONS", json.dumps(result).upper())

    def test_protected_status_is_locked_validated_and_metadata_minimal(self) -> None:
        with self.assertRaisesRegex(
            security_core.StateLifecycleError, "protected state does not exist"
        ):
            security_core.inspect_protected_state(
                local_context=local_context(),
                state_directory=self.state_directory,
            )

        envelope = make_envelope(self.private_key)
        self.stage(envelope)
        pending = security_core.inspect_protected_state(
            local_context=local_context(),
            state_directory=self.state_directory,
        )
        self.assertEqual(
            set(pending),
            {
                "activeLastKnownGood",
                "apiVersion",
                "highestSeenSequence",
                "kind",
                "lastAbortedCandidate",
                "pendingCandidate",
            },
        )
        self.assertEqual(
            pending["apiVersion"], security_core.AGENT_STATUS_API_VERSION
        )
        self.assertEqual(pending["kind"], "EdgeAgentProtectedStateStatus")
        self.assertEqual(pending["highestSeenSequence"], 1)
        self.assertIsNone(pending["activeLastKnownGood"])
        self.assertIsNone(pending["lastAbortedCandidate"])
        self.assertEqual(
            pending["pendingCandidate"],
            {"manifestDigest": envelope["manifestDigest"], "sequence": 1},
        )
        self.assertNotIn("artifactDigests", json.dumps(pending))
        self.assertNotIn("verifiedKeyIds", json.dumps(pending))

        self.commit(envelope)
        committed = security_core.inspect_protected_state(
            local_context=local_context(),
            state_directory=self.state_directory,
        )
        self.assertEqual(committed["activeLastKnownGood"], pending["pendingCandidate"])
        self.assertIsNone(committed["pendingCandidate"])
        self.assertIsNone(committed["lastAbortedCandidate"])

        with self.assertRaisesRegex(
            security_core.StateSecurityError, "identity does not match"
        ):
            security_core.inspect_protected_state(
                local_context=local_context(node_id="sbc2"),
                state_directory=self.state_directory,
            )

    def test_first_ever_abort_requires_reviewed_reenrollment_before_retry(self) -> None:
        first = make_envelope(self.private_key)
        self.stage(first)
        self.abort(first)
        state = self.load_state()
        self.assertIsNone(state["activeLastKnownGood"])
        self.assertIsNone(state["pendingCandidate"])
        self.assertEqual(state["highestSeenSequence"], 1)
        self.assertEqual(
            state["lastAbortedCandidate"],
            {"manifestDigest": first["manifestDigest"], "sequence": 1},
        )

        with self.assertRaises(security_core.EnvelopeRejected):
            self.stage(first)

        null_lineage_retry = make_envelope(self.private_key, sequence=2)
        with self.assertRaises(security_core.EnvelopeRejected) as null_lineage:
            self.stage(null_lineage_retry)
        self.assertIn("structural validation failed", str(null_lineage.exception))

        aborted_lineage_retry = make_envelope(
            self.private_key,
            sequence=2,
            previous_envelope=first,
        )
        with self.assertRaises(security_core.EnvelopeRejected) as aborted_lineage:
            self.stage(aborted_lineage_retry)
        self.assertIn(
            "initial high-water state requires null lineage",
            str(aborted_lineage.exception),
        )

        unchanged = self.load_state()
        self.assertIsNone(unchanged["activeLastKnownGood"])
        self.assertIsNone(unchanged["pendingCandidate"])
        self.assertEqual(unchanged["highestSeenSequence"], 1)
        self.assertEqual(
            unchanged["lastAbortedCandidate"], state["lastAbortedCandidate"]
        )

    def test_at_least_one_authorized_signature_is_sufficient(self) -> None:
        envelope = make_envelope(self.private_key)
        invalid = copy.deepcopy(envelope["signatures"][0])
        invalid["keyId"] = "retired-key"
        invalid["value"] = base64.b64encode(b"x" * 64).decode("ascii")
        envelope["signatures"].insert(0, invalid)
        result = self.stage(envelope)
        self.assertEqual(result.verified_key_ids, (KEY_ID,))

    def test_wrong_key_id_key_material_and_signature_are_rejected(self) -> None:
        cases = []
        wrong_id = make_envelope(self.private_key, key_id="untrusted-key")
        cases.append((wrong_id, self.keyring))

        wrong_private = Ed25519PrivateKey.generate()
        wrong_material = make_envelope(self.private_key)
        cases.append(
            (
                wrong_material,
                security_core.PinnedKeyring({KEY_ID: public_bytes(wrong_private)}),
            )
        )

        wrong_signature = make_envelope(self.private_key)
        signature_bytes = bytearray(base64.b64decode(wrong_signature["signatures"][0]["value"]))
        signature_bytes[0] ^= 1
        wrong_signature["signatures"][0]["value"] = base64.b64encode(signature_bytes).decode(
            "ascii"
        )
        cases.append((wrong_signature, self.keyring))

        for index, (envelope, keyring) in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaises(security_core.SignatureVerificationError):
                    self.stage(envelope, keyring=keyring)
                self.assertFalse(
                    (self.state_directory / security_core.StateStore.STATE_FILE).exists()
                )

    def test_duplicate_member_input_is_rejected_before_signature_verification(self) -> None:
        raw = b'{"manifest":{},"manifest":{},"signatures":[]}'
        with self.assertRaises(security_core.EnvelopeRejected) as caught:
            security_core.verify_and_stage(
                raw,
                local_context=local_context(),
                keyring=self.keyring,
                state_directory=self.state_directory,
                now=NOW,
            )
        self.assertIn("duplicate", str(caught.exception))

    def test_replay_and_stale_previous_digest_are_rejected(self) -> None:
        first = make_envelope(self.private_key)
        self.stage(first)
        self.commit(first)
        with self.assertRaises(security_core.EnvelopeRejected) as replay:
            self.stage(first)
        self.assertIn("replay/downgrade", str(replay.exception))

        second = make_envelope(self.private_key, sequence=2, previous_envelope=first)
        second["manifest"]["previousDigest"] = "sha256:" + "f" * 64
        second["manifest"]["rollbackTarget"]["manifestDigest"] = "sha256:" + "f" * 64
        second["manifestDigest"] = manifest_tool.manifest_digest(second["manifest"])
        signed = security_core.SIGNED_BYTES_PREFIX + manifest_tool.canonical_json_bytes(
            second["manifest"]
        )
        second["signatures"][0]["value"] = base64.b64encode(
            self.private_key.sign(signed)
        ).decode("ascii")
        with self.assertRaises(security_core.EnvelopeRejected) as stale:
            self.stage(second)
        self.assertIn("accepted last-known-good digest", str(stale.exception))

        wrong_artifacts = make_envelope(
            self.private_key,
            sequence=2,
            previous_envelope=first,
        )
        wrong_artifacts["manifest"]["rollbackTarget"]["artifactDigests"][0] = (
            "sha256:" + "f" * 64
        )
        wrong_artifacts["manifestDigest"] = manifest_tool.manifest_digest(
            wrong_artifacts["manifest"]
        )
        signed = security_core.SIGNED_BYTES_PREFIX + manifest_tool.canonical_json_bytes(
            wrong_artifacts["manifest"]
        )
        wrong_artifacts["signatures"][0]["value"] = base64.b64encode(
            self.private_key.sign(signed)
        ).decode("ascii")
        with self.assertRaises(security_core.EnvelopeRejected) as artifact_lineage:
            self.stage(wrong_artifacts)
        self.assertIn("rollback artifact digests", str(artifact_lineage.exception))

    def test_expired_manifest_is_rejected(self) -> None:
        envelope = make_envelope(self.private_key)
        with self.assertRaises(security_core.EnvelopeRejected) as caught:
            self.stage(
                envelope,
                now=datetime(2026, 8, 30, 5, 0, tzinfo=timezone.utc),
            )
        self.assertIn("activation has expired", str(caught.exception))

    def test_draft_2020_12_shape_validation_precedes_semantics(self) -> None:
        envelope = make_envelope(self.private_key)
        del envelope["apiVersion"]
        with mock.patch.object(manifest_tool, "validate_envelope") as semantic:
            with self.assertRaises(security_core.EnvelopeRejected) as caught:
                self.stage(envelope)
        semantic.assert_not_called()
        self.assertIn("Draft 2020-12 structural validation failed", str(caught.exception))
        self.assertFalse(
            (self.state_directory / security_core.StateStore.STATE_FILE).exists()
        )

    def test_structural_validator_dependency_and_schema_fail_closed(self) -> None:
        envelope = make_envelope(self.private_key)
        with mock.patch.object(
            security_core,
            "_jsonschema_types",
            side_effect=security_core.DependencyUnavailable(
                "Draft 2020-12 structural validation requires python3-jsonschema"
            ),
        ):
            with self.assertRaises(security_core.DependencyUnavailable) as dependency:
                self.stage(envelope)
        self.assertIn("python3-jsonschema", str(dependency.exception))

        missing = self.state_directory / "missing-schema.json"
        with mock.patch.object(security_core, "DESIRED_STATE_SCHEMA_PATH", missing):
            with self.assertRaises(
                security_core.SchemaValidationUnavailable
            ) as unavailable:
                self.stage(envelope)
        self.assertIn("schema is unavailable", str(unavailable.exception))

    def test_local_network_authority_is_canonical_narrow_and_nonoverlapping(self) -> None:
        invalid_tenant_changes = (
            {"expected_advertised_public_ip": "198.51.100.20"},
            {"expected_advertised_public_ip": "2001:db8::20"},
            {"authorized_pbx_source_cidrs": ("10.0.0.0/8",)},
            {"authorized_pbx_source_cidrs": ("10.20.1.4/24",)},
            {
                "authorized_pbx_source_cidrs": (
                    "10.20.1.0/24",
                    "10.20.1.4/32",
                )
            },
            {"authorized_pbx_source_cidrs": ["10.20.1.4/32"]},
            {"authorized_microsoft_source_cidrs": ("52.112.0.0/14",)},
        )
        for changes in invalid_tenant_changes:
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    replace(local_context(), **changes)

        with self.assertRaises(ValueError):
            replace(
                cluster_context(),
                authorized_microsoft_source_cidrs=("10.0.0.0/14",),
            )
        with self.assertRaises(ValueError):
            replace(
                cluster_context(),
                authorized_microsoft_source_cidrs=("52.0.0.0/8",),
            )
        with self.assertRaises(ValueError):
            replace(
                cluster_context(),
                authorized_microsoft_source_cidrs=(
                    "52.112.0.0/14",
                    "52.112.0.0/15",
                ),
            )

    def test_schema_validation_context_receives_local_network_authority(self) -> None:
        tenant = security_core._validation_context(local_context(), 0, None, NOW)
        self.assertEqual(tenant.expected_advertised_public_ip, "20.74.155.72")
        self.assertEqual(
            tenant.authorized_pbx_source_cidrs,
            ("203.0.113.10/32",),
        )
        self.assertEqual(tenant.authorized_microsoft_source_cidrs, ())

        cluster = security_core._validation_context(cluster_context(), 0, None, NOW)
        self.assertIsNone(cluster.expected_advertised_public_ip)
        self.assertEqual(cluster.authorized_pbx_source_cidrs, ())
        self.assertEqual(
            cluster.authorized_microsoft_source_cidrs,
            ("52.112.0.0/14", "52.120.0.0/14"),
        )

    def test_tenant_network_allocation_is_local_authority(self) -> None:
        with self.assertRaises(ValueError):
            replace(local_context(), tenant_listener_port=5061)

        def resources(envelope, resource_type):
            return [
                resource
                for resource in envelope["manifest"]["resourceSet"]["resources"]
                if resource["type"] == resource_type
            ]

        mutations = (
            ("teams-port", "tenant.listener", "port", 5061),
            ("other-listener", "tenant.listener", "port", 15062),
            ("shifted-media-start", "tenant.media", "portStart", 20002),
            ("outside-media-end", "tenant.media", "portEnd", 30255),
            (
                "wrong-advertised-public-ip",
                "tenant.media",
                "advertisedAddress",
                "20.74.155.73",
            ),
        )
        for name, resource_type, field, value in mutations:
            with self.subTest(case=name):
                envelope = make_envelope(self.private_key)
                resources(envelope, resource_type)[0]["spec"][field] = value
                envelope["manifestDigest"] = manifest_tool.manifest_digest(
                    envelope["manifest"]
                )
                signed = security_core.SIGNED_BYTES_PREFIX + manifest_tool.canonical_json_bytes(
                    envelope["manifest"]
                )
                envelope["signatures"][0]["value"] = base64.b64encode(
                    self.private_key.sign(signed)
                ).decode("ascii")
                with self.assertRaises(security_core.EnvelopeRejected):
                    self.stage(envelope)

        for resource_type, field in (
            ("tenant.connector", "sourceCidrs"),
            ("tenant.listener", "allowedSourceCidrs"),
        ):
            with self.subTest(resource_type=resource_type, field=field):
                envelope = make_envelope(self.private_key)
                resources(envelope, resource_type)[0]["spec"][field] = [
                    "203.0.113.11/32"
                ]
                envelope["manifestDigest"] = manifest_tool.manifest_digest(
                    envelope["manifest"]
                )
                signed = (
                    security_core.SIGNED_BYTES_PREFIX
                    + manifest_tool.canonical_json_bytes(envelope["manifest"])
                )
                envelope["signatures"][0]["value"] = base64.b64encode(
                    self.private_key.sign(signed)
                ).decode("ascii")
                with self.assertRaises(security_core.EnvelopeRejected) as caught:
                    self.stage(envelope)
                self.assertIn("locally authorized", str(caught.exception))

        extra_listener = make_envelope(self.private_key)
        duplicate = copy.deepcopy(resources(extra_listener, "tenant.listener")[0])
        duplicate["resourceId"] = "listener-vivolution-pbx-second"
        extra_listener["manifest"]["resourceSet"]["resources"].append(duplicate)
        extra_listener["manifestDigest"] = manifest_tool.manifest_digest(
            extra_listener["manifest"]
        )
        signed = security_core.SIGNED_BYTES_PREFIX + manifest_tool.canonical_json_bytes(
            extra_listener["manifest"]
        )
        extra_listener["signatures"][0]["value"] = base64.b64encode(
            self.private_key.sign(signed)
        ).decode("ascii")
        with self.assertRaises(security_core.EnvelopeRejected) as caught:
            self.stage(extra_listener)
        self.assertIn("exactly one listener", str(caught.exception))

    def test_state_identity_cannot_be_rebound(self) -> None:
        first = make_envelope(self.private_key)
        self.stage(first)
        second = make_envelope(
            self.private_key,
            sequence=2,
            previous_envelope=first,
            node_id="sbc2",
        )
        with self.assertRaises(security_core.StateSecurityError) as caught:
            self.stage(second, local_context=local_context("sbc2"))
        self.assertIn("immutable local context", str(caught.exception))

        with self.assertRaises(security_core.StateSecurityError):
            self.stage(
                make_envelope(self.private_key, sequence=2, previous_envelope=first),
                local_context=replace(local_context(), tenant_listener_port=15062),
            )

        with self.assertRaises(security_core.StateSecurityError):
            self.stage(
                make_envelope(self.private_key, sequence=2, previous_envelope=first),
                local_context=replace(
                    local_context(), expected_advertised_public_ip="20.74.155.73"
                ),
            )

        with self.assertRaises(security_core.StateSecurityError):
            self.stage(
                make_envelope(self.private_key, sequence=2, previous_envelope=first),
                local_context=replace(
                    local_context(),
                    authorized_pbx_source_cidrs=("203.0.113.11/32",),
                ),
            )

        slot_b = make_envelope(self.private_key, sequence=2, previous_envelope=first)
        slot_b["manifest"]["target"]["slot"] = "B"
        slot_b["manifestDigest"] = manifest_tool.manifest_digest(slot_b["manifest"])
        signed = security_core.SIGNED_BYTES_PREFIX + manifest_tool.canonical_json_bytes(
            slot_b["manifest"]
        )
        slot_b["signatures"][0]["value"] = base64.b64encode(
            self.private_key.sign(signed)
        ).decode("ascii")
        with self.assertRaises(security_core.StateSecurityError):
            self.stage(slot_b, local_context=replace(local_context(), slot="B"))

    def test_cluster_microsoft_network_authority_cannot_be_rebound(self) -> None:
        context = cluster_context()
        state = {
            "activeLastKnownGood": None,
            "formatVersion": security_core.STATE_FORMAT_VERSION,
            "highestSeenSequence": 1,
            "identity": context.identity_record(),
            "lastAbortedCandidate": {
                "manifestDigest": "sha256:" + "0" * 64,
                "sequence": 1,
            },
            "pendingCandidate": None,
        }
        store = security_core.StateStore(self.state_directory)
        with store.locked_directory() as directory_fd:
            store.write_locked(directory_fd, state)
        rebound = replace(
            context,
            authorized_microsoft_source_cidrs=(
                "52.112.0.0/14",
                "52.124.0.0/14",
            ),
        )
        with store.locked_directory() as directory_fd:
            with self.assertRaises(security_core.StateSecurityError) as caught:
                store.load_locked(directory_fd, rebound)
        self.assertIn("immutable local context", str(caught.exception))

    def test_signed_wrong_slot_is_rejected_by_local_context(self) -> None:
        envelope = make_envelope(self.private_key)
        envelope["manifest"]["target"]["slot"] = "B"
        envelope["manifestDigest"] = manifest_tool.manifest_digest(envelope["manifest"])
        signed = security_core.SIGNED_BYTES_PREFIX + manifest_tool.canonical_json_bytes(
            envelope["manifest"]
        )
        envelope["signatures"][0]["value"] = base64.b64encode(
            self.private_key.sign(signed)
        ).decode("ascii")
        with self.assertRaises(security_core.EnvelopeRejected) as caught:
            self.stage(envelope)
        self.assertIn("immutable local context", str(caught.exception))

    def test_corrupt_and_noncanonical_state_are_rejected_without_replacement(self) -> None:
        first = make_envelope(self.private_key)
        self.stage(first)
        state_path = self.state_directory / security_core.StateStore.STATE_FILE
        second = make_envelope(self.private_key, sequence=2, previous_envelope=first)

        for raw in (b'{"broken":', b'{"formatVersion":1, "formatVersion":1}'):
            with self.subTest(raw=raw):
                state_path.write_bytes(raw)
                os.chmod(state_path, 0o600)
                with self.assertRaises(security_core.StateCorruptionError):
                    self.stage(second)
                self.assertEqual(state_path.read_bytes(), raw)

    def test_v1_state_is_refused_without_automatic_migration(self) -> None:
        first = make_envelope(self.private_key)
        self.stage(first)
        current = self.load_state()
        legacy = {
            "formatVersion": 1,
            "highWaterSequence": 1,
            "identity": current["identity"],
            "lastKnownGood": current["pendingCandidate"],
        }
        raw = manifest_tool.canonical_json_bytes(legacy)
        (self.state_directory / security_core.StateStore.STATE_FILE).unlink()
        state_path = self.state_directory / security_core.StateStore.LEGACY_STATE_FILE
        state_path.write_bytes(raw)
        os.chmod(state_path, 0o600)
        with self.assertRaises(security_core.StateVersionError) as caught:
            self.load_state()
        self.assertIn("automatic migration is refused", str(caught.exception))
        self.assertEqual(state_path.read_bytes(), raw)

    def test_v2_state_is_refused_without_signed_health_plan_migration(self) -> None:
        first = make_envelope(self.private_key)
        self.stage(first)
        current = self.load_state()
        previous = copy.deepcopy(current)
        previous["formatVersion"] = 2
        previous["pendingCandidate"].pop("localHealthGatePlanDigest")
        raw = manifest_tool.canonical_json_bytes(previous)
        (self.state_directory / security_core.StateStore.STATE_FILE).unlink()
        previous_path = (
            self.state_directory / security_core.StateStore.PREVIOUS_STATE_FILE
        )
        previous_path.write_bytes(raw)
        os.chmod(previous_path, 0o600)
        with self.assertRaisesRegex(
            security_core.StateVersionError, "lacks a signed local-health plan"
        ):
            self.load_state()
        self.assertEqual(previous_path.read_bytes(), raw)

    def test_protected_plan_digest_corruption_fails_closed(self) -> None:
        envelope = make_envelope(self.private_key)
        self.stage(envelope)
        state_path = self.state_directory / security_core.StateStore.STATE_FILE
        state = manifest_tool.parse_json_text(
            state_path.read_text(encoding="utf-8")
        )
        state["pendingCandidate"]["localHealthGatePlanDigest"] = "not-a-digest"
        raw = manifest_tool.canonical_json_bytes(state)
        state_path.write_bytes(raw)
        os.chmod(state_path, 0o600)
        with self.assertRaisesRegex(
            security_core.StateCorruptionError, "health-gate plan digest"
        ):
            self.load_state()
        self.assertEqual(state_path.read_bytes(), raw)

    def test_last_aborted_tombstone_corruption_fails_closed(self) -> None:
        envelope = make_envelope(self.private_key)
        self.stage(envelope)
        self.abort(envelope)
        state_path = self.state_directory / security_core.StateStore.STATE_FILE
        original = self.load_state()

        mutations = []
        invalid_digest = copy.deepcopy(original)
        invalid_digest["lastAbortedCandidate"]["manifestDigest"] = "not-a-digest"
        mutations.append(invalid_digest)
        boolean_sequence = copy.deepcopy(original)
        boolean_sequence["lastAbortedCandidate"]["sequence"] = True
        mutations.append(boolean_sequence)
        future_sequence = copy.deepcopy(original)
        future_sequence["lastAbortedCandidate"]["sequence"] = 2
        mutations.append(future_sequence)
        unknown_member = copy.deepcopy(original)
        unknown_member["lastAbortedCandidate"]["unexpected"] = "forbidden"
        mutations.append(unknown_member)

        for mutation in mutations:
            with self.subTest(mutation=mutation):
                raw = manifest_tool.canonical_json_bytes(mutation)
                state_path.write_bytes(raw)
                os.chmod(state_path, 0o600)
                with self.assertRaises(security_core.StateCorruptionError):
                    self.load_state()
                self.assertEqual(state_path.read_bytes(), raw)

    def test_boolean_cannot_impersonate_integer_in_protected_state(self) -> None:
        first = make_envelope(self.private_key)
        self.stage(first)
        state_path = self.state_directory / security_core.StateStore.STATE_FILE
        state = manifest_tool.parse_json_text(state_path.read_text(encoding="utf-8"))
        state["pendingCandidate"]["sequence"] = True
        raw = manifest_tool.canonical_json_bytes(state)
        state_path.write_bytes(raw)
        os.chmod(state_path, 0o600)
        second = make_envelope(self.private_key, sequence=2, previous_envelope=first)
        with self.assertRaises(security_core.StateCorruptionError):
            self.stage(second)
        self.assertEqual(state_path.read_bytes(), raw)

    def test_symlink_state_and_symlink_directory_are_rejected(self) -> None:
        envelope = make_envelope(self.private_key)
        external = self.state_directory.parent / (self.state_directory.name + "-external")
        external.write_text("do not replace", encoding="utf-8")
        self.addCleanup(lambda: external.unlink(missing_ok=True))
        state_path = self.state_directory / security_core.StateStore.STATE_FILE
        state_path.symlink_to(external)
        with self.assertRaises(security_core.StateSecurityError):
            self.stage(envelope)
        self.assertEqual(external.read_text(encoding="utf-8"), "do not replace")

        state_path.unlink()
        link = self.state_directory.parent / (self.state_directory.name + "-link")
        link.symlink_to(self.state_directory, target_is_directory=True)
        self.addCleanup(lambda: link.unlink(missing_ok=True))
        with self.assertRaises(security_core.StateSecurityError):
            self.stage(envelope, state_directory=link)

    def test_relative_and_traversal_state_paths_are_rejected(self) -> None:
        envelope = make_envelope(self.private_key)
        with self.assertRaises(security_core.StateSecurityError):
            self.stage(envelope, state_directory=Path("relative-state"))
        traversal = self.state_directory / "missing" / ".."
        with self.assertRaises(security_core.StateSecurityError):
            self.stage(envelope, state_directory=traversal)

    def test_failed_replace_preserves_old_state_and_stale_temp_is_ignored(self) -> None:
        first = make_envelope(self.private_key)
        self.stage(first)
        self.commit(first)
        state_path = self.state_directory / security_core.StateStore.STATE_FILE
        old_state = state_path.read_bytes()
        second = make_envelope(self.private_key, sequence=2, previous_envelope=first)

        with mock.patch.object(
            security_core.os,
            "replace",
            side_effect=OSError("simulated crash before rename"),
        ):
            with self.assertRaises(OSError):
                self.stage(second)
        self.assertEqual(state_path.read_bytes(), old_state)
        self.assertEqual(
            list(self.state_directory.glob(security_core.StateStore.TEMP_PREFIX + "*")),
            [],
        )

        stale = self.state_directory / (
            security_core.StateStore.TEMP_PREFIX + "stale-crash"
        )
        stale.write_bytes(b"partial and untrusted")
        os.chmod(stale, 0o600)
        result = self.stage(second)
        self.assertEqual(result.sequence, 2)
        self.assertTrue(stale.exists())
        staged_state = state_path.read_bytes()
        with mock.patch.object(
            security_core.os,
            "replace",
            side_effect=OSError("simulated crash before commit rename"),
        ):
            with self.assertRaises(OSError):
                self.commit(second)
        self.assertEqual(state_path.read_bytes(), staged_state)
        state = self.load_state()
        self.assertEqual(state["activeLastKnownGood"]["sequence"], 1)
        self.assertEqual(state["pendingCandidate"]["sequence"], 2)

    def test_concurrent_staging_serializes_high_water_update(self) -> None:
        envelope = make_envelope(self.private_key)
        available_methods = multiprocessing.get_all_start_methods()
        method = "fork" if "fork" in available_methods else available_methods[0]
        process_context = multiprocessing.get_context(method)
        barrier = process_context.Barrier(2)
        result_queue = process_context.Queue()
        processes = [
            process_context.Process(
                target=_concurrent_worker,
                args=(
                    str(self.state_directory),
                    envelope_bytes(envelope),
                    self.public_key_bytes,
                    barrier,
                    result_queue,
                ),
            )
            for _ in range(2)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=20)
            self.assertFalse(process.is_alive(), "concurrent staging process hung")
            self.assertEqual(process.exitcode, 0)
        outcomes = sorted(result_queue.get(timeout=2) for _ in processes)
        self.assertEqual([item[0] for item in outcomes], ["error", "ok"])
        self.assertEqual(outcomes[0][1], "EnvelopeRejected")

        store = security_core.StateStore(self.state_directory)
        with store.locked_directory() as directory_fd:
            state = store.load_locked(directory_fd, local_context())
        self.assertEqual(state["highestSeenSequence"], 1)
        self.assertIsNone(state["activeLastKnownGood"])
        self.assertEqual(state["pendingCandidate"]["sequence"], 1)

    def test_cli_returns_canonical_metadata_only_evidence(self) -> None:
        envelope = make_envelope(self.private_key)
        envelope_path = self.state_directory.parent / (self.state_directory.name + "-envelope.json")
        envelope_path.write_bytes(envelope_bytes(envelope))
        self.addCleanup(lambda: envelope_path.unlink(missing_ok=True))
        encoded_key = base64.b64encode(self.public_key_bytes).decode("ascii")
        context_args = [
            "--state-dir",
            str(self.state_directory),
            "--scope",
            "TENANT",
            "--cluster-id",
            "cluster-uaen-poc-01",
            "--node-id",
            "sbc1",
            "--generation",
            "1",
            "--slot",
            "A",
            "--customer-account-id",
            "vivolution-technologies-llc",
            "--m365-tenant-id",
            "9b7a1c2d-3e4f-4a5b-8c6d-7e8f9012abcd",
            "--tenant-context-id",
            "tenant-vivolution-poc",
            "--service-instance-id",
            "service-vivolution-pbx-relay",
            "--allocation-id",
            "allocation-vivolution-uaen-poc",
            "--tenant-listener-port",
            "15061",
            "--tenant-media-port-start",
            "20000",
            "--tenant-media-port-end",
            "20255",
            "--pbx-media-destination-port-start",
            "30000",
            "--pbx-media-destination-port-end",
            "30127",
            "--cluster-media-port-start",
            "20000",
            "--cluster-media-port-end",
            "29999",
            "--expected-advertised-public-ip",
            "20.74.155.72",
            "--authorized-pbx-source-cidr",
            "203.0.113.10/32",
        ]
        broad_context_args = list(context_args)
        broad_context_args[
            broad_context_args.index("203.0.113.10/32")
        ] = "10.0.0.0/8"
        rejected = subprocess.run(
            [
                sys.executable,
                "-m",
                "edge.agent",
                "verify-and-stage",
                str(envelope_path),
                *broad_context_args,
                "--pinned-key",
                "{}={}".format(KEY_ID, encoded_key),
                "--now",
                "2026-08-30T04:45:00Z",
            ],
            cwd=REPOSITORY,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(rejected.returncode, 1)
        self.assertIn("broader than", rejected.stderr)
        self.assertFalse(
            (self.state_directory / security_core.StateStore.STATE_FILE).exists()
        )

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "edge.agent",
                "verify-and-stage",
                str(envelope_path),
                *context_args,
                "--pinned-key",
                "{}={}".format(KEY_ID, encoded_key),
                "--now",
                "2026-08-30T04:45:00Z",
            ],
            cwd=REPOSITORY,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual(evidence["status"], "VERIFIED_AND_STAGED_METADATA_ONLY")
        self.assertNotIn("configuration", evidence)

        pending_status = subprocess.run(
            [
                sys.executable,
                "-m",
                "edge.agent",
                "status",
                *context_args,
            ],
            cwd=REPOSITORY,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(pending_status.returncode, 0, pending_status.stderr)
        pending_status_value = json.loads(pending_status.stdout)
        self.assertEqual(
            pending_status.stdout.strip().encode("utf-8"),
            manifest_tool.canonical_json_bytes(pending_status_value),
        )
        self.assertEqual(
            pending_status_value["pendingCandidate"],
            {"manifestDigest": envelope["manifestDigest"], "sequence": 1},
        )

        runtime_evidence = runtime_success_evidence(envelope)
        self.write_runtime_evidence(runtime_evidence)
        commit_stdout = io.StringIO()
        commit_stderr = io.StringIO()
        first, second_patch, third = self.runtime_evidence_patches()
        with first, second_patch, third, redirect_stdout(
            commit_stdout
        ), redirect_stderr(commit_stderr):
            commit_returncode = agent_cli.main(
                [
                    "commit-pending",
                    *context_args,
                    "--sequence",
                    "1",
                    "--manifest-digest",
                    envelope["manifestDigest"],
                    "--runtime-evidence-digest",
                    runtime_evidence["evidenceDigest"],
                ]
            )
        self.assertEqual(commit_returncode, 0, commit_stderr.getvalue())
        self.assertEqual(
            json.loads(commit_stdout.getvalue())["status"],
            "PENDING_COMMITTED_AFTER_SIGNED_LOCAL_HEALTH",
        )

        committed_status = subprocess.run(
            [sys.executable, "-m", "edge.agent", "status", *context_args],
            cwd=REPOSITORY,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(committed_status.returncode, 0, committed_status.stderr)
        committed_status_value = json.loads(committed_status.stdout)
        self.assertEqual(
            committed_status_value["activeLastKnownGood"],
            {"manifestDigest": envelope["manifestDigest"], "sequence": 1},
        )
        self.assertIsNone(committed_status_value["pendingCandidate"])

        second = make_envelope(self.private_key, sequence=2, previous_envelope=envelope)
        envelope_path.write_bytes(envelope_bytes(second))
        stage_second = subprocess.run(
            [
                sys.executable,
                "-m",
                "edge.agent",
                "verify-and-stage",
                str(envelope_path),
                *context_args,
                "--pinned-key",
                "{}={}".format(KEY_ID, encoded_key),
                "--now",
                "2026-08-30T04:45:00Z",
            ],
            cwd=REPOSITORY,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(stage_second.returncode, 0, stage_second.stderr)
        abort = subprocess.run(
            [
                sys.executable,
                "-m",
                "edge.agent",
                "abort-pending",
                *context_args,
                "--sequence",
                "2",
                "--manifest-digest",
                second["manifestDigest"],
            ],
            cwd=REPOSITORY,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(abort.returncode, 0, abort.stderr)
        self.assertEqual(
            json.loads(abort.stdout)["status"],
            "PENDING_ABORTED_ACTIVE_LKG_PRESERVED",
        )
        final_state = self.load_state()
        self.assertEqual(final_state["activeLastKnownGood"]["sequence"], 1)
        self.assertEqual(final_state["highestSeenSequence"], 2)
        self.assertIsNone(final_state["pendingCandidate"])
        self.assertEqual(
            final_state["lastAbortedCandidate"],
            {"manifestDigest": second["manifestDigest"], "sequence": 2},
        )
        final_status = security_core.inspect_protected_state(
            local_context=local_context(),
            state_directory=self.state_directory,
        )
        self.assertEqual(
            final_status["lastAbortedCandidate"],
            {"manifestDigest": second["manifestDigest"], "sequence": 2},
        )


if __name__ == "__main__":
    unittest.main()
