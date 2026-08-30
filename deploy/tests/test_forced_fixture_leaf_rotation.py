from __future__ import annotations

import base64
import csv
from datetime import datetime, timedelta
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
REQUEST_ID = "20260831T010203Z-123456abcdef"
STATE_SCRIPT = ROOT / "deploy" / "scripts" / "forced_fixture_leaf_rotation_state.py"
EVIDENCE_SCRIPT = ROOT / "deploy" / "scripts" / "forced_fixture_leaf_rotation_evidence.py"
PLAYBOOK = (
    ROOT
    / "deploy"
    / "playbooks"
    / "qualify-forced-synthetic-fixture-leaf-rotation.yml"
)
ROLE_DEFAULTS = (
    ROOT
    / "poc"
    / "voice-fixture"
    / "roles"
    / "voice_fixture"
    / "defaults"
    / "main.yml"
)
ROLE_TASKS = (
    ROOT
    / "poc"
    / "voice-fixture"
    / "roles"
    / "voice_fixture"
    / "tasks"
    / "main.yml"
)


def load(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


state = load("forced_fixture_leaf_rotation_state_test", STATE_SCRIPT)
evidence = load("forced_fixture_leaf_rotation_evidence_test", EVIDENCE_SCRIPT)


def certificate(character: str, serial: str) -> dict[str, str]:
    return {
        "pemSha256": character * 64,
        "serial": serial,
        "sha256Fingerprint": character * 64,
    }


def snapshots() -> tuple[dict[str, object], dict[str, object]]:
    ca = certificate("a", "AA")
    before = {
        "ca": ca,
        "generation": "/etc/vivolution/voice-fixture/pki-generations/generation-" + "1" * 32,
        "leaves": {
            "asterisk": certificate("b", "B1"),
            "sipp": certificate("c", "C1"),
            "sbc1": certificate("d", "D1"),
            "sbc2": certificate("e", "E1"),
        },
        "rotationRequest": None,
    }
    after = {
        "ca": dict(ca),
        "generation": "/etc/vivolution/voice-fixture/pki-generations/generation-" + "2" * 32,
        "leaves": {
            "asterisk": certificate("f", "F1"),
            "sipp": certificate("1", "11"),
            "sbc1": certificate("2", "21"),
            "sbc2": certificate("3", "31"),
        },
        "rotationRequest": {
            "acknowledgement": state.ACKNOWLEDGEMENT,
            "apiVersion": state.GENERATION_REQUEST_API_VERSION,
            "requestId": REQUEST_ID,
            "scope": state.SCOPE,
        },
    }
    return before, after


class ForcedFixtureLeafRotationStateTests(unittest.TestCase):
    def test_transition_requires_new_generation_all_changed_leaves_and_same_ca(self) -> None:
        before, after = snapshots()
        state.validate_transition(before, after)

        unchanged_leaf = json.loads(json.dumps(after))
        unchanged_leaf["leaves"]["sbc2"] = before["leaves"]["sbc2"]
        with self.assertRaisesRegex(
            state.ForcedFixtureRotationStateError, "did not change sbc2"
        ):
            state.validate_transition(before, unchanged_leaf)

        changed_ca = json.loads(json.dumps(after))
        changed_ca["ca"] = certificate("9", "91")
        with self.assertRaisesRegex(
            state.ForcedFixtureRotationStateError, "changed the fixture CA"
        ):
            state.validate_transition(before, changed_ca)

    def test_selected_state_is_exact_and_canonical(self) -> None:
        before, after = snapshots()
        record = {
            "acknowledgement": state.ACKNOWLEDGEMENT,
            "after": after,
            "apiVersion": state.API_VERSION,
            "before": before,
            "phase": "SELECTED",
            "requestId": REQUEST_ID,
            "scope": state.SCOPE,
            "selectedAtEpochMs": 1_788_138_123_000,
        }
        self.assertEqual(
            state.validate_state(record, record["requestId"]), record
        )
        raw = state.canonical_bytes(record)
        self.assertTrue(raw.endswith(b"\n"))
        self.assertEqual(json.loads(raw), record)

    def test_unrelated_transition_after_prepare_cannot_satisfy_request(self) -> None:
        before, after = snapshots()
        unrelated = json.loads(json.dumps(after))
        unrelated["rotationRequest"] = {
            "acknowledgement": None,
            "apiVersion": state.GENERATION_REQUEST_API_VERSION,
            "requestId": None,
            "scope": state.OPERATIONAL_SCOPE,
        }
        prepared = state._prepared_state(REQUEST_ID, before)
        with self.assertRaisesRegex(
            state.ForcedFixtureRotationStateError,
            "not bound to this forced-rotation request",
        ):
            state._selected_state(prepared, unrelated)

        different_request = json.loads(json.dumps(after))
        different_request["rotationRequest"]["requestId"] = (
            "20260831T010204Z-abcdef123456"
        )
        with self.assertRaisesRegex(
            state.ForcedFixtureRotationStateError,
            "not bound to this forced-rotation request",
        ):
            state._selected_state(prepared, different_request)


class ForcedFixtureLeafRotationEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        os.chmod(self.directory, 0o700)
        before, after = snapshots()
        self.state = {
            "acknowledgement": state.ACKNOWLEDGEMENT,
            "after": after,
            "apiVersion": state.API_VERSION,
            "before": before,
            "phase": "SELECTED",
            "requestId": REQUEST_ID,
            "scope": state.SCOPE,
            "selectedAtEpochMs": 1_788_138_123_000,
        }
        self.write("state.json", evidence.canonical_bytes(self.state))
        self.write(
            "active-server-leaves.json",
            evidence.canonical_bytes(
                {
                    "asterisk": self.state["after"]["leaves"]["asterisk"]["sha256Fingerprint"],
                    "sipp": self.state["after"]["leaves"]["sipp"]["sha256Fingerprint"],
                }
            ),
        )
        self.credential_digests = {
            "fixtureCaCrt": "sha256:" + self.state["after"]["ca"]["pemSha256"],
            "sbc1": {
                "fixtureClientCrt": "sha256:" + self.state["after"]["leaves"]["sbc1"]["pemSha256"],
                "fixtureClientKey": "sha256:" + "6" * 64,
            },
            "sbc2": {
                "fixtureClientCrt": "sha256:" + self.state["after"]["leaves"]["sbc2"]["pemSha256"],
                "fixtureClientKey": "sha256:" + "7" * 64,
            },
        }
        self.write(
            "credential-digests.json",
            evidence.canonical_bytes(self.credential_digests),
        )
        self.write_fleet_phases()
        for node, target, character in (
            ("sbc1", "10.20.2.4", "4"),
            ("sbc2", "10.20.2.5", "5"),
        ):
            self.write_edge(node, character)
            self.write_bundle(node, target)
            self.write_cdr_sources(node)

    def write(self, name: str, content: bytes) -> None:
        path = self.directory / name
        path.write_bytes(content)
        os.chmod(path, 0o600)

    def facts(self, node: str) -> dict[str, object]:
        slot, private, public = (
            ("A", "10.20.2.4", "198.51.100.14")
            if node == "sbc1"
            else ("B", "10.20.2.5", "198.51.100.15")
        )
        return {
            "allocationId": "alloc-vivolution-1",
            "authorizedPbxSourceIpv4Cidrs": ["10.20.1.4/32"],
            "clusterId": "cluster-vivolution-poc",
            "clusterMediaPortEnd": 29999,
            "clusterMediaPortStart": 20000,
            "customerAccountId": "customer-vivolution-1",
            "generation": 1,
            "m365TenantId": "11111111-1111-4111-8111-111111111111",
            "nodeFqdn": f"{node}.voice.vivolution.ae",
            "nodeId": node,
            "pbxMediaDestinationPortEnd": 21127,
            "pbxMediaDestinationPortStart": 21000,
            "privateIpv4": private,
            "publicIpv4": public,
            "rtpengineNgHost": "127.0.0.1",
            "rtpengineNgPort": 2223,
            "serviceInstanceId": "service-vivolution-1",
            "slot": slot,
            "syntheticTeamsSourceIpv4Cidrs": [],
            "teamsMediaSourceIpv4Cidrs": [],
            "teamsSignalingSourceIpv4Cidrs": [],
            "teamsTlsPort": 5061,
            "tenantContextId": "tenant-vivolution-1",
            "tenantListenerPort": 15061,
            "tenantMediaPortEnd": 20255,
            "tenantMediaPortStart": 20000,
        }

    def authority(self, node: str, *, renewed: bool) -> dict[str, object]:
        facts = self.facts(node)
        secrets = {
            "edgeCertificateChainPem": "sha256:" + "8" * 64,
            "edgePrivateKeyPem": "sha256:" + "9" * 64,
            "fixtureCaCrt": self.credential_digests["fixtureCaCrt"],
            "fixtureClientCrt": (
                self.credential_digests[node]["fixtureClientCrt"]
                if renewed
                else "sha256:" + ("d" if node == "sbc1" else "e") * 64
            ),
            "fixtureClientKey": (
                self.credential_digests[node]["fixtureClientKey"]
                if renewed
                else "sha256:" + ("a" if node == "sbc1" else "b") * 64
            ),
            "microsoftCaBundlePem": "sha256:" + "c" * 64,
            "pbxCaBundlePem": "sha256:" + "d" * 64,
            "publicCaBundlePem": "sha256:" + "e" * 64,
        }
        return {
            "administratorSourceIpv4Cidrs": ["203.0.113.10/32"],
            "apiVersion": "edge.vivolution.ae/runtime-authority/v0.1",
            "azureDhcpServerIpv4": "168.63.129.16",
            "generation": facts["generation"],
            "nodeId": node,
            "profile": "SYNTHETIC_PRIVATE",
            "secretDigests": secrets,
            "slot": facts["slot"],
        }

    def runtime_snapshot(self, node: str) -> dict[str, object]:
        slot = "A" if node == "sbc1" else "B"
        manifest = "sha256:" + ("1" if node == "sbc1" else "2") * 64
        release = "sha256:" + ("3" if node == "sbc1" else "4") * 64
        active = {
            "kind": "CANDIDATE",
            "manifestDigest": manifest,
            "relativePath": f"slots/{slot}/0000000000000001-{manifest.split(':')[1]}",
            "releaseDigest": release,
            "sequence": 1,
            "slot": slot,
        }
        status = {
            "active": active,
            "apiVersion": "edge.vivolution.ae/runtime/v0.1",
            "highestSeenSequence": 1,
            "journalPresent": False,
            "kind": "EdgeRuntimeStatus",
            "lastEvidenceDigest": "sha256:" + "5" * 64,
            "previous": None,
        }
        checks = [
            {"name": name, "status": "PASSED"}
            for name in evidence.active_edge_contract.REQUIRED_RUNTIME_CHECKS
        ]
        return {
            "agentState": {
                "group": "vivolution-edge-agent",
                "mode": "0600",
                "nlink": 1,
                "owner": "vivolution-edge-agent",
                "sha256": "sha256:" + ("6" if node == "sbc1" else "7") * 64,
            },
            "agentStatus": {
                "activeLastKnownGood": {"manifestDigest": manifest, "sequence": 1},
                "apiVersion": "edge.vivolution.ae/agent-state/v0.1",
                "highestSeenSequence": 1,
                "kind": "EdgeAgentProtectedStateStatus",
                "lastAbortedCandidate": None,
                "pendingCandidate": None,
            },
            "bootId": (
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
                if node == "sbc1"
                else "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
            ),
            "health": {
                "active": active,
                "apiVersion": "edge.vivolution.ae/runtime/v0.1",
                "highestSeenSequence": 1,
                "kind": "EdgeRuntimeHealth",
                "runtimeChecks": checks,
            },
            "recoveryUnitEnabled": "enabled",
            "status": status,
            "transactionJournalPresent": False,
            "unitStates": {
                name: "active"
                for name in evidence.active_edge_contract.REQUIRED_ACTIVE_UNITS
            },
        }

    def edge_snapshot(self, node: str, *, renewed: bool, captured: int) -> dict[str, object]:
        facts_raw = evidence.canonical_bytes(self.facts(node))
        authority_raw = evidence.canonical_bytes(self.authority(node, renewed=renewed))
        return {
            "apiVersion": evidence.EDGE_SNAPSHOT_API_VERSION,
            "capturedAtEpochMs": captured,
            "fixtureRotationJournalPresent": False,
            "identitySources": {
                "nodeFactsBase64": base64.b64encode(facts_raw).decode(),
                "nodeFactsMetadata": {"group": "root", "mode": "0600", "nlink": 1, "owner": "root"},
                "nodeFactsSha256": evidence.sha256_digest(facts_raw),
                "runtimeAuthorityBase64": base64.b64encode(authority_raw).decode(),
                "runtimeAuthorityMetadata": {"group": "root", "mode": "0600", "nlink": 1, "owner": "root"},
                "runtimeAuthoritySha256": evidence.sha256_digest(authority_raw),
            },
            "nodeId": node,
            "snapshot": self.runtime_snapshot(node),
        }

    def write_fleet_phases(self) -> None:
        renewed = {
            "fleet-pre": {"sbc1": False, "sbc2": False},
            "sbc1-pre": {"sbc1": False, "sbc2": False},
            "sbc1-post": {"sbc1": True, "sbc2": False},
            "sbc2-pre": {"sbc1": True, "sbc2": False},
            "sbc2-post": {"sbc1": True, "sbc2": True},
            "post-calls": {"sbc1": True, "sbc2": True},
        }
        for index, phase in enumerate(evidence.PHASES):
            record = {
                "apiVersion": evidence.PHASE_API_VERSION,
                "phase": phase,
                "snapshots": {
                    node: self.edge_snapshot(
                        node, renewed=renewed[phase][node], captured=1_788_138_123_000 + index
                    )
                    for node in ("sbc1", "sbc2")
                },
            }
            self.write(f"{phase}.json", evidence.canonical_bytes(record))

    def write_edge(self, node: str, character: str) -> None:
        authority_raw = evidence.canonical_bytes(self.authority(node, renewed=True))
        record = {
            "apiVersion": "edge.vivolution.ae/fixture-pki-rotation/v0.1",
            "authorityDigest": evidence.sha256_digest(authority_raw),
            "fixtureCaDigest": "sha256:" + self.state["after"]["ca"]["pemSha256"],
            "fixtureClientCertificateDigest": (
                "sha256:" + self.state["after"]["leaves"][node]["pemSha256"]
            ),
            "kind": "SyntheticFixturePkiRotationEvidence",
            "nodeId": node,
            "opensipsRestarted": True,
            "status": "FIXTURE_PKI_ROTATED",
            "timestamp": "2026-08-31T01:02:04Z",
        }
        record["evidenceDigest"] = evidence.sha256_digest(
            evidence.canonical_bytes(record).rstrip(b"\n")
        )
        self.write(f"{node}-edge.json", evidence.canonical_bytes(record))

    def write_bundle(
        self, node: str, target: str, *, test_id: str | None = None
    ) -> None:
        test_id = test_id or f"20260831T010204Z-{node}-1"
        raw_cdr = self.raw_cdr(test_id, node)
        cdr_contract = evidence.fixture_contract._load_cdr_contract()
        fixture_cdr = cdr_contract.canonical_bytes(
            cdr_contract.compile_fixture_cdr(raw_cdr, test_id, node)
        )
        artifacts = {
            "RESULT": b"PASS\n",
            "asterisk-cdr-delta.csv": raw_cdr,
            "fixture-cdr.json": fixture_cdr,
            "readiness.txt": b"READY\n",
            "summary.txt": (
                f"node={node}\n"
                f"target={target}\n"
                f"test_id={test_id}\n"
                "cdr_records=2\n"
                "rtp_uas_delta=12\n"
                "rtp_selected_peer_delta=11\n"
                "rtp_echo_delta=10\n"
            ).encode(),
            "teams-to-pbx-rtp.json": b"{}\n",
            "teams-to-pbx-summary.json": b"{}\n",
        }
        manifest = "".join(
            f"{hashlib.sha256(content).hexdigest()}  ./{name}\n"
            for name, content in sorted(artifacts.items())
        ).encode()
        bundle = {
            "apiVersion": evidence.fixture_contract.BUNDLE_API_VERSION,
            "artifacts": {
                name: base64.b64encode(content).decode()
                for name, content in artifacts.items()
            },
            "manifestBase64": base64.b64encode(manifest).decode(),
            "testId": test_id,
        }
        self.write(f"{node}-bundle.json", evidence.canonical_bytes(bundle))

    def raw_cdr(self, test_id: str, node: str) -> bytes:
        started = datetime.strptime(test_id.split("-")[0], "%Y%m%dT%H%M%SZ")
        origin_extension = "9201" if node == "sbc1" else "9202"

        def stamp(offset: int) -> str:
            return (started + timedelta(seconds=offset)).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        rows = [
            [
                stamp(1), stamp(1), stamp(5), "4", "4", "ANSWERED",
                "+9710000001001", "+9710000001001",
                "PJSIP/edge-inbound-00000001", "", "1.1", "1.1",
                "vivo-synth-t2p", test_id,
            ],
            [
                stamp(6), stamp(6), stamp(10), "4", "4", "ANSWERED", "",
                origin_extension, f"Local/{origin_extension}@fixture-origin-00000002;2",
                f"PJSIP/{node}-00000003", "1.2", "1.2", "vivo-synth-p2t", test_id,
            ],
        ]
        stream = io.StringIO(newline="")
        csv.writer(stream, quoting=csv.QUOTE_ALL, lineterminator="\n").writerows(rows)
        return stream.getvalue().encode()

    def write_cdr_sources(self, node: str) -> None:
        bundle_raw = (self.directory / f"{node}-bundle.json").read_bytes()
        artifacts, manifest, test_id = evidence.fixture_contract._parse_bundle(
            bundle_raw, node
        )
        slot = "A" if node == "sbc1" else "B"
        facts_raw = evidence.canonical_bytes(self.facts(node))
        authority_raw = evidence.canonical_bytes(self.authority(node, renewed=True))
        node_identity = {
            "allocationId": "alloc-vivolution-1",
            "clusterId": "cluster-vivolution-poc",
            "generation": 1,
            "nodeFactsDigest": evidence.sha256_digest(facts_raw),
            "nodeId": node,
            "routeToken": "ABCDEF123456",
            "runtimeAuthorityDigest": evidence.sha256_digest(authority_raw),
            "serviceInstanceId": "service-vivolution-1",
            "slot": slot,
            "tenantContextId": "tenant-vivolution-1",
        }
        calls = []
        for index, direction in enumerate(
            ("TEAMS_FIXTURE_TO_PBX_FIXTURE", "PBX_FIXTURE_TO_TEAMS_FIXTURE")
        ):
            start = 1_788_138_124_000_000 + index * 1_000_000
            calls.append(
                {
                    "direction": direction,
                    "elapsedMilliseconds": 250,
                    "finalJournalRecordDigest": "sha256:" + str(index + 3) * 64,
                    "finalRealtimeUnixMicroseconds": start + 250_000,
                    "journalBootIdDigest": "sha256:" + str(index + 5) * 64,
                    "result": "ACCEPTED",
                    "startJournalRecordDigest": "sha256:" + str(index + 7) * 64,
                    "startRealtimeUnixMicroseconds": start,
                }
            )
        edge_cdr = {
            "apiVersion": "edge.vivolution.ae/synthetic-edge-cdr/v0.1",
            "calls": calls,
            "kind": "SyntheticEdgeCdrEvidence",
            "liveM365Interoperability": "NOT_ASSERTED",
            "nodeIdentity": node_identity,
            "scope": "SYNTHETIC_PRIVATE_NO_PSTN",
            "sourceJournal": {
                "marker": "VIVO_SYNTHETIC_CDR_V1",
                "opensipsUid": 101,
                "recordCount": 4,
                "systemdUnit": "opensips.service",
            },
            "status": "TWO_LOGICAL_SYNTHETIC_CALLS_ACCOUNTED",
            "testId": test_id,
        }
        cdr_contract = evidence.fixture_contract._load_cdr_contract()
        edge_cdr["edgeCdrDigest"] = cdr_contract.sha256_digest(
            cdr_contract.canonical_bytes(edge_cdr)
        )
        edge_raw = cdr_contract.canonical_bytes(edge_cdr)
        self.write(f"{node}-edge-cdr.json", edge_raw)

        fixture_cdr = json.loads(artifacts["fixture-cdr.json"])
        reconciliation = {
            "apiVersion": "edge.vivolution.ae/synthetic-cdr-reconciliation/v0.1",
            "calledNumber": "+9710000001001",
            "kind": "SyntheticEdgeFixtureCdrReconciliation",
            "liveM365Interoperability": "NOT_ASSERTED",
            "matchedCalls": [
                {
                    "direction": direction,
                    "edgeElapsedMilliseconds": edge_cdr["calls"][index]["elapsedMilliseconds"],
                    "edgeResult": "ACCEPTED",
                    "fixtureBillableSeconds": fixture_cdr["records"][index]["billableSeconds"],
                    "fixtureDisposition": "ANSWERED",
                    "fixtureRecordDigest": fixture_cdr["records"][index]["recordDigest"],
                }
                for index, direction in enumerate(
                    ("TEAMS_FIXTURE_TO_PBX_FIXTURE", "PBX_FIXTURE_TO_TEAMS_FIXTURE")
                )
            ],
            "nodeIdentity": node_identity,
            "scope": "SYNTHETIC_PRIVATE_NO_PSTN",
            "sourceDigests": {
                "edgeCdr": evidence.sha256_digest(edge_raw),
                "fixtureCdr": evidence.sha256_digest(artifacts["fixture-cdr.json"]),
                "fixtureManifest": evidence.sha256_digest(manifest),
            },
            "status": "SYNTHETIC_EDGE_FIXTURE_CDR_RECONCILED",
            "testId": test_id,
        }
        reconciliation["reconciliationDigest"] = evidence.sha256_digest(
            evidence.canonical_bytes(reconciliation)
        )
        self.write(
            f"{node}-cdr-reconciliation.json",
            evidence.canonical_bytes(reconciliation),
        )

    def test_compiler_accepts_exact_forced_rotation_and_fresh_calls(self) -> None:
        record = evidence.compile_evidence(self.directory)
        self.assertEqual(
            record["status"], "SYNTHETIC_FIXTURE_LEAF_ROTATION_ACCEPTED"
        )
        self.assertTrue(record["fixtureCaUnchanged"])
        self.assertEqual(record["leafCertificatesChanged"], list(state.LEAF_NAMES))
        self.assertEqual(record["liveM365Interoperability"], "NOT_ASSERTED")
        self.assertEqual(record["pstnInteroperability"], "NOT_TESTED_NOT_CLAIMED")

    def test_compiler_rejects_edge_not_bound_to_selected_client_leaf(self) -> None:
        path = self.directory / "sbc1-edge.json"
        record = json.loads(path.read_text())
        record["fixtureClientCertificateDigest"] = "sha256:" + "9" * 64
        unsigned = dict(record)
        unsigned.pop("evidenceDigest")
        record["evidenceDigest"] = evidence.sha256_digest(
            evidence.canonical_bytes(unsigned).rstrip(b"\n")
        )
        self.write("sbc1-edge.json", evidence.canonical_bytes(record))
        with self.assertRaisesRegex(
            evidence.ForcedFixtureRotationEvidenceError, "did not re-pin"
        ):
            evidence.compile_evidence(self.directory)

    def test_compiler_rejects_unselected_actively_served_leaf(self) -> None:
        self.write(
            "active-server-leaves.json",
            evidence.canonical_bytes({"asterisk": "9" * 64, "sipp": "1" * 64}),
        )
        with self.assertRaisesRegex(
            evidence.ForcedFixtureRotationEvidenceError, "actively served|active fixture"
        ):
            evidence.compile_evidence(self.directory)

    def test_compiler_rejects_call_from_before_selection(self) -> None:
        old_id = "20260831T010201Z-sbc2-1"
        self.write_bundle("sbc2", "10.20.2.5", test_id=old_id)
        with self.assertRaisesRegex(
            evidence.ForcedFixtureRotationEvidenceError, "predates"
        ):
            evidence.compile_evidence(self.directory)

    def test_compiler_rejects_peer_runtime_drift_during_serial_repin(self) -> None:
        path = self.directory / "sbc1-post.json"
        record = json.loads(path.read_text())
        record["snapshots"]["sbc2"]["snapshot"]["status"][
            "lastEvidenceDigest"
        ] = "sha256:" + "f" * 64
        self.write(path.name, evidence.canonical_bytes(record))
        with self.assertRaisesRegex(
            evidence.ForcedFixtureRotationEvidenceError,
            "runtime, Agent, boot, unit, or health state changed",
        ):
            evidence.compile_evidence(self.directory)

    def test_compiler_rejects_authority_change_outside_serial_target(self) -> None:
        path = self.directory / "sbc1-post.json"
        record = json.loads(path.read_text())
        peer = record["snapshots"]["sbc2"]
        authority_raw = evidence.canonical_bytes(self.authority("sbc2", renewed=True))
        peer["identitySources"]["runtimeAuthorityBase64"] = base64.b64encode(
            authority_raw
        ).decode()
        peer["identitySources"]["runtimeAuthoritySha256"] = evidence.sha256_digest(
            authority_raw
        )
        self.write(path.name, evidence.canonical_bytes(record))
        with self.assertRaisesRegex(
            evidence.ForcedFixtureRotationEvidenceError,
            "authority changed outside",
        ):
            evidence.compile_evidence(self.directory)

    def test_compiler_rejects_selected_client_key_not_pinned(self) -> None:
        record = json.loads((self.directory / "credential-digests.json").read_text())
        record["sbc2"]["fixtureClientKey"] = "sha256:" + "f" * 64
        self.write("credential-digests.json", evidence.canonical_bytes(record))
        with self.assertRaisesRegex(
            evidence.ForcedFixtureRotationEvidenceError,
            "selected credential set",
        ):
            evidence.compile_evidence(self.directory)

    def test_compiler_rejects_reconciliation_not_bound_to_raw_edge_cdr(self) -> None:
        path = self.directory / "sbc1-cdr-reconciliation.json"
        record = json.loads(path.read_text())
        record["matchedCalls"][0]["edgeElapsedMilliseconds"] += 1
        unsigned = dict(record)
        unsigned.pop("reconciliationDigest")
        record["reconciliationDigest"] = evidence.sha256_digest(
            evidence.canonical_bytes(unsigned)
        )
        self.write(path.name, evidence.canonical_bytes(record))
        with self.assertRaisesRegex(
            evidence.ForcedFixtureRotationEvidenceError,
            "reconciliation is invalid",
        ):
            evidence.compile_evidence(self.directory)

    def test_acceptance_write_is_exact_request_idempotent(self) -> None:
        record = evidence.compile_evidence(self.directory)
        path = self.directory / "acceptance.json"
        raw = evidence.canonical_bytes(record)
        evidence._atomic_write(path, raw)
        before = path.stat()
        evidence._atomic_write(path, raw)
        after = path.stat()
        self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))
        with self.assertRaisesRegex(
            evidence.ForcedFixtureRotationEvidenceError,
            "existing acceptance evidence differs",
        ):
            evidence._atomic_write(path, raw.replace(b"NOT_ASSERTED", b"NOT-ASSERTED", 1))


class ForcedFixtureLeafRotationStaticTests(unittest.TestCase):
    def test_playbook_is_explicit_serial_resumable_and_synthetic_only(self) -> None:
        playbook = PLAYBOOK.read_text(encoding="utf-8")
        helper = STATE_SCRIPT.read_text(encoding="utf-8")
        self.assertIn(state.ACKNOWLEDGEMENT, playbook)
        self.assertIn("fixture_rotation_request_id", playbook)
        self.assertIn("voice_fixture_force_leaf_rotation_request_id", playbook)
        self.assertIn("voice_fixture_force_leaf_rotation_expected_generation", playbook)
        self.assertRegex(
            playbook,
            r"(?s)Force and journal one exact CP1 synthetic fixture leaf generation.*?gather_facts: true",
        )
        self.assertIn("serial: 1", playbook)
        self.assertIn("forced_fixture_leaf_rotation_state.py", playbook)
        self.assertIn("edge_fixture_rotation", playbook)
        self.assertIn("vivolution-voice-fixture-test", playbook)
        self.assertIn("--collect-result-dir", playbook)
        self.assertIn("vivolution-edge-synthetic-cdr-export", playbook)
        self.assertIn("synthetic_cdr_evidence.py", playbook)
        self.assertIn("forced_fixture_leaf_rotation_edge_snapshot.py", playbook)
        self.assertIn("credential-digests.json", playbook)
        self.assertIn("force: false", playbook)
        self.assertIn("fixture_rotation_request_already_accepted", playbook)
        self.assertLess(
            playbook.index("Revalidate an existing exact-request acceptance before any mutation"),
            playbook.index("Prepare or reconcile the durable forced-rotation request"),
        )
        for phase in ("fleet-pre", "post-calls"):
            self.assertIn(phase, playbook)
        self.assertIn("inventory_hostname ~ '-pre'", playbook)
        self.assertIn("inventory_hostname ~ '-post'", playbook)
        self.assertIn("NOT_TESTED_NOT_CLAIMED", playbook)
        self.assertIn("NOT_ASSERTED", playbook)
        self.assertNotIn("connection: local", playbook)
        self.assertIn("fcntl.flock", helper)
        self.assertIn('getattr(os, "O_NOFOLLOW", 0)', helper)
        self.assertIn("os.replace", helper)
        self.assertIn("another forced rotation request is pending", helper)
        self.assertIn("generation-request.json", helper)
        self.assertIn("selected generation is not bound", helper)
        self.assertNotIn("rmtree", helper)

    def test_edge_snapshot_collector_binds_protected_active_state(self) -> None:
        collector = (
            ROOT
            / "deploy"
            / "scripts"
            / "forced_fixture_leaf_rotation_edge_snapshot.py"
        ).read_text(encoding="utf-8")
        for value in (
            "/etc/vivolution-edge/node-facts.json",
            "/var/lib/vivolution-edge/runtime/runtime-authority.json",
            "edge-state-v3.json",
            "vivolution-edge-runtime",
            "vivolution-edge-agent",
            "transaction.json",
            "fixtureRotationJournalPresent",
            "O_NOFOLLOW",
        ):
            self.assertIn(value, collector)

    def test_fixture_role_force_is_leaf_only_and_acknowledged(self) -> None:
        defaults = ROLE_DEFAULTS.read_text(encoding="utf-8")
        tasks = ROLE_TASKS.read_text(encoding="utf-8")
        self.assertIn("voice_fixture_force_leaf_rotation: false", defaults)
        self.assertIn("voice_fixture_force_leaf_rotation_acknowledgement", defaults)
        self.assertIn("voice_fixture_force_leaf_rotation_request_id", defaults)
        self.assertIn("voice_fixture_force_leaf_rotation_expected_generation", defaults)
        self.assertIn(state.ACKNOWLEDGEMENT, tasks)
        self.assertIn("not (voice_fixture_ca_rotation_required | bool)", tasks)
        self.assertIn("(voice_fixture_force_leaf_rotation | bool) or", tasks)
        self.assertIn("Bind this generation to its exact rotation authority", tasks)
        self.assertIn("generation-request.json", tasks)


if __name__ == "__main__":
    unittest.main()
