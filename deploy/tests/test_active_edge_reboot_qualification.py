from __future__ import annotations

import base64
import copy
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "scripts" / "active_edge_reboot_evidence.py"
PLAYBOOK = ROOT / "deploy" / "playbooks" / "qualify-active-edge-reboots.yml"

SPEC = importlib.util.spec_from_file_location("active_edge_reboot_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)


class ActiveEdgeRebootEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name) / "20260831T000000Z-012345abcdef"
        self.directory.mkdir(mode=0o700)
        self.observations = {
            "sbc1": self.observation(
                "sbc1",
                "sbc2",
                "04aa0fe1-dfef-4c95-a111-111111111111",
                "04aa0fe1-dfef-4c95-a222-222222222222",
                "04aa0fe1-dfef-4c95-a333-333333333333",
                "20260831T000040Z-sbc1-1",
                10_000_000_000,
            ),
            "sbc2": self.observation(
                "sbc2",
                "sbc1",
                "04aa0fe1-dfef-4c95-a333-333333333333",
                "04aa0fe1-dfef-4c95-a555-555555555555",
                "04aa0fe1-dfef-4c95-a222-222222222222",
                "20260831T000140Z-sbc2-2",
                70_000_000_000,
            ),
        }
        for node in evidence.REBOOT_ORDER:
            self.write_json(f"{node}-observation.json", self.observations[node])
            test_id = self.observations[node]["fixture"]["testId"]
            bundle, edge_cdr, reconciliation = self.fixture_evidence(
                node, test_id
            )
            self.write_json(f"{node}-fixture-bundle.json", bundle)
            self.write_bytes(f"{node}-edge-cdr.json", edge_cdr)
            self.write_bytes(f"{node}-cdr-reconciliation.json", reconciliation)
            bundle = (self.directory / f"{node}-fixture-bundle.json").read_bytes()
            self.observations[node]["fixture"]["bundleSha256"] = evidence.sha256_digest(
                bundle
            )
            self.observations[node]["fixture"]["edgeCdrSha256"] = evidence.sha256_digest(
                edge_cdr
            )
            self.observations[node]["fixture"][
                "cdrReconciliationSha256"
            ] = evidence.sha256_digest(reconciliation)
            self.write_json(f"{node}-observation.json", self.observations[node])
        self.write_request()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_json(self, name: str, value: object) -> None:
        path = self.directory / name
        path.write_bytes(evidence.canonical_bytes(value))
        os.chmod(path, 0o600)

    def write_bytes(self, name: str, value: bytes) -> None:
        path = self.directory / name
        path.write_bytes(value)
        os.chmod(path, 0o600)

    def write_request(self) -> None:
        references = []
        for node in evidence.REBOOT_ORDER:
            name = f"{node}-observation.json"
            references.append(
                {
                    "fileName": name,
                    "nodeId": node,
                    "sha256": evidence.sha256_digest((self.directory / name).read_bytes()),
                }
            )
        self.write_json(
            "request.json",
            {
                "acknowledgement": evidence.ACKNOWLEDGEMENT,
                "apiVersion": evidence.REQUEST_API_VERSION,
                "liveM365Interoperability": evidence.LIVE_M365_STATUS,
                "observations": references,
                "rebootOrder": list(evidence.REBOOT_ORDER),
                "scope": evidence.SCOPE,
            },
        )

    @staticmethod
    def facts(node: str) -> dict[str, object]:
        slot, private, public = {
            "sbc1": ("A", "10.20.2.4", "20.46.45.96"),
            "sbc2": ("B", "10.20.2.5", "20.216.14.173"),
        }[node]
        return {
            "allocationId": "allocation-vivolution-poc",
            "authorizedPbxSourceIpv4Cidrs": ["10.20.1.4/32"],
            "clusterId": "cluster-vivolution-poc",
            "clusterMediaPortEnd": 29999,
            "clusterMediaPortStart": 20000,
            "customerAccountId": "customer-vivolution",
            "generation": 2,
            "m365TenantId": "123e4567-e89b-42d3-a456-426614174000",
            "nodeFqdn": f"{node}.voice.vivolution.ae",
            "nodeId": node,
            "privateIpv4": private,
            "publicIpv4": public,
            "pbxMediaDestinationPortEnd": 21127,
            "pbxMediaDestinationPortStart": 21000,
            "rtpengineNgHost": "127.0.0.1",
            "rtpengineNgPort": 2223,
            "serviceInstanceId": "service-vivolution-poc",
            "slot": slot,
            "syntheticTeamsSourceIpv4Cidrs": [],
            "teamsMediaSourceIpv4Cidrs": ["52.112.0.0/14"],
            "teamsSignalingSourceIpv4Cidrs": ["52.112.0.0/14"],
            "teamsTlsPort": 5061,
            "tenantContextId": "tenant-vivolution-poc",
            "tenantListenerPort": 15061,
            "tenantMediaPortEnd": 20255,
            "tenantMediaPortStart": 20000,
        }

    @staticmethod
    def authority(node: str) -> dict[str, object]:
        return {
            "administratorSourceIpv4Cidrs": ["203.0.113.1/32"],
            "apiVersion": "edge.vivolution.ae/runtime-authority/v0.1",
            "azureDhcpServerIpv4": "168.63.129.16",
            "generation": 2,
            "nodeId": node,
            "profile": "SYNTHETIC_PRIVATE",
            "secretDigests": {
                name: "sha256:" + format(index + 1, "064x")
                for index, name in enumerate(sorted(evidence._SYNTHETIC_SECRET_NAMES))
            },
            "slot": "A" if node == "sbc1" else "B",
        }

    @staticmethod
    def status(node: str) -> dict[str, object]:
        sequence = 2 if node == "sbc1" else 1
        active = {
            "kind": "CANDIDATE",
            "manifestDigest": "sha256:" + ("a" if node == "sbc1" else "b") * 64,
            "relativePath": "slots/A/{:016d}-{}".format(
                sequence, ("a" if node == "sbc1" else "b") * 64
            ),
            "releaseDigest": "sha256:" + ("c" if node == "sbc1" else "d") * 64,
            "sequence": sequence,
            "slot": "A",
        }
        return {
            "active": active,
            "apiVersion": "edge.vivolution.ae/runtime/v0.1",
            "highestSeenSequence": sequence,
            "journalPresent": False,
            "kind": "EdgeRuntimeStatus",
            "lastEvidenceDigest": "sha256:" + ("e" if node == "sbc1" else "f") * 64,
            "previous": None,
        }

    @classmethod
    def health(cls, node: str) -> dict[str, object]:
        status = cls.status(node)
        return {
            "active": status["active"],
            "apiVersion": "edge.vivolution.ae/runtime/v0.1",
            "highestSeenSequence": status["highestSeenSequence"],
            "kind": "EdgeRuntimeHealth",
            "runtimeChecks": [
                {"name": name, "status": "PASSED"}
                for name in evidence.REQUIRED_RUNTIME_CHECKS
            ],
        }

    @classmethod
    def agent_status(cls, node: str) -> dict[str, object]:
        runtime = cls.status(node)
        return {
            "activeLastKnownGood": {
                "manifestDigest": runtime["active"]["manifestDigest"],
                "sequence": runtime["active"]["sequence"],
            },
            "apiVersion": "edge.vivolution.ae/agent-state/v0.1",
            "highestSeenSequence": runtime["highestSeenSequence"],
            "kind": "EdgeAgentProtectedStateStatus",
            "lastAbortedCandidate": None,
            "pendingCandidate": None,
        }

    @classmethod
    def snapshot(cls, node: str, boot_id: str) -> dict[str, object]:
        return {
            "agentState": {
                "group": "vivolution-edge-agent",
                "mode": "0600",
                "nlink": 1,
                "owner": "vivolution-edge-agent",
                "sha256": "sha256:" + ("7" if node == "sbc1" else "8") * 64,
            },
            "agentStatus": cls.agent_status(node),
            "bootId": boot_id,
            "health": cls.health(node),
            "recoveryUnitEnabled": "enabled",
            "status": cls.status(node),
            "transactionJournalPresent": False,
            "unitStates": {name: "active" for name in evidence.REQUIRED_ACTIVE_UNITS},
        }

    @classmethod
    def identity_sources(cls, node: str) -> dict[str, object]:
        facts_raw = evidence.canonical_bytes(cls.facts(node))
        authority_raw = evidence.canonical_bytes(cls.authority(node))
        facts_digest = evidence.sha256_digest(facts_raw)
        authority_digest = evidence.sha256_digest(authority_raw)
        return {
            "nodeFactsAfterSha256": facts_digest,
            "nodeFactsBase64": base64.b64encode(facts_raw).decode("ascii"),
            "nodeFactsMetadata": {
                "group": "root",
                "mode": "0600",
                "nlink": 1,
                "owner": "root",
            },
            "nodeFactsSha256": facts_digest,
            "runtimeAuthorityAfterSha256": authority_digest,
            "runtimeAuthorityBase64": base64.b64encode(authority_raw).decode("ascii"),
            "runtimeAuthorityMetadata": {
                "group": "root",
                "mode": "0600",
                "nlink": 1,
                "owner": "root",
            },
            "runtimeAuthoritySha256": authority_digest,
        }

    @classmethod
    def observation(
        cls,
        node: str,
        peer: str,
        boot_before: str,
        boot_after: str,
        peer_boot: str,
        test_id: str,
        start: int,
    ) -> dict[str, object]:
        pre = cls.snapshot(node, boot_before)
        post = cls.snapshot(node, boot_after)
        peer_snapshot = cls.snapshot(peer, peer_boot)
        call_epoch_ms = int(
            datetime.strptime(test_id.split("-", 1)[0], "%Y%m%dT%H%M%SZ")
            .replace(tzinfo=timezone.utc)
            .timestamp()
            * 1000
        )
        return {
            "apiVersion": evidence.OBSERVATION_API_VERSION,
            "completedAtEpochMs": call_epoch_ms + 20_000,
            "completedAtMonotonicNs": start + 50_000_000_000,
            "fixture": {
                "bundleFile": f"{node}-fixture-bundle.json",
                "bundleSha256": "sha256:" + "0" * 64,
                "cdrReconciliationFile": f"{node}-cdr-reconciliation.json",
                "cdrReconciliationSha256": "sha256:" + "0" * 64,
                "edgeCdrFile": f"{node}-edge-cdr.json",
                "edgeCdrSha256": "sha256:" + "0" * 64,
                "startedAtEpochMs": call_epoch_ms,
                "startedAtMonotonicNs": start + 31_000_000_000,
                "testId": test_id,
            },
            "nodeId": node,
            "peer": {
                "afterTargetCall": copy.deepcopy(peer_snapshot),
                "before": copy.deepcopy(peer_snapshot),
                "duringTargetSshLoss": copy.deepcopy(peer_snapshot),
                "identitySources": cls.identity_sources(peer),
            },
            "peerNodeId": peer,
            "reboot": {
                "rebootScheduledAtEpochMs": call_epoch_ms - 31_000,
                "rebootScheduledAtMonotonicNs": start,
                "readyObservedAtEpochMs": call_epoch_ms - 6_000,
                "readyObservedAtMonotonicNs": start + 25_000_000_000,
                "scheduledUnit": "vivolution-active-edge-reboot-qualifier",
                "sshLossObservedAtEpochMs": call_epoch_ms - 21_000,
                "sshLossObservedAtMonotonicNs": start + 10_000_000_000,
                "sshLossTimeoutSeconds": 60,
                "sshReconnectObservedAtEpochMs": call_epoch_ms - 11_000,
                "sshReconnectObservedAtMonotonicNs": start + 20_000_000_000,
                "sshReconnectTimeoutSeconds": 300,
                "totalReconnectBoundSeconds": 360,
                "totalReadyBoundSeconds": 480,
            },
            "target": {
                "postCall": copy.deepcopy(post),
                "postReboot": copy.deepcopy(post),
                "pre": copy.deepcopy(pre),
            },
            "targetIdentitySources": cls.identity_sources(node),
        }

    @classmethod
    def fixture_evidence(
        cls, node: str, test_id: str
    ) -> tuple[dict[str, object], bytes, bytes]:
        target = "10.20.2.4" if node == "sbc1" else "10.20.2.5"
        raw_cdr = cls.raw_cdr(test_id, node)
        fixture_contract = evidence._load_fixture_contract()
        cdr_contract = fixture_contract._load_cdr_contract()
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
                "rtp_echo_delta=10\n"
                "rtp_selected_peer_delta=11\n"
                "rtp_uas_delta=12\n"
            ).encode("utf-8"),
            "teams-to-pbx-rtp.json": b"{}\n",
            "teams-to-pbx-summary.json": b"{}\n",
        }
        manifest = b"".join(
            f"{hashlib.sha256(content).hexdigest()}  ./{name}\n".encode("ascii")
            for name, content in sorted(artifacts.items())
        )
        bundle = {
            "apiVersion": "edge.vivolution.ae/synthetic-fixture-result-bundle/v0.1",
            "artifacts": {
                name: base64.b64encode(content).decode("ascii")
                for name, content in artifacts.items()
            },
            "manifestBase64": base64.b64encode(manifest).decode("ascii"),
            "testId": test_id,
        }
        identity = cls.identity_sources(node)
        edge_cdr = cls.edge_cdr(
            node,
            test_id,
            identity["nodeFactsSha256"],
            identity["runtimeAuthoritySha256"],
        )
        reconciliation = cls.cdr_reconciliation(
            test_id, fixture_cdr, manifest, edge_cdr
        )
        return bundle, edge_cdr, reconciliation

    @staticmethod
    def raw_cdr(test_id: str, node: str) -> bytes:
        started = datetime.strptime(test_id.split("-", 1)[0], "%Y%m%dT%H%M%SZ")
        extension = "9201" if node == "sbc1" else "9202"

        def stamp(offset: int) -> str:
            return (started + timedelta(seconds=offset)).strftime("%Y-%m-%d %H:%M:%S")

        suffix = test_id.rsplit("-", 1)[1]
        rows = [
            [
                stamp(1), stamp(1), stamp(5), "4", "4", "ANSWERED",
                evidence._load_fixture_contract().CALLED_NUMBER,
                evidence._load_fixture_contract().CALLED_NUMBER,
                "PJSIP/edge-inbound-00000001", "", f"{suffix}.1", f"{suffix}.1",
                "vivo-synth-t2p", test_id,
            ],
            [
                stamp(6), stamp(6), stamp(10), "4", "4", "ANSWERED", "", extension,
                f"Local/{extension}@fixture-origin-00000002;2",
                f"PJSIP/{node}-00000003", f"{suffix}.2", f"{suffix}.2",
                "vivo-synth-p2t", test_id,
            ],
        ]
        stream = io.StringIO(newline="")
        csv.writer(stream, quoting=csv.QUOTE_ALL, lineterminator="\n").writerows(rows)
        return stream.getvalue().encode("utf-8")

    @classmethod
    def edge_cdr(
        cls,
        node: str,
        test_id: str,
        node_facts_digest: object,
        authority_digest: object,
    ) -> bytes:
        facts = cls.facts(node)
        calls = []
        for index, direction in enumerate(
            ("TEAMS_FIXTURE_TO_PBX_FIXTURE", "PBX_FIXTURE_TO_TEAMS_FIXTURE")
        ):
            start = 1_788_076_800_000_000 + index * 1_000_000
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
        record = {
            "apiVersion": "edge.vivolution.ae/synthetic-edge-cdr/v0.1",
            "calls": calls,
            "kind": "SyntheticEdgeCdrEvidence",
            "liveM365Interoperability": "NOT_ASSERTED",
            "nodeIdentity": {
                "allocationId": facts["allocationId"],
                "clusterId": facts["clusterId"],
                "generation": facts["generation"],
                "nodeFactsDigest": node_facts_digest,
                "nodeId": node,
                "routeToken": "ABCDEF123456",
                "runtimeAuthorityDigest": authority_digest,
                "serviceInstanceId": facts["serviceInstanceId"],
                "slot": facts["slot"],
                "tenantContextId": facts["tenantContextId"],
            },
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
        record["edgeCdrDigest"] = evidence.sha256_digest(evidence.canonical_bytes(record))
        return evidence.canonical_bytes(record)

    @staticmethod
    def cdr_reconciliation(
        test_id: str,
        fixture_cdr_raw: bytes,
        manifest_raw: bytes,
        edge_cdr_raw: bytes,
    ) -> bytes:
        fixture_cdr = json.loads(fixture_cdr_raw)
        edge_cdr = json.loads(edge_cdr_raw)
        matched = []
        for fixture_call, edge_call in zip(fixture_cdr["records"], edge_cdr["calls"]):
            matched.append(
                {
                    "direction": edge_call["direction"],
                    "edgeElapsedMilliseconds": edge_call["elapsedMilliseconds"],
                    "edgeResult": "ACCEPTED",
                    "fixtureBillableSeconds": fixture_call["billableSeconds"],
                    "fixtureDisposition": "ANSWERED",
                    "fixtureRecordDigest": fixture_call["recordDigest"],
                }
            )
        record = {
            "apiVersion": "edge.vivolution.ae/synthetic-cdr-reconciliation/v0.1",
            "calledNumber": evidence._load_fixture_contract().CALLED_NUMBER,
            "kind": "SyntheticEdgeFixtureCdrReconciliation",
            "liveM365Interoperability": "NOT_ASSERTED",
            "matchedCalls": matched,
            "nodeIdentity": edge_cdr["nodeIdentity"],
            "scope": "SYNTHETIC_PRIVATE_NO_PSTN",
            "sourceDigests": {
                "edgeCdr": evidence.sha256_digest(edge_cdr_raw),
                "fixtureCdr": evidence.sha256_digest(fixture_cdr_raw),
                "fixtureManifest": evidence.sha256_digest(manifest_raw),
            },
            "status": "SYNTHETIC_EDGE_FIXTURE_CDR_RECONCILED",
            "testId": test_id,
        }
        record["reconciliationDigest"] = evidence.sha256_digest(
            evidence.canonical_bytes(record)
        )
        return evidence.canonical_bytes(record)

    def rewrite_observation(self, node: str) -> None:
        self.write_json(f"{node}-observation.json", self.observations[node])
        self.write_request()

    def test_compiles_exact_serial_reboot_and_complete_fixture_evidence(self) -> None:
        result = evidence.compile_evidence(self.directory)
        self.assertEqual(result["status"], "ACTIVE_SYNTHETIC_EDGE_REBOOTS_QUALIFIED")
        self.assertEqual(result["rebootOrder"], ["sbc1", "sbc2"])
        self.assertEqual(
            [item["fixtureCall"]["result"] for item in result["runtimeNodes"]],
            ["PASS", "PASS"],
        )
        self.assertRegex(result["evidenceDigest"], r"^sha256:[0-9a-f]{64}$")

    def test_rejects_unchanged_target_boot_id(self) -> None:
        self.observations["sbc1"]["target"]["postReboot"]["bootId"] = self.observations[
            "sbc1"
        ]["target"]["pre"]["bootId"]
        self.observations["sbc1"]["target"]["postCall"]["bootId"] = self.observations[
            "sbc1"
        ]["target"]["pre"]["bootId"]
        self.rewrite_observation("sbc1")
        with self.assertRaisesRegex(evidence.ActiveEdgeRebootEvidenceError, "did not change"):
            evidence.compile_evidence(self.directory)

    def test_rejects_peer_health_drift_during_target_loss(self) -> None:
        self.observations["sbc1"]["peer"]["duringTargetSshLoss"]["health"][
            "runtimeChecks"
        ][0]["status"] = "FAILED"
        self.rewrite_observation("sbc1")
        with self.assertRaisesRegex(evidence.ActiveEdgeRebootEvidenceError, "did not pass"):
            evidence.compile_evidence(self.directory)

    def test_rejects_incomplete_runtime_check_inventory(self) -> None:
        for phase in ("pre", "postReboot", "postCall"):
            self.observations["sbc1"]["target"][phase]["health"][
                "runtimeChecks"
            ].pop()
        self.rewrite_observation("sbc1")
        with self.assertRaisesRegex(evidence.ActiveEdgeRebootEvidenceError, "incomplete"):
            evidence.compile_evidence(self.directory)

    def test_rejects_fixture_bundle_tampering(self) -> None:
        path = self.directory / "sbc1-fixture-bundle.json"
        path.write_bytes(path.read_bytes() + b" ")
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(evidence.ActiveEdgeRebootEvidenceError, "digest differs"):
            evidence.compile_evidence(self.directory)

    def test_rejects_raw_fixture_cdr_drift_even_when_all_outer_hashes_are_updated(self) -> None:
        node = "sbc1"
        bundle_path = self.directory / f"{node}-fixture-bundle.json"
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        artifacts = {
            name: base64.b64decode(value)
            for name, value in bundle["artifacts"].items()
        }
        artifacts["asterisk-cdr-delta.csv"] = artifacts[
            "asterisk-cdr-delta.csv"
        ].replace(b'"4","4","ANSWERED"', b'"4","3","ANSWERED"', 1)
        manifest = b"".join(
            f"{hashlib.sha256(content).hexdigest()}  ./{name}\n".encode("ascii")
            for name, content in sorted(artifacts.items())
        )
        bundle["artifacts"] = {
            name: base64.b64encode(content).decode("ascii")
            for name, content in artifacts.items()
        }
        bundle["manifestBase64"] = base64.b64encode(manifest).decode("ascii")
        self.write_json(f"{node}-fixture-bundle.json", bundle)

        reconciliation_path = self.directory / f"{node}-cdr-reconciliation.json"
        reconciliation = json.loads(reconciliation_path.read_text(encoding="utf-8"))
        reconciliation["sourceDigests"]["fixtureManifest"] = evidence.sha256_digest(
            manifest
        )
        unsigned = dict(reconciliation)
        unsigned.pop("reconciliationDigest")
        reconciliation["reconciliationDigest"] = evidence.sha256_digest(
            evidence.canonical_bytes(unsigned)
        )
        self.write_json(f"{node}-cdr-reconciliation.json", reconciliation)
        self.observations[node]["fixture"]["bundleSha256"] = evidence.sha256_digest(
            bundle_path.read_bytes()
        )
        self.observations[node]["fixture"][
            "cdrReconciliationSha256"
        ] = evidence.sha256_digest(reconciliation_path.read_bytes())
        self.rewrite_observation(node)

        with self.assertRaisesRegex(
            evidence.ActiveEdgeRebootEvidenceError,
            "fixture CDR differs from its raw records",
        ):
            evidence.compile_evidence(self.directory)

    def test_rejects_edge_cdr_identity_drift_even_when_reconciliation_is_rehashed(self) -> None:
        node = "sbc1"
        edge_path = self.directory / f"{node}-edge-cdr.json"
        edge_cdr = json.loads(edge_path.read_text(encoding="utf-8"))
        edge_cdr["nodeIdentity"]["nodeFactsDigest"] = "sha256:" + "9" * 64
        unsigned_edge = dict(edge_cdr)
        unsigned_edge.pop("edgeCdrDigest")
        edge_cdr["edgeCdrDigest"] = evidence.sha256_digest(
            evidence.canonical_bytes(unsigned_edge)
        )
        self.write_json(f"{node}-edge-cdr.json", edge_cdr)

        reconciliation_path = self.directory / f"{node}-cdr-reconciliation.json"
        reconciliation = json.loads(reconciliation_path.read_text(encoding="utf-8"))
        reconciliation["nodeIdentity"] = copy.deepcopy(edge_cdr["nodeIdentity"])
        reconciliation["sourceDigests"]["edgeCdr"] = evidence.sha256_digest(
            edge_path.read_bytes()
        )
        unsigned_reconciliation = dict(reconciliation)
        unsigned_reconciliation.pop("reconciliationDigest")
        reconciliation["reconciliationDigest"] = evidence.sha256_digest(
            evidence.canonical_bytes(unsigned_reconciliation)
        )
        self.write_json(f"{node}-cdr-reconciliation.json", reconciliation)

        self.observations[node]["fixture"]["edgeCdrSha256"] = evidence.sha256_digest(
            edge_path.read_bytes()
        )
        self.observations[node]["fixture"][
            "cdrReconciliationSha256"
        ] = evidence.sha256_digest(reconciliation_path.read_bytes())
        self.rewrite_observation(node)

        with self.assertRaisesRegex(
            evidence.ActiveEdgeRebootEvidenceError,
            "not bound to the qualified identity sources",
        ):
            evidence.compile_evidence(self.directory)

    def test_rejects_wrong_acknowledgement(self) -> None:
        request = json.loads((self.directory / "request.json").read_text(encoding="utf-8"))
        request["acknowledgement"] = "REBOOT_EDGES"
        self.write_json("request.json", request)
        with self.assertRaisesRegex(evidence.ActiveEdgeRebootEvidenceError, "not exact"):
            evidence.compile_evidence(self.directory)

    def test_rejects_overlapping_node_reboot_observations(self) -> None:
        first_fixture_start = self.observations["sbc1"]["fixture"][
            "startedAtMonotonicNs"
        ]
        second = self.observations["sbc2"]["reboot"]
        origin_ns = (
            second["rebootScheduledAtEpochMs"] * 1_000_000
            - second["rebootScheduledAtMonotonicNs"]
        )
        shifted = {
            "rebootScheduledAtMonotonicNs": first_fixture_start - 5_000_000_000,
            "sshLossObservedAtMonotonicNs": first_fixture_start - 4_000_000_000,
            "sshReconnectObservedAtMonotonicNs": first_fixture_start - 3_000_000_000,
            "readyObservedAtMonotonicNs": first_fixture_start - 2_000_000_000,
        }
        for key, value in shifted.items():
            second[key] = value
            second[key.replace("MonotonicNs", "EpochMs")] = (
                origin_ns + value
            ) // 1_000_000
        self.rewrite_observation("sbc2")
        with self.assertRaisesRegex(evidence.ActiveEdgeRebootEvidenceError, "serialized"):
            evidence.compile_evidence(self.directory)

    def test_rejects_rehashed_controller_clock_origin_change(self) -> None:
        self.observations["sbc1"]["reboot"][
            "sshReconnectObservedAtEpochMs"
        ] += 120_000
        self.rewrite_observation("sbc1")
        with self.assertRaisesRegex(
            evidence.ActiveEdgeRebootEvidenceError,
            "clock origin",
        ):
            evidence.compile_evidence(self.directory)

    def test_rejects_fixture_timestamp_between_reconnect_and_readiness(self) -> None:
        observation = self.observations["sbc1"]
        call_epoch_ms = int(
            datetime.strptime(
                observation["fixture"]["testId"].split("-", 1)[0],
                "%Y%m%dT%H%M%SZ",
            )
            .replace(tzinfo=timezone.utc)
            .timestamp()
            * 1000
        )
        observation["fixture"]["startedAtEpochMs"] = call_epoch_ms - 9_000
        observation["fixture"]["startedAtMonotonicNs"] = (
            observation["reboot"]["rebootScheduledAtMonotonicNs"]
            + 22_000_000_000
        )
        self.rewrite_observation("sbc1")
        with self.assertRaisesRegex(
            evidence.ActiveEdgeRebootEvidenceError,
            "predates full runtime readiness",
        ):
            evidence.compile_evidence(self.directory)

    def test_rejects_same_node_candidate_drift_between_observations(self) -> None:
        sequence = 3
        manifest = "sha256:" + "9" * 64
        active = {
            "kind": "CANDIDATE",
            "manifestDigest": manifest,
            "relativePath": f"slots/B/{sequence:016d}-{'9' * 64}",
            "releaseDigest": "sha256:" + "6" * 64,
            "sequence": sequence,
            "slot": "B",
        }
        for phase in ("pre", "postReboot", "postCall"):
            snapshot = self.observations["sbc2"]["target"][phase]
            snapshot["status"]["active"] = copy.deepcopy(active)
            snapshot["status"]["highestSeenSequence"] = sequence
            snapshot["health"]["active"] = copy.deepcopy(active)
            snapshot["health"]["highestSeenSequence"] = sequence
            snapshot["agentStatus"]["activeLastKnownGood"] = {
                "manifestDigest": manifest,
                "sequence": sequence,
            }
            snapshot["agentStatus"]["highestSeenSequence"] = sequence
        self.rewrite_observation("sbc2")
        with self.assertRaisesRegex(
            evidence.ActiveEdgeRebootEvidenceError,
            "drifted between serialized observations",
        ):
            evidence.compile_evidence(self.directory)


class ActiveEdgeRebootPlaybookStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = PLAYBOOK.read_text(encoding="utf-8")

    def test_is_exactly_acknowledged_and_serialized_sbc1_then_sbc2(self) -> None:
        self.assertIn(evidence.ACKNOWLEDGEMENT, self.source)
        self.assertIn("hosts: edge_nodes", self.source)
        self.assertIn("order: sorted", self.source)
        self.assertIn("serial: 1", self.source)
        self.assertIn("ansible_play_hosts_all == ['sbc1', 'sbc2']", self.source)

    def test_observes_bounded_ssh_loss_reconnect_and_boot_id_change(self) -> None:
        self.assertIn("state: stopped", self.source)
        self.assertIn("timeout: 60", self.source)
        self.assertIn("ansible.builtin.wait_for_connection", self.source)
        self.assertIn("timeout: 300", self.source)
        self.assertIn("/proc/sys/kernel/random/boot_id", self.source)
        self.assertIn("edge_active_reboot_target_boot_id_after.stdout | trim !=", self.source)
        self.assertIn("assess-reconnect", self.source)
        self.assertIn(
            "SSH_RECONNECT_BOUND_OR_CLOCK_ORIGIN_EXPIRED_RECONCILED",
            self.source,
        )

    def test_durably_binds_actual_peer_loss_observation_and_journal_timings(self) -> None:
        for token in (
            "edge_active_reboot_peer_during_observation",
            "peer-during-loss",
            "--peer-observation-file",
            "edge_active_reboot_peer_during_durable",
            "mark-reconnected",
            "mark-qualified",
        ):
            self.assertIn(token, self.source)
        self.assertNotIn(
            'duringTargetSshLoss: "{{ edge_active_reboot_preflight.peer }}"',
            self.source,
        )

    def test_requires_candidate_identity_journal_free_health_and_peer_continuity(self) -> None:
        for token in (
            "active.kind == 'CANDIDATE'",
            "lastEvidenceDigest",
            "transaction.json",
            "runtimeChecks",
            "edge_active_reboot_peer_status_during_raw",
            "edge_active_reboot_peer_health_during_raw",
            "vivolution-edge-runtime-recover.service",
        ):
            self.assertIn(token, self.source)
        self.assertIn(
            "edge_active_reboot_preflight.target ==\n                edge_active_reboot_current_target_snapshot or",
            self.source,
        )
        self.assertNotIn(
            "edge_active_reboot_preflight.target.status == edge_active_reboot_target_status_before",
            self.source,
        )

    def test_uses_fresh_complete_fixture_bundle_and_ignored_evidence_path(self) -> None:
        self.assertIn("vivolution-voice-fixture-test", self.source)
        self.assertIn("--collect-result-dir", self.source)
        self.assertIn("generated/active-edge-reboot", self.source)
        self.assertIn("active_edge_reboot_evidence.py", self.source)
        self.assertNotIn("install-edge.yml", self.source)
        self.assertNotIn("import_playbook", self.source)


if __name__ == "__main__":
    unittest.main()
