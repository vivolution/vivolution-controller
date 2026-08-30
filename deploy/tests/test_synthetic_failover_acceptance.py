from __future__ import annotations

from datetime import datetime, timezone
from datetime import timedelta
import csv
import hashlib
import importlib.util
import json
import io
import os
from pathlib import Path
import base64
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "scripts" / "synthetic_failover_evidence.py"
PLAYBOOK = ROOT / "deploy" / "playbooks" / "qualify-synthetic-node-failover.yml"

SPEC = importlib.util.spec_from_file_location("synthetic_failover_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)


def epoch_ms(value: str) -> int:
    return int(
        datetime.strptime(value, "%Y%m%dT%H%M%SZ")
        .replace(tzinfo=timezone.utc)
        .timestamp()
        * 1000
    )


class SyntheticFailoverEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        os.chmod(self.directory, 0o700)
        self.started = epoch_ms("20260830T080010Z")
        self.completed = epoch_ms("20260830T080030Z")
        self.started_monotonic = 10_000_000_000
        self.completed_monotonic = 30_000_000_000
        self.request = {
            "acknowledgement": evidence.ACKNOWLEDGEMENT,
            "alternate": {
                "activeManifestDigest": "sha256:" + "b" * 64,
                "activeSequence": 1,
                "nodeId": "sbc2",
                "privateIpv4": "10.20.2.5",
                "slot": "B",
            },
            "apiVersion": evidence.REQUEST_API_VERSION,
            "completedAtEpochMs": self.completed,
            "completedAtMonotonicNs": self.completed_monotonic,
            "failureStartedAtEpochMs": self.started,
            "failureStartedAtMonotonicNs": self.started_monotonic,
            "gateSeconds": 120,
            "liveM365Interoperability": "NOT_ASSERTED",
            "primary": {
                "activeManifestDigest": "sha256:" + "a" * 64,
                "activeSequence": 1,
                "nodeId": "sbc1",
                "privateIpv4": "10.20.2.4",
                "slot": "A",
            },
            "restoredPrimary": {
                "activeManifestDigest": "sha256:" + "a" * 64,
                "activeSequence": 1,
                "nodeId": "sbc1",
                "privateIpv4": "10.20.2.4",
                "slot": "A",
            },
            "routeIdentity": {
                "allocationId": "alloc-vivolution-1",
                "calledNumber": "+9710000001001",
                "clusterId": "cluster-vivolution-poc",
                "customerAccountId": "customer-vivolution",
                "directions": [
                    "TEAMS_FIXTURE_TO_PBX_FIXTURE",
                    "PBX_FIXTURE_TO_TEAMS_FIXTURE",
                ],
                "m365TenantId": "00000000-0000-0000-0000-000000000000",
                "serviceInstanceId": "service-vivolution-1",
                "tenantContextId": "tenant-vivolution-1",
            },
            "testedFailure": {
                "injection": "SYSTEMD_STOP_COMPLETE_DATA_PLANE",
                "primaryNodeId": "sbc1",
                "servicesStopped": [
                    "opensips.service",
                    "rtpengine-daemon.service",
                ],
                "signalingListener": "CLOSED_FROM_FIXTURE_CONTROLLER",
            },
        }
        self.write("request.json", evidence._canonical_bytes(self.request))
        self.write_phase("primary", "20260830T080000Z-sbc1-1", "sbc1", "10.20.2.4")
        self.write_phase("alternate", "20260830T080020Z-sbc2-2", "sbc2", "10.20.2.5")
        self.write_phase("restored", "20260830T080040Z-sbc1-3", "sbc1", "10.20.2.4")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, name: str, content: bytes) -> None:
        path = self.directory / name
        path.write_bytes(content)
        os.chmod(path, 0o600)

    def write_request(self) -> None:
        self.write("request.json", evidence._canonical_bytes(self.request))

    def write_phase(
        self,
        phase: str,
        test_id: str,
        node: str,
        target: str,
        *,
        rtp_uas_delta: int = 12,
    ) -> None:
        summary = (
            f"node={node}\n"
            f"target={target}\n"
            f"test_id={test_id}\n"
            "cdr_records=2\n"
            f"rtp_uas_delta={rtp_uas_delta}\n"
            "rtp_selected_peer_delta=11\n"
            "rtp_echo_delta=10\n"
        ).encode("utf-8")
        result = b"PASS\n"
        asterisk_cdr = self.raw_cdr(test_id, node)
        cdr_contract = evidence._load_cdr_contract()
        fixture_cdr = cdr_contract.canonical_bytes(
            cdr_contract.compile_fixture_cdr(asterisk_cdr, test_id, node)
        )
        edge_cdr = self.edge_cdr(test_id, node)
        artifacts = {
            "RESULT": result,
            "asterisk-cdr-delta.csv": asterisk_cdr,
            "fixture-cdr.json": fixture_cdr,
            "readiness.txt": b"READY\n",
            "summary.txt": summary,
            "teams-to-pbx-rtp.json": b"{}\n",
            "teams-to-pbx-sipp-errors.log": b"",
            "teams-to-pbx-summary.json": b"{}\n",
        }
        manifest = self.write_bundle(phase, test_id, artifacts)
        self.write(f"{phase}-edge-cdr.json", edge_cdr)
        self.write_cdr_reconciliation(
            phase, test_id, node, fixture_cdr, manifest, edge_cdr
        )

    def write_bundle(
        self, phase: str, test_id: str, artifacts: dict[str, bytes]
    ) -> bytes:
        manifest = "".join(
            f"{hashlib.sha256(content).hexdigest()}  ./{name}\n"
            for name, content in sorted(artifacts.items())
        ).encode("ascii")
        bundle = {
            "apiVersion": evidence.BUNDLE_API_VERSION,
            "artifacts": {
                name: base64.b64encode(content).decode("ascii")
                for name, content in artifacts.items()
            },
            "manifestBase64": base64.b64encode(manifest).decode("ascii"),
            "testId": test_id,
        }
        self.write(f"{phase}-bundle.json", evidence._canonical_bytes(bundle))
        return manifest

    def read_bundle(self, phase: str) -> dict[str, object]:
        return json.loads((self.directory / f"{phase}-bundle.json").read_text())

    def rewrite_bundle(self, phase: str, bundle: dict[str, object]) -> None:
        self.write(f"{phase}-bundle.json", evidence._canonical_bytes(bundle))

    def raw_cdr(self, test_id: str, node: str) -> bytes:
        started = datetime.strptime(test_id.split("-")[0], "%Y%m%dT%H%M%SZ")
        origin_extension = "9201" if node == "sbc1" else "9202"
        def stamp(offset: int) -> str:
            return (started + timedelta(seconds=offset)).strftime("%Y-%m-%d %H:%M:%S")

        suffix = test_id.rsplit("-", 1)[1]
        rows = [
            [
                stamp(1), stamp(1), stamp(5), "4", "4", "ANSWERED",
                evidence.CALLED_NUMBER, evidence.CALLED_NUMBER,
                "PJSIP/edge-inbound-00000001", "", f"{suffix}.1", f"{suffix}.1",
                "vivo-synth-t2p", test_id,
            ],
            [
                stamp(6), stamp(6), stamp(10), "4", "4", "ANSWERED", "", origin_extension,
                f"Local/{origin_extension}@fixture-origin-00000002;2", f"PJSIP/{node}-00000003",
                f"{suffix}.2", f"{suffix}.2", "vivo-synth-p2t", test_id,
            ],
        ]
        stream = io.StringIO(newline="")
        csv.writer(stream, quoting=csv.QUOTE_ALL, lineterminator="\n").writerows(rows)
        return stream.getvalue().encode("utf-8")

    def edge_cdr(self, test_id: str, node: str) -> bytes:
        slot = "A" if node == "sbc1" else "B"
        node_identity = {
            "allocationId": "alloc-vivolution-1",
            "clusterId": "cluster-vivolution-poc",
            "generation": 1,
            "nodeFactsDigest": "sha256:" + "1" * 64,
            "nodeId": node,
            "routeToken": "ABCDEF123456",
            "runtimeAuthorityDigest": "sha256:" + "2" * 64,
            "serviceInstanceId": "service-vivolution-1",
            "slot": slot,
            "tenantContextId": "tenant-vivolution-1",
        }
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
        record["edgeCdrDigest"] = evidence._sha256(evidence._canonical_bytes(record))
        return evidence._canonical_bytes(record)

    def write_cdr_reconciliation(
        self,
        phase: str,
        test_id: str,
        node: str,
        fixture_cdr_raw: bytes,
        manifest_raw: bytes,
        edge_cdr_raw: bytes,
    ) -> None:
        fixture_cdr = json.loads(fixture_cdr_raw)
        edge_cdr = json.loads(edge_cdr_raw)
        record = {
            "apiVersion": "edge.vivolution.ae/synthetic-cdr-reconciliation/v0.1",
            "calledNumber": evidence.CALLED_NUMBER,
            "kind": "SyntheticEdgeFixtureCdrReconciliation",
            "liveM365Interoperability": "NOT_ASSERTED",
            "matchedCalls": [
                {
                    "direction": "TEAMS_FIXTURE_TO_PBX_FIXTURE",
                    "edgeElapsedMilliseconds": edge_cdr["calls"][0]["elapsedMilliseconds"],
                    "edgeResult": "ACCEPTED",
                    "fixtureBillableSeconds": fixture_cdr["records"][0]["billableSeconds"],
                    "fixtureDisposition": "ANSWERED",
                    "fixtureRecordDigest": fixture_cdr["records"][0]["recordDigest"],
                },
                {
                    "direction": "PBX_FIXTURE_TO_TEAMS_FIXTURE",
                    "edgeElapsedMilliseconds": edge_cdr["calls"][1]["elapsedMilliseconds"],
                    "edgeResult": "ACCEPTED",
                    "fixtureBillableSeconds": fixture_cdr["records"][1]["billableSeconds"],
                    "fixtureDisposition": "ANSWERED",
                    "fixtureRecordDigest": fixture_cdr["records"][1]["recordDigest"],
                },
            ],
            "nodeIdentity": edge_cdr["nodeIdentity"],
            "scope": "SYNTHETIC_PRIVATE_NO_PSTN",
            "sourceDigests": {
                "edgeCdr": evidence._sha256(edge_cdr_raw),
                "fixtureCdr": evidence._sha256(fixture_cdr_raw),
                "fixtureManifest": evidence._sha256(manifest_raw),
            },
            "status": "SYNTHETIC_EDGE_FIXTURE_CDR_RECONCILED",
            "testId": test_id,
        }
        record["reconciliationDigest"] = evidence._sha256(
            evidence._canonical_bytes(record)
        )
        self.write(
            f"{phase}-cdr-reconciliation.json", evidence._canonical_bytes(record)
        )

    def test_complete_private_failover_compiles_exact_acceptance(self) -> None:
        result = evidence.compile_evidence(self.directory)
        self.assertEqual(result["status"], "SYNTHETIC_NEW_CALL_FAILOVER_ACCEPTED")
        self.assertEqual(result["liveM365Interoperability"], "NOT_ASSERTED")
        self.assertEqual(result["activeCallMigration"], "NOT_TESTED_NOT_CLAIMED")
        self.assertEqual(result["failoverElapsedMilliseconds"], 20_000)
        self.assertEqual(
            [call["phase"] for call in result["fixtureCalls"]],
            [
                "PRIMARY_BASELINE",
                "ALTERNATE_AFTER_PRIMARY_STOP",
                "PRIMARY_AFTER_RESTORE",
            ],
        )
        self.assertEqual(
            [call["nodeId"] for call in result["fixtureCalls"]],
            ["sbc1", "sbc2", "sbc1"],
        )
        unsigned = dict(result)
        digest = unsigned.pop("evidenceDigest")
        self.assertEqual(digest, evidence._sha256(evidence._canonical_bytes(unsigned)))

    def test_elapsed_time_cannot_exceed_120_second_gate(self) -> None:
        self.request["completedAtMonotonicNs"] = (
            self.started_monotonic + 120_000_000_001
        )
        self.write_request()
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "inside 120 seconds"):
            evidence.compile_evidence(self.directory)

    def test_synthetic_evidence_cannot_be_relabelled_live_m365(self) -> None:
        self.request["liveM365Interoperability"] = "PASSED"
        self.write_request()
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "must not assert live M365"):
            evidence.compile_evidence(self.directory)

    def test_alternate_must_be_exact_sbc2_runtime_and_call(self) -> None:
        self.request["alternate"]["nodeId"] = "sbc1"
        self.write_request()
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "fixed POC node"):
            evidence.compile_evidence(self.directory)

    def test_restored_primary_must_match_original_active_runtime(self) -> None:
        self.request["restoredPrimary"]["activeSequence"] = 2
        self.write_request()
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "exact pre-failure"):
            evidence.compile_evidence(self.directory)

    def test_fixture_summary_is_bound_to_its_manifest(self) -> None:
        bundle = self.read_bundle("alternate")
        encoded = bundle["artifacts"]["summary.txt"]
        changed = base64.b64decode(encoded).replace(b"cdr_records=2", b"cdr_records=3")
        bundle["artifacts"]["summary.txt"] = base64.b64encode(changed).decode("ascii")
        self.rewrite_bundle("alternate", bundle)
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "differs from its manifest"):
            evidence.compile_evidence(self.directory)

    def test_every_fixture_phase_requires_rtp_and_two_cdrs(self) -> None:
        self.write_phase(
            "alternate",
            "20260830T080020Z-sbc2-2",
            "sbc2",
            "10.20.2.5",
            rtp_uas_delta=0,
        )
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "did not prove traffic"):
            evidence.compile_evidence(self.directory)

    def test_linked_input_is_rejected(self) -> None:
        target = self.directory / "primary-bundle.json"
        target.unlink()
        target.symlink_to("alternate-bundle.json")
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "single-link"):
            evidence.compile_evidence(self.directory)

    def test_manifested_but_unfetched_artifact_is_rejected(self) -> None:
        bundle = self.read_bundle("alternate")
        manifest = base64.b64decode(bundle["manifestBase64"])
        missing = b"not-fetched\n"
        manifest += (
            f"{hashlib.sha256(missing).hexdigest()}  ./unit-policy.txt\n".encode("ascii")
        )
        bundle["manifestBase64"] = base64.b64encode(manifest).decode("ascii")
        self.rewrite_bundle("alternate", bundle)
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "missing, extra, or unverified"):
            evidence.compile_evidence(self.directory)

    def test_unmanifested_bundle_artifact_is_rejected(self) -> None:
        bundle = self.read_bundle("alternate")
        bundle["artifacts"]["unit-policy.txt"] = base64.b64encode(b"extra\n").decode(
            "ascii"
        )
        self.rewrite_bundle("alternate", bundle)
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "missing, extra, or unverified"):
            evidence.compile_evidence(self.directory)

    def test_unpermitted_manifest_path_is_rejected(self) -> None:
        bundle = self.read_bundle("alternate")
        content = b"unexpected\n"
        lines = base64.b64decode(bundle["manifestBase64"]).decode("ascii").splitlines()
        lines.append(f"{hashlib.sha256(content).hexdigest()}  ./secrets.txt")
        manifest = ("\n".join(sorted(lines, key=lambda line: line[66:])) + "\n").encode(
            "ascii"
        )
        bundle["manifestBase64"] = base64.b64encode(manifest).decode("ascii")
        bundle["artifacts"]["secrets.txt"] = base64.b64encode(content).decode("ascii")
        self.rewrite_bundle("alternate", bundle)
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "unpermitted"):
            evidence.compile_evidence(self.directory)

    def test_extra_local_evidence_file_is_rejected(self) -> None:
        self.write("not-part-of-evidence.txt", b"extra\n")
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "three result bundles"):
            evidence.compile_evidence(self.directory)

    def test_each_phase_requires_exact_cdr_reconciliation(self) -> None:
        path = self.directory / "alternate-cdr-reconciliation.json"
        record = json.loads(path.read_text())
        record["status"] = "NOT_RECONCILED"
        unsigned = dict(record)
        unsigned.pop("reconciliationDigest")
        record["reconciliationDigest"] = evidence._sha256(
            evidence._canonical_bytes(unsigned)
        )
        self.write(path.name, evidence._canonical_bytes(record))
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "identity is invalid"):
            evidence.compile_evidence(self.directory)

    def test_cdr_reconciliation_must_bind_the_same_tenant_allocation(self) -> None:
        path = self.directory / "alternate-cdr-reconciliation.json"
        record = json.loads(path.read_text())
        record["nodeIdentity"]["allocationId"] = "alloc-other-tenant"
        unsigned = dict(record)
        unsigned.pop("reconciliationDigest")
        record["reconciliationDigest"] = evidence._sha256(
            evidence._canonical_bytes(unsigned)
        )
        self.write(path.name, evidence._canonical_bytes(record))
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "logical tenant route"):
            evidence.compile_evidence(self.directory)

    def test_cdr_reconciliation_must_bind_exact_collected_sources(self) -> None:
        path = self.directory / "alternate-cdr-reconciliation.json"
        record = json.loads(path.read_text())
        record["sourceDigests"]["fixtureManifest"] = "sha256:" + "f" * 64
        unsigned = dict(record)
        unsigned.pop("reconciliationDigest")
        record["reconciliationDigest"] = evidence._sha256(
            evidence._canonical_bytes(unsigned)
        )
        self.write(path.name, evidence._canonical_bytes(record))
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "source digests are unbound"):
            evidence.compile_evidence(self.directory)

    def test_cdr_matches_must_be_derived_from_exact_raw_sources(self) -> None:
        path = self.directory / "alternate-cdr-reconciliation.json"
        record = json.loads(path.read_text())
        record["matchedCalls"][0]["edgeElapsedMilliseconds"] = 119_999
        record["matchedCalls"][0]["fixtureBillableSeconds"] = 119
        record["matchedCalls"][0]["fixtureRecordDigest"] = "sha256:" + "f" * 64
        unsigned = dict(record)
        unsigned.pop("reconciliationDigest")
        record["reconciliationDigest"] = evidence._sha256(
            evidence._canonical_bytes(unsigned)
        )
        self.write(path.name, evidence._canonical_bytes(record))
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "differs from raw sources"):
            evidence.compile_evidence(self.directory)


class SyntheticFailoverRemoteCollectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.result = (
            Path(self.temporary.name) / "20260830T080020Z-sbc2-90210"
        )
        self.result.mkdir(mode=0o750)
        os.chmod(self.result, 0o750)
        self.owner_uid = os.getuid()
        self.owner_gid = os.getgid()
        self.artifacts = {
            "RESULT": b"PASS\n",
            "asterisk-cdr-delta.csv": b"answered,twice\n",
            "fixture-cdr.json": b"{}\n",
            "readiness.txt": b"READY\n",
            "summary.txt": b"summary\n",
            "teams-to-pbx-rtp.json": b"{}\n",
            "teams-to-pbx-summary.json": b"{}\n",
        }
        self.write_source()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_source(self) -> None:
        for name, content in self.artifacts.items():
            path = self.result / name
            path.write_bytes(content)
            os.chmod(path, 0o640)
        manifest = "".join(
            f"{hashlib.sha256(content).hexdigest()}  ./{name}\n"
            for name, content in sorted(self.artifacts.items())
        ).encode("ascii")
        path = self.result / "MANIFEST.sha256"
        if path.exists():
            os.chmod(path, 0o640)
        path.write_bytes(manifest)
        os.chmod(path, 0o440)

    def collect(self, **overrides: int) -> dict[str, object]:
        arguments = {
            "root_uid": self.owner_uid,
            "root_gid": self.owner_gid,
            "fixture_uid": self.owner_uid,
            "fixture_gid": self.owner_gid,
        }
        arguments.update(overrides)
        return evidence._collect_fixture_result(self.result, **arguments)

    def test_collector_fetches_every_manifested_artifact(self) -> None:
        bundle = self.collect()
        self.assertEqual(set(bundle["artifacts"]), set(self.artifacts))

    def test_collector_accepts_manifested_empty_bounded_error_log(self) -> None:
        self.artifacts["teams-to-pbx-sipp-errors.log"] = b""
        self.write_source()
        bundle = self.collect()
        self.assertEqual(bundle["artifacts"]["teams-to-pbx-sipp-errors.log"], "")

    def test_collector_uses_distinct_real_fixture_ownership_classes(self) -> None:
        fixture_identity = evidence._expected_artifact_identity(
            "teams-to-pbx-summary.json",
            root_uid=0,
            root_gid=0,
            fixture_uid=10002,
            fixture_gid=10002,
        )
        for root_copied_name in (
            "pbx-to-teams-rtp-after.json",
            "pbx-to-teams-sipp-errors.log",
            "fixture-cdr.json",
        ):
            self.assertEqual(
                evidence._expected_artifact_identity(
                    root_copied_name,
                    root_uid=0,
                    root_gid=0,
                    fixture_uid=10002,
                    fixture_gid=10002,
                ),
                (0, 0),
            )
        self.assertEqual(fixture_identity, (10002, 10002))

    def test_collector_rejects_missing_artifact(self) -> None:
        (self.result / "readiness.txt").unlink()
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "missing, extra"):
            self.collect()

    def test_collector_rejects_extra_unmanifested_artifact(self) -> None:
        path = self.result / "unit-policy.txt"
        path.write_bytes(b"unmanifested\n")
        os.chmod(path, 0o640)
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "missing, extra"):
            self.collect()

    def test_collector_rejects_symlink_artifact(self) -> None:
        path = self.result / "readiness.txt"
        path.unlink()
        path.symlink_to("RESULT")
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "unsafe type"):
            self.collect()

    def test_collector_rejects_hard_linked_artifact(self) -> None:
        os.link(self.result / "readiness.txt", self.result / "unit-policy.txt")
        self.artifacts["unit-policy.txt"] = self.artifacts["readiness.txt"]
        manifest = "".join(
            f"{hashlib.sha256(content).hexdigest()}  ./{name}\n"
            for name, content in sorted(self.artifacts.items())
        ).encode("ascii")
        manifest_path = self.result / "MANIFEST.sha256"
        os.chmod(manifest_path, 0o640)
        manifest_path.write_bytes(manifest)
        os.chmod(manifest_path, 0o440)
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "unsafe type"):
            self.collect()

    def test_collector_rejects_wrong_mode(self) -> None:
        os.chmod(self.result / "readiness.txt", 0o600)
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "owner, group, or mode"):
            self.collect()

    def test_collector_rejects_wrong_owner_contract(self) -> None:
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "unsafe type"):
            self.collect(root_uid=self.owner_uid + 1)

    def test_collector_rejects_hash_mismatch(self) -> None:
        path = self.result / "readiness.txt"
        os.chmod(path, 0o640)
        path.write_bytes(b"TAMPERED\n")
        os.chmod(path, 0o640)
        with self.assertRaisesRegex(evidence.FailoverEvidenceError, "differs from its manifest"):
            self.collect()


class SyntheticFailoverPlaybookStaticTests(unittest.TestCase):
    def test_playbook_is_exact_disruptive_synthetic_workflow(self) -> None:
        source = PLAYBOOK.read_text(encoding="utf-8")
        for token in (
            "RUN_SYNTHETIC_SBC1_TO_SBC2_FAILOVER_WITHIN_120_SECONDS",
            "groups.get('edge_nodes', []) | sort == ['sbc1', 'sbc2']",
            "hostvars['sbc1'].edge_runtime_profile == 'SYNTHETIC_PRIVATE'",
            "hostvars['sbc2'].edge_runtime_profile == 'SYNTHETIC_PRIVATE'",
            "SYSTEMD_STOP_COMPLETE_DATA_PLANE",
            "CLOSED_FROM_FIXTURE_CONTROLLER",
            "SYNTHETIC_NEW_CALL_FAILOVER_ACCEPTED",
            "liveM365Interoperability: NOT_ASSERTED",
            "activeCallMigration=NOT_TESTED_NOT_CLAIMED",
        ):
            self.assertIn(token, source)
        self.assertNotIn("ansible.builtin.shell", source)
        self.assertNotIn("ignore_errors", source)
        self.assertNotIn("az ", source)
        self.assertNotIn("MicrosoftTeams", source)

    def test_clock_contains_stop_detection_alternate_call_and_not_restore(self) -> None:
        source = PLAYBOOK.read_text(encoding="utf-8")
        clock_start = source.index("Start the conservative 120-second failover clock")
        stop = source.index("Deliberately stop the complete SBC1 data plane")
        listener = source.index("Prove SBC1 TLS 5061 is closed from the fixture controller")
        alternate = source.index("Place the new same-route call through alternate SBC2")
        clock_end = source.index("End the failover clock only after the alternate call passed")
        restore = source.index("Restore SBC1 media before signaling")
        self.assertLess(clock_start, stop)
        self.assertLess(stop, listener)
        self.assertLess(listener, alternate)
        self.assertLess(alternate, clock_end)
        self.assertLess(clock_end, restore)
        self.assertIn("edge_failover_gate_seconds: 120", source)
        self.assertIn("time.monotonic_ns()", source)
        self.assertIn("edge_failover_gate_seconds | int * 1000000000", source)
        self.assertIn("/usr/bin/timeout", source)
        self.assertIn("edge_failover_alternate_call_timeout_seconds: 110", source)

    def test_restoration_and_fresh_primary_call_are_in_always_path(self) -> None:
        source = PLAYBOOK.read_text(encoding="utf-8")
        always = source.index("      always:")
        restore = source.index("Restore SBC1 media before signaling")
        health = source.index("Re-prove protected runtime health after SBC1 restoration")
        retest = source.index("Re-prove both call directions through restored SBC1")
        unlock = source.index("Release only this failover exercise lock")
        final_gate = source.index("Require accepted failover and exact healthy primary restoration")
        self.assertLess(always, restore)
        self.assertLess(restore, health)
        self.assertLess(health, retest)
        self.assertLess(retest, unlock)
        self.assertLess(unlock, final_gate)
        self.assertIn("rtpengine-daemon.service\n            - opensips.service", source)

    def test_node_local_deadman_is_armed_before_stop_and_removed_after_retest(self) -> None:
        source = PLAYBOOK.read_text(encoding="utf-8")
        acquire = source.index("Acquire the primary-node failover exercise lock")
        marker = source.index("Persist exact recovery identity before arming any disruption")
        injector = source.index("Install the node-local atomic deadman-and-stop payload")
        require_payloads = source.index(
            "Require exact durable recovery payloads before the timed disruption"
        )
        clock = source.index("Start the conservative 120-second failover clock")
        stop = source.index(
            "Deliberately stop the complete SBC1 data plane only through the armed node-local injector"
        )
        prove_active = source.index(
            "Prove the deadman timer remained active after failure injection"
        )
        restore_gate = source.index("Require exact restoration before disarming the node-local deadman")
        disarm = source.index("Disarm the node-local timer only after exact restoration")
        inactive = source.index("Require the node-local deadman inactive before marker removal")
        remove = source.index("Remove exact recovery payloads only after successful disarm")
        unlock = source.index("Release only this failover exercise lock after marker removal")
        self.assertLess(acquire, marker)
        self.assertLess(marker, injector)
        self.assertLess(injector, require_payloads)
        self.assertLess(require_payloads, clock)
        self.assertLess(clock, stop)
        self.assertLess(stop, prove_active)
        self.assertLess(stop, restore_gate)
        self.assertLess(restore_gate, disarm)
        self.assertLess(disarm, inactive)
        self.assertLess(inactive, remove)
        self.assertLess(remove, unlock)
        injector_payload = source[
            source.index("Install the node-local atomic deadman-and-stop payload") :
            source.index("Inspect the durable recovery boundary before starting the clock")
        ]
        self.assertLess(
            injector_payload.index("/usr/bin/systemd-run"),
            injector_payload.index("/usr/bin/systemctl stop opensips.service"),
        )
        self.assertIn("/usr/bin/systemd-run \\\n              --quiet", injector_payload)
        self.assertLess(
            injector_payload.index("/usr/bin/systemctl stop opensips.service"),
            injector_payload.index("/usr/bin/systemctl stop rtpengine-daemon.service"),
        )
        self.assertEqual(injector_payload.count("--kill-after=5s 45s"), 2)
        safe_cleanup = source[
            source.index("Remove exact prior recovery payloads after successful disarm") :
            source.index("Release prior failover recovery directory after successful retest")
        ]
        normal_cleanup = source[
            source.index("Remove exact recovery payloads only after successful disarm") :
            source.index("Release only this failover exercise lock after marker removal")
        ]
        for cleanup in (safe_cleanup, normal_cleanup):
            self.assertLess(
                cleanup.index("edge_failover_injector_path"),
                cleanup.index("edge_failover_deadman_path"),
            )
            self.assertLess(
                cleanup.index("edge_failover_deadman_path"),
                cleanup.index("edge_failover_marker_path"),
            )
        self.assertIn("--on-active={{ edge_failover_deadman_delay_seconds }}s", source)
        self.assertIn("edge_failover_deadman_delay_seconds: 150", source)
        self.assertIn("/var/lib/vivolution-edge/synthetic-failover-recovery", source)
        self.assertIn("Recover prior SBC1 media before signaling on safe rerun", source)

    def test_all_manifested_artifacts_and_three_cdrs_are_bound(self) -> None:
        source = PLAYBOOK.read_text(encoding="utf-8")
        for token in (
            "--collect-result-dir",
            "Preserve every complete fixture result bundle locally",
            "asterisk-cdr-delta.csv",
            "fixture-cdr.json",
            "vivolution-edge-synthetic-cdr-export",
            "Reconcile exact Edge and fixture CDRs for every phase offline",
            "SYNTHETIC_EDGE_FIXTURE_CDR_RECONCILED",
            "-cdr-reconciliation.json",
        ):
            self.assertIn(token, source)

    def test_operator_docs_preserve_the_synthetic_only_boundary(self) -> None:
        fixture = (ROOT / "poc" / "voice-fixture" / "README.md").read_text(
            encoding="utf-8"
        )
        execution = (ROOT / "poc" / "turnkey-first-tenant-execution.md").read_text(
            encoding="utf-8"
        )
        matrix = (ROOT / "poc" / "test-matrix.md").read_text(encoding="utf-8")
        deployment = (ROOT / "deploy" / "README.md").read_text(encoding="utf-8")
        combined = "\n".join((fixture, execution, matrix, deployment))
        for token in (
            "qualify-synthetic-node-failover.yml",
            "RUN_SYNTHETIC_SBC1_TO_SBC2_FAILOVER_WITHIN_120_SECONDS",
            "liveM365Interoperability=NOT_ASSERTED",
            "activeCallMigration=NOT_TESTED_NOT_CLAIMED",
            "Microsoft OPTIONS/gateway selection",
        ):
            self.assertIn(token, combined)
        self.assertIn("unconditional recovery", deployment)
        self.assertIn("120,000 milliseconds", fixture)


if __name__ == "__main__":
    unittest.main()
