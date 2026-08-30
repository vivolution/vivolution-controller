from __future__ import annotations

import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from edge.compiler.core import NodeFacts
from edge.runtime.contracts import RuntimeAuthority


ROOT = Path(__file__).resolve().parents[3]
FIXTURE_SOURCE = (
    ROOT
    / "poc/voice-fixture/roles/voice_fixture/files/bin/synthetic_cdr_evidence.py"
)
EDGE_SOURCE = (
    ROOT
    / "deploy/roles/edge_runtime_install/files/edge_synthetic_cdr_export.py"
)


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture = load("fixture_cdr_evidence", FIXTURE_SOURCE)
edge = load("edge_cdr_export", EDGE_SOURCE)


TEST_ID = "20260830T080000Z-sbc1-1234"
BOOT_ID = "1" * 32


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
        "pbxMediaDestinationPortEnd": 21127,
        "pbxMediaDestinationPortStart": 21000,
        "privateIpv4": "10.20.2.4",
        "publicIpv4": "20.74.155.72",
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


def authority_record(profile: str = "SYNTHETIC_PRIVATE") -> dict:
    names = {
        "edgeCertificateChainPem",
        "edgePrivateKeyPem",
        "microsoftCaBundlePem",
        "pbxCaBundlePem",
        "publicCaBundlePem",
    }
    if profile == "SYNTHETIC_PRIVATE":
        names.update({"fixtureCaCrt", "fixtureClientCrt", "fixtureClientKey"})
    return {
        "administratorSourceIpv4Cidrs": ["83.110.90.142/32"],
        "apiVersion": "edge.vivolution.ae/runtime-authority/v0.1",
        "azureDhcpServerIpv4": "168.63.129.16",
        "generation": 1 if profile == "SYNTHETIC_PRIVATE" else 2,
        "nodeId": "sbc1",
        "profile": profile,
        "secretDigests": {name: "sha256:" + "a" * 64 for name in names},
        "slot": "A",
    }


def raw_cdr(test_id: str = TEST_ID) -> bytes:
    rows = [
        [
            "2026-08-30 08:00:01",
            "2026-08-30 08:00:01",
            "2026-08-30 08:00:05",
            "4",
            "4",
            "ANSWERED",
            "+9710000001001",
            "+9710000001001",
            "PJSIP/edge-inbound-00000001",
            "",
            "1756540801.1",
            "1756540801.1",
            "vivo-synth-t2p",
            test_id,
        ],
        [
            "2026-08-30 08:00:06",
            "2026-08-30 08:00:06",
            "2026-08-30 08:00:10",
            "4",
            "4",
            "ANSWERED",
            "",
            "9201",
            "Local/9201@fixture-origin-00000002;2",
            "PJSIP/sbc1-00000003",
            "1756540806.2",
            "1756540806.2",
            "vivo-synth-p2t",
            test_id,
        ],
    ]
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def journal_rows(test_id: str = TEST_ID, *, uid: str = "101") -> list[dict]:
    facts = NodeFacts.from_mapping(facts_record())
    token = edge._route_token(facts)
    epoch_usec = 1_788_076_800_000_000
    rows = []
    counter = 0
    for direction in fixture.DIRECTIONS:
        for event, result, delta in (("START", None, 0), ("FINAL", "ACCEPTED", 250_000)):
            counter += 1
            message = (
                f"{edge.MARKER}|event={event}|route={token}|direction={direction}"
                f"|test_id={test_id}"
            )
            if result is not None:
                message += f"|result={result}"
            rows.append(
                {
                    "MESSAGE": "NOTICE:script: " + message,
                    "SYSLOG_IDENTIFIER": "opensips",
                    "_BOOT_ID": BOOT_ID,
                    "_COMM": "opensips",
                    "_SYSTEMD_UNIT": "opensips.service",
                    "_UID": uid,
                    "__CURSOR": f"s=fixture;i={counter}",
                    "__REALTIME_TIMESTAMP": str(epoch_usec + counter * 1_000_000 + delta),
                }
            )
    return rows


def edge_evidence(rows: list[dict] | None = None) -> dict:
    facts_raw = edge.canonical_bytes(facts_record())
    authority_raw = edge.canonical_bytes(authority_record())
    return dict(
        edge.compile_edge_cdr(
            rows if rows is not None else journal_rows(),
            NodeFacts.from_mapping(facts_record()),
            RuntimeAuthority.from_mapping(authority_record()),
            node_facts_raw=facts_raw,
            runtime_authority_raw=authority_raw,
            opensips_uid=101,
            test_id=TEST_ID,
        )
    )


class SyntheticCdrEvidenceTests(unittest.TestCase):
    def test_fixture_normalization_selects_exact_logical_calls_without_pii(self) -> None:
        evidence = fixture.compile_fixture_cdr(raw_cdr(), TEST_ID, "sbc1")
        fixture.validate_fixture_cdr(evidence)
        self.assertEqual([item["direction"] for item in evidence["records"]], list(fixture.DIRECTIONS))
        self.assertEqual({item["disposition"] for item in evidence["records"]}, {"ANSWERED"})
        serialized = fixture.canonical_bytes(evidence)
        self.assertNotIn(b"PJSIP/", serialized)
        self.assertNotIn(b"Local/", serialized)
        self.assertNotIn(b"1756540801.1", serialized)
        self.assertIn(b"NOT_ASSERTED", serialized)

    def test_fixture_normalization_rejects_cross_test_and_duplicate_direction(self) -> None:
        contaminated = raw_cdr().replace(TEST_ID.encode(), b"20260830T080000Z-sbc1-9999", 1)
        with self.assertRaisesRegex(fixture.CdrEvidenceError, "exactly both logical"):
            fixture.compile_fixture_cdr(contaminated, TEST_ID, "sbc1")
        duplicate = raw_cdr() + raw_cdr().splitlines(keepends=True)[0]
        with self.assertRaisesRegex(fixture.CdrEvidenceError, "duplicate logical"):
            fixture.compile_fixture_cdr(duplicate, TEST_ID, "sbc1")
        same_linked_call = raw_cdr().replace(b'"1756540806.2"', b'"1756540801.1"')
        with self.assertRaisesRegex(fixture.CdrEvidenceError, "two distinct calls"):
            fixture.compile_fixture_cdr(same_linked_call, TEST_ID, "sbc1")
        stale = raw_cdr().replace(b"2026-08-30 08:00", b"2026-08-30 07:00")
        with self.assertRaisesRegex(fixture.CdrEvidenceError, "outside the fixture test window"):
            fixture.compile_fixture_cdr(stale, TEST_ID, "sbc1")

    def test_edge_export_requires_exact_service_provenance_and_two_directions(self) -> None:
        evidence = edge_evidence()
        fixture.validate_edge_cdr(evidence)
        self.assertEqual(evidence["status"], "TWO_LOGICAL_SYNTHETIC_CALLS_ACCOUNTED")
        self.assertEqual([item["result"] for item in evidence["calls"]], ["ACCEPTED", "ACCEPTED"])
        serialized = edge.canonical_bytes(evidence)
        self.assertNotIn(b"NOTICE:script", serialized)
        self.assertNotIn(b"Call-ID", serialized)

        forged_uid = journal_rows(uid="0")
        with self.assertRaisesRegex(edge.EdgeCdrExportError, "provenance"):
            edge_evidence(forged_uid)
        forged_prefix = journal_rows()
        forged_prefix[0]["MESSAGE"] = forged_prefix[0]["MESSAGE"].replace(
            "NOTICE:script: ", "attacker-controlled: ", 1
        )
        with self.assertRaisesRegex(edge.EdgeCdrExportError, "unexpected log prefix"):
            edge_evidence(forged_prefix)
        reused_cursor = journal_rows()
        reused_cursor[1]["__CURSOR"] = reused_cursor[0]["__CURSOR"]
        with self.assertRaisesRegex(edge.EdgeCdrExportError, "reuse a journal cursor"):
            edge_evidence(reused_cursor)
        missing = journal_rows()[:-1]
        with self.assertRaisesRegex(edge.EdgeCdrExportError, "exactly two complete"):
            edge_evidence(missing)

    def test_edge_export_refuses_direct_routing_authority(self) -> None:
        direct_facts = facts_record()
        direct_facts["generation"] = 2
        with self.assertRaisesRegex(edge.EdgeCdrExportError, "restricted to the fixed synthetic"):
            edge.compile_edge_cdr(
                journal_rows(),
                NodeFacts.from_mapping(direct_facts),
                RuntimeAuthority.from_mapping(authority_record("DIRECT_ROUTING")),
                node_facts_raw=edge.canonical_bytes(direct_facts),
                runtime_authority_raw=edge.canonical_bytes(authority_record("DIRECT_ROUTING")),
                opensips_uid=101,
                test_id=TEST_ID,
            )

    def test_offline_reconciliation_binds_raw_fixture_manifest_and_edge(self) -> None:
        asterisk = raw_cdr()
        fixture_evidence = fixture.compile_fixture_cdr(asterisk, TEST_ID, "sbc1")
        fixture_raw = fixture.canonical_bytes(fixture_evidence)
        edge_raw = edge.canonical_bytes(edge_evidence())
        result_raw = b"PASS\n"
        manifest_lines = {
            "./RESULT": hashlib.sha256(result_raw).hexdigest(),
            "./asterisk-cdr-delta.csv": hashlib.sha256(asterisk).hexdigest(),
            "./fixture-cdr.json": hashlib.sha256(fixture_raw).hexdigest(),
        }
        manifest_raw = "".join(
            f"{digest}  {name}\n" for name, digest in sorted(manifest_lines.items())
        ).encode("ascii")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "evidence"
            directory.mkdir(mode=0o700)
            inputs = {
                "edge-cdr.json": edge_raw,
                "fixture-asterisk-cdr-delta.csv": asterisk,
                "fixture-cdr.json": fixture_raw,
                "fixture-MANIFEST.sha256": manifest_raw,
                "fixture-RESULT": result_raw,
            }
            for name, content in inputs.items():
                path = directory / name
                path.write_bytes(content)
                path.chmod(0o600)
            reconciliation = fixture.compile_reconciliation(directory)
            self.assertEqual(
                reconciliation["status"], "SYNTHETIC_EDGE_FIXTURE_CDR_RECONCILED"
            )
            self.assertEqual(reconciliation["liveM365Interoperability"], "NOT_ASSERTED")
            self.assertEqual(len(reconciliation["matchedCalls"]), 2)

            (directory / "fixture-asterisk-cdr-delta.csv").write_bytes(
                asterisk.replace(b'"4","4"', b'"5","4"', 1)
            )
            (directory / "fixture-asterisk-cdr-delta.csv").chmod(0o600)
            with self.assertRaisesRegex(fixture.CdrEvidenceError, "differs from the raw"):
                fixture.compile_reconciliation(directory)

    def test_role_installs_root_locked_bounded_tools(self) -> None:
        runtime_tasks = (ROOT / "deploy/roles/edge_runtime_install/tasks/main.yml").read_text()
        fixture_tasks = (ROOT / "poc/voice-fixture/roles/voice_fixture/tasks/main.yml").read_text()
        repositories = (ROOT / "deploy/roles/edge_repositories/tasks/main.yml").read_text()
        self.assertIn("/var/lib/vivolution-edge/synthetic-cdr-evidence", runtime_tasks)
        self.assertIn("vivolution-edge-synthetic-cdr-export", runtime_tasks)
        self.assertIn("mode: '0500'", runtime_tasks)
        self.assertIn("vivolution-synthetic-cdr-evidence", fixture_tasks)
        self.assertIn("/usr/sbin/opensips", repositories)
        self.assertIn("opensips: /usr/sbin/opensips", repositories)
        self.assertIn("VIVO_XLOG_CORE_PROBE", repositories)
        self.assertNotIn("xlog.so", repositories)

    def test_operator_contract_does_not_expand_synthetic_cdr_claims(self) -> None:
        contract = (ROOT / "poc/synthetic-cdr-evidence.md").read_text()
        for boundary in (
            "does **not** prove live Microsoft 365 interoperability",
            "not billed or connected-call duration",
            "fails closed at 512 files or 16 MiB",
            "no production CDR database",
            "host root and system journal are the evidence trust boundary",
        ):
            self.assertIn(boundary, contract)


if __name__ == "__main__":
    unittest.main()
