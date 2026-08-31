from __future__ import annotations

import csv
import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = (
    ROOT
    / "roles/carrier_gateway/files/bin/carrier_cdr_evidence.py"
)
SPEC = importlib.util.spec_from_file_location("carrier_cdr_evidence", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def row(account: str = "vivo-carrier-test-in", evidence_id: str = "tone") -> list[str]:
    return [
        "2026-08-31T12:00:00+0000",
        "2026-08-31T12:00:01+0000",
        "2026-08-31T12:00:03+0000",
        "3",
        "2",
        "ANSWERED",
        "+971501234567",
        "+9710000002001",
        "PJSIP/redacted",
        "PJSIP/redacted-2",
        "unique-secret",
        "linked-secret",
        account,
        evidence_id,
    ]


class CarrierCdrEvidenceTests(unittest.TestCase):
    def write_rows(self, path: pathlib.Path, rows: list[list[str]]) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            csv.writer(handle).writerows(rows)

    def test_normalizes_without_exporting_numbers_or_channel_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "carrier.csv"
            self.write_rows(source, [row()])
            result = MODULE.normalize(source)
            payload = json.dumps(result, sort_keys=True)
            self.assertEqual(result["recordCount"], 1)
            self.assertEqual(result["records"][0]["direction"], "EDGE_TO_LOCAL_TEST")
            self.assertEqual(result["records"][0]["evidenceId"], "tone")
            self.assertNotIn("+971501234567", payload)
            self.assertNotIn("unique-secret", payload)
            self.assertRegex(result["records"][0]["recordDigest"], r"^sha256:[0-9a-f]{64}$")

    def test_writes_new_protected_manifested_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "carrier.csv"
            output = root / "evidence"
            self.write_rows(source, [row("vivo-carrier-test-out", "sbc1")])
            MODULE.write_new(output, MODULE.normalize(source))
            self.assertTrue((output / "evidence.json").is_file())
            self.assertTrue((output / "MANIFEST.sha256").is_file())
            self.assertEqual((output.stat().st_mode & 0o777), 0o700)
            with self.assertRaises(MODULE.EvidenceError):
                MODULE.write_new(output, MODULE.normalize(source))

    def test_rejects_unknown_account_unsafe_id_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "carrier.csv"
            self.write_rows(source, [row("unknown")])
            with self.assertRaises(MODULE.EvidenceError):
                MODULE.normalize(source)
            self.write_rows(source, [row(evidence_id="unsafe/value")])
            with self.assertRaises(MODULE.EvidenceError):
                MODULE.normalize(source)
            link = root / "link.csv"
            link.symlink_to(source)
            with self.assertRaises(MODULE.EvidenceError):
                MODULE.normalize(link)


if __name__ == "__main__":
    unittest.main()
