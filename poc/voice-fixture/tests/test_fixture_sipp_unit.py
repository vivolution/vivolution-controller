#!/usr/bin/env python3
"""Pure offline unit tests for the fixture runner's safety boundary."""

import argparse
import importlib.util
import ipaddress
from pathlib import Path
import tempfile
import unittest


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "roles/voice_fixture/files/sipp/bin/fixture_sipp.py"
)
SPEC = importlib.util.spec_from_file_location("fixture_sipp", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class FixtureSippUnitTests(unittest.TestCase):
    def test_rtp_requires_a_complete_version_two_header(self) -> None:
        self.assertTrue(FIXTURE.is_valid_rtp(b"\x80" + b"\x00" * 11))
        self.assertFalse(FIXTURE.is_valid_rtp(b"\x80" + b"\x00" * 10))
        self.assertFalse(FIXTURE.is_valid_rtp(b"\x40" + b"\x00" * 11))

    def test_only_two_private_edge_addresses_are_allowed(self) -> None:
        self.assertEqual(
            FIXTURE.EDGE_IPS,
            {ipaddress.ip_address("10.20.2.4"), ipaddress.ip_address("10.20.2.5")},
        )
        self.assertTrue(all(address in FIXTURE.EDGE_NETWORK for address in FIXTURE.EDGE_IPS))
        self.assertEqual(
            FIXTURE.EDGE_SERVER_NAMES[ipaddress.ip_address("10.20.2.4")],
            "sbc1.voice.vivolution.ae",
        )
        self.assertEqual(FIXTURE.TLS_PROBE_PORT, 25063)

    def test_public_or_wrong_port_uac_target_is_rejected_before_socket_use(self) -> None:
        public = argparse.Namespace(
            target_ip="198.51.100.10",
            target_port=5061,
            test_id="offline-test",
            output_dir="/results",
        )
        with self.assertRaisesRegex(ValueError, "fixed SBC1 or SBC2"):
            FIXTURE.run_uac(public)

        wrong_port = argparse.Namespace(
            target_ip="10.20.2.4",
            target_port=5060,
            test_id="offline-test",
            output_dir="/results",
        )
        with self.assertRaisesRegex(ValueError, "TLS 5061"):
            FIXTURE.run_uac(wrong_port)

    def test_unbounded_or_injected_test_ids_are_rejected(self) -> None:
        self.assertIsNotNone(FIXTURE.TEST_ID_RE.fullmatch("20260830T000000Z-sbc1-1"))
        self.assertIsNone(FIXTURE.TEST_ID_RE.fullmatch("bad id; touch /tmp/x"))
        self.assertIsNone(FIXTURE.TEST_ID_RE.fullmatch("x" * 65))

    def test_atomic_json_replaces_a_complete_document(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "counter.json"
            FIXTURE.atomic_json(target, {"packets_received": 1})
            self.assertEqual(target.read_text(encoding="utf-8"), '{\n  "packets_received": 1\n}\n')
            self.assertEqual(target.stat().st_mode & 0o777, 0o640)

    def test_result_path_cannot_escape_mounted_results_root(self) -> None:
        with self.assertRaisesRegex(ValueError, "below /results"):
            FIXTURE.ensure_results_root(Path("/tmp/not-results"))

    def test_long_running_uas_has_no_periodic_statistics_file(self) -> None:
        arguments = FIXTURE.common_sipp_args(
            bind_port=25061,
            scenario="/opt/fixture/scenarios/teams-uas.xml",
            stats=None,
            errors=Path("/results/runtime/teams-uas-errors.log"),
            ca_file="/run/fixture-pki/ca.crt",
        )
        self.assertNotIn("-trace_stat", arguments)
        self.assertNotIn("-stf", arguments)
        self.assertIn("-max_log_size", arguments)


if __name__ == "__main__":
    unittest.main()
