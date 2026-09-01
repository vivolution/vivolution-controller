from __future__ import annotations

import fcntl
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
GUARD_PATH = (
    ROOT
    / "roles/carrier_certificate/files/carrier_certificate_operation_guard.py"
)
SPEC = importlib.util.spec_from_file_location("carrier_certificate_guard", GUARD_PATH)
assert SPEC is not None and SPEC.loader is not None
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class CarrierCertificateGuardTests(unittest.TestCase):
    def layout(self, root: Path) -> dict[str, object]:
        state = root / "state"
        acme = state / "acme"
        rotation = state / "rotation"
        pki = root / "pki"
        egress_pki = root / "egress-pki"
        for path, mode in (
            (state, 0o700),
            (acme, 0o700),
            (rotation, 0o700),
            (pki, 0o750),
            (egress_pki, 0o750),
        ):
            path.mkdir()
            path.chmod(mode)
        certificate = pki / "carrier.fullchain.pem"
        private_key = pki / "carrier.key"
        certificate.write_bytes(b"certificate\n")
        private_key.write_bytes(b"private-key\n")
        certificate.chmod(0o440)
        private_key.chmod(0o440)
        egress_certificate = egress_pki / "carrier.fullchain.pem"
        egress_private_key = egress_pki / "carrier.key"
        egress_certificate.write_bytes(certificate.read_bytes())
        egress_private_key.write_bytes(private_key.read_bytes())
        egress_certificate.chmod(0o440)
        egress_private_key.chmod(0o440)
        return {
            "STATE_ROOT": state,
            "ACME_ROOT": acme,
            "ROTATION_ROOT": rotation,
            "PKI_ROOT": pki,
            "LIVE_CERT": certificate,
            "LIVE_KEY": private_key,
            "EGRESS_PKI_ROOT": egress_pki,
            "EGRESS_LIVE_CERT": egress_certificate,
            "EGRESS_LIVE_KEY": egress_private_key,
            "MAINTENANCE_GATE": state / "maintenance.json",
            "RENEW_LOCK": acme / "renew.lock",
            "ROTATION_LOCK": rotation / "rotation.lock",
            "ROTATION_JOURNAL": rotation / "transaction.json",
            "ROOT_UID": os.geteuid(),
            "ROOT_GID": os.getegid(),
            "RUNTIME_GID": os.getegid(),
            "EGRESS_RUNTIME_GID": os.getegid(),
        }

    def test_gate_blocks_workers_binds_pki_and_releases_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            values = self.layout(Path(temporary))
            with mock.patch.multiple(guard, **values):
                self.assertEqual(
                    guard.begin_maintenance("configuration-rollback"),
                    "CARRIER_CERTIFICATE_MAINTENANCE_GATED",
                )
                with self.assertRaises(guard.MaintenanceBlocked):
                    guard.assert_available()
                self.assertEqual(
                    guard.assert_quiescent("configuration-rollback"),
                    "CARRIER_CERTIFICATE_OPERATIONS_QUIESCENT",
                )
                snapshot = guard.snapshot_pki("configuration-rollback")
                self.assertEqual(snapshot["status"], "CARRIER_PKI_SNAPSHOT_BOUND")
                self.assertEqual(len(snapshot["certificateSha256"]), 64)
                self.assertEqual(len(snapshot["privateKeySha256"]), 64)
                self.assertEqual(
                    snapshot["egressCertificateSha256"],
                    snapshot["certificateSha256"],
                )
                self.assertEqual(
                    snapshot["egressPrivateKeySha256"],
                    snapshot["privateKeySha256"],
                )
                self.assertEqual(
                    guard.end_maintenance("configuration-rollback"),
                    "CARRIER_CERTIFICATE_MAINTENANCE_RELEASED",
                )
                self.assertEqual(
                    guard.assert_available(),
                    "CARRIER_CERTIFICATE_OPERATION_AVAILABLE",
                )

    def test_active_lock_is_rejected_and_other_purpose_cannot_reuse_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            values = self.layout(Path(temporary))
            with mock.patch.multiple(guard, **values):
                guard.begin_maintenance("configuration-rollback")
                with self.assertRaisesRegex(guard.GuardError, "exact purpose"):
                    guard.begin_maintenance("teardown")
                descriptor = os.open(values["RENEW_LOCK"], os.O_RDWR | os.O_CREAT, 0o600)
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    with self.assertRaisesRegex(guard.GuardError, "remains active"):
                        guard.assert_locks_quiescent("configuration-rollback")
                finally:
                    os.close(descriptor)

    def test_unresolved_journal_can_only_release_for_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            values = self.layout(Path(temporary))
            with mock.patch.multiple(guard, **values):
                guard.begin_maintenance("teardown")
                values["ROTATION_JOURNAL"].write_text("{}\n")
                with self.assertRaisesRegex(guard.GuardError, "journal remains"):
                    guard.assert_quiescent("teardown")
                self.assertEqual(
                    guard.release_for_recovery("teardown"),
                    "CARRIER_CERTIFICATE_MAINTENANCE_RELEASED_FOR_RECOVERY",
                )
                self.assertFalse(values["MAINTENANCE_GATE"].exists())


if __name__ == "__main__":
    unittest.main()
