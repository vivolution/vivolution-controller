from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (
    ROOT
    / "roles"
    / "voice_fixture"
    / "files"
    / "bin"
    / "reserve_fixture_ca_serials.py"
)


def load():
    specification = importlib.util.spec_from_file_location(
        "fixture_ca_serial_reservation_test", SCRIPT
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


serials = load()


class FixtureCaSerialReservationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state_root = self.root / "issuer-state"
        self.current_root = self.root / "current"
        self.current_root.mkdir(mode=0o700)
        self.current = self.current_root / "ca.srl"
        self.patches = [
            mock.patch.object(serials, "STATE_ROOT", self.state_root),
            mock.patch.object(serials, "COUNTER", self.state_root / "ca.srl"),
            mock.patch.object(serials, "LOCK", self.state_root / "reservation.lock"),
            mock.patch.object(serials, "CURRENT_COUNTER", self.current),
            mock.patch.object(serials, "ROOT_UID", os.getuid()),
            mock.patch.object(serials, "ROOT_GID", os.getgid()),
            mock.patch.object(serials.os, "geteuid", return_value=0),
            mock.patch.object(serials.os, "chown", return_value=None),
            mock.patch.object(serials.os, "fchown", return_value=None),
        ]
        for patcher in self.patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    @staticmethod
    def write_counter(path: Path, value: int) -> None:
        path.write_text(format(value, "X") + "\n", encoding="ascii")
        os.chmod(path, 0o600)

    def test_reservation_is_committed_before_use_and_never_reused(self) -> None:
        self.write_counter(self.current, 0x10)
        first = serials.reserve(4)
        self.assertEqual(first["serials"], ["0x11", "0x12", "0x13", "0x14"])
        self.assertEqual(int((self.state_root / "ca.srl").read_text().strip(), 16), 0x14)

        # Simulate an issued orphan: selected generation still reports 0x10,
        # while the durable high-water mark already committed the first batch.
        second = serials.reserve(4)
        self.assertEqual(second["serials"], ["0x15", "0x16", "0x17", "0x18"])
        self.assertTrue(set(first["serials"]).isdisjoint(second["serials"]))

    def test_selected_counter_cannot_advance_beyond_durable_authority(self) -> None:
        self.state_root.mkdir(mode=0o700)
        self.write_counter(self.state_root / "ca.srl", 0x20)
        self.write_counter(self.current, 0x21)
        with self.assertRaisesRegex(
            serials.SerialReservationError, "ahead of durable issuer authority"
        ):
            serials.reserve(4)


if __name__ == "__main__":
    unittest.main()
