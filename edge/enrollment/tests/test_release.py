from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from edge.enrollment.release import (
    RELEASE_FILES,
    ReleaseIdentityError,
    calculate_release_digest,
    load_installed_release_digest,
)

SOURCE_ROOT = Path(__file__).resolve().parents[1]


class ReleaseIdentityTests(unittest.TestCase):
    def test_source_release_digest_is_deterministic_and_canonical(self) -> None:
        first = calculate_release_digest(SOURCE_ROOT, expected_uid=os.geteuid())
        second = calculate_release_digest(SOURCE_ROOT, expected_uid=os.geteuid())
        self.assertEqual(first, second)
        self.assertRegex(first, r"\Asha256:[0-9a-f]{64}\Z")

    def test_any_executable_source_change_changes_release_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary)
            for name in RELEASE_FILES:
                (clone / name).write_bytes((SOURCE_ROOT / name).read_bytes())
            before = calculate_release_digest(clone, expected_uid=os.geteuid())
            (clone / "client.py").write_bytes((clone / "client.py").read_bytes() + b"\n")
            after = calculate_release_digest(clone, expected_uid=os.geteuid())
            self.assertNotEqual(before, after)

    def test_missing_or_linked_source_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            clone = Path(temporary)
            for name in RELEASE_FILES:
                (clone / name).write_bytes((SOURCE_ROOT / name).read_bytes())
            (clone / "protocol.py").unlink()
            (clone / "protocol.py").symlink_to(SOURCE_ROOT / "protocol.py")
            with self.assertRaises(ReleaseIdentityError):
                calculate_release_digest(clone, expected_uid=os.geteuid())

    def test_installed_digest_file_is_verified_against_exact_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = root / "sources"
            sources.mkdir()
            for name in RELEASE_FILES:
                target = sources / name
                target.write_bytes((SOURCE_ROOT / name).read_bytes())
                target.chmod(0o444)
            digest = calculate_release_digest(
                sources, expected_uid=os.geteuid(), expected_mode=0o444
            )
            identity = root / "enrollment-release-digest"
            identity.write_text(digest + "\n", encoding="ascii")
            identity.chmod(0o444)
            self.assertEqual(
                load_installed_release_digest(
                    digest_path=identity,
                    source_root=sources,
                    expected_uid=os.geteuid(),
                    expected_mode=0o444,
                ),
                digest,
            )
            (sources / "client.py").chmod(0o644)
            (sources / "client.py").write_bytes(
                (sources / "client.py").read_bytes() + b"\n"
            )
            (sources / "client.py").chmod(0o444)
            with self.assertRaisesRegex(ReleaseIdentityError, "differs"):
                load_installed_release_digest(
                    digest_path=identity,
                    source_root=sources,
                    expected_uid=os.geteuid(),
                    expected_mode=0o444,
                )


if __name__ == "__main__":
    unittest.main()
