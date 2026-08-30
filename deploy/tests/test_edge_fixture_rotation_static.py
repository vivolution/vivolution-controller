from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT
    / "deploy"
    / "roles"
    / "edge_fixture_rotation"
    / "files"
    / "rotate_synthetic_fixture_pki.py"
)
TASKS = (
    ROOT
    / "deploy"
    / "roles"
    / "edge_fixture_rotation"
    / "tasks"
    / "main.yml"
)
PLAYBOOK = ROOT / "deploy" / "playbooks" / "rotate-synthetic-fixture-pki.yml"

SPEC = importlib.util.spec_from_file_location("rotate_synthetic_fixture_pki", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
rotation = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = rotation
SPEC.loader.exec_module(rotation)


class EdgeFixtureRotationStaticTests(unittest.TestCase):
    def test_every_interrupted_phase_restores_prior_except_durable_healthy(self) -> None:
        for phase in (
            "PREPARED",
            "SERVICE_STOPPED",
            "SECRETS_INSTALLED",
            "AUTHORITY_RECONCILED",
        ):
            with self.subTest(phase=phase):
                self.assertEqual(
                    rotation.recovery_action_for_phase(phase), "RESTORE_PRIOR"
                )
        self.assertEqual(
            rotation.recovery_action_for_phase("HEALTHY"), "FINALIZE_NEW"
        )
        with self.assertRaises(rotation.FixtureRotationError):
            rotation.recovery_action_for_phase("UNKNOWN")

    def test_rotation_is_locked_fixed_path_and_profile_validated(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("fcntl.flock", source)
        self.assertIn("os.O_NOFOLLOW", source)
        self.assertIn("os.replace", source)
        self.assertIn("os.fsync", source)
        self.assertIn('authority.profile != "SYNTHETIC_PRIVATE"', source)
        self.assertIn("validate_secret_material", source)
        self.assertIn("runtime activation transaction is pending", source)
        self.assertNotIn("shell=True", source)

    def test_role_requires_exact_inputs_digests_and_complete_fleet_ack(self) -> None:
        tasks = TASKS.read_text(encoding="utf-8")
        playbook = PLAYBOOK.read_text(encoding="utf-8")
        self.assertIn("ROTATE_SYNTHETIC_FIXTURE_PKI_ON_BOTH_EDGES", tasks)
        self.assertIn("edge_runtime_profile == 'SYNTHETIC_PRIVATE'", tasks)
        self.assertIn("item.stat.checksum == item.item.sha256", tasks)
        self.assertIn("serial: 1", playbook)
        self.assertIn("groups['edge_nodes'] | sort == ['sbc1', 'sbc2']", playbook)
        self.assertIn("vivolution-voice-fixture-test", playbook)
        self.assertIn("validate_checksum: true", playbook)


if __name__ == "__main__":
    unittest.main()
