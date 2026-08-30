from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import unittest


DEPLOY = Path(__file__).resolve().parents[1]
PLAYBOOK = DEPLOY / "playbooks" / "refresh-active-edge-cdr-exporter.yml"


class EdgeCdrExporterRefreshStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = PLAYBOOK.read_text(encoding="utf-8")

    def section(self, start: str, end: str) -> str:
        first = self.source.index(f"- name: {start}")
        second = self.source.index(f"- name: {end}", first + 1)
        return self.source[first:second]

    def test_play_is_serial_and_requires_exact_private_fleet(self) -> None:
        header = self.source[: self.source.index("  vars:")]
        for value in (
            "hosts: edge_nodes",
            "become: true",
            "any_errors_fatal: true",
            "order: sorted",
            "serial: 1",
        ):
            self.assertIn(value, header)
        boundary = self.section(
            "Require explicit bounded CDR exporter digest authority",
            "Define fixed same-directory CDR exporter transaction paths",
        )
        self.assertIn("REFRESH_ACTIVE_SYNTHETIC_CDR_EXPORTER", boundary)
        self.assertIn("NO_CONCURRENT_EDGE_ACTIVATION_OR_RECOVERY", boundary)
        self.assertIn("ansible_play_hosts_all", boundary)
        self.assertIn("profile == 'SYNTHETIC_PRIVATE'", boundary)
        self.assertIn("expected_old_sha256 is match", boundary)
        self.assertIn("expected_new_sha256 is match", boundary)
        for field in (
            "activeSequence",
            "generation",
            "lastEvidenceDigest",
            "manifestDigest",
            "runtimeReleaseDigest",
        ):
            self.assertIn(field, boundary)

    def test_only_fixed_exporter_path_is_refreshable(self) -> None:
        variables = self.source[
            self.source.index("  vars:") : self.source.index("  pre_tasks:")
        ]
        self.assertIn(
            "roles/edge_runtime_install/files/edge_synthetic_cdr_export.py",
            variables,
        )
        self.assertIn(
            "/usr/local/sbin/vivolution-edge-synthetic-cdr-export", variables
        )
        derived = self.section(
            "Require exact derived CDR transaction and evidence paths",
            "Inspect the reviewed controller CDR exporter",
        )
        self.assertIn(
            "/usr/local/sbin/.vivolution-edge-synthetic-cdr-export.refresh-",
            derived,
        )
        self.assertIn("/generated/cdr-exporter-refresh/", derived)
        self.assertNotIn("ansible.builtin.shell", self.source)
        self.assertNotIn("unsafe_writes", self.source)

    def test_installed_identity_and_runtime_are_exact_preconditions(self) -> None:
        authority = self.section(
            "Bind CDR exporter refresh to exact installed private authority",
            "Inspect installed CDR exporter hierarchy and runtime journal",
        )
        for value in (
            "edge_cluster_id",
            "edge_tenant_context_id",
            "edge_allocation_id",
            "edge_public_ipv4",
            "edge_private_ipv4",
        ):
            self.assertIn(value, authority)
        installed = self.section(
            "Require exact installed old CDR exporter and no runtime transaction",
            "Find abandoned CDR exporter refresh transaction files",
        )
        for value in (
            "stat.nlink | int == 1",
            "stat.pw_name == 'root'",
            "stat.gr_name == 'root'",
            "stat.mode == '0500'",
            "expected_old_sha256",
        ):
            self.assertIn(value, installed)
        self.assertIn("/var/lib/vivolution-edge/runtime/transaction.json", self.source)
        runtime = self.section(
            "Require exact committed healthy runtime before CDR exporter refresh",
            "Inspect deterministic CDR exporter evidence path",
        )
        self.assertIn("active.kind == 'CANDIDATE'", runtime)
        self.assertIn("journalPresent", runtime)
        self.assertIn("activeSequence", runtime)
        self.assertIn("manifestDigest", runtime)
        self.assertIn("runtimeReleaseDigest", runtime)
        self.assertIn("lastEvidenceDigest", runtime)

    def test_same_directory_swap_and_rollback_are_digest_guarded(self) -> None:
        transaction = self.section(
            "Require exact protected CDR exporter transaction bytes",
            "Atomically install reviewed CDR exporter",
        )
        for value in (
            "item.stat.nlink | int == 1",
            "item.stat.mode == '0500'",
            "item.stat.checksum == item.item.sha256",
        ):
            self.assertIn(value, transaction)
        swap = self.section(
            "Atomically install reviewed CDR exporter",
            "Inspect installed reviewed CDR exporter",
        )
        self.assertIn("os.path.dirname(stage) != parent", swap)
        self.assertIn("os.replace(stage, target)", swap)
        self.assertIn("os.O_DIRECTORY | os.O_NOFOLLOW", swap)
        self.assertIn("os.fsync(directory_fd)", swap)
        rollback = self.section(
            "Atomically restore exact original CDR exporter",
            "Remove failed CDR exporter stage",
        )
        self.assertIn("os.replace(backup, target)", rollback)
        self.assertIn("os.fsync(directory_fd)", rollback)
        self.assertIn("Compile rolled-back original CDR exporter", self.source)
        self.assertIn(
            "Require unchanged healthy runtime after CDR exporter rollback",
            self.source,
        )

    def test_new_exporter_import_is_exact_prefix_and_runtime_gated(self) -> None:
        validation = self.section(
            "Compile and import installed CDR exporter in isolated interpreter",
            "Reprove locked runtime health after CDR exporter refresh",
        )
        self.assertIn("importlib.util.spec_from_file_location", validation)
        self.assertIn('module.MARKER != "VIVO_SYNTHETIC_CDR_V1"', validation)
        self.assertIn(
            '("", "NOTICE:", "NOTICE:script: ")', validation
        )
        postcondition = self.section(
            "Require unchanged healthy runtime after CDR exporter refresh",
            "Build deterministic non-secret CDR exporter refresh evidence",
        )
        self.assertIn(
            "edge_cdr_exporter_refresh_runtime_after_raw.stdout | from_json",
            postcondition,
        )
        self.assertIn("edge_cdr_exporter_refresh_runtime_before", postcondition)
        self.assertIn("rejectattr('status', 'equalto', 'PASSED')", postcondition)

    def test_evidence_is_new_protected_and_deterministic(self) -> None:
        evidence = self.section(
            "Build deterministic non-secret CDR exporter refresh evidence",
            "Serialize deterministic CDR exporter refresh evidence",
        )
        self.assertIn("ACTIVE_SYNTHETIC_CDR_EXPORTER_REFRESHED", evidence)
        self.assertIn("oldSha256", evidence)
        self.assertIn("newSha256", evidence)
        self.assertIn("runtimeStateUnchanged: true", evidence)
        self.assertNotIn("timestamp", evidence)
        preservation = self.section(
            "Preserve deterministic CDR exporter refresh evidence",
            "Verify protected CDR exporter refresh evidence",
        )
        self.assertIn("mode: '0600'", preservation)
        self.assertIn("force: false", preservation)
        guard = self.section(
            "Require protected CDR exporter evidence before removing rollback",
            "Report exact reviewed CDR exporter refresh",
        )
        self.assertIn("stat.checksum == edge_cdr_exporter_refresh_evidence_sha256", guard)

    def test_ansible_syntax(self) -> None:
        executable = shutil.which("ansible-playbook")
        if executable is None:
            self.skipTest("ansible-playbook is unavailable")
        inventory = (
            DEPLOY
            / "inventories"
            / "poc-edge-template"
            / "generated"
            / "azure-poc"
            / "hosts.yml"
        )
        completed = subprocess.run(
            [
                executable,
                "--syntax-check",
                "--inventory",
                str(inventory),
                str(PLAYBOOK),
            ],
            cwd=DEPLOY.parent,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"{completed.stdout}\n{completed.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
