from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from edge.agent.security_core import _candidate_status


DEPLOY = Path(__file__).resolve().parents[1]
PLAYBOOK = DEPLOY / "playbooks" / "refresh-active-edge-runtime-source.yml"


class EdgeRuntimeSourceRefreshStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = PLAYBOOK.read_text(encoding="utf-8")

    def section(self, start: str, end: str) -> str:
        first = self.source.index(f"- name: {start}")
        second = self.source.index(f"- name: {end}", first + 1)
        return self.source[first:second]

    def test_play_is_serial_fail_closed_and_targets_exact_play_hosts(self) -> None:
        header = self.source[: self.source.index("  vars:")]
        self.assertIn("hosts: edge_nodes", header)
        self.assertIn("become: true", header)
        self.assertIn("any_errors_fatal: true", header)
        self.assertIn("order: sorted", header)
        self.assertIn("serial: 1", header)
        boundary = self.section(
            "Require explicit bounded fleet and digest authority",
            "Define fixed same-directory transaction paths",
        )
        self.assertIn(
            "REFRESH_ACTIVE_SYNTHETIC_RUNTIME_CONTRACTS_SOURCE", boundary
        )
        self.assertIn("NO_CONCURRENT_EDGE_ACTIVATION_OR_RECOVERY", boundary)
        self.assertIn(
            "edge_runtime_source_refresh_expected_old_sha256 is match", boundary
        )
        self.assertIn(
            "edge_runtime_source_refresh_expected_new_sha256 is match", boundary
        )
        self.assertIn("ansible_play_hosts_all", boundary)
        self.assertIn(
            "edge_runtime_source_refresh_agent_state_dir == '/var/lib/vivolution-edge/agent-state/tenant'",
            boundary,
        )
        self.assertIn(
            "edge_runtime_source_refresh_target == edge_runtime_source_refresh_targets[inventory_hostname]",
            boundary,
        )
        self.assertIn(
            "edge_runtime_source_refresh_target.nodeId == inventory_hostname",
            boundary,
        )
        self.assertIn(
            "edge_runtime_source_refresh_target.profile == 'SYNTHETIC_PRIVATE'",
            boundary,
        )
        for field in (
            "activeSequence",
            "manifestDigest",
            "runtimeReleaseDigest",
            "lastEvidenceDigest",
        ):
            self.assertIn(field, boundary)
        derived = self.section(
            "Require exact derived transaction and evidence paths",
            "Inspect the reviewed controller source",
        )
        self.assertIn(
            "/usr/lib/vivolution-edge/python/edge/runtime/.contracts.py.refresh-",
            derived,
        )
        self.assertIn("inventory_dir ~ '/generated/runtime-source-refresh/'", derived)

    def test_only_fixed_contracts_source_is_refreshable(self) -> None:
        variables = self.source[
            self.source.index("  vars:") : self.source.index("  pre_tasks:")
        ]
        self.assertIn("edge/runtime/contracts.py", variables)
        self.assertIn(
            "/usr/lib/vivolution-edge/python/edge/runtime/contracts.py", variables
        )
        self.assertNotIn("edge/runtime/core.py", self.source)
        self.assertNotIn("edge/agent/security_core.py", self.source)
        self.assertNotIn("ansible.builtin.shell", self.source)
        self.assertNotIn("unsafe_writes", self.source)

    def test_extra_var_cannot_silently_redirect_agent_state_authority(self) -> None:
        executable = shutil.which("ansible-playbook")
        if executable is None:
            self.skipTest("ansible-playbook is unavailable")
        play = [
            {
                "name": "Exercise the fixed Agent state authority assertion",
                "hosts": "all",
                "gather_facts": False,
                "vars": {
                    "edge_runtime_source_refresh_agent_state_dir": (
                        "/var/lib/vivolution-edge/agent-state/tenant"
                    )
                },
                "tasks": [
                    {
                        "name": "Require fixed Agent state authority",
                        "ansible.builtin.assert": {
                            "that": [
                                "edge_runtime_source_refresh_agent_state_dir == '/var/lib/vivolution-edge/agent-state/tenant'"
                            ]
                        },
                    }
                ],
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "precedence.json"
            path.write_text(json.dumps(play), encoding="utf-8")
            completed = subprocess.run(
                [
                    executable,
                    "--inventory",
                    "localhost,",
                    "--connection",
                    "local",
                    "--extra-vars",
                    "edge_runtime_source_refresh_agent_state_dir=/tmp/redirected-agent-state",
                    str(path),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Assertion failed", completed.stdout)

    def test_authority_runtime_and_agent_are_exact_preconditions(self) -> None:
        authority = self.section(
            "Bind refresh to the exact installed synthetic node authority",
            "Inspect installed source hierarchy and runtime journal",
        )
        for value in (
            "edge_cluster_id",
            "edge_customer_account_id",
            "edge_m365_tenant_id",
            "edge_tenant_context_id",
            "edge_service_instance_id",
            "edge_allocation_id",
            "edge_public_ipv4",
            "edge_private_ipv4",
        ):
            self.assertIn(value, authority)
        runtime = self.section(
            "Require one committed healthy candidate and no runtime transaction",
            "Build the exact tenant Agent status context",
        )
        self.assertIn("active.kind == 'CANDIDATE'", runtime)
        self.assertIn("journalPresent", runtime)
        self.assertIn(
            "active.sequence | int == edge_runtime_source_refresh_target.activeSequence",
            runtime,
        )
        self.assertIn(
            "active.manifestDigest == edge_runtime_source_refresh_target.manifestDigest",
            runtime,
        )
        self.assertIn(
            "active.releaseDigest == edge_runtime_source_refresh_target.runtimeReleaseDigest",
            runtime,
        )
        self.assertIn(
            "lastEvidenceDigest == edge_runtime_source_refresh_target.lastEvidenceDigest",
            runtime,
        )
        agent = self.section(
            "Require exact committed Agent LKG with no pending candidate",
            "Inspect deterministic controller evidence path",
        )
        self.assertIn("pendingCandidate is none", agent)
        self.assertIn("activeLastKnownGood", agent)
        self.assertIn("highestSeenSequence", agent)

    def test_complete_agent_state_bytes_are_digest_bound(self) -> None:
        complete_candidate = {
            "artifactDigests": ["sha256:" + "a" * 64],
            "expiresAt": "2026-08-31T00:00:00Z",
            "issuedAt": "2026-08-30T00:00:00Z",
            "localHealthGatePlanDigest": "sha256:" + "b" * 64,
            "manifestDigest": "sha256:" + "c" * 64,
            "manifestId": "manifest-1",
            "sequence": 1,
            "slot": "A",
            "verifiedKeyIds": ["edge-signing-key-1"],
        }
        self.assertEqual(len(complete_candidate), 9)
        self.assertEqual(
            _candidate_status(complete_candidate),
            {
                "manifestDigest": complete_candidate["manifestDigest"],
                "sequence": 1,
            },
        )
        before = self.section(
            "Inspect protected Agent state generations",
            "Require one exact current protected Agent state file",
        )
        self.assertIn("get_checksum: true", before)
        self.assertIn("checksum_algorithm: sha256", before)
        after = self.section(
            "Reinspect complete protected Agent state bytes after source refresh",
            "Parse exact post-refresh protected state",
        )
        self.assertIn("edge-state-v3.json", after)
        postconditions = self.section(
            "Require healthy runtime and byte-for-byte protected state identity",
            "Reinspect immutable source parent hierarchy after refresh",
        )
        self.assertIn(
            "edge_runtime_source_refresh_agent_state_after.stat.checksum == edge_runtime_source_refresh_agent_state_paths.results[0].stat.checksum",
            postconditions,
        )

    def test_same_directory_atomic_swap_is_digest_and_metadata_guarded(self) -> None:
        transaction_guard = self.section(
            "Require exact protected same-directory transaction bytes",
            "Atomically install reviewed source on the same filesystem",
        )
        for fragment in (
            "item.stat.nlink | int == 1",
            "item.stat.pw_name == 'root'",
            "item.stat.gr_name == 'root'",
            "item.stat.mode == '0444'",
            "item.stat.checksum == item.item.sha256",
        ):
            self.assertIn(fragment, transaction_guard)
        swap = self.section(
            "Atomically install reviewed source on the same filesystem",
            "Inspect atomically replaced source",
        )
        self.assertIn("os.path.dirname(stage) != parent", swap)
        self.assertIn("os.lstat", swap)
        self.assertIn("st_nlink != 1", swap)
        self.assertIn("os.replace(stage, target)", swap)
        self.assertIn("os.O_DIRECTORY | os.O_NOFOLLOW", swap)
        self.assertIn("os.fsync(directory_fd)", swap)

    def test_new_source_is_compiled_imported_and_health_gated(self) -> None:
        validation = self.section(
            "Compile and import the installed source in an isolated interpreter",
            "Reprove locked runtime health through the refreshed source",
        )
        self.assertIn("- /usr/bin/python3", validation)
        self.assertIn("- -I", validation)
        self.assertIn("- -B", validation)
        self.assertIn('compile(raw, str(source), "exec")', validation)
        self.assertIn('importlib.import_module("edge.runtime.contracts")', validation)
        self.assertIn("module.__file__", validation)
        health = self.section(
            "Reprove locked runtime health through the refreshed source",
            "Re-read protected runtime status after refreshed-source health",
        )
        self.assertIn(
            "argv: [/usr/local/sbin/vivolution-edge-runtime, health]", health
        )

    def test_any_post_swap_failure_restores_exact_old_bytes(self) -> None:
        rollback = self.section(
            "Atomically restore exact original source bytes",
            "Remove only the failed transaction stage",
        )
        self.assertIn("os.lstat(backup)", rollback)
        self.assertIn("os.replace(backup, target)", rollback)
        self.assertIn("os.chown(target, 0, 0)", rollback)
        self.assertIn("os.chmod(target, 0o444)", rollback)
        self.assertIn("os.fsync(directory_fd)", rollback)
        self.assertIn("Compile and import rolled-back original source", self.source)
        self.assertIn(
            "Reprove locked runtime health after exact source rollback", self.source
        )
        rollback_state = self.section(
            "Require exact protected state and health after rollback",
            "Report source refresh failure only after exact rollback",
        )
        self.assertIn(
            "edge_runtime_source_refresh_runtime_before", rollback_state
        )
        self.assertIn("edge_runtime_source_refresh_agent_before", rollback_state)
        self.assertIn(
            "edge_runtime_source_refresh_rollback_agent_state.stat.checksum == edge_runtime_source_refresh_agent_state_paths.results[0].stat.checksum",
            rollback_state,
        )

    def test_success_preserves_runtime_agent_identity_and_parent_immutability(self) -> None:
        postconditions = self.section(
            "Require healthy runtime and byte-for-byte protected state identity",
            "Reinspect immutable source parent hierarchy after refresh",
        )
        self.assertIn(
            "edge_runtime_source_refresh_runtime_after == edge_runtime_source_refresh_runtime_before",
            postconditions,
        )
        self.assertIn(
            "edge_runtime_source_refresh_agent_after == edge_runtime_source_refresh_agent_before",
            postconditions,
        )
        parent = self.section(
            "Require immutable parent modes after source refresh",
            "Build deterministic non-secret source refresh evidence",
        )
        self.assertIn("item.stat.mode == '0555'", parent)
        source = self.section(
            "Require exact installed new source protection",
            "Compile and import the installed source in an isolated interpreter",
        )
        self.assertIn("stat.nlink | int == 1", source)
        self.assertIn("stat.mode == '0444'", source)

    def test_evidence_is_deterministic_and_non_secret(self) -> None:
        evidence = self.section(
            "Build deterministic non-secret source refresh evidence",
            "Serialize and digest deterministic source refresh evidence",
        )
        self.assertIn("ACTIVE_SYNTHETIC_RUNTIME_SOURCE_REFRESHED", evidence)
        self.assertIn("profile: SYNTHETIC_PRIVATE", evidence)
        self.assertNotIn("timestamp:", evidence)
        self.assertNotIn("sourceBytes", evidence)
        self.assertNotIn("privateKey", self.source)
        self.assertIn("oldSha256:", evidence)
        self.assertIn("newSha256:", evidence)
        self.assertIn("lastEvidenceDigest:", evidence)
        self.assertIn("agentHighestSeenSequence:", evidence)
        self.assertIn("agentStateSha256:", evidence)
        serialization = self.section(
            "Serialize and digest deterministic source refresh evidence",
            "Create protected deterministic controller evidence directory",
        )
        self.assertIn("hash('sha256')", serialization)
        evidence_guard = self.section(
            "Require protected deterministic evidence before releasing rollback bytes",
            "Report exact reviewed source refresh",
        )
        self.assertIn(
            "stat.checksum == edge_runtime_source_refresh_evidence_sha256",
            evidence_guard,
        )

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
