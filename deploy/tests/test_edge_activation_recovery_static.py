from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

DEPLOY = Path(__file__).resolve().parents[1]
ROOT = DEPLOY.parent


class EdgeActivationRecoveryStaticTests(unittest.TestCase):
    def read_deploy(self, relative: str) -> str:
        return (DEPLOY / relative).read_text(encoding="utf-8")

    def read_root(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def render_recovery_fact(
        self, task_name: str, fact_name: str, variables: dict[str, object]
    ) -> str:
        executable = shutil.which("ansible-playbook")
        if executable is None:
            self.skipTest("ansible-playbook is unavailable")
        first_line = Path(executable).read_text(encoding="utf-8").splitlines()[0]
        self.assertTrue(first_line.startswith("#!"))
        ansible_python = first_line[2:]
        script = r"""
import json
import sys

import yaml
from jinja2 import Environment

playbook = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
task_name = sys.argv[2]
fact_name = sys.argv[3]
variables = json.loads(sys.argv[4])
tasks = playbook[0]["tasks"]
task = next(item for item in tasks if item.get("name") == task_name)
expression = task["ansible.builtin.set_fact"][fact_name]
environment = Environment(autoescape=False)
environment.filters["bool"] = bool
print(environment.from_string(expression).render(**variables).strip())
"""
        completed = subprocess.run(
            [
                ansible_python,
                "-c",
                script,
                str(DEPLOY / "playbooks/recover-edge-activation.yml"),
                task_name,
                fact_name,
                json.dumps(variables, separators=(",", ":")),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"{completed.stdout}\n{completed.stderr}",
        )
        return completed.stdout.strip()

    def run_local_assertions(
        self,
        assertions: list[str],
        variables: dict[str, object],
        *,
        inventory_host: str = "sbc1",
    ) -> subprocess.CompletedProcess[str]:
        executable = shutil.which("ansible-playbook")
        if executable is None:
            self.skipTest("ansible-playbook is unavailable")
        playbook = [
            {
                "name": "Exercise the recovery identity boundary",
                "hosts": "all",
                "gather_facts": False,
                "vars": variables,
                "tasks": [
                    {
                        "name": "Evaluate the production recovery assertions",
                        "ansible.builtin.assert": {"that": assertions},
                    }
                ],
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.yml"
            path.write_text(json.dumps(playbook), encoding="utf-8")
            return subprocess.run(
                [
                    executable,
                    "--inventory",
                    f"{inventory_host},",
                    "--connection",
                    "local",
                    str(path),
                ],
                text=True,
                capture_output=True,
                check=False,
            )

    def test_runtime_health_is_locked_journal_free_and_baseline_only(self) -> None:
        core = self.read_root("edge/runtime/core.py")
        method = core[core.index("    def health(") : core.index("    def rollback(")]
        self.assertLess(method.index("with self._lock()"), method.index("self._initialize()"))
        self.assertLess(method.index("self._read_journal()"), method.index("self._initialize()"))
        self.assertLess(
            method.index("self._read_journal()"),
            method.index("self._baseline_health(state.active)"),
        )
        self.assertIn("transaction journal exists", method)
        self.assertIn('"kind": "EdgeRuntimeHealth"', method)
        self.assertIn('"active": state.active.record()', method)
        self.assertIn('"highestSeenSequence": state.highest_seen_sequence', method)
        self.assertIn('"runtimeChecks"', method)
        self.assertNotIn('"healthGates"', method)
        self.assertNotIn("_recover_locked", method)
        self.assertNotIn("_write_state", method)

        cli = self.read_root("edge/runtime/cli.py")
        wrapper = self.read_deploy(
            "roles/edge_runtime_install/templates/vivolution-edge-runtime.j2"
        )
        self.assertIn('commands.add_parser("health")', cli)
        self.assertIn("result = manager.health()", cli)
        self.assertIn("health|recover|status", wrapper)
        self.assertIn('[ "$#" -eq 1 ]', wrapper)

    def test_agent_status_uses_existing_lock_and_full_state_validation(self) -> None:
        core = self.read_root("edge/agent/security_core.py")
        method = core[
            core.index("def inspect_protected_state(") : core.index(
                "def verify_and_stage("
            )
        ]
        self.assertIn("with store.locked_directory()", method)
        self.assertIn("store.load_locked(directory_fd, local_context)", method)
        self.assertIn("protected state does not exist", method)
        self.assertIn('"kind": "EdgeAgentProtectedStateStatus"', method)
        self.assertIn('"activeLastKnownGood"', method)
        self.assertIn('"lastAbortedCandidate"', method)
        self.assertIn('"pendingCandidate"', method)
        for forbidden in (
            "artifactDigests",
            "verifiedKeyIds",
            "signatures",
            "privateKey",
            "configuration",
        ):
            self.assertNotIn(forbidden, method)

        cli = self.read_root("edge/agent/cli.py")
        self.assertIn('"status"', cli)
        self.assertIn("_add_context_arguments(status)", cli)
        self.assertIn("inspect_protected_state(", cli)

    def test_recovery_requires_second_exact_identity_and_durable_runtime_first(self) -> None:
        playbook = self.read_deploy("playbooks/recover-edge-activation.yml")
        for token in (
            "RECOVER_EXACT_EDGE_ACTIVATION",
            "edge_activation_recovery_node_id",
            "edge_activation_recovery_profile",
            "edge_activation_recovery_generation",
            "edge_activation_recovery_sequence",
            "edge_activation_recovery_manifest_digest",
        ):
            self.assertIn(token, playbook)
        self.assertIn("edge_activation_recovery_node_id == inventory_hostname", playbook)
        self.assertNotIn(
            "edge_activation_recovery_node_id == edge_expected_hostname", playbook
        )
        self.assertIn(
            "edge_recovery_os_hostname.stdout | trim == edge_expected_hostname",
            playbook,
        )
        self.assertIn("/usr/bin/hostnamectl, --static", playbook)
        self.assertIn("edge_activation_recovery_profile == edge_runtime_profile", playbook)
        self.assertIn(
            "edge_activation_recovery_manifest_digest == edge_activation_manifest_digest",
            playbook,
        )
        self.assertIn("Bind recovery to the installed node and full tenant allocation identity", playbook)
        self.assertIn(
            "Require the exact Agent path-walk authority before recovery",
            playbook,
        )
        self.assertIn("edge_recovery_state_traversal_root.stat.mode == '0751'", playbook)
        self.assertIn("edge_recovery_state_traversal_acl.acl | sort", playbook)
        self.assertIn("user:vivolution-edge-agent:r-x", playbook)
        self.assertLess(
            playbook.index("Require the exact Agent path-walk authority before recovery"),
            playbook.index("Define only candidate-specific recovery and cleanup paths"),
        )

        recover = playbook.index("Reconcile any durable runtime transaction journal first")
        status = playbook.index("Read the protected runtime status after journal recovery")
        health = playbook.index("Prove baseline health under the runtime lock")
        agent = playbook.index("Inspect validated protected Agent state")
        self.assertLess(recover, status)
        self.assertLess(status, health)
        self.assertLess(health, agent)
        self.assertIn("NO_RECOVERY_REQUIRED", playbook)
        self.assertIn("COMMITTED_TRANSACTION_RECOVERY_FINALIZED", playbook)
        self.assertIn("CRASH_RECOVERED_TO_PRIOR_LKG", playbook)
        self.assertIn("edge_recovery_runtime_recover.keys()", playbook)

    def test_recovery_identity_accepts_distinct_logical_and_os_hostnames(self) -> None:
        assertions = [
            "edge_activation_recovery_node_id == inventory_hostname",
            "edge_expected_hostname is match('^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')",
            "edge_recovery_os_hostname.stdout | trim == edge_expected_hostname",
        ]
        playbook = self.read_deploy("playbooks/recover-edge-activation.yml")
        for expression in assertions:
            self.assertIn(f"- {expression}", playbook)
        variables = {
            "edge_activation_recovery_node_id": "sbc1",
            "edge_expected_hostname": "viv-sbc-poc-sbc1",
            "edge_recovery_os_hostname": {"stdout": "viv-sbc-poc-sbc1\n"},
        }
        accepted = self.run_local_assertions(assertions, variables)
        self.assertEqual(
            accepted.returncode,
            0,
            msg=f"{accepted.stdout}\n{accepted.stderr}",
        )

        mismatched = self.run_local_assertions(
            assertions,
            {
                **variables,
                "edge_recovery_os_hostname": {"stdout": "sbc1\n"},
            },
        )
        self.assertNotEqual(mismatched.returncode, 0)

    def test_only_five_identity_proven_reconciliation_outcomes_are_accepted(self) -> None:
        playbook = self.read_deploy("playbooks/recover-edge-activation.yml")
        classify = playbook[
            playbook.index("Select the only legal exact reconciliation outcome") :
            playbook.index("Commit the exact pending Agent candidate")
        ]
        for outcome in (
            "PRE_STAGE_CLEANUP",
            "COMMIT",
            "ABORT",
            "ALREADY_COMMITTED",
            "ALREADY_ABORTED",
        ):
            self.assertIn(outcome, classify)
        self.assertIn("INVALID", classify)
        self.assertIn("edge_recovery_pending_is_candidate", classify)
        self.assertIn("edge_recovery_last_aborted_is_candidate", classify)
        self.assertIn("edge_recovery_runtime_is_candidate", classify)
        self.assertIn("edge_recovery_runtime_matches_agent_lkg", classify)
        self.assertIn("COMMIT_PENDING", classify)
        self.assertIn("ABORT_PENDING", classify)
        self.assertIn(
            "edge_recovery_agent_before.lastAbortedCandidate.manifestDigest == edge_activation_recovery_manifest_digest",
            playbook,
        )

        self.assertIn("'commit-pending'", playbook)
        self.assertIn("'abort-pending'", playbook)
        self.assertIn("--runtime-evidence-digest", playbook)
        self.assertIn("edge_recovery_runtime_status.lastEvidenceDigest", playbook)
        self.assertNotIn("--health-gates-passed", playbook)
        self.assertLess(
            playbook.index("Prove baseline health under the runtime lock"),
            playbook.index("Commit the exact pending Agent candidate"),
        )
        self.assertLess(
            playbook.index("Prove baseline health under the runtime lock"),
            playbook.index("Abort the exact pending Agent candidate"),
        )

    def test_never_staged_and_staged_before_runtime_interruptions_are_recoverable(self) -> None:
        playbook = self.read_deploy("playbooks/recover-edge-activation.yml")
        self.assertIn("edge-state-v3.json", playbook)
        self.assertIn("edge-state-v2.json", playbook)
        self.assertIn("accepted-state-v1.json", playbook)
        self.assertIn("ERROR: protected state does not exist", playbook)
        self.assertIn("EdgeAgentProtectedStateAbsent", playbook)
        self.assertIn("Classify exact never-staged candidate debris", playbook)
        self.assertIn("edge_recovery_pre_stage_debris", playbook)
        self.assertIn("PRE_STAGE_CLEANUP", playbook)
        self.assertIn(
            "edge_recovery_runtime_status.highestSeenSequence | int <= edge_activation_recovery_sequence | int",
            playbook,
        )
        self.assertIn(
            "edge_recovery_runtime_health.highestSeenSequence | int == edge_recovery_runtime_status.highestSeenSequence | int",
            playbook,
        )
        self.assertIn("agentStatePresent", playbook)
        self.assertIn("runtimeHighestSeenSequence", playbook)
        self.assertIn("agentHighestSeenSequence", playbook)
        self.assertIn("agentLastAbortedCandidate", playbook)

    def test_recovery_classification_matrix_renders_exactly(self) -> None:
        pre_stage_task = "Classify exact never-staged candidate debris"
        outcome_task = "Select the only legal exact reconciliation outcome"

        def pre_stage(
            *,
            state_present: bool,
            agent_highest: int,
            pending: object,
            runtime_highest: int,
            target: int,
            matches_lkg: bool = True,
            recovery_status: str = "NO_RECOVERY_REQUIRED",
        ) -> bool:
            rendered = self.render_recovery_fact(
                pre_stage_task,
                "edge_recovery_pre_stage_debris",
                {
                    "edge_recovery_runtime_recover": {"status": recovery_status},
                    "edge_recovery_runtime_status": {
                        "highestSeenSequence": runtime_highest
                    },
                    "edge_activation_recovery_sequence": target,
                    "edge_recovery_runtime_matches_agent_lkg": matches_lkg,
                    "edge_recovery_agent_state_present": state_present,
                    "edge_recovery_agent_before": {
                        "pendingCandidate": pending,
                        "highestSeenSequence": agent_highest,
                    },
                },
            )
            self.assertIn(rendered, {"True", "False"})
            return rendered == "True"

        def outcome(
            *,
            pre: bool,
            pending_is_candidate: bool,
            runtime_is_candidate: bool,
            matches_lkg: bool,
            state_present: bool,
            pending: object,
            agent_highest: int,
            active_is_candidate: bool,
            last_aborted_is_candidate: bool,
            target: int,
        ) -> str:
            return self.render_recovery_fact(
                outcome_task,
                "edge_recovery_outcome",
                {
                    "edge_recovery_pre_stage_debris": pre,
                    "edge_recovery_pending_is_candidate": pending_is_candidate,
                    "edge_recovery_last_aborted_is_candidate": last_aborted_is_candidate,
                    "edge_recovery_runtime_is_candidate": runtime_is_candidate,
                    "edge_recovery_runtime_matches_agent_lkg": matches_lkg,
                    "edge_recovery_agent_state_present": state_present,
                    "edge_recovery_agent_before": {
                        "pendingCandidate": pending,
                        "highestSeenSequence": agent_highest,
                    },
                    "edge_recovery_agent_active_is_candidate": active_is_candidate,
                    "edge_activation_recovery_sequence": target,
                },
            )

        self.assertTrue(
            pre_stage(
                state_present=False,
                agent_highest=-1,
                pending=None,
                runtime_highest=0,
                target=1,
            )
        )
        self.assertTrue(
            pre_stage(
                state_present=True,
                agent_highest=5,
                pending=None,
                runtime_highest=5,
                target=6,
            )
        )
        self.assertFalse(
            pre_stage(
                state_present=True,
                agent_highest=6,
                pending={"sequence": 6},
                runtime_highest=5,
                target=6,
            )
        )
        self.assertFalse(
            pre_stage(
                state_present=True,
                agent_highest=6,
                pending=None,
                runtime_highest=5,
                target=6,
            )
        )

        cases = (
            (
                "PRE_STAGE_CLEANUP",
                dict(
                    pre=True,
                    pending_is_candidate=False,
                    runtime_is_candidate=False,
                    matches_lkg=True,
                    state_present=False,
                    pending=None,
                    agent_highest=-1,
                    active_is_candidate=False,
                    last_aborted_is_candidate=False,
                    target=1,
                ),
            ),
            (
                "ABORT",
                dict(
                    pre=False,
                    pending_is_candidate=True,
                    runtime_is_candidate=False,
                    matches_lkg=True,
                    state_present=True,
                    pending={"sequence": 6},
                    agent_highest=6,
                    active_is_candidate=False,
                    last_aborted_is_candidate=False,
                    target=6,
                ),
            ),
            (
                "ALREADY_ABORTED",
                dict(
                    pre=False,
                    pending_is_candidate=False,
                    runtime_is_candidate=False,
                    matches_lkg=True,
                    state_present=True,
                    pending=None,
                    agent_highest=6,
                    active_is_candidate=False,
                    last_aborted_is_candidate=True,
                    target=6,
                ),
            ),
            (
                "COMMIT",
                dict(
                    pre=False,
                    pending_is_candidate=True,
                    runtime_is_candidate=True,
                    matches_lkg=False,
                    state_present=True,
                    pending={"sequence": 6},
                    agent_highest=6,
                    active_is_candidate=False,
                    last_aborted_is_candidate=False,
                    target=6,
                ),
            ),
            (
                "ALREADY_COMMITTED",
                dict(
                    pre=False,
                    pending_is_candidate=False,
                    runtime_is_candidate=True,
                    matches_lkg=False,
                    state_present=True,
                    pending=None,
                    agent_highest=6,
                    active_is_candidate=True,
                    last_aborted_is_candidate=False,
                    target=6,
                ),
            ),
        )
        for expected, values in cases:
            with self.subTest(expected=expected):
                self.assertEqual(outcome(**values), expected)

        self.assertEqual(
            outcome(
                pre=False,
                pending_is_candidate=False,
                runtime_is_candidate=False,
                matches_lkg=True,
                state_present=True,
                pending=None,
                agent_highest=6,
                active_is_candidate=False,
                last_aborted_is_candidate=False,
                target=6,
            ),
            "INVALID",
        )

    def test_postconditions_precede_bounded_cleanup_and_evidence_is_retained(self) -> None:
        playbook = self.read_deploy("playbooks/recover-edge-activation.yml")
        postcondition = playbook.index("Require exact terminal Agent and runtime postconditions")
        evidence = playbook.index("Preserve exact terminal activation recovery evidence")
        inspect_cleanup = playbook.index("Inspect only the exact abandoned candidate paths")
        remove = playbook.index("Remove only reconciled candidate-specific abandoned handoff paths")
        self.assertLess(postcondition, evidence)
        self.assertLess(evidence, inspect_cleanup)
        self.assertLess(inspect_cleanup, remove)
        self.assertIn("runtime-recovery-{{", playbook)
        self.assertIn("activation-recovery-{{ edge_recovery_outcome", playbook)
        self.assertIn("Refuse replaced or permissive evidence paths", playbook)
        self.assertIn("/var/lib/vivolution-edge/agent-work/", playbook)
        self.assertIn("/var/lib/vivolution-edge/runtime-inbox/", playbook)
        self.assertIn("not (item.stat.islnk", playbook)
        self.assertIn("item.stat.mode == '0700'", playbook)
        cleanup = playbook[remove:]
        self.assertIn("edge_recovery_work_dir", cleanup)
        self.assertIn("edge_recovery_inbox_dir", cleanup)
        self.assertNotIn("runtime_root", cleanup)
        self.assertNotIn("activation-evidence", cleanup)
        self.assertNotIn("ansible.builtin.shell", playbook)
        self.assertNotIn("az ", playbook)
        self.assertNotIn("graph.microsoft", playbook.lower())

    def test_recovery_playbook_passes_ansible_syntax(self) -> None:
        executable = shutil.which("ansible-playbook")
        if executable is None:
            self.skipTest("ansible-playbook is unavailable")
        completed = subprocess.run(
            [
                executable,
                "--syntax-check",
                "-i",
                "inventories/poc-edge-template/hosts.yml",
                "playbooks/recover-edge-activation.yml",
            ],
            cwd=DEPLOY,
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
