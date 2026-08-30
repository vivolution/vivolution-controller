from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "scripts" / "active_edge_reboot_journal.py"

SPEC = importlib.util.spec_from_file_location("active_edge_reboot_journal", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
journal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(journal)


class ActiveEdgeRebootJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "active-edge-reboot"
        self.root.mkdir(mode=0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def args(self, **values: object) -> argparse.Namespace:
        return argparse.Namespace(evidence_root=str(self.root), **values)

    def begin(self) -> dict[str, object]:
        return dict(
            journal._begin(
                self.args(acknowledgement=journal.ACKNOWLEDGEMENT)
            )
        )

    @staticmethod
    def preflight(node: str) -> dict[str, object]:
        peer = "sbc2" if node == "sbc1" else "sbc1"
        boot = (
            "04aa0fe1-dfef-4c95-a111-111111111111"
            if node == "sbc1"
            else "04aa0fe1-dfef-4c95-a222-222222222222"
        )
        return {
            "apiVersion": "edge.vivolution.ae/active-edge-reboot-preflight/v0.1",
            "nodeId": node,
            "peer": {"bootId": "04aa0fe1-dfef-4c95-a333-333333333333"},
            "peerIdentitySources": {"nodeFactsSha256": "sha256:" + "1" * 64},
            "peerNodeId": peer,
            "target": {
                "agentState": {},
                "agentStatus": {},
                "bootId": boot,
                "health": {},
                "recoveryUnitEnabled": "enabled",
                "status": {},
                "transactionJournalPresent": False,
                "unitStates": {},
            },
            "targetIdentitySources": {"nodeFactsSha256": "sha256:" + "2" * 64},
        }

    def staging(self, state: dict[str, object], node: str) -> Path:
        path = Path(state["evidenceDirectory"]) / f".{node}-preflight-staging.json"
        path.write_bytes(journal.canonical_bytes(self.preflight(node)))
        os.chmod(path, 0o600)
        return path

    def arm(self, state: dict[str, object], node: str, start: int) -> dict[str, object]:
        path = self.staging(state, node)
        return dict(
            journal._mutate(
                self.args(
                    node=node,
                    preflight_file=str(path),
                ),
                "arm",
            )
        )

    def transition(
        self, node: str, operation: str, *, timing: int | None = None
    ) -> dict[str, object]:
        values: dict[str, object] = {"node": node}
        if timing is not None:
            values["timing"] = json.dumps(
                {"epochMs": 1_788_131_600_000 + timing // 1_000_000, "monotonicNs": timing},
                sort_keys=True,
                separators=(",", ":"),
            )
        if operation == "loss":
            state = self.begin()
            peer_path = (
                Path(state["evidenceDirectory"])
                / f".{node}-peer-during-loss-staging.json"
            )
            peer_path.write_bytes(
                journal.canonical_bytes(self.preflight(node)["peer"])
            )
            os.chmod(peer_path, 0o600)
            values["peer_observation_file"] = str(peer_path)
        return dict(journal._mutate(self.args(**values), operation))

    def qualification_observation(self, node: str) -> dict[str, object]:
        state = self.begin()
        item = state["nodes"][node]
        preflight = self.preflight(node)
        peer_during = journal._peer_during_loss(self.args(node=node))
        return {
            "nodeId": node,
            "peer": {
                "before": preflight["peer"],
                "duringTargetSshLoss": peer_during,
                "identitySources": preflight["peerIdentitySources"],
            },
            "peerNodeId": preflight["peerNodeId"],
            "reboot": {
                "rebootScheduledAtEpochMs": item["scheduleTiming"]["epochMs"],
                "rebootScheduledAtMonotonicNs": item["scheduleTiming"]["monotonicNs"],
                "sshLossObservedAtEpochMs": item["lossTiming"]["epochMs"],
                "sshLossObservedAtMonotonicNs": item["lossTiming"]["monotonicNs"],
                "sshReconnectObservedAtEpochMs": item["reconnectTiming"]["epochMs"],
                "sshReconnectObservedAtMonotonicNs": item["reconnectTiming"]["monotonicNs"],
            },
            "target": {"pre": preflight["target"]},
            "targetIdentitySources": preflight["targetIdentitySources"],
        }

    def qualify(self, state: dict[str, object], node: str) -> dict[str, object]:
        state = self.begin()
        observation = Path(state["evidenceDirectory"]) / f"{node}-observation.json"
        observation.write_bytes(
            journal.canonical_bytes(self.qualification_observation(node))
        )
        os.chmod(observation, 0o600)
        return dict(
            journal._mutate(
                self.args(node=node, observation_file=str(observation)),
                "qualified",
            )
        )

    def test_begin_is_idempotent_and_keeps_one_exact_run(self) -> None:
        first = self.begin()
        second = self.begin()
        self.assertEqual(first, second)
        self.assertEqual(first["currentNode"], "sbc1")
        self.assertEqual(first["status"], "IN_PROGRESS")
        self.assertEqual(len(list(self.root.glob("20*-*"))), 1)

    def test_begin_recovers_empty_crashed_initializer(self) -> None:
        initializer = self.root / ".active-run.init-deadbeef"
        initializer.mkdir(mode=0o700)
        state = self.begin()
        self.assertEqual(state["status"], "IN_PROGRESS")
        self.assertFalse(initializer.exists())

    def test_begin_recovers_empty_final_active_directory(self) -> None:
        active = self.root / journal.STATE_DIRECTORY_NAME
        active.mkdir(mode=0o700)
        state = self.begin()
        self.assertEqual(state["status"], "IN_PROGRESS")
        self.assertTrue((active / journal.STATE_FILE_NAME).exists())

    def test_arm_recovers_preflight_written_before_state_transition(self) -> None:
        state = self.begin()
        orphan = self.root / journal.STATE_DIRECTORY_NAME / "sbc1-preflight.json"
        orphan.write_bytes(journal.canonical_bytes(self.preflight("sbc1")))
        os.chmod(orphan, 0o600)
        armed = self.arm(state, "sbc1", 10_000_000_000)
        self.assertEqual(armed["nodes"]["sbc1"]["phase"], "ARMED")
        self.assertTrue(orphan.exists())
        self.assertFalse(
            (Path(state["evidenceDirectory"]) / ".sbc1-preflight-staging.json").exists()
        )

    def test_durable_transitions_resume_without_allocating_another_run(self) -> None:
        state = self.begin()
        armed = self.arm(state, "sbc1", 10_000_000_000)
        self.assertEqual(armed["nodes"]["sbc1"]["phase"], "ARMED")
        self.transition("sbc1", "scheduled", timing=10_500_000_000)
        lost = self.transition("sbc1", "loss", timing=20_000_000_000)
        self.assertEqual(lost["nodes"]["sbc1"]["phase"], "SSH_LOST")
        resumed = self.begin()
        self.assertEqual(resumed["runId"], state["runId"])
        self.assertEqual(resumed["nodes"]["sbc1"]["phase"], "SSH_LOST")
        connected = self.transition("sbc1", "reconnected", timing=30_000_000_000)
        self.assertEqual(connected["nodes"]["sbc1"]["phase"], "RECONNECTED")

    def test_delayed_armed_resume_uses_fresh_successful_schedule_timing(self) -> None:
        state = self.begin()
        armed = self.arm(state, "sbc1", 10_000_000_000)
        self.assertIsNone(armed["nodes"]["sbc1"]["scheduleTiming"])
        resumed = self.begin()
        scheduled = self.transition("sbc1", "scheduled", timing=500_000_000_000)
        self.assertEqual(
            scheduled["nodes"]["sbc1"]["scheduleTiming"]["monotonicNs"],
            500_000_000_000,
        )
        lost = self.transition("sbc1", "loss", timing=510_000_000_000)
        self.assertEqual(lost["nodes"]["sbc1"]["phase"], "SSH_LOST")
        self.assertEqual(resumed["runId"], scheduled["runId"])

    def test_abort_is_durable_and_begin_never_allocates_a_second_run(self) -> None:
        state = self.begin()
        self.arm(state, "sbc1", 10_000_000_000)
        aborted = dict(
            journal._mutate(
                self.args(
                    node="sbc1",
                    reason="REBOOT_OCCURRED_WITHOUT_OBSERVED_SSH_LOSS",
                ),
                "abort",
            )
        )
        self.assertEqual(aborted["status"], "ABORTED_RECONCILED")
        self.assertEqual(self.begin(), aborted)
        self.assertEqual(len(list(self.root.glob("20*-*"))), 1)

    def test_delayed_ssh_lost_resume_is_classified_and_terminally_reconciled(self) -> None:
        state = self.begin()
        self.arm(state, "sbc1", 10_000_000_000)
        self.transition("sbc1", "scheduled", timing=10_500_000_000)
        self.transition("sbc1", "loss", timing=20_000_000_000)
        assessment = journal._assess_reconnect(
            self.args(
                node="sbc1",
                timing=json.dumps(
                    {
                        "epochMs": 1_788_132_000_000,
                        "monotonicNs": 500_000_000_000,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
        )
        self.assertEqual(
            assessment["assessment"], "EXPIRED_OR_CLOCK_ORIGIN_CHANGED"
        )
        aborted = dict(
            journal._mutate(
                self.args(
                    node="sbc1",
                    reason="SSH_RECONNECT_BOUND_OR_CLOCK_ORIGIN_EXPIRED_RECONCILED",
                ),
                "abort",
            )
        )
        self.assertEqual(aborted["status"], "ABORTED_RECONCILED")
        self.assertEqual(self.begin(), aborted)

    def test_reconnect_rejects_changed_controller_clock_origin(self) -> None:
        state = self.begin()
        self.arm(state, "sbc1", 10_000_000_000)
        self.transition("sbc1", "scheduled", timing=10_500_000_000)
        self.transition("sbc1", "loss", timing=20_000_000_000)
        inconsistent = json.dumps(
            {
                "epochMs": 1_788_141_600_030,
                "monotonicNs": 30_000_000_000,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        assessment = journal._assess_reconnect(
            self.args(node="sbc1", timing=inconsistent)
        )
        self.assertEqual(
            assessment["assessment"], "EXPIRED_OR_CLOCK_ORIGIN_CHANGED"
        )
        with self.assertRaisesRegex(journal.JournalError, "clock origin"):
            journal._mutate(
                self.args(node="sbc1", timing=inconsistent),
                "reconnected",
            )

    def test_loss_durably_binds_actual_peer_observation_bytes(self) -> None:
        state = self.begin()
        self.arm(state, "sbc1", 10_000_000_000)
        self.transition("sbc1", "scheduled", timing=10_500_000_000)
        lost = self.transition("sbc1", "loss", timing=20_000_000_000)
        item = lost["nodes"]["sbc1"]
        peer_path = (
            self.root
            / journal.STATE_DIRECTORY_NAME
            / item["lossPeerObservationFile"]
        )
        self.assertEqual(
            item["lossPeerObservationDigest"],
            journal.sha256_digest(peer_path.read_bytes()),
        )
        self.assertEqual(
            journal._peer_during_loss(self.args(node="sbc1")),
            self.preflight("sbc1")["peer"],
        )

    def test_mark_qualified_rejects_rehashed_timing_decoupled_from_journal(self) -> None:
        state = self.begin()
        self.arm(state, "sbc1", 10_000_000_000)
        self.transition("sbc1", "scheduled", timing=10_500_000_000)
        self.transition("sbc1", "loss", timing=20_000_000_000)
        self.transition("sbc1", "reconnected", timing=30_000_000_000)
        observation_value = self.qualification_observation("sbc1")
        observation_value["reboot"]["rebootScheduledAtEpochMs"] += 1
        observation = Path(state["evidenceDirectory"]) / "sbc1-observation.json"
        observation.write_bytes(journal.canonical_bytes(observation_value))
        os.chmod(observation, 0o600)
        with self.assertRaisesRegex(journal.JournalError, "timing differs"):
            journal._mutate(
                self.args(node="sbc1", observation_file=str(observation)),
                "qualified",
            )

    def test_complete_is_idempotent_and_binds_fixed_evidence(self) -> None:
        state = self.begin()
        self.arm(state, "sbc1", 10_000_000_000)
        self.transition("sbc1", "scheduled", timing=10_500_000_000)
        self.transition("sbc1", "loss", timing=20_000_000_000)
        self.transition("sbc1", "reconnected", timing=30_000_000_000)
        state = self.qualify(state, "sbc1")
        self.arm(state, "sbc2", 100_000_000_000)
        self.transition("sbc2", "scheduled", timing=100_500_000_000)
        self.transition("sbc2", "loss", timing=110_000_000_000)
        self.transition("sbc2", "reconnected", timing=120_000_000_000)
        state = self.qualify(state, "sbc2")
        acceptance = Path(state["evidenceDirectory"]) / "acceptance.json"
        acceptance.write_bytes(
            journal.canonical_bytes(
                {"status": "ACTIVE_SYNTHETIC_EDGE_REBOOTS_QUALIFIED"}
            )
        )
        os.chmod(acceptance, 0o600)
        completed = dict(
            journal._complete(self.args(acceptance_file=str(acceptance)))
        )
        self.assertEqual(completed["status"], "COMPLETE")
        self.assertEqual(
            dict(journal._complete(self.args(acceptance_file=str(acceptance)))),
            completed,
        )
        acceptance.write_bytes(
            journal.canonical_bytes(
                {
                    "status": "ACTIVE_SYNTHETIC_EDGE_REBOOTS_QUALIFIED",
                    "tampered": True,
                }
            )
        )
        with self.assertRaisesRegex(journal.JournalError, "evidence binding"):
            self.begin()


if __name__ == "__main__":
    unittest.main()
