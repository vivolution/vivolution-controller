from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "scripts" / "active_edge_reboot_journal.py"
ROLLOVER_PLAYBOOK = (
    ROOT / "deploy" / "playbooks" / "rollover-active-edge-reboot.yml"
)

SPEC = importlib.util.spec_from_file_location("active_edge_reboot_journal", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
journal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(journal)


class InjectedCrash(BaseException):
    pass


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

    def abort(self) -> dict[str, object]:
        state = self.begin()
        self.arm(state, "sbc1", 10_000_000_000)
        return dict(
            journal._mutate(
                self.args(
                    node="sbc1",
                    reason="READY_BOUND_EXPIRED_RECONCILED",
                ),
                "abort",
            )
        )

    def rollover(self, terminal: dict[str, object]) -> dict[str, object]:
        return dict(
            journal._rollover(
                self.args(
                    acknowledgement=journal.ROLLOVER_ACKNOWLEDGEMENT,
                    terminal_run_id=terminal["runId"],
                    terminal_state_digest=terminal["stateDigest"],
                )
            )
        )

    def assert_rollover_metadata_staging_recovers(
        self, file_name: str, phase: str
    ) -> None:
        terminal = self.abort()
        target = Path(terminal["evidenceDirectory"]) / file_name

        def checkpoint(path: Path, observed_phase: str) -> None:
            if path == target and observed_phase == phase:
                raise InjectedCrash(f"{file_name}:{phase}")

        with mock.patch.object(
            journal,
            "_exclusive_write_checkpoint",
            side_effect=checkpoint,
        ):
            with self.assertRaises(InjectedCrash):
                self.rollover(terminal)
        staging = journal._exclusive_staging_path(target)
        self.assertFalse(target.exists())
        self.assertTrue(staging.is_file())
        if phase == "after-create":
            self.assertEqual(staging.stat().st_size, 0)
        else:
            self.assertGreater(staging.stat().st_size, 0)

        recovered = self.rollover(terminal)
        self.assertEqual(
            recovered["status"],
            "ARCHIVED_RECONCILED_RUN_AND_ALLOCATED_FRESH_RUN",
        )
        self.assertTrue(target.is_file())
        self.assertFalse(staging.exists())

    def assert_preexisting_rollover_staging_is_preserved_and_rejected(
        self, final_name: str
    ) -> None:
        terminal = self.abort()
        staging = journal._exclusive_staging_path(
            Path(terminal["evidenceDirectory"]) / final_name
        )
        retained = f"unrelated:{final_name}\n".encode("utf-8")
        staging.write_bytes(retained)
        os.chmod(staging, 0o600)
        active_path = (
            self.root / journal.STATE_DIRECTORY_NAME / journal.STATE_FILE_NAME
        )
        active_before = active_path.read_bytes()
        runs_before = {path.name for path in self.root.glob("20*-*")}

        with self.assertRaisesRegex(journal.JournalError, "reserved"):
            self.rollover(terminal)

        self.assertEqual(staging.read_bytes(), retained)
        self.assertEqual(active_path.read_bytes(), active_before)
        self.assertEqual(
            {path.name for path in self.root.glob("20*-*")}, runs_before
        )
        self.assertFalse(
            (self.root / journal.ROLLOVER_TRANSACTION_FILE_NAME).exists()
        )
        self.assertEqual(
            list(self.root.glob(".active-run.rollover-*")),
            [],
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

    def test_rollover_preserves_and_manifests_terminal_evidence(self) -> None:
        terminal = self.abort()
        evidence = Path(terminal["evidenceDirectory"])
        retained = evidence / "retained-partial-evidence.json"
        retained_content = journal.canonical_bytes({"retained": True})
        retained.write_bytes(retained_content)
        os.chmod(retained, 0o600)

        result = self.rollover(terminal)
        self.assertEqual(
            result["status"],
            "ARCHIVED_RECONCILED_RUN_AND_ALLOCATED_FRESH_RUN",
        )
        self.assertEqual(result["archivedRunId"], terminal["runId"])
        self.assertEqual(result["archivedStateDigest"], terminal["stateDigest"])
        self.assertEqual(retained.read_bytes(), retained_content)

        archived_state = json.loads(
            (
                evidence
                / journal.ARCHIVED_JOURNAL_DIRECTORY_NAME
                / journal.STATE_FILE_NAME
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(archived_state, terminal)
        manifest = json.loads(
            (evidence / journal.ROLLOVER_MANIFEST_FILE_NAME).read_text(
                encoding="utf-8"
            )
        )
        inventory = {item["path"]: item for item in manifest["files"]}
        self.assertEqual(
            inventory["retained-partial-evidence.json"]["sha256"],
            journal.sha256_digest(retained_content),
        )
        self.assertIn("journal/state.json", inventory)
        self.assertEqual(manifest["manifestDigest"], result["archiveManifestDigest"])

        fresh = self.begin()
        self.assertEqual(fresh["runId"], result["newRunId"])
        self.assertEqual(fresh["stateDigest"], result["newStateDigest"])
        self.assertEqual(fresh["status"], "IN_PROGRESS")
        self.assertEqual(fresh["currentNode"], "sbc1")
        self.assertEqual(len(list(self.root.glob("20*-*"))), 2)
        self.assertEqual(self.rollover(terminal), result)

    def test_exclusive_write_recovers_every_durable_boundary(self) -> None:
        phases = (
            "after-create",
            "after-write",
            "after-file-fsync",
            "after-link",
            "after-link-fsync",
            "after-unlink",
            "after-unlink-fsync",
        )
        content = journal.canonical_bytes({"exclusive": "authority"})
        for index, phase in enumerate(phases):
            with self.subTest(phase=phase):
                target = self.root / f"exclusive-{index}.json"

                def checkpoint(path: Path, observed_phase: str) -> None:
                    if path == target and observed_phase == phase:
                        raise InjectedCrash(phase)

                with mock.patch.object(
                    journal,
                    "_exclusive_write_checkpoint",
                    side_effect=checkpoint,
                ):
                    with self.assertRaises(InjectedCrash):
                        journal._atomic_write(target, content, replace=False)
                journal._atomic_write(target, content, replace=False)
                self.assertEqual(target.read_bytes(), content)
                self.assertEqual(target.stat().st_nlink, 1)
                self.assertFalse(journal._exclusive_staging_path(target).exists())

    def test_exclusive_link_recovery_covers_every_authority_filename(self) -> None:
        names = (
            journal.ROLLOVER_TRANSACTION_FILE_NAME,
            journal.ROLLOVER_MANIFEST_FILE_NAME,
            journal.ROLLOVER_RECEIPT_FILE_NAME,
            "sbc1-preflight.json",
        )
        for index, name in enumerate(names):
            with self.subTest(name=name):
                directory = self.root / f"exclusive-authority-{index}"
                directory.mkdir(mode=0o700)
                target = directory / name
                content = journal.canonical_bytes({"authority": name})

                def checkpoint(path: Path, phase: str) -> None:
                    if path == target and phase == "after-link":
                        raise InjectedCrash(name)

                with mock.patch.object(
                    journal,
                    "_exclusive_write_checkpoint",
                    side_effect=checkpoint,
                ):
                    with self.assertRaises(InjectedCrash):
                        journal._atomic_write(target, content, replace=False)
                self.assertEqual(target.stat().st_nlink, 2)
                journal._atomic_write(target, content, replace=False)
                self.assertEqual(target.read_bytes(), content)
                self.assertEqual(target.stat().st_nlink, 1)

    def test_exclusive_recovery_rejects_symlinks_and_unaccounted_hardlinks(self) -> None:
        content = journal.canonical_bytes({"protected": True})
        authority = self.root / "authority.json"
        authority.write_bytes(content)
        os.chmod(authority, 0o600)

        symlink_target = self.root / "symlink-target.json"
        symlink_target.symlink_to(authority)
        with self.assertRaisesRegex(journal.JournalError, "linked"):
            journal._atomic_write(symlink_target, content, replace=False)

        hardlink_target = self.root / "hardlink-target.json"
        os.link(authority, hardlink_target)
        with self.assertRaisesRegex(journal.JournalError, "unaccounted hard link"):
            journal._atomic_write(hardlink_target, content, replace=False)

    def test_rollover_requires_exact_separate_authority_without_mutation(self) -> None:
        terminal = self.abort()
        active_before = (
            self.root / journal.STATE_DIRECTORY_NAME / journal.STATE_FILE_NAME
        ).read_bytes()
        with self.assertRaisesRegex(journal.JournalError, "acknowledgement"):
            journal._rollover(
                self.args(
                    acknowledgement=journal.ACKNOWLEDGEMENT,
                    terminal_run_id=terminal["runId"],
                    terminal_state_digest=terminal["stateDigest"],
                )
            )
        with self.assertRaisesRegex(journal.JournalError, "exact terminal"):
            journal._rollover(
                self.args(
                    acknowledgement=journal.ROLLOVER_ACKNOWLEDGEMENT,
                    terminal_run_id=terminal["runId"],
                    terminal_state_digest="sha256:" + "0" * 64,
                )
            )
        self.assertEqual(
            (
                self.root / journal.STATE_DIRECTORY_NAME / journal.STATE_FILE_NAME
            ).read_bytes(),
            active_before,
        )
        self.assertFalse(
            (self.root / journal.ROLLOVER_TRANSACTION_FILE_NAME).exists()
        )

    def test_preexisting_manifest_staging_is_preserved_and_rejected(self) -> None:
        self.assert_preexisting_rollover_staging_is_preserved_and_rejected(
            journal.ROLLOVER_MANIFEST_FILE_NAME
        )

    def test_preexisting_receipt_staging_is_preserved_and_rejected(self) -> None:
        self.assert_preexisting_rollover_staging_is_preserved_and_rejected(
            journal.ROLLOVER_RECEIPT_FILE_NAME
        )

    def test_rollover_rejects_an_in_progress_run(self) -> None:
        current = self.begin()
        with self.assertRaisesRegex(journal.JournalError, "exact terminal"):
            self.rollover(current)
        self.assertEqual(self.begin(), current)

    def test_pending_rollover_blocks_begin_and_recovers_before_archive(self) -> None:
        terminal = self.abort()
        with mock.patch.object(
            journal,
            "_archive_terminal_journal",
            side_effect=OSError("injected pre-archive crash"),
        ):
            with self.assertRaisesRegex(OSError, "injected"):
                self.rollover(terminal)
        self.assertTrue(
            (self.root / journal.ROLLOVER_TRANSACTION_FILE_NAME).exists()
        )
        with self.assertRaisesRegex(journal.JournalError, "rollover transaction"):
            self.begin()
        recovered = self.rollover(terminal)
        self.assertEqual(
            recovered["status"],
            "ARCHIVED_RECONCILED_RUN_AND_ALLOCATED_FRESH_RUN",
        )

    def test_rollover_recovers_transaction_link_before_staging_unlink(self) -> None:
        terminal = self.abort()
        transaction = self.root / journal.ROLLOVER_TRANSACTION_FILE_NAME

        def checkpoint(path: Path, phase: str) -> None:
            if path == transaction and phase == "after-link":
                raise InjectedCrash("transaction linked")

        with mock.patch.object(
            journal,
            "_exclusive_write_checkpoint",
            side_effect=checkpoint,
        ):
            with self.assertRaises(InjectedCrash):
                self.rollover(terminal)
        self.assertEqual(transaction.stat().st_nlink, 2)
        recovered = self.rollover(terminal)
        self.assertEqual(
            recovered["status"],
            "ARCHIVED_RECONCILED_RUN_AND_ALLOCATED_FRESH_RUN",
        )
        self.assertFalse(journal._exclusive_staging_path(transaction).exists())

    def test_rollover_recovers_empty_manifest_staging_before_target_link(self) -> None:
        self.assert_rollover_metadata_staging_recovers(
            journal.ROLLOVER_MANIFEST_FILE_NAME,
            "after-create",
        )

    def test_rollover_recovers_full_manifest_staging_before_target_link(self) -> None:
        self.assert_rollover_metadata_staging_recovers(
            journal.ROLLOVER_MANIFEST_FILE_NAME,
            "after-file-fsync",
        )

    def test_rollover_recovers_empty_receipt_staging_before_target_link(self) -> None:
        self.assert_rollover_metadata_staging_recovers(
            journal.ROLLOVER_RECEIPT_FILE_NAME,
            "after-create",
        )

    def test_rollover_recovers_full_receipt_staging_before_target_link(self) -> None:
        self.assert_rollover_metadata_staging_recovers(
            journal.ROLLOVER_RECEIPT_FILE_NAME,
            "after-file-fsync",
        )

    def test_rollover_recovers_empty_initializer_after_mkdir(self) -> None:
        terminal = self.abort()
        original = journal._atomic_write

        def fail_initializer(
            path: Path, content: bytes, *, replace: bool
        ) -> None:
            if (
                path.name == journal.STATE_FILE_NAME
                and path.parent.name.startswith(".active-run.rollover-")
            ):
                raise InjectedCrash("initializer directory created")
            original(path, content, replace=replace)

        with mock.patch.object(
            journal,
            "_atomic_write",
            side_effect=fail_initializer,
        ):
            with self.assertRaises(InjectedCrash):
                self.rollover(terminal)
        transaction = json.loads(
            (self.root / journal.ROLLOVER_TRANSACTION_FILE_NAME).read_text(
                encoding="utf-8"
            )
        )
        initializer = journal._rollover_initializer(
            self.root, transaction["newRunId"]
        )
        self.assertTrue(initializer.is_dir())
        self.assertEqual(list(initializer.iterdir()), [])

        recovered = self.rollover(terminal)
        self.assertEqual(recovered["newRunId"], transaction["newRunId"])
        self.assertEqual(self.begin()["runId"], transaction["newRunId"])

    def test_rollover_recovers_after_atomic_terminal_archive(self) -> None:
        terminal = self.abort()
        original = journal._archive_terminal_journal

        def archive_then_crash(*args: object, **kwargs: object) -> object:
            value = original(*args, **kwargs)
            raise OSError("injected post-archive crash")

        with mock.patch.object(
            journal,
            "_archive_terminal_journal",
            side_effect=archive_then_crash,
        ):
            with self.assertRaisesRegex(OSError, "injected"):
                self.rollover(terminal)
        self.assertFalse((self.root / journal.STATE_DIRECTORY_NAME).exists())
        self.assertTrue(
            (
                Path(terminal["evidenceDirectory"])
                / journal.ARCHIVED_JOURNAL_DIRECTORY_NAME
                / journal.STATE_FILE_NAME
            ).exists()
        )
        with self.assertRaisesRegex(journal.JournalError, "rollover transaction"):
            self.begin()
        recovered = self.rollover(terminal)
        self.assertEqual(recovered["archivedRunId"], terminal["runId"])

    def test_rollover_recovers_after_fresh_journal_activation(self) -> None:
        terminal = self.abort()
        original = journal._activate_rollover_journal

        def activate_then_crash(*args: object, **kwargs: object) -> object:
            value = original(*args, **kwargs)
            raise OSError("injected post-activation crash")

        with mock.patch.object(
            journal,
            "_activate_rollover_journal",
            side_effect=activate_then_crash,
        ):
            with self.assertRaisesRegex(OSError, "injected"):
                self.rollover(terminal)
        with self.assertRaisesRegex(journal.JournalError, "rollover transaction"):
            self.begin()
        recovered = self.rollover(terminal)
        self.assertEqual(self.begin()["runId"], recovered["newRunId"])

    def test_rollover_receipt_detects_retained_evidence_tampering(self) -> None:
        terminal = self.abort()
        evidence = Path(terminal["evidenceDirectory"])
        retained = evidence / "retained.json"
        retained.write_bytes(journal.canonical_bytes({"value": 1}))
        os.chmod(retained, 0o600)
        self.rollover(terminal)
        retained.write_bytes(journal.canonical_bytes({"value": 2}))
        with self.assertRaisesRegex(journal.JournalError, "retained evidence"):
            self.rollover(terminal)

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


class ActiveEdgeRebootRolloverPlaybookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = ROLLOVER_PLAYBOOK.read_text(encoding="utf-8")

    def test_rollover_is_local_only_and_carries_no_reboot_authority(self) -> None:
        self.assertEqual(self.source.count("  hosts:"), 1)
        self.assertIn("hosts: localhost", self.source)
        self.assertNotIn("hosts: edge_nodes", self.source)
        self.assertNotIn("ansible.builtin.reboot", self.source)
        self.assertNotIn("wait_for_connection", self.source)
        self.assertNotIn("vivolution-active-edge-reboot-qualifier", self.source)
        self.assertNotIn("REBOOT_ACTIVE_SYNTHETIC_EDGES_SBC1_THEN_SBC2_ONCE", self.source)

    def test_rollover_requires_exact_terminal_identity_and_separate_ack(self) -> None:
        for token in (
            journal.ROLLOVER_ACKNOWLEDGEMENT,
            "edge_active_reboot_rollover_terminal_run_id",
            "edge_active_reboot_rollover_terminal_state_digest",
            "rollover-archive-manifest.json",
            "rollover-receipt.json",
            "journal/state.json",
            "nodes.sbc1.phase ==\n            'PENDING'",
            "nodes.sbc2.phase ==\n            'PENDING'",
        ):
            self.assertIn(token, self.source)


if __name__ == "__main__":
    unittest.main()
