from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import remediate_edge_os_disk_sku as remediation  # noqa: E402


SUBSCRIPTION = remediation.EXPECTED_SUBSCRIPTION_ID
TENANT = remediation.EXPECTED_TENANT_ID


class FakeFleet:
    def __init__(self) -> None:
        self.azure_commands: list[list[str]] = []
        self.remote_commands: list[tuple[str, list[str], bool]] = []
        self.power = {role: "PowerState/running" for role in remediation.NODE_ORDER}
        self.sku = {role: remediation.SOURCE_SKU for role in remediation.NODE_ORDER}
        self.boot_generation = {role: 1 for role in remediation.NODE_ORDER}
        self.disk_update_failures = 0
        self.fixture_counter = 0
        self.fixture_failures: set[int] = set()
        self.fixture_interruptions: set[int] = set()
        self.principals = {
            "sbc1": "11111111-1111-4111-8111-111111111111",
            "sbc2": "22222222-2222-4222-8222-222222222222",
        }
        self.unique_ids = {
            "sbc1": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "sbc2": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        }
        self.disk_names = {
            "sbc1": "viv-sbc-poc-sbc1-osdisk_f7c4802c379144a5ad2c32424f19f79a",
            "sbc2": "viv-sbc-poc-sbc2-osdisk_276a881c6092432da7770cad78a839a3",
        }

    @staticmethod
    def resource_id(kind: str, name: str) -> str:
        return (
            f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{remediation.RESOURCE_GROUP}"
            f"/providers/{kind}/{name}"
        )

    def role_from_name(self, name: str) -> str:
        for spec in remediation.NODE_SPECS:
            if name in {
                spec.vm_name,
                spec.nic_name,
                spec.public_ip_name,
                self.disk_names[spec.role],
            }:
                return spec.role
        raise AssertionError(name)

    def azure(self, argv):
        argv = list(argv)
        self.azure_commands.append(argv)
        if argv[1:3] == ["account", "show"]:
            return json.dumps({"id": SUBSCRIPTION, "tenantId": TENANT})
        if argv[1:3] == ["group", "show"]:
            return json.dumps(
                {
                    "id": f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{remediation.RESOURCE_GROUP}",
                    "location": remediation.LOCATION,
                    "name": remediation.RESOURCE_GROUP,
                    "provisioningState": "Succeeded",
                }
            )
        if argv[1:3] == ["vm", "show"]:
            name = argv[argv.index("--name") + 1]
            role = self.role_from_name(name)
            spec = remediation.SPEC_BY_ROLE[role]
            return json.dumps(
                {
                    "availabilitySetId": self.resource_id(
                        "Microsoft.Compute/availabilitySets",
                        remediation.AVAILABILITY_SET_NAME,
                    ),
                    "id": self.resource_id("Microsoft.Compute/virtualMachines", name),
                    "identityPrincipalId": self.principals[role],
                    "identityType": "SystemAssigned",
                    "location": remediation.LOCATION,
                    "name": name,
                    "networkInterfaces": [
                        {
                            "deleteOption": "Detach",
                            "id": self.resource_id(
                                "Microsoft.Network/networkInterfaces", spec.nic_name
                            ),
                            "primary": True,
                        }
                    ],
                    "osDiskId": self.resource_id(
                        "Microsoft.Compute/disks", self.disk_names[role]
                    ),
                    "osDiskName": spec.logical_disk_name,
                    "provisioningState": "Succeeded",
                    "vmSize": spec.vm_size,
                }
            )
        if argv[1:3] == ["vm", "get-instance-view"]:
            name = argv[argv.index("--name") + 1]
            role = self.role_from_name(name)
            return json.dumps(
                [
                    {"code": "ProvisioningState/succeeded"},
                    {"code": self.power[role]},
                ]
            )
        if argv[1:3] == ["disk", "show"]:
            name = argv[argv.index("--name") + 1]
            role = self.role_from_name(name)
            spec = remediation.SPEC_BY_ROLE[role]
            return json.dumps(
                {
                    "diskSizeGiB": spec.disk_size_gib,
                    "encryptionType": "EncryptionAtRestWithPlatformKey",
                    "id": self.resource_id("Microsoft.Compute/disks", name),
                    "location": remediation.LOCATION,
                    "managedBy": self.resource_id(
                        "Microsoft.Compute/virtualMachines", spec.vm_name
                    ),
                    "name": name,
                    "networkAccessPolicy": "DenyAll",
                    "provisioningState": "Succeeded",
                    "publicNetworkAccess": "Disabled",
                    "securityType": "TrustedLaunch",
                    "sku": self.sku[role],
                    "uniqueId": self.unique_ids[role],
                }
            )
        if argv[1:4] == ["network", "nic", "show"]:
            name = argv[argv.index("--name") + 1]
            role = self.role_from_name(name)
            spec = remediation.SPEC_BY_ROLE[role]
            return json.dumps(
                {
                    "id": self.resource_id("Microsoft.Network/networkInterfaces", name),
                    "ipConfigurations": [
                        {
                            "name": "ipconfig1",
                            "primary": True,
                            "privateIpAddress": spec.private_ip,
                            "privateIpAllocationMethod": "Static",
                            "publicIpId": self.resource_id(
                                "Microsoft.Network/publicIPAddresses",
                                spec.public_ip_name,
                            ),
                        }
                    ],
                    "location": remediation.LOCATION,
                    "name": name,
                    "provisioningState": "Succeeded",
                    "vmId": self.resource_id(
                        "Microsoft.Compute/virtualMachines", spec.vm_name
                    ),
                }
            )
        if argv[1:4] == ["network", "public-ip", "show"]:
            name = argv[argv.index("--name") + 1]
            role = self.role_from_name(name)
            spec = remediation.SPEC_BY_ROLE[role]
            return json.dumps(
                {
                    "allocationMethod": "Static",
                    "id": self.resource_id("Microsoft.Network/publicIPAddresses", name),
                    "ipAddress": spec.public_ip,
                    "location": remediation.LOCATION,
                    "name": name,
                    "provisioningState": "Succeeded",
                    "sku": "Standard",
                    "tier": "Regional",
                }
            )
        if argv[1:3] == ["vm", "deallocate"]:
            name = argv[argv.index("--ids") + 1].rsplit("/", 1)[-1]
            role = self.role_from_name(name)
            self.assert_no_other_node_deallocated(role)
            self.power[role] = "PowerState/deallocated"
            return ""
        if argv[1:3] == ["disk", "update"]:
            name = argv[argv.index("--ids") + 1].rsplit("/", 1)[-1]
            role = self.role_from_name(name)
            if self.power[role] != "PowerState/deallocated":
                raise AssertionError("disk update while VM allocated")
            if self.disk_update_failures:
                self.disk_update_failures -= 1
                raise remediation.DiskSkuRemediationError("injected disk update failure")
            self.sku[role] = remediation.TARGET_SKU
            return ""
        if argv[1:3] == ["vm", "start"]:
            name = argv[argv.index("--ids") + 1].rsplit("/", 1)[-1]
            role = self.role_from_name(name)
            self.power[role] = "PowerState/running"
            self.boot_generation[role] += 1
            return ""
        raise AssertionError(argv)

    def assert_no_other_node_deallocated(self, role: str) -> None:
        others = [
            item
            for item in remediation.NODE_ORDER
            if item != role and self.power[item] == "PowerState/deallocated"
        ]
        if others:
            raise AssertionError(f"simultaneous Edge deallocation: {others}")

    @staticmethod
    def status(role: str):
        sequence = 3 if role == "sbc1" else 2
        slot = "A" if role == "sbc1" else "B"
        active = {
            "kind": "CANDIDATE",
            "manifestDigest": f"sha256:{('c' if role == 'sbc1' else 'd') * 64}",
            "relativePath": f"slots/{slot}/000000000000000{sequence}-{'a' * 64}",
            "releaseDigest": f"sha256:{'b' * 64}",
            "sequence": sequence,
            "slot": slot,
        }
        return {
            "active": active,
            "apiVersion": "edge.vivolution.ae/runtime/v0.1",
            "highestSeenSequence": sequence,
            "journalPresent": False,
            "kind": "EdgeRuntimeStatus",
            "lastEvidenceDigest": f"sha256:{'e' * 64}",
            "previous": None,
        }

    def remote(self, endpoint, argv, become):
        argv = list(argv)
        self.remote_commands.append((endpoint, argv, become))
        if endpoint in remediation.NODE_ORDER and self.power[endpoint] != "PowerState/running":
            raise remediation.DiskSkuRemediationError(f"{endpoint} offline")
        if argv == ["/bin/hostname"]:
            return remediation.SPEC_BY_ROLE[endpoint].vm_name + "\n"
        if argv == ["/usr/bin/cat", "/proc/sys/kernel/random/boot_id"]:
            generation = self.boot_generation[endpoint]
            return f"00000000-0000-4000-8000-{generation:012d}\n"
        if argv == ["/usr/local/sbin/vivolution-edge-runtime", "status"]:
            return json.dumps(self.status(endpoint))
        if argv == ["/usr/local/sbin/vivolution-edge-runtime", "health"]:
            status = self.status(endpoint)
            return json.dumps(
                {
                    "active": status["active"],
                    "apiVersion": "edge.vivolution.ae/runtime/v0.1",
                    "highestSeenSequence": status["highestSeenSequence"],
                    "kind": "EdgeRuntimeHealth",
                    "runtimeChecks": [
                        {"name": "systemd-opensips", "status": "PASSED"}
                    ],
                }
            )
        if argv and argv[0] == "/usr/bin/sha256sum":
            return "\n".join(
                [
                    f"{'1' * 64}  /etc/vivolution-edge/node-facts.json",
                    f"{'2' * 64}  /var/lib/vivolution-edge/runtime/runtime-authority.json",
                ]
            ) + "\n"
        if argv[:2] == ["/usr/bin/systemctl", "is-active"]:
            return "active\n"
        if argv == ["/usr/local/libexec/vivolution-voice-fixture-readiness"]:
            return "READY\n"
        if argv and argv[-2:-1] == ["/usr/local/sbin/vivolution-voice-fixture-test"]:
            role = argv[-1]
            self.fixture_counter += 1
            if self.fixture_counter in self.fixture_interruptions:
                raise KeyboardInterrupt
            if self.fixture_counter in self.fixture_failures:
                raise remediation.DiskSkuRemediationError("injected fixture failure")
            return f"fixture test 20260831T010101Z-{role}-{self.fixture_counter}: PASS\n"
        raise AssertionError((endpoint, argv, become))


class RemediationTests(unittest.TestCase):
    def test_ssh_known_hosts_path_with_spaces_is_config_quoted(self):
        with tempfile.TemporaryDirectory(prefix="disk sku ssh ") as raw:
            root = Path(raw)
            key = root / "private key"
            known = root / "known hosts"
            key.write_text("private")
            known.write_text("host key")
            os.chmod(key, 0o600)
            os.chmod(known, 0o600)
            subprocess_result = mock.Mock(
                returncode=0, stdout="ok\n", stderr=""
            )
            with mock.patch.object(
                remediation.subprocess, "run", return_value=subprocess_result
            ) as run:
                runner = remediation.SshRemoteRunner(key, known)
                self.assertEqual(runner("sbc1", ["/bin/hostname"], False), "ok\n")
            command = run.call_args.args[0]
            option = command[command.index("-o", command.index("StrictHostKeyChecking=yes") + 1) + 1]
            self.assertEqual(option, f'UserKnownHostsFile="{known.resolve()}"')
            self.assertIn("ServerAliveInterval=10", command)
            self.assertIn("ServerAliveCountMax=3", command)
            self.assertEqual(run.call_args.kwargs["timeout"], 240)

    def test_ssh_local_timeout_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            key = root / "key"
            known = root / "known_hosts"
            key.write_text("private")
            known.write_text("host key")
            os.chmod(key, 0o600)
            os.chmod(known, 0o600)
            runner = remediation.SshRemoteRunner(key, known)
            with mock.patch.object(
                remediation.subprocess,
                "run",
                side_effect=remediation.subprocess.TimeoutExpired("ssh", 240),
            ):
                with self.assertRaisesRegex(
                    remediation.DiskSkuRemediationError,
                    "remote command timed out on sbc2",
                ):
                    runner("sbc2", ["/bin/hostname"], False)

    def test_plan_is_read_only_and_binds_sbc2_then_sbc1_exactly(self):
        fleet = FakeFleet()
        plan = remediation.plan_remediation(
            SUBSCRIPTION,
            TENANT,
            azure_runner=fleet.azure,
            remote_runner=fleet.remote,
        )
        self.assertEqual(plan["nodeOrder"], ["sbc2", "sbc1"])
        self.assertEqual(
            [action["role"] for action in plan["actions"]], ["sbc2", "sbc1"]
        )
        self.assertRegex(plan["planSha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            plan["nodes"]["sbc2"]["control"]["disk"]["uniqueId"],
            fleet.unique_ids["sbc2"],
        )
        self.assertFalse(
            any(
                command[1:3]
                in (["vm", "deallocate"], ["disk", "update"], ["vm", "start"])
                for command in fleet.azure_commands
            )
        )
        self.assertFalse(
            any("vivolution-voice-fixture-test" in argv for _, argv, _ in fleet.remote_commands)
        )

    def test_apply_serializes_exact_mutations_and_calls(self):
        fleet = FakeFleet()
        plan = remediation.plan_remediation(
            SUBSCRIPTION,
            TENANT,
            azure_runner=fleet.azure,
            remote_runner=fleet.remote,
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            journal = root / "journal.json"
            result = remediation.apply_remediation(
                SUBSCRIPTION,
                TENANT,
                approved_plan_sha256=plan["planSha256"],
                confirmation=remediation.CONFIRMATION,
                journal_path=journal,
                azure_runner=fleet.azure,
                remote_runner=fleet.remote,
                sleeper=lambda _: None,
                lock_path=root / "fleet.lock",
            )
            state = json.loads(journal.read_text())

        self.assertEqual(result["status"], "POC_EDGE_OS_DISK_SKU_REMEDIATION_APPLIED")
        self.assertEqual(state["status"], "COMPLETE")
        self.assertEqual(
            [state["nodes"][role]["phase"] for role in remediation.NODE_ORDER],
            ["QUALIFIED", "QUALIFIED"],
        )
        self.assertTrue(
            all(state["nodes"][role]["outagePeerCall"] for role in remediation.NODE_ORDER)
        )
        mutations = [
            command
            for command in fleet.azure_commands
            if command[1:3]
            in (["vm", "deallocate"], ["disk", "update"], ["vm", "start"])
        ]
        self.assertEqual(
            [command[1:3] for command in mutations],
            [
                ["vm", "deallocate"],
                ["disk", "update"],
                ["vm", "start"],
                ["vm", "deallocate"],
                ["disk", "update"],
                ["vm", "start"],
            ],
        )
        self.assertIn("viv-sbc-poc-sbc2", mutations[0][mutations[0].index("--ids") + 1])
        self.assertIn("viv-sbc-poc-sbc1", mutations[3][mutations[3].index("--ids") + 1])
        self.assertTrue(all("--ids" in command for command in mutations))
        fixture_roles = [
            argv[-1]
            for _, argv, _ in fleet.remote_commands
            if "/usr/local/sbin/vivolution-voice-fixture-test" in argv
        ]
        self.assertEqual(fixture_roles, ["sbc1", "sbc1", "sbc2", "sbc2", "sbc2", "sbc1"])
        readiness = [
            become
            for _, argv, become in fleet.remote_commands
            if argv == ["/usr/local/libexec/vivolution-voice-fixture-readiness"]
        ]
        self.assertTrue(readiness)
        self.assertTrue(all(readiness))
        self.assertEqual(fleet.sku, {"sbc2": remediation.TARGET_SKU, "sbc1": remediation.TARGET_SKU})
        self.assertEqual(fleet.power, {"sbc2": "PowerState/running", "sbc1": "PowerState/running"})

    def test_failed_update_recovers_availability_and_same_journal_resumes(self):
        fleet = FakeFleet()
        plan = remediation.plan_remediation(
            SUBSCRIPTION,
            TENANT,
            azure_runner=fleet.azure,
            remote_runner=fleet.remote,
        )
        fleet.disk_update_failures = 1
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            journal = root / "journal.json"
            with self.assertRaisesRegex(
                remediation.DiskSkuRemediationError,
                "availability recovery=RECOVERED_RUNNING_HEALTHY",
            ):
                remediation.apply_remediation(
                    SUBSCRIPTION,
                    TENANT,
                    approved_plan_sha256=plan["planSha256"],
                    confirmation=remediation.CONFIRMATION,
                    journal_path=journal,
                    azure_runner=fleet.azure,
                    remote_runner=fleet.remote,
                    sleeper=lambda _: None,
                    lock_path=root / "fleet.lock",
                )
            interrupted = json.loads(journal.read_text())
            self.assertEqual(interrupted["nodes"]["sbc2"]["phase"], "SKU_UPDATE_REQUESTED")
            self.assertEqual(fleet.power["sbc2"], "PowerState/running")
            result = remediation.apply_remediation(
                SUBSCRIPTION,
                TENANT,
                approved_plan_sha256=plan["planSha256"],
                confirmation=remediation.CONFIRMATION,
                journal_path=journal,
                azure_runner=fleet.azure,
                remote_runner=fleet.remote,
                sleeper=lambda _: None,
                lock_path=root / "fleet.lock",
            )
        self.assertEqual(result["status"], "POC_EDGE_OS_DISK_SKU_REMEDIATION_APPLIED")

    def test_failed_outage_call_stays_deallocated_phase_and_resume_reproves_it(self):
        fleet = FakeFleet()
        plan = remediation.plan_remediation(
            SUBSCRIPTION,
            TENANT,
            azure_runner=fleet.azure,
            remote_runner=fleet.remote,
        )
        fleet.fixture_failures.add(2)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            journal = root / "journal.json"
            with self.assertRaisesRegex(
                remediation.DiskSkuRemediationError,
                "availability recovery=RECOVERED_RUNNING_HEALTHY",
            ):
                remediation.apply_remediation(
                    SUBSCRIPTION,
                    TENANT,
                    approved_plan_sha256=plan["planSha256"],
                    confirmation=remediation.CONFIRMATION,
                    journal_path=journal,
                    azure_runner=fleet.azure,
                    remote_runner=fleet.remote,
                    sleeper=lambda _: None,
                    lock_path=root / "fleet.lock",
                )
            interrupted = json.loads(journal.read_text())
            self.assertEqual(interrupted["nodes"]["sbc2"]["phase"], "DEALLOCATED")
            self.assertIsNone(interrupted["nodes"]["sbc2"]["outagePeerCall"])
            result = remediation.apply_remediation(
                SUBSCRIPTION,
                TENANT,
                approved_plan_sha256=plan["planSha256"],
                confirmation=remediation.CONFIRMATION,
                journal_path=journal,
                azure_runner=fleet.azure,
                remote_runner=fleet.remote,
                sleeper=lambda _: None,
                lock_path=root / "fleet.lock",
            )
            final = json.loads(journal.read_text())
        self.assertEqual(result["status"], "POC_EDGE_OS_DISK_SKU_REMEDIATION_APPLIED")
        self.assertTrue(final["nodes"]["sbc2"]["outagePeerCall"])

    def test_complete_rerun_reproves_live_sku_and_runtime(self):
        fleet = FakeFleet()
        plan = remediation.plan_remediation(
            SUBSCRIPTION,
            TENANT,
            azure_runner=fleet.azure,
            remote_runner=fleet.remote,
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            journal = root / "journal.json"
            remediation.apply_remediation(
                SUBSCRIPTION,
                TENANT,
                approved_plan_sha256=plan["planSha256"],
                confirmation=remediation.CONFIRMATION,
                journal_path=journal,
                azure_runner=fleet.azure,
                remote_runner=fleet.remote,
                sleeper=lambda _: None,
                lock_path=root / "fleet.lock",
            )
            mutation_count = sum(
                command[1:3]
                in (["vm", "deallocate"], ["disk", "update"], ["vm", "start"])
                for command in fleet.azure_commands
            )
            fleet.sku["sbc2"] = remediation.SOURCE_SKU
            with self.assertRaisesRegex(
                remediation.DiskSkuRemediationError, "final SKU verification failed"
            ):
                remediation.apply_remediation(
                    SUBSCRIPTION,
                    TENANT,
                    approved_plan_sha256=plan["planSha256"],
                    confirmation=remediation.CONFIRMATION,
                    journal_path=journal,
                    azure_runner=fleet.azure,
                    remote_runner=fleet.remote,
                    sleeper=lambda _: None,
                    lock_path=root / "fleet.lock",
                )
        self.assertEqual(
            mutation_count,
            sum(
                command[1:3]
                in (["vm", "deallocate"], ["disk", "update"], ["vm", "start"])
                for command in fleet.azure_commands
            ),
        )

    def test_fleet_lock_contention_rejects_before_azure_or_remote_access(self):
        fleet = FakeFleet()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            with mock.patch.object(
                remediation.fcntl, "flock", side_effect=BlockingIOError
            ):
                with self.assertRaisesRegex(
                    remediation.DiskSkuRemediationError,
                    "another Edge OS-disk remediation process",
                ):
                    remediation.apply_remediation(
                        SUBSCRIPTION,
                        TENANT,
                        approved_plan_sha256="0" * 64,
                        confirmation=remediation.CONFIRMATION,
                        journal_path=root / "journal.json",
                        azure_runner=fleet.azure,
                        remote_runner=fleet.remote,
                        sleeper=lambda _: None,
                        lock_path=root / "fleet.lock",
                    )
        self.assertEqual(fleet.azure_commands, [])
        self.assertEqual(fleet.remote_commands, [])

    def test_mixed_fresh_fleet_is_fail_closed_without_mutation(self):
        fleet = FakeFleet()
        fleet.sku["sbc2"] = remediation.TARGET_SKU
        plan = remediation.plan_remediation(
            SUBSCRIPTION,
            TENANT,
            azure_runner=fleet.azure,
            remote_runner=fleet.remote,
        )
        self.assertEqual([action["role"] for action in plan["actions"]], ["sbc1"])
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            with self.assertRaisesRegex(
                remediation.DiskSkuRemediationError, "mixed Premium/Standard"
            ):
                remediation.apply_remediation(
                    SUBSCRIPTION,
                    TENANT,
                    approved_plan_sha256=plan["planSha256"],
                    confirmation=remediation.CONFIRMATION,
                    journal_path=root / "journal.json",
                    azure_runner=fleet.azure,
                    remote_runner=fleet.remote,
                    sleeper=lambda _: None,
                    lock_path=root / "fleet.lock",
                )
        self.assertFalse(
            any(
                command[1:3]
                in (["vm", "deallocate"], ["disk", "update"], ["vm", "start"])
                for command in fleet.azure_commands
            )
        )

    def test_keyboard_interrupt_after_deallocation_recovers_availability(self):
        fleet = FakeFleet()
        plan = remediation.plan_remediation(
            SUBSCRIPTION,
            TENANT,
            azure_runner=fleet.azure,
            remote_runner=fleet.remote,
        )
        fleet.fixture_interruptions.add(2)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            journal = root / "journal.json"
            with self.assertRaisesRegex(
                remediation.DiskSkuRemediationError,
                "disk correction interrupted; availability recovery=RECOVERED_RUNNING_HEALTHY",
            ):
                remediation.apply_remediation(
                    SUBSCRIPTION,
                    TENANT,
                    approved_plan_sha256=plan["planSha256"],
                    confirmation=remediation.CONFIRMATION,
                    journal_path=journal,
                    azure_runner=fleet.azure,
                    remote_runner=fleet.remote,
                    sleeper=lambda _: None,
                    lock_path=root / "fleet.lock",
                )
            state = json.loads(journal.read_text())
        self.assertEqual(state["nodes"]["sbc2"]["phase"], "DEALLOCATED")
        self.assertEqual(fleet.power["sbc2"], "PowerState/running")

    def test_wrong_digest_or_acknowledgement_fails_before_mutation(self):
        fleet = FakeFleet()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o700)
            journal = root / "journal.json"
            for digest, acknowledgement in (
                ("0" * 64, remediation.CONFIRMATION),
                ("1" * 64, "wrong"),
            ):
                with self.assertRaises(remediation.DiskSkuRemediationError):
                    remediation.apply_remediation(
                        SUBSCRIPTION,
                        TENANT,
                        approved_plan_sha256=digest,
                        confirmation=acknowledgement,
                        journal_path=journal,
                        azure_runner=fleet.azure,
                        remote_runner=fleet.remote,
                        sleeper=lambda _: None,
                        lock_path=root / "fleet.lock",
                    )
        self.assertFalse(
            any(
                command[1:3]
                in (["vm", "deallocate"], ["disk", "update"], ["vm", "start"])
                for command in fleet.azure_commands
            )
        )

    def test_identity_drift_and_insecure_journal_are_rejected(self):
        fleet = FakeFleet()
        fleet.principals["sbc1"] = fleet.principals["sbc2"]
        with self.assertRaisesRegex(
            remediation.DiskSkuRemediationError, "identities are not distinct"
        ):
            remediation.plan_remediation(
                SUBSCRIPTION,
                TENANT,
                azure_runner=fleet.azure,
                remote_runner=fleet.remote,
            )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            os.chmod(root, 0o755)
            with self.assertRaisesRegex(
                remediation.DiskSkuRemediationError, "mode 0700"
            ):
                remediation._load_journal(root / "journal.json")

    def test_cross_node_reimage_disk_id_is_rejected_before_any_mutation(self):
        fleet = FakeFleet()
        fleet.disk_names["sbc2"] = fleet.disk_names["sbc1"]
        with self.assertRaisesRegex(
            remediation.DiskSkuRemediationError,
            "attached disk identity is unbounded",
        ):
            remediation.plan_remediation(
                SUBSCRIPTION,
                TENANT,
                azure_runner=fleet.azure,
                remote_runner=fleet.remote,
            )
        self.assertFalse(
            any(
                command[1:3]
                in (["vm", "deallocate"], ["disk", "update"], ["vm", "start"])
                for command in fleet.azure_commands
            )
        )


if __name__ == "__main__":
    unittest.main()
