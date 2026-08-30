from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import lockdown_os_disks as lockdown  # noqa: E402


SUBSCRIPTION = "a806949c-240f-4541-8c61-fd97f6d1f953"
REIMAGE_SUFFIX = "f7c4802c379144a5ad2c32424f19f79a"


class FakeAzure:
    def __init__(self) -> None:
        self.commands = []
        self.attachments = dict(lockdown.VM_TO_DISK_BASE)
        self.inventory_override = None
        self.final_inventory_override = None
        self.public_network_access = "Disabled"
        self.final_public_network_access_override = {}
        self.tags_override = None
        self.managed_by_override = {}
        self.disk_id_override = {}
        self.vm_id_override = {}
        self.os_disk_id_override = {}
        self.logical_disk_name_override = {}
        self.final_attachment_override = None
        self.vm_show_count = 0
        self.disk_list_count = 0
        self.disk_show_count = {}
        self.vm_provisioning_state = "Succeeded"

    @staticmethod
    def vm_id(vm_name):
        return (
            f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{lockdown.RESOURCE_GROUP}"
            f"/providers/Microsoft.Compute/virtualMachines/{vm_name}"
        )

    @staticmethod
    def disk_id(disk_name):
        return (
            f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{lockdown.RESOURCE_GROUP}"
            f"/providers/Microsoft.Compute/disks/{disk_name}"
        )

    def vm_for_disk(self, disk_name):
        matches = [vm for vm, attached in self.attachments.items() if attached == disk_name]
        if len(matches) != 1:
            raise AssertionError((disk_name, matches))
        return matches[0]

    def default_inventory(self):
        return [
            {
                "id": self.disk_id(disk_name),
                "managedBy": self.vm_id(vm_name),
                "name": disk_name,
            }
            for vm_name, disk_name in sorted(self.attachments.items())
        ]

    def __call__(self, argv):
        self.commands.append(list(argv))
        if argv[1:3] == ["account", "show"]:
            return json.dumps({"id": SUBSCRIPTION})
        if argv[1:3] == ["group", "show"]:
            return json.dumps({"location": "uaenorth", "name": lockdown.RESOURCE_GROUP})
        if argv[1:3] == ["vm", "show"]:
            vm_name = argv[argv.index("--name") + 1]
            self.vm_show_count += 1
            if self.final_attachment_override is not None and self.vm_show_count > 3:
                disk_name = self.final_attachment_override.get(
                    vm_name, self.attachments[vm_name]
                )
            else:
                disk_name = self.attachments[vm_name]
            return json.dumps(
                {
                    "id": self.vm_id_override.get(vm_name, self.vm_id(vm_name)),
                    "name": vm_name,
                    "provisioningState": self.vm_provisioning_state,
                    "osDiskId": self.os_disk_id_override.get(
                        vm_name, self.disk_id(disk_name)
                    ),
                    "osDiskName": self.logical_disk_name_override.get(
                        vm_name, lockdown.VM_TO_DISK_BASE[vm_name]
                    ),
                }
            )
        if argv[1:3] == ["disk", "list"]:
            self.disk_list_count += 1
            override = (
                self.final_inventory_override
                if self.disk_list_count > 1 and self.final_inventory_override is not None
                else self.inventory_override
            )
            inventory = self.default_inventory() if override is None else override
            return json.dumps(inventory)
        if argv[1:3] == ["disk", "update"]:
            return ""
        if argv[1:3] == ["tag", "create"]:
            resource_id = argv[argv.index("--resource-id") + 1]
            disk_name = resource_id.rsplit("/", 1)[-1]
            self.vm_for_disk(disk_name)
            tags = argv[argv.index("--tags") + 1 : argv.index("--query")]
            parsed = dict(item.split("=", 1) for item in tags)
            return json.dumps(self.tags_override or parsed)
        if argv[1:3] == ["disk", "show"]:
            disk_name = argv[argv.index("--name") + 1]
            self.disk_show_count[disk_name] = self.disk_show_count.get(disk_name, 0) + 1
            vm_name = self.vm_for_disk(disk_name)
            base_name = lockdown.VM_TO_DISK_BASE[vm_name]
            return json.dumps(
                {
                    "id": self.disk_id_override.get(
                        disk_name, self.disk_id(disk_name)
                    ),
                    "managedBy": self.managed_by_override.get(
                        disk_name, self.vm_id(vm_name)
                    ),
                    "name": disk_name,
                    "networkAccessPolicy": "DenyAll",
                    "provisioningState": "Succeeded",
                    "publicNetworkAccess": (
                        self.final_public_network_access_override.get(
                            disk_name, self.public_network_access
                        )
                        if self.disk_show_count[disk_name] > 1
                        else self.public_network_access
                    ),
                    "tags": self.tags_override or lockdown.DISK_TAGS[base_name],
                }
            )
        raise AssertionError(argv)


class DiskLockdownTests(unittest.TestCase):
    def test_exact_three_original_disks_are_updated_idempotently(self):
        azure = FakeAzure()
        for _ in range(2):
            evidence = lockdown.lock_down(SUBSCRIPTION, runner=azure)
            self.assertEqual(evidence["status"], "POC_OS_DISKS_NETWORK_LOCKED")
            self.assertEqual(
                [record["name"] for record in evidence["disks"]],
                sorted(lockdown.DISK_TO_VM),
            )

        updates = [command for command in azure.commands if command[1:3] == ["disk", "update"]]
        tag_replacements = [
            command for command in azure.commands if command[1:3] == ["tag", "create"]
        ]
        final_reads = [command for command in azure.commands if command[1:3] == ["disk", "show"]]
        self.assertEqual(len(updates), 6)
        self.assertEqual(len(tag_replacements), 6)
        self.assertEqual(len(final_reads), 12)
        for command in updates:
            self.assertIn("--public-network-access", command)
            self.assertEqual(command[command.index("--public-network-access") + 1], "Disabled")
            self.assertEqual(command[command.index("--network-access-policy") + 1], "DenyAll")
            self.assertNotIn("--tags", command)

    def test_exact_reimage_attached_disk_names_are_updated_idempotently(self):
        azure = FakeAzure()
        sbc1_vm = "viv-sbc-poc-sbc1"
        sbc2_vm = "viv-sbc-poc-sbc2"
        sbc1_name = f"{lockdown.VM_TO_DISK_BASE[sbc1_vm]}_{REIMAGE_SUFFIX}"
        sbc2_name = (
            f"{lockdown.VM_TO_DISK_BASE[sbc2_vm]}_"
            "0123456789abcdef0123456789abcdef_abcdef0123456789abcdef0123456789"
        )
        azure.attachments[sbc1_vm] = sbc1_name
        azure.attachments[sbc2_vm] = sbc2_name

        for _ in range(2):
            evidence = lockdown.lock_down(SUBSCRIPTION, runner=azure)
            self.assertEqual(
                {record["name"] for record in evidence["disks"]},
                set(azure.attachments.values()),
            )

        derived_tag_commands = [
            command
            for command in azure.commands
            if command[1:3] == ["tag", "create"]
            and command[command.index("--resource-id") + 1].endswith(sbc1_name)
        ]
        self.assertEqual(len(derived_tag_commands), 2)
        for command in derived_tag_commands:
            tags = command[command.index("--tags") + 1 : command.index("--query")]
            self.assertEqual(
                tags,
                [
                    f"{key}={value}"
                    for key, value in sorted(
                        lockdown.DISK_TAGS[lockdown.VM_TO_DISK_BASE[sbc1_vm]].items()
                    )
                ],
            )

    def test_missing_extra_or_unattached_disk_fails_before_updates(self):
        baseline = FakeAzure().default_inventory()
        cases = {
            "missing": baseline[:-1],
            "extra": baseline
            + [
                {
                    "id": FakeAzure.disk_id("unexpected-osdisk"),
                    "managedBy": None,
                    "name": "unexpected-osdisk",
                }
            ],
            "replacement": baseline[:-1]
            + [
                {
                    "id": FakeAzure.disk_id("unexpected-osdisk"),
                    "managedBy": None,
                    "name": "unexpected-osdisk",
                }
            ],
        }
        for label, inventory in cases.items():
            with self.subTest(label=label):
                azure = FakeAzure()
                azure.inventory_override = inventory
                with self.assertRaisesRegex(
                    lockdown.DiskLockdownError,
                    "exactly the three attached|extra or unattached",
                ):
                    lockdown.lock_down(SUBSCRIPTION, runner=azure)
                self.assertFalse(
                    any(command[1:3] == ["disk", "update"] for command in azure.commands)
                )

    def test_wrong_disk_attachment_owner_fails_before_updates(self):
        azure = FakeAzure()
        inventory = azure.default_inventory()
        inventory[1]["managedBy"] = azure.vm_id("viv-sbc-poc-sbc2")
        azure.inventory_override = inventory
        with self.assertRaisesRegex(lockdown.DiskLockdownError, "exact POC VM"):
            lockdown.lock_down(SUBSCRIPTION, runner=azure)
        self.assertFalse(any(command[1:3] == ["disk", "update"] for command in azure.commands))

    def test_unbounded_or_cross_resource_attachment_identity_is_rejected(self):
        cases = (
            "viv-sbc-poc-sbc1-osdisk_not-a-reimage-suffix",
            "viv-sbc-poc-sbc2-osdisk_" + REIMAGE_SUFFIX,
            "unexpected-osdisk_" + REIMAGE_SUFFIX,
        )
        for disk_name in cases:
            with self.subTest(disk_name=disk_name):
                azure = FakeAzure()
                azure.attachments["viv-sbc-poc-sbc1"] = disk_name
                with self.assertRaisesRegex(
                    lockdown.DiskLockdownError, "bounded reimage-derived identity"
                ):
                    lockdown.lock_down(SUBSCRIPTION, runner=azure)
                self.assertFalse(
                    any(command[1:3] == ["disk", "list"] for command in azure.commands)
                )

    def test_attachment_resource_id_and_distinctness_are_rejected(self):
        azure = FakeAzure()
        azure.os_disk_id_override["viv-sbc-poc-sbc1"] = FakeAzure.disk_id(
            "viv-sbc-poc-sbc2-osdisk"
        )
        with self.assertRaisesRegex(lockdown.DiskLockdownError, "bounded reimage-derived"):
            lockdown.lock_down(SUBSCRIPTION, runner=azure)

        azure = FakeAzure()
        azure.os_disk_id_override["viv-sbc-poc-sbc1"] = FakeAzure.disk_id(
            "viv-sbc-poc-sbc1-osdisk"
        ).replace(SUBSCRIPTION, "00000000-0000-0000-0000-000000000000")
        with self.assertRaisesRegex(lockdown.DiskLockdownError, "resource ID drifted"):
            lockdown.lock_down(SUBSCRIPTION, runner=azure)

        azure = FakeAzure()
        azure.attachments["viv-sbc-poc-sbc2"] = "viv-sbc-poc-sbc1-osdisk"
        with self.assertRaisesRegex(lockdown.DiskLockdownError, "bounded reimage-derived"):
            lockdown.lock_down(SUBSCRIPTION, runner=azure)

    def test_logical_vm_disk_name_must_remain_the_exact_base(self):
        azure = FakeAzure()
        azure.logical_disk_name_override["viv-sbc-poc-sbc1"] = (
            f"{lockdown.VM_TO_DISK_BASE['viv-sbc-poc-sbc1']}_{REIMAGE_SUFFIX}"
        )
        with self.assertRaisesRegex(lockdown.DiskLockdownError, "logical OS-disk name drifted"):
            lockdown.lock_down(SUBSCRIPTION, runner=azure)

    def test_attachment_change_during_lockdown_is_rejected(self):
        azure = FakeAzure()
        azure.final_attachment_override = {
            "viv-sbc-poc-sbc1": (
                f"{lockdown.VM_TO_DISK_BASE['viv-sbc-poc-sbc1']}_{REIMAGE_SUFFIX}"
            )
        }
        with self.assertRaisesRegex(lockdown.DiskLockdownError, "changed during lockdown"):
            lockdown.lock_down(SUBSCRIPTION, runner=azure)

    def test_extra_disk_created_during_lockdown_is_rejected(self):
        azure = FakeAzure()
        azure.final_inventory_override = azure.default_inventory() + [
            {
                "id": azure.disk_id("unexpected-osdisk"),
                "managedBy": None,
                "name": "unexpected-osdisk",
            }
        ]
        with self.assertRaisesRegex(lockdown.DiskLockdownError, "exactly the three attached"):
            lockdown.lock_down(SUBSCRIPTION, runner=azure)

    def test_final_disk_control_drift_is_rejected(self):
        azure = FakeAzure()
        cp1_disk = lockdown.VM_TO_DISK_BASE["viv-sbc-poc-cp1"]
        azure.final_public_network_access_override[cp1_disk] = "Enabled"
        with self.assertRaisesRegex(lockdown.DiskLockdownError, "not Disabled"):
            lockdown.lock_down(SUBSCRIPTION, runner=azure)

    def test_vm_mid_provisioning_is_rejected_before_disk_inventory_or_updates(self):
        azure = FakeAzure()
        azure.vm_provisioning_state = "Updating"
        with self.assertRaisesRegex(lockdown.DiskLockdownError, "provisioning did not succeed"):
            lockdown.lock_down(SUBSCRIPTION, runner=azure)
        self.assertFalse(
            any(
                command[1:3] in (["disk", "list"], ["disk", "update"])
                for command in azure.commands
            )
        )

    def test_wrong_subscription_or_postcondition_is_rejected(self):
        azure = FakeAzure()
        with self.assertRaisesRegex(lockdown.DiskLockdownError, "canonical lowercase UUID"):
            lockdown.lock_down("NOT-A-SUBSCRIPTION", runner=azure)

        azure = FakeAzure()
        azure.public_network_access = "Enabled"
        with self.assertRaisesRegex(lockdown.DiskLockdownError, "not Disabled"):
            lockdown.lock_down(SUBSCRIPTION, runner=azure)

        azure = FakeAzure()
        azure.tags_override = {"purpose": "unrelated"}
        with self.assertRaisesRegex(lockdown.DiskLockdownError, "ownership tags drifted"):
            lockdown.lock_down(SUBSCRIPTION, runner=azure)


if __name__ == "__main__":
    unittest.main()
