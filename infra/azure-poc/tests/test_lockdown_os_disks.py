from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import lockdown_os_disks as lockdown  # noqa: E402


SUBSCRIPTION = "a806949c-240f-4541-8c61-fd97f6d1f953"


class FakeAzure:
    def __init__(self) -> None:
        self.commands = []
        self.inventory = sorted(lockdown.DISK_TO_VM)
        self.public_network_access = "Disabled"
        self.tags_override = None
        self.current_name = None

    def __call__(self, argv):
        self.commands.append(list(argv))
        if argv[1:3] == ["account", "show"]:
            return json.dumps({"id": SUBSCRIPTION})
        if argv[1:3] == ["group", "show"]:
            return json.dumps({"location": "uaenorth", "name": lockdown.RESOURCE_GROUP})
        if argv[1:3] == ["disk", "list"]:
            return json.dumps(self.inventory)
        if argv[1:3] == ["disk", "update"]:
            name = argv[argv.index("--name") + 1]
            self.current_name = name
            return ""
        if argv[1:3] == ["tag", "create"]:
            resource_id = argv[argv.index("--resource-id") + 1]
            name = resource_id.rsplit("/", 1)[-1]
            tags = argv[argv.index("--tags") + 1 : argv.index("--query")]
            parsed = dict(item.split("=", 1) for item in tags)
            return json.dumps(self.tags_override or parsed)
        if argv[1:3] == ["disk", "show"]:
            name = argv[argv.index("--name") + 1]
            vm = lockdown.DISK_TO_VM[name]
            return json.dumps(
                {
                    "managedBy": (
                        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{lockdown.RESOURCE_GROUP}"
                        f"/providers/Microsoft.Compute/virtualMachines/{vm}"
                    ),
                    "name": name,
                    "networkAccessPolicy": "DenyAll",
                    "provisioningState": "Succeeded",
                    "publicNetworkAccess": self.public_network_access,
                    "tags": self.tags_override or lockdown.DISK_TAGS[name],
                }
            )
        raise AssertionError(argv)


class DiskLockdownTests(unittest.TestCase):
    def test_exact_three_disks_are_updated_idempotently(self):
        azure = FakeAzure()
        evidence = lockdown.lock_down(SUBSCRIPTION, runner=azure)
        self.assertEqual(evidence["status"], "POC_OS_DISKS_NETWORK_LOCKED")
        updates = [command for command in azure.commands if command[1:3] == ["disk", "update"]]
        tag_replacements = [
            command for command in azure.commands if command[1:3] == ["tag", "create"]
        ]
        final_reads = [command for command in azure.commands if command[1:3] == ["disk", "show"]]
        self.assertEqual(len(updates), 3)
        self.assertEqual(len(tag_replacements), 3)
        self.assertEqual(len(final_reads), 3)
        for command in updates:
            self.assertIn("--public-network-access", command)
            self.assertEqual(command[command.index("--public-network-access") + 1], "Disabled")
            self.assertEqual(command[command.index("--network-access-policy") + 1], "DenyAll")
            self.assertNotIn("--tags", command)
        for command in tag_replacements:
            tags = command[command.index("--tags") + 1 : command.index("--query")]
            name = command[command.index("--resource-id") + 1].rsplit("/", 1)[-1]
            self.assertEqual(
                tags,
                [
                    f"{key}={value}"
                    for key, value in sorted(lockdown.DISK_TAGS[name].items())
                ],
            )

    def test_missing_or_extra_disk_fails_before_updates(self):
        for inventory in (
            sorted(lockdown.DISK_TO_VM)[:-1],
            sorted(lockdown.DISK_TO_VM) + ["unexpected-osdisk"],
        ):
            with self.subTest(inventory=inventory):
                azure = FakeAzure()
                azure.inventory = inventory
                with self.assertRaisesRegex(lockdown.DiskLockdownError, "exactly the three"):
                    lockdown.lock_down(SUBSCRIPTION, runner=azure)
                self.assertFalse(
                    any(command[1:3] == ["disk", "update"] for command in azure.commands)
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
