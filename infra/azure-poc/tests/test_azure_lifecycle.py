from __future__ import annotations

import copy
import datetime as dt
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import azure_lifecycle_contract as contract  # noqa: E402
import predeploy_guard  # noqa: E402
import teardown_core_poc  # noqa: E402


TODAY = dt.date(2026, 8, 30)


class FakeAzure:
    def __init__(self, *, core_deployed: bool = False) -> None:
        self.commands: list[list[str]] = []
        self.account = {
            "id": contract.EXPECTED_SUBSCRIPTION_ID,
            "tenantId": contract.EXPECTED_TENANT_ID,
        }
        self.group_exists = {
            contract.POC_RESOURCE_GROUP: True,
            contract.PRESERVED_CP1_RESOURCE_GROUP: True,
            contract.DNS_RESOURCE_GROUP: True,
        }
        self.groups = {
            contract.POC_RESOURCE_GROUP: self._group(
                contract.POC_RESOURCE_GROUP, tags=contract.COMMON_TAGS
            ),
            contract.PRESERVED_CP1_RESOURCE_GROUP: self._group(
                contract.PRESERVED_CP1_RESOURCE_GROUP,
                tags={"lifecycle": "qualified-controller"},
            ),
        }
        self.resources = self._core_resources() if core_deployed else []
        self.budget = self._budget()
        self.poc_locks: list[dict[str, object]] = []
        self.preserved_locks = [self._preservation_lock()]
        self.parent_records: list[dict[str, str]] = []
        self.child_zones: set[str] = set()
        self.vm_states = {
            "viv-sbc-poc-cp1": "PowerState/deallocated",
            "viv-sbc-poc-sbc1": "PowerState/deallocated",
            "viv-sbc-poc-sbc2": "PowerState/deallocated",
        }

    @staticmethod
    def _value(argv: list[str], option: str) -> str:
        return argv[argv.index(option) + 1]

    @staticmethod
    def _group(name: str, *, tags: object) -> dict[str, object]:
        return {
            "id": contract.resource_group_id(contract.EXPECTED_SUBSCRIPTION_ID, name),
            "location": contract.LOCATION,
            "name": name,
            "properties": {"provisioningState": "Succeeded"},
            "tags": copy.deepcopy(tags),
        }

    @staticmethod
    def _budget() -> dict[str, object]:
        notifications = {}
        for threshold in (75, 90, 100):
            notifications[f"actual-{threshold}"] = {
                "contactEmails": [contract.BUDGET_CONTACT_EMAIL],
                "contactGroups": [],
                "contactRoles": [],
                "enabled": True,
                "operator": "GreaterThanOrEqualTo",
                "threshold": threshold,
                "thresholdType": "Actual",
            }
        return {
            "id": contract.budget_id(contract.EXPECTED_SUBSCRIPTION_ID),
            "name": contract.BUDGET_NAME,
            "properties": {
                "amount": 100,
                "category": "Cost",
                "notifications": notifications,
                "timeGrain": "Monthly",
                "timePeriod": {
                    "endDate": "2027-08-01T00:00:00Z",
                    "startDate": "2026-08-01T00:00:00Z",
                },
            },
            "type": "Microsoft.Consumption/budgets",
        }

    @staticmethod
    def _preservation_lock() -> dict[str, str]:
        group_id = contract.resource_group_id(
            contract.EXPECTED_SUBSCRIPTION_ID,
            contract.PRESERVED_CP1_RESOURCE_GROUP,
        )
        lock_id = (
            f"{group_id}"
            f"/providers/Microsoft.Authorization/locks/{contract.PRESERVATION_LOCK_NAME}"
        )
        return {
            "id": lock_id,
            "level": contract.PRESERVATION_LOCK_LEVEL,
            "name": contract.PRESERVATION_LOCK_NAME,
            "notes": contract.PRESERVATION_LOCK_NOTES,
        }

    @staticmethod
    def _core_resources() -> list[dict[str, object]]:
        resources = []
        for spec in contract.expected_resource_specs():
            record: dict[str, object] = {
                "id": contract.resource_id(
                    contract.EXPECTED_SUBSCRIPTION_ID,
                    spec.resource_type,
                    spec.name,
                ),
                "location": contract.LOCATION,
                "managedBy": None,
                "name": spec.name,
                "tags": dict(spec.tags),
                "type": spec.resource_type,
            }
            if spec.managed_by_vm is not None:
                record["managedBy"] = contract.resource_id(
                    contract.EXPECTED_SUBSCRIPTION_ID,
                    "Microsoft.Compute/virtualMachines",
                    spec.managed_by_vm,
                )
            resources.append(record)
        return resources

    def __call__(self, raw_argv):
        argv = list(raw_argv)
        self.commands.append(argv)
        command = argv[1:]
        if command[:2] == ["account", "show"]:
            return json.dumps(self.account)
        if command[:2] == ["group", "show"]:
            name = self._value(argv, "--name")
            if not self.group_exists.get(name, False):
                raise AssertionError(f"show called for absent group {name}")
            return json.dumps(self.groups[name])
        if command[:2] == ["group", "exists"]:
            return json.dumps(self.group_exists.get(self._value(argv, "--name"), False))
        if command[:2] == ["resource", "list"]:
            group = self._value(argv, "--resource-group")
            if group == contract.POC_RESOURCE_GROUP:
                return json.dumps(self.resources)
            name = self._value(argv, "--name")
            if name in self.child_zones:
                return json.dumps(
                    [
                        {
                            "id": contract.zone_id(
                                contract.EXPECTED_SUBSCRIPTION_ID, name
                            ),
                            "name": name,
                            "type": "Microsoft.Network/dnsZones",
                        }
                    ]
                )
            return "[]"
        if command[0] == "rest":
            return json.dumps(self.budget)
        if command[:2] == ["lock", "list"]:
            group = self._value(argv, "--resource-group")
            if group == contract.POC_RESOURCE_GROUP:
                return json.dumps(self.poc_locks)
            return json.dumps(self.preserved_locks)
        if command[:4] == ["network", "dns", "zone", "show"]:
            return json.dumps(
                {
                    "id": contract.zone_id(
                        contract.EXPECTED_SUBSCRIPTION_ID, contract.PARENT_ZONE
                    ),
                    "name": contract.PARENT_ZONE,
                    "zoneType": "Public",
                }
            )
        if command[:4] == ["network", "dns", "record-set", "list"]:
            return json.dumps(self.parent_records)
        if command[:2] == ["vm", "get-instance-view"]:
            return json.dumps(self.vm_states[self._value(argv, "--name")])
        if command[:2] == ["group", "delete"]:
            name = self._value(argv, "--name")
            if name != contract.POC_RESOURCE_GROUP:
                raise AssertionError(f"unsafe deletion target {name}")
            self.group_exists[name] = False
            self.resources = []
            return ""
        raise AssertionError(argv)

    @property
    def mutations(self) -> list[list[str]]:
        return [
            command
            for command in self.commands
            if command[1:3] == ["group", "delete"]
        ]


class PredeployGuardTests(unittest.TestCase):
    def test_exact_empty_budgeted_locked_boundary_passes_read_only(self) -> None:
        azure = FakeAzure()
        azure.resources.append(
            {
                "id": contract.budget_id(contract.EXPECTED_SUBSCRIPTION_ID),
                "location": None,
                "managedBy": None,
                "name": contract.BUDGET_NAME,
                "tags": None,
                "type": "Microsoft.Consumption/budgets",
            }
        )
        evidence = predeploy_guard.guard_predeploy(
            contract.EXPECTED_SUBSCRIPTION_ID,
            contract.EXPECTED_TENANT_ID,
            runner=azure,
            today=TODAY,
        )
        self.assertEqual(evidence["status"], "POC_PREDEPLOY_GUARD_PASSED")
        self.assertEqual(evidence["budget"]["thresholds"], [75, 90, 100])
        self.assertEqual(evidence["pocResourceGroup"]["resources"], [])
        self.assertRegex(evidence["evidenceSha256"], r"^[0-9a-f]{64}$")
        self.assertFalse(azure.mutations)

    def test_nonempty_or_mistagged_poc_group_is_rejected(self) -> None:
        azure = FakeAzure()
        azure.resources.append(
            {
                "id": "unrelated",
                "location": contract.LOCATION,
                "name": "unrelated",
                "tags": {},
                "type": "Microsoft.Storage/storageAccounts",
            }
        )
        with self.assertRaisesRegex(contract.LifecycleError, "not empty"):
            predeploy_guard.guard_predeploy(
                contract.EXPECTED_SUBSCRIPTION_ID,
                contract.EXPECTED_TENANT_ID,
                runner=azure,
                today=TODAY,
            )
        self.assertFalse(azure.mutations)

        azure = FakeAzure()
        azure.groups[contract.POC_RESOURCE_GROUP]["tags"] = {"purpose": "unrelated"}
        with self.assertRaisesRegex(contract.LifecycleError, "ownership tags"):
            predeploy_guard.guard_predeploy(
                contract.EXPECTED_SUBSCRIPTION_ID,
                contract.EXPECTED_TENANT_ID,
                runner=azure,
                today=TODAY,
            )

    def test_budget_amount_threshold_and_contact_drift_are_rejected(self) -> None:
        mutations = (
            (lambda budget: budget["properties"].update(amount=101), "amount/category"),
            (
                lambda budget: budget["properties"]["notifications"]["actual-90"].update(
                    threshold=80
                ),
                "notification contract",
            ),
            (
                lambda budget: budget["properties"]["notifications"]["actual-75"].update(
                    contactEmails=["unapproved@example.invalid"]
                ),
                "notification contract",
            ),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                azure = FakeAzure()
                mutate(azure.budget)
                with self.assertRaisesRegex(contract.LifecycleError, message):
                    predeploy_guard.guard_predeploy(
                        contract.EXPECTED_SUBSCRIPTION_ID,
                        contract.EXPECTED_TENANT_ID,
                        runner=azure,
                        today=TODAY,
                    )
                self.assertFalse(azure.mutations)

    def test_preservation_lock_and_complete_dns_absence_are_mandatory(self) -> None:
        azure = FakeAzure()
        azure.preserved_locks = []
        with self.assertRaisesRegex(contract.LifecycleError, "exactly one lock"):
            predeploy_guard.guard_predeploy(
                contract.EXPECTED_SUBSCRIPTION_ID,
                contract.EXPECTED_TENANT_ID,
                runner=azure,
                today=TODAY,
            )

        azure = FakeAzure()
        azure.parent_records = [
            {"name": "sbc1", "type": "Microsoft.Network/dnsZones/TXT"}
        ]
        with self.assertRaisesRegex(contract.LifecycleError, "not completely absent"):
            predeploy_guard.guard_predeploy(
                contract.EXPECTED_SUBSCRIPTION_ID,
                contract.EXPECTED_TENANT_ID,
                runner=azure,
                today=TODAY,
            )

        azure = FakeAzure()
        azure.child_zones.add(contract.ACME_CHILD_ZONES[0])
        with self.assertRaisesRegex(contract.LifecycleError, "child zones"):
            predeploy_guard.guard_predeploy(
                contract.EXPECTED_SUBSCRIPTION_ID,
                contract.EXPECTED_TENANT_ID,
                runner=azure,
                today=TODAY,
            )

    def test_wrong_account_location_or_poc_lock_fails_closed(self) -> None:
        azure = FakeAzure()
        with self.assertRaisesRegex(contract.LifecycleError, "outside"):
            predeploy_guard.guard_predeploy(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                contract.EXPECTED_TENANT_ID,
                runner=azure,
                today=TODAY,
            )
        self.assertFalse(azure.commands)

        azure = FakeAzure()
        azure.account["tenantId"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        with self.assertRaisesRegex(contract.LifecycleError, "reviewed target"):
            predeploy_guard.guard_predeploy(
                contract.EXPECTED_SUBSCRIPTION_ID,
                contract.EXPECTED_TENANT_ID,
                runner=azure,
                today=TODAY,
            )

        azure = FakeAzure()
        azure.groups[contract.POC_RESOURCE_GROUP]["location"] = "westus"
        with self.assertRaisesRegex(contract.LifecycleError, "location drifted"):
            predeploy_guard.guard_predeploy(
                contract.EXPECTED_SUBSCRIPTION_ID,
                contract.EXPECTED_TENANT_ID,
                runner=azure,
                today=TODAY,
            )

        azure = FakeAzure()
        azure.poc_locks = [{"name": "unexpected"}]
        with self.assertRaisesRegex(contract.LifecycleError, "management lock"):
            predeploy_guard.guard_predeploy(
                contract.EXPECTED_SUBSCRIPTION_ID,
                contract.EXPECTED_TENANT_ID,
                runner=azure,
                today=TODAY,
            )


class CoreTeardownTests(unittest.TestCase):
    def test_plan_binds_exact_inventory_and_deallocated_vms_without_mutation(self) -> None:
        azure = FakeAzure(core_deployed=True)
        azure.resources.append(
            {
                "id": contract.budget_id(contract.EXPECTED_SUBSCRIPTION_ID),
                "location": None,
                "managedBy": None,
                "name": contract.BUDGET_NAME,
                "tags": None,
                "type": "Microsoft.Consumption/budgets",
            }
        )
        plan = teardown_core_poc.plan_teardown(
            contract.EXPECTED_SUBSCRIPTION_ID,
            contract.EXPECTED_TENANT_ID,
            runner=azure,
            today=TODAY,
        )
        self.assertEqual(plan["status"], "POC_CORE_TEARDOWN_PLAN_READY")
        self.assertEqual(len(plan["validated"]["inventory"]), 17)
        self.assertEqual(len(plan["actions"]), 1)
        self.assertEqual(
            plan["actions"][0]["name"], contract.POC_RESOURCE_GROUP
        )
        self.assertNotIn(
            contract.PRESERVED_CP1_RESOURCE_GROUP,
            {action["name"] for action in plan["actions"]},
        )
        self.assertFalse(azure.mutations)

    def test_inventory_extra_missing_tag_and_disk_attachment_drift_fail(self) -> None:
        cases = []
        azure = FakeAzure(core_deployed=True)
        azure.resources.pop()
        cases.append((azure, "missing, extra, or renamed"))

        azure = FakeAzure(core_deployed=True)
        azure.resources.append(
            {
                "id": "unrelated",
                "location": contract.LOCATION,
                "managedBy": None,
                "name": "unrelated",
                "tags": {},
                "type": "Microsoft.Storage/storageAccounts",
            }
        )
        cases.append((azure, "missing, extra, or renamed"))

        azure = FakeAzure(core_deployed=True)
        azure.resources[0]["tags"] = {"purpose": "unrelated"}
        cases.append((azure, "identity/location/tags drifted"))

        azure = FakeAzure(core_deployed=True)
        disk = next(
            resource
            for resource in azure.resources
            if resource["type"] == "Microsoft.Compute/disks"
        )
        disk["managedBy"] = "unrelated"
        cases.append((azure, "not attached to its exact VM"))

        for azure, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(contract.LifecycleError, message):
                    teardown_core_poc.plan_teardown(
                        contract.EXPECTED_SUBSCRIPTION_ID,
                        contract.EXPECTED_TENANT_ID,
                        runner=azure,
                        today=TODAY,
                    )
                self.assertFalse(azure.mutations)

    def test_running_vm_or_incomplete_dns_teardown_blocks_plan(self) -> None:
        azure = FakeAzure(core_deployed=True)
        azure.vm_states["viv-sbc-poc-sbc2"] = "PowerState/running"
        with self.assertRaisesRegex(contract.LifecycleError, "not Azure-deallocated"):
            teardown_core_poc.plan_teardown(
                contract.EXPECTED_SUBSCRIPTION_ID,
                contract.EXPECTED_TENANT_ID,
                runner=azure,
                today=TODAY,
            )

        azure = FakeAzure(core_deployed=True)
        azure.parent_records = [
            {"name": "cp1-poc", "type": "Microsoft.Network/dnsZones/A"}
        ]
        with self.assertRaisesRegex(contract.LifecycleError, "not completely absent"):
            teardown_core_poc.plan_teardown(
                contract.EXPECTED_SUBSCRIPTION_ID,
                contract.EXPECTED_TENANT_ID,
                runner=azure,
                today=TODAY,
            )

    def test_stale_digest_or_wrong_confirmation_cannot_delete(self) -> None:
        azure = FakeAzure(core_deployed=True)
        plan = teardown_core_poc.plan_teardown(
            contract.EXPECTED_SUBSCRIPTION_ID,
            contract.EXPECTED_TENANT_ID,
            runner=azure,
            today=TODAY,
        )
        with self.assertRaisesRegex(contract.LifecycleError, "confirmation"):
            teardown_core_poc.apply_teardown(
                contract.EXPECTED_SUBSCRIPTION_ID,
                contract.EXPECTED_TENANT_ID,
                approved_plan_sha256=plan["planSha256"],
                confirmation="delete",
                runner=azure,
                today=TODAY,
            )
        self.assertFalse(azure.mutations)

        with self.assertRaisesRegex(contract.LifecycleError, "does not match"):
            teardown_core_poc.apply_teardown(
                contract.EXPECTED_SUBSCRIPTION_ID,
                contract.EXPECTED_TENANT_ID,
                approved_plan_sha256="0" * 64,
                confirmation=teardown_core_poc.CONFIRMATION,
                runner=azure,
                today=TODAY,
            )
        self.assertFalse(azure.mutations)

        azure.resources[0]["tags"] = {"purpose": "changed-after-plan"}
        with self.assertRaises(contract.LifecycleError):
            teardown_core_poc.apply_teardown(
                contract.EXPECTED_SUBSCRIPTION_ID,
                contract.EXPECTED_TENANT_ID,
                approved_plan_sha256=plan["planSha256"],
                confirmation=teardown_core_poc.CONFIRMATION,
                runner=azure,
                today=TODAY,
            )
        self.assertFalse(azure.mutations)

    def test_apply_deletes_only_core_group_and_proves_protected_groups_remain(self) -> None:
        azure = FakeAzure(core_deployed=True)
        plan = teardown_core_poc.plan_teardown(
            contract.EXPECTED_SUBSCRIPTION_ID,
            contract.EXPECTED_TENANT_ID,
            runner=azure,
            today=TODAY,
        )
        result = teardown_core_poc.apply_teardown(
            contract.EXPECTED_SUBSCRIPTION_ID,
            contract.EXPECTED_TENANT_ID,
            approved_plan_sha256=plan["planSha256"],
            confirmation=teardown_core_poc.CONFIRMATION,
            runner=azure,
            today=TODAY,
        )
        self.assertEqual(result["status"], "POC_CORE_TEARDOWN_APPLIED")
        self.assertEqual(len(azure.mutations), 1)
        command = azure.mutations[0]
        self.assertEqual(
            command[command.index("--name") + 1], contract.POC_RESOURCE_GROUP
        )
        self.assertTrue(azure.group_exists[contract.PRESERVED_CP1_RESOURCE_GROUP])
        self.assertTrue(azure.group_exists[contract.DNS_RESOURCE_GROUP])

    def test_absent_group_is_idempotent_and_never_deletes_protected_groups(self) -> None:
        azure = FakeAzure()
        azure.group_exists[contract.POC_RESOURCE_GROUP] = False
        plan = teardown_core_poc.plan_teardown(
            contract.EXPECTED_SUBSCRIPTION_ID,
            contract.EXPECTED_TENANT_ID,
            runner=azure,
            today=TODAY,
        )
        self.assertEqual(plan["status"], "POC_CORE_ALREADY_ABSENT")
        self.assertEqual(plan["actions"], [])
        result = teardown_core_poc.apply_teardown(
            contract.EXPECTED_SUBSCRIPTION_ID,
            contract.EXPECTED_TENANT_ID,
            approved_plan_sha256=plan["planSha256"],
            confirmation=teardown_core_poc.CONFIRMATION,
            runner=azure,
            today=TODAY,
        )
        self.assertEqual(result["deletedActions"], 0)
        self.assertFalse(azure.mutations)

    def test_sources_are_plan_first_and_documented(self) -> None:
        predeploy_source = (ROOT / "predeploy_guard.py").read_text()
        teardown_source = (ROOT / "teardown_core_poc.py").read_text()
        readme = (ROOT / "README.md").read_text()
        self.assertNotIn('"delete"', predeploy_source)
        self.assertIn('default="plan"', teardown_source)
        self.assertIn("approved_plan_sha256", teardown_source)
        self.assertIn("predeploy_guard.py", readme)
        self.assertIn("teardown_core_poc.py", readme)
        self.assertIn("DNS/ACME teardown must run first", readme)


if __name__ == "__main__":
    unittest.main()
