from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import reconcile_dns_acme_authority as reconcile  # noqa: E402


SBC1_PRINCIPAL = "11111111-1111-4111-8111-111111111111"
SBC2_PRINCIPAL = "22222222-2222-4222-8222-222222222222"


def inputs() -> reconcile.ExpectedInputs:
    return reconcile.ExpectedInputs(
        subscription_id=reconcile.EXPECTED_SUBSCRIPTION_ID,
        tenant_id=reconcile.EXPECTED_TENANT_ID,
        sbc1_principal_id=SBC1_PRINCIPAL,
        sbc2_principal_id=SBC2_PRINCIPAL,
    )


class FakeAzure:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.account = {
            "id": reconcile.EXPECTED_SUBSCRIPTION_ID,
            "tenantId": reconcile.EXPECTED_TENANT_ID,
        }
        self.role_definition = {
            "assignableScopes": [
                f"/subscriptions/{reconcile.EXPECTED_SUBSCRIPTION_ID}"
            ],
            "description": reconcile.EDGE_ACME_TXT_ROLE_DESCRIPTION,
            "id": reconcile.contract._role_definition_id(
                reconcile.EXPECTED_SUBSCRIPTION_ID,
                reconcile.EDGE_ACME_TXT_ROLE_ID,
            ),
            "name": reconcile.EDGE_ACME_TXT_ROLE_ID,
            "permissions": [
                {
                    "actions": sorted(reconcile.EDGE_ACME_TXT_ROLE_ACTIONS),
                    "notActions": [],
                    "dataActions": [],
                    "notDataActions": [],
                }
            ],
            "roleName": reconcile.EDGE_ACME_TXT_ROLE_NAME,
            "roleType": "CustomRole",
        }
        self.vm_power_states = {
            reconcile.EDGE_VMS[reconcile.CHILD_ZONES[0]]: "PowerState/deallocated",
            reconcile.EDGE_VMS[reconcile.CHILD_ZONES[1]]: "PowerState/deallocated",
        }
        self.children: dict[str, dict] = {}
        self.child_records: dict[str, list[dict]] = {}
        self.assignments: dict[str, list[dict]] = {}
        self.inherited_assignments = {
            SBC1_PRINCIPAL: [],
            SBC2_PRINCIPAL: [],
        }
        self.locks: dict[str, list[dict]] = {}
        self.parent_records: list[dict] = []
        self.inject_custom_assignment_change_after_first_mutation = False
        self.injected = False
        self._seed()

    def _seed(self) -> None:
        servers_by_zone = {
            reconcile.CHILD_ZONES[0]: [
                "ns1-01.azure-dns.com.",
                "ns2-01.azure-dns.net.",
                "ns3-01.azure-dns.org.",
                "ns4-01.azure-dns.info.",
            ],
            reconcile.CHILD_ZONES[1]: [
                "ns1-02.azure-dns.com.",
                "ns2-02.azure-dns.net.",
                "ns3-02.azure-dns.org.",
                "ns4-02.azure-dns.info.",
            ],
        }
        principals = {
            reconcile.CHILD_ZONES[0]: SBC1_PRINCIPAL,
            reconcile.CHILD_ZONES[1]: SBC2_PRINCIPAL,
        }
        role_kinds = (
            ("custom", reconcile.EDGE_ACME_TXT_ROLE_ID),
            ("reader", reconcile.LEGACY_READER_ROLE_ID),
            ("contributor", reconcile.LEGACY_DNS_ZONE_CONTRIBUTOR_ROLE_ID),
        )
        for index, zone in enumerate(reconcile.CHILD_ZONES, start=1):
            zone_id = reconcile.contract._zone_id(
                reconcile.EXPECTED_SUBSCRIPTION_ID, zone
            )
            self.children[zone] = {
                "etag": f"zone-etag-{index}",
                "id": zone_id,
                "name": zone,
                "nameServers": servers_by_zone[zone],
                "tags": dict(reconcile.ZONE_TAGS),
                "zoneType": "Public",
            }
            self.child_records[zone] = [
                {
                    "etag": f"ns-etag-{index}",
                    "id": f"{zone_id}/NS/@",
                    "name": "@",
                    "type": "Microsoft.Network/dnsZones/NS",
                },
                {
                    "etag": f"soa-etag-{index}",
                    "id": f"{zone_id}/SOA/@",
                    "name": "@",
                    "type": "Microsoft.Network/dnsZones/SOA",
                },
                {
                    "etag": f"challenge-etag-{index}",
                    "id": f"{zone_id}/TXT/_acme-challenge",
                    "name": "_acme-challenge",
                    "type": "Microsoft.Network/dnsZones/TXT",
                },
            ]
            self.assignments[zone] = []
            for role_index, (kind, role_id) in enumerate(role_kinds, start=1):
                assignment_uuid = (
                    f"{index}{role_index}111111-1111-4111-8111-111111111111"
                )[:36]
                self.assignments[zone].append(
                    {
                        "id": (
                            f"{zone_id}/providers/Microsoft.Authorization/roleAssignments/"
                            f"{assignment_uuid}"
                        ),
                        "kind": kind,
                        "principalId": principals[zone],
                        "principalType": "ServicePrincipal",
                        "roleDefinitionId": reconcile.contract._role_definition_id(
                            reconcile.EXPECTED_SUBSCRIPTION_ID, role_id
                        ),
                        "scope": zone_id,
                    }
                )
            self.locks[zone] = [
                {
                    "id": (
                        f"{zone_id}/providers/Microsoft.Authorization/locks/"
                        f"{reconcile.LEGACY_LOCK_NAME}"
                    ),
                    "level": reconcile.LEGACY_LOCK_LEVEL,
                    "name": reconcile.LEGACY_LOCK_NAME,
                    "notes": reconcile.LEGACY_LOCK_NOTES[zone],
                }
            ]

        for spec in reconcile._parent_authority_specs():
            zone_id = reconcile.contract._zone_id(
                reconcile.EXPECTED_SUBSCRIPTION_ID, reconcile.PARENT_ZONE
            )
            kind = spec["type"]
            record = {
                "etag": f"parent-etag-{len(self.parent_records) + 1}",
                "id": f"{zone_id}/{kind}/{spec['name']}",
                "name": spec["name"],
                "ttl": spec["ttl"],
                "type": f"Microsoft.Network/dnsZones/{kind}",
            }
            if kind == "CNAME":
                record["cnameRecord"] = {"cname": spec["cname"] + "."}
            else:
                record["nsRecords"] = [
                    {"nsdname": value}
                    for value in servers_by_zone[spec["child"]]
                ]
            self.parent_records.append(record)

    @staticmethod
    def _value(argv: list[str], option: str) -> str:
        return argv[argv.index(option) + 1]

    def _maybe_inject(self) -> None:
        if (
            self.inject_custom_assignment_change_after_first_mutation
            and not self.injected
        ):
            zone = reconcile.CHILD_ZONES[0]
            custom = next(
                record for record in self.assignments[zone] if record["kind"] == "custom"
            )
            custom["id"] = custom["id"].rsplit("/", 1)[0] + (
                "/99999999-9999-4999-8999-999999999999"
            )
            self.injected = True

    def __call__(self, raw_argv):
        argv = list(raw_argv)
        self.commands.append(argv)
        command = argv[1:]
        if command[:2] == ["account", "show"]:
            return json.dumps(self.account)
        if command[:2] == ["group", "show"]:
            name = self._value(argv, "--name")
            location = (
                reconcile.contract.POC_LOCATION
                if name == reconcile.POC_RESOURCE_GROUP
                else "eastus"
            )
            return json.dumps(
                {
                    "id": reconcile.contract._resource_group_id(
                        reconcile.EXPECTED_SUBSCRIPTION_ID, name
                    ),
                    "location": location,
                    "name": name,
                }
            )
        if command[:3] == ["role", "definition", "list"]:
            return json.dumps([self.role_definition])
        if command[:2] == ["vm", "show"]:
            vm_name = self._value(argv, "--name")
            zone = next(
                zone for zone, expected_name in reconcile.EDGE_VMS.items()
                if expected_name == vm_name
            )
            principal = (
                SBC1_PRINCIPAL
                if zone == reconcile.CHILD_ZONES[0]
                else SBC2_PRINCIPAL
            )
            return json.dumps(
                {
                    "id": (
                        f"/subscriptions/{reconcile.EXPECTED_SUBSCRIPTION_ID}/"
                        f"resourceGroups/{reconcile.POC_RESOURCE_GROUP}/providers/"
                        f"Microsoft.Compute/virtualMachines/{vm_name}"
                    ),
                    "identityType": "SystemAssigned",
                    "name": vm_name,
                    "principalId": principal,
                    "provisioningState": "Succeeded",
                }
            )
        if command[:2] == ["vm", "get-instance-view"]:
            vm_name = self._value(argv, "--name")
            return json.dumps(
                ["ProvisioningState/succeeded", self.vm_power_states[vm_name]]
            )
        if command[:2] == ["resource", "list"]:
            zone = self._value(argv, "--name")
            child = self.children.get(zone)
            return json.dumps(
                []
                if child is None
                else [
                    {
                        "id": child["id"],
                        "name": zone,
                        "type": "Microsoft.Network/dnsZones",
                    }
                ]
            )
        if command[:4] == ["network", "dns", "zone", "show"]:
            zone = self._value(argv, "--name")
            if zone in self.children:
                return json.dumps(self.children[zone])
            return json.dumps(
                {
                    "id": reconcile.contract._zone_id(
                        reconcile.EXPECTED_SUBSCRIPTION_ID, reconcile.PARENT_ZONE
                    ),
                    "name": reconcile.PARENT_ZONE,
                    "zoneType": "Public",
                }
            )
        if command[:4] == ["network", "dns", "record-set", "list"]:
            zone = self._value(argv, "--zone-name")
            return json.dumps(
                self.parent_records
                if zone == reconcile.PARENT_ZONE
                else self.child_records[zone]
            )
        if command[:3] == ["role", "assignment", "list"]:
            if "--assignee-object-id" in argv:
                principal = self._value(argv, "--assignee-object-id")
                if "--all" not in argv:
                    scope = self._value(argv, "--scope")
                    return json.dumps(
                        [
                            {key: value for key, value in record.items() if key != "kind"}
                            for zone in reconcile.CHILD_ZONES
                            for record in self.assignments[zone]
                            if record["principalId"] == principal
                            and record["scope"].lower() == scope.lower()
                        ]
                        + self.inherited_assignments[principal]
                    )
                return json.dumps(
                    [
                        {key: value for key, value in record.items() if key != "kind"}
                        for zone in reconcile.CHILD_ZONES
                        for record in self.assignments[zone]
                        if record["principalId"] == principal
                    ]
                )
            if "--all" in argv:
                return json.dumps(
                    [
                        {key: value for key, value in record.items() if key != "kind"}
                        for zone in reconcile.CHILD_ZONES
                        for record in self.assignments[zone]
                        if record["kind"] == "custom"
                    ]
                )
            zone = self._value(argv, "--scope").rsplit("/", 1)[-1]
            return json.dumps(
                [{key: value for key, value in record.items() if key != "kind"}
                 for record in self.assignments[zone]
                 if record["scope"].lower() == self._value(argv, "--scope").lower()]
            )
        if command[:2] == ["lock", "list"]:
            return json.dumps(self.locks[self._value(argv, "--resource-name")])

        if command[:2] == ["lock", "delete"]:
            target = self._value(argv, "--ids")
            for zone in reconcile.CHILD_ZONES:
                self.locks[zone] = [
                    record for record in self.locks[zone] if record["id"] != target
                ]
            self._maybe_inject()
            return ""
        if command[:5] == ["network", "dns", "record-set", "txt", "delete"]:
            zone = self._value(argv, "--zone-name")
            record = next(
                value
                for value in self.child_records[zone]
                if value["name"] == "_acme-challenge"
            )
            if self._value(argv, "--if-match") != record["etag"]:
                raise AssertionError("challenge record ETag mismatch")
            self.child_records[zone].remove(record)
            self._maybe_inject()
            return ""
        if command[:3] == ["role", "assignment", "delete"]:
            target = self._value(argv, "--ids")
            for zone in reconcile.CHILD_ZONES:
                self.assignments[zone] = [
                    record
                    for record in self.assignments[zone]
                    if record["id"] != target
                ]
            self._maybe_inject()
            return ""
        raise AssertionError(argv)

    @property
    def mutation_commands(self) -> list[list[str]]:
        return [command for command in self.commands if "delete" in command[1:]]


class ReconcileDnsAcmeAuthorityTests(unittest.TestCase):
    def test_plan_is_read_only_and_binds_exact_legacy_ids_and_etags(self) -> None:
        azure = FakeAzure()
        plan = reconcile.plan_reconciliation(inputs(), runner=azure)
        self.assertEqual(
            plan["status"],
            "POC_DNS_ACME_AUTHORITY_RECONCILIATION_PLAN_READY",
        )
        self.assertEqual(len(plan["actions"]), 8)
        self.assertRegex(plan["planSha256"], r"^[0-9a-f]{64}$")
        self.assertFalse(azure.mutation_commands)
        challenge_actions = [
            action
            for action in plan["actions"]
            if action["kind"] == "DELETE_STALE_ACME_CHALLENGE_TXT"
        ]
        self.assertEqual(
            [action["etag"] for action in challenge_actions],
            ["challenge-etag-1", "challenge-etag-2"],
        )
        self.assertEqual(
            [item["roleAssignmentCount"] for item in plan["observed"]["childZones"]],
            [3, 3],
        )
        self.assertEqual(
            [item["legacyLockCount"] for item in plan["observed"]["childZones"]],
            [1, 1],
        )
        for offset in (0, 4):
            self.assertEqual(
                [action["kind"] for action in plan["actions"][offset : offset + 4]],
                [
                    "DELETE_LEGACY_ZONE_LOCK",
                    "DELETE_LEGACY_ROLE_ASSIGNMENT",
                    "DELETE_LEGACY_ROLE_ASSIGNMENT",
                    "DELETE_STALE_ACME_CHALLENGE_TXT",
                ],
            )
            self.assertEqual(
                [
                    plan["actions"][offset + 1]["roleKind"],
                    plan["actions"][offset + 2]["roleKind"],
                ],
                ["LEGACY_DNS_ZONE_CONTRIBUTOR", "LEGACY_READER"],
            )

    def test_apply_requires_exact_fresh_digest_and_confirmation(self) -> None:
        azure = FakeAzure()
        plan = reconcile.plan_reconciliation(inputs(), runner=azure)
        with self.assertRaisesRegex(
            reconcile.AuthorityReconciliationError, "confirmation"
        ):
            reconcile.apply_reconciliation(
                inputs(),
                approved_plan_sha256=plan["planSha256"],
                confirmation="reconcile",
                runner=azure,
            )
        with self.assertRaisesRegex(
            reconcile.AuthorityReconciliationError, "does not match"
        ):
            reconcile.apply_reconciliation(
                inputs(),
                approved_plan_sha256="0" * 64,
                confirmation=reconcile.CONFIRMATION,
                runner=azure,
            )
        self.assertFalse(azure.mutation_commands)

    def test_apply_removes_only_legacy_authority_and_proves_final_absence(self) -> None:
        azure = FakeAzure()
        plan = reconcile.plan_reconciliation(inputs(), runner=azure)
        result = reconcile.apply_reconciliation(
            inputs(),
            approved_plan_sha256=plan["planSha256"],
            confirmation=reconcile.CONFIRMATION,
            runner=azure,
        )
        self.assertEqual(
            result["status"],
            "POC_DNS_ACME_AUTHORITY_RECONCILIATION_APPLIED",
        )
        self.assertEqual(result["appliedActions"], 8)
        self.assertEqual(len(azure.mutation_commands), 8)
        for zone in reconcile.CHILD_ZONES:
            self.assertEqual(azure.locks[zone], [])
            self.assertEqual(
                [record["kind"] for record in azure.assignments[zone]], ["custom"]
            )
            self.assertNotIn(
                "_acme-challenge",
                {record["name"] for record in azure.child_records[zone]},
            )
        self.assertFalse(
            any(
                command[1:4] in (
                    ["network", "dns", "zone"],
                    ["role", "definition", "delete"],
                )
                or command[1:3] == ["group", "delete"]
                for command in azure.mutation_commands
            )
        )
        qualified = reconcile.plan_reconciliation(inputs(), runner=azure)
        self.assertEqual(
            qualified["status"], "POC_DNS_ACME_AUTHORITY_RECONCILED"
        )
        self.assertEqual(qualified["actions"], [])
        self.assertEqual(
            [item["challengeRecordStatus"] for item in qualified["observed"]["childZones"]],
            ["ABSENT", "ABSENT"],
        )
        self.assertEqual(
            [item["roleAssignmentCount"] for item in qualified["observed"]["childZones"]],
            [1, 1],
        )
        for vm_name in azure.vm_power_states:
            azure.vm_power_states[vm_name] = "PowerState/running"
        self.assertEqual(
            reconcile.plan_reconciliation(inputs(), runner=azure)["status"],
            "POC_DNS_ACME_AUTHORITY_RECONCILED",
        )

    def test_interrupted_partial_state_replans_only_exact_remainder(self) -> None:
        azure = FakeAzure()
        first = reconcile.CHILD_ZONES[0]
        azure.locks[first] = []
        azure.child_records[first] = [
            record
            for record in azure.child_records[first]
            if record["name"] != "_acme-challenge"
        ]
        azure.assignments[first] = [
            record
            for record in azure.assignments[first]
            if record["kind"] != "reader"
        ]
        plan = reconcile.plan_reconciliation(inputs(), runner=azure)
        self.assertEqual(len(plan["actions"]), 5)
        result = reconcile.apply_reconciliation(
            inputs(),
            approved_plan_sha256=plan["planSha256"],
            confirmation=reconcile.CONFIRMATION,
            runner=azure,
        )
        self.assertEqual(result["appliedActions"], 5)
        self.assertEqual(
            reconcile.plan_reconciliation(inputs(), runner=azure)["status"],
            "POC_DNS_ACME_AUTHORITY_RECONCILED",
        )

    def test_custom_authority_is_revalidated_before_every_mutation(self) -> None:
        azure = FakeAzure()
        plan = reconcile.plan_reconciliation(inputs(), runner=azure)
        azure.inject_custom_assignment_change_after_first_mutation = True
        with self.assertRaisesRegex(
            reconcile.AuthorityReconciliationError, "authority changed"
        ):
            reconcile.apply_reconciliation(
                inputs(),
                approved_plan_sha256=plan["planSha256"],
                confirmation=reconcile.CONFIRMATION,
                runner=azure,
            )
        self.assertEqual(len(azure.mutation_commands), 1)

    def test_legacy_reconciliation_refuses_a_running_edge_vm(self) -> None:
        azure = FakeAzure()
        azure.vm_power_states[reconcile.EDGE_VMS[reconcile.CHILD_ZONES[0]]] = (
            "PowerState/running"
        )
        with self.assertRaisesRegex(
            reconcile.AuthorityReconciliationError, "Azure-deallocated"
        ):
            reconcile.plan_reconciliation(inputs(), runner=azure)
        self.assertFalse(azure.mutation_commands)

    def test_unexpected_role_lock_record_or_parent_drift_fails_closed(self) -> None:
        cases = []

        azure = FakeAzure()
        azure.role_definition["permissions"][0]["actions"].append(
            "Microsoft.Network/dnszones/delete"
        )
        cases.append((azure, "custom-role definition drifted"))

        azure = FakeAzure()
        zone = reconcile.CHILD_ZONES[0]
        azure.assignments[zone] = [
            record for record in azure.assignments[zone] if record["kind"] != "custom"
        ]
        cases.append((azure, "exactly one scoped assignment per node"))

        azure = FakeAzure()
        zone = reconcile.CHILD_ZONES[0]
        broad = dict(next(
            record for record in azure.assignments[zone] if record["kind"] == "custom"
        ))
        broad["id"] = (
            f"/subscriptions/{reconcile.EXPECTED_SUBSCRIPTION_ID}/providers/"
            "Microsoft.Authorization/roleAssignments/"
            "99999999-9999-4999-8999-999999999999"
        )
        broad["scope"] = f"/subscriptions/{reconcile.EXPECTED_SUBSCRIPTION_ID}"
        azure.assignments[zone].append(broad)
        cases.append((azure, "unexpected subscription assignment"))

        azure = FakeAzure()
        zone = reconcile.CHILD_ZONES[0]
        external = dict(next(
            record for record in azure.assignments[zone] if record["kind"] == "reader"
        ))
        external["id"] = (
            f"/subscriptions/{reconcile.EXPECTED_SUBSCRIPTION_ID}/providers/"
            "Microsoft.Authorization/roleAssignments/"
            "88888888-8888-4888-8888-888888888888"
        )
        external["kind"] = "owner"
        external["roleDefinitionId"] = reconcile.contract._role_definition_id(
            reconcile.EXPECTED_SUBSCRIPTION_ID,
            "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
        )
        external["scope"] = f"/subscriptions/{reconcile.EXPECTED_SUBSCRIPTION_ID}"
        azure.assignments[zone].append(external)
        cases.append((azure, "unexpected Azure RBAC assignment"))

        azure = FakeAzure()
        azure.inherited_assignments[SBC1_PRINCIPAL].append(
            {
                "id": (
                    "/providers/Microsoft.Management/managementGroups/root/providers/"
                    "Microsoft.Authorization/roleAssignments/"
                    "77777777-7777-4777-8777-777777777777"
                ),
                "principalId": SBC1_PRINCIPAL,
                "principalType": "ServicePrincipal",
                "roleDefinitionId": reconcile.contract._role_definition_id(
                    reconcile.EXPECTED_SUBSCRIPTION_ID,
                    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                ),
                "scope": "/providers/Microsoft.Management/managementGroups/root",
            }
        )
        cases.append((azure, "unexpected Azure RBAC assignment"))

        azure = FakeAzure()
        zone = reconcile.CHILD_ZONES[0]
        azure.locks[zone][0]["notes"] = "unrelated"
        cases.append((azure, "lock identity drifted"))

        azure = FakeAzure()
        zone = reconcile.CHILD_ZONES[0]
        azure.child_records[zone].append(
            {
                "etag": "unrelated-etag",
                "id": f"{azure.children[zone]['id']}/TXT/business-data",
                "name": "business-data",
                "type": "Microsoft.Network/dnsZones/TXT",
            }
        )
        cases.append((azure, "unexpected record set"))

        azure = FakeAzure()
        azure.parent_records[0]["cnameRecord"] = {"cname": "wrong.example."}
        cases.append((azure, "target drifted"))

        for azure, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(
                    reconcile.AuthorityReconciliationError, message
                ):
                    reconcile.plan_reconciliation(inputs(), runner=azure)
                self.assertFalse(azure.mutation_commands)

    def test_wrong_subscription_or_tenant_fails_before_discovery(self) -> None:
        azure = FakeAzure()
        bad = reconcile.ExpectedInputs(
            subscription_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            tenant_id=reconcile.EXPECTED_TENANT_ID,
            sbc1_principal_id=SBC1_PRINCIPAL,
            sbc2_principal_id=SBC2_PRINCIPAL,
        )
        with self.assertRaisesRegex(
            reconcile.AuthorityReconciliationError, "outside"
        ):
            reconcile.plan_reconciliation(bad, runner=azure)
        self.assertFalse(azure.commands)

    def test_documentation_requires_plan_first_and_exact_final_qualification(self) -> None:
        readme = (ROOT / "README.md").read_text()
        for value in (
            "Exact incremental ACME-authority reconciliation",
            "reconcile_dns_acme_authority.py",
            "planSha256",
            reconcile.CONFIRMATION,
            "POC_DNS_ACME_AUTHORITY_RECONCILED",
            "zero child-zone locks",
            "exactly one custom-role assignment per node",
        ):
            self.assertIn(value, readme)


if __name__ == "__main__":
    unittest.main()
