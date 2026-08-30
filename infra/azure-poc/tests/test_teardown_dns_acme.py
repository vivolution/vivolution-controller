from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import teardown_dns_acme as teardown  # noqa: E402


CP1_IP = "20.10.0.4"
SBC1_IP = "20.10.0.5"
SBC2_IP = "20.10.0.6"
SBC1_PRINCIPAL = "11111111-1111-4111-8111-111111111111"
SBC2_PRINCIPAL = "22222222-2222-4222-8222-222222222222"


def inputs() -> teardown.ExpectedInputs:
    return teardown.ExpectedInputs(
        subscription_id=teardown.EXPECTED_SUBSCRIPTION_ID,
        tenant_id=teardown.EXPECTED_TENANT_ID,
        cp1_public_ipv4=CP1_IP,
        sbc1_public_ipv4=SBC1_IP,
        sbc2_public_ipv4=SBC2_IP,
        sbc1_principal_id=SBC1_PRINCIPAL,
        sbc2_principal_id=SBC2_PRINCIPAL,
    )


class FakeAzure:
    def __init__(self) -> None:
        self.commands: list[list[str]] = []
        self.inject_child_record_after_first_lock_delete = False
        self.injected_child_record = False
        self.account = {
            "id": teardown.EXPECTED_SUBSCRIPTION_ID,
            "tenantId": teardown.EXPECTED_TENANT_ID,
        }
        self.children = {}
        self.child_records = {}
        self.assignments = {}
        self.locks = {}
        self.parent_records = {}
        self._seed()

    def _seed(self) -> None:
        servers_by_zone = {
            teardown.CHILD_ZONES[0]: [
                "ns1-01.azure-dns.com.",
                "ns2-01.azure-dns.net.",
                "ns3-01.azure-dns.org.",
                "ns4-01.azure-dns.info.",
            ],
            teardown.CHILD_ZONES[1]: [
                "ns1-02.azure-dns.com.",
                "ns2-02.azure-dns.net.",
                "ns3-02.azure-dns.org.",
                "ns4-02.azure-dns.info.",
            ],
        }
        principals = {
            teardown.CHILD_ZONES[0]: SBC1_PRINCIPAL,
            teardown.CHILD_ZONES[1]: SBC2_PRINCIPAL,
        }
        for index, zone in enumerate(teardown.CHILD_ZONES, start=1):
            zone_id = teardown._zone_id(teardown.EXPECTED_SUBSCRIPTION_ID, zone)
            self.children[zone] = {
                "etag": f"child-zone-etag-{index}",
                "id": zone_id,
                "name": zone,
                "nameServers": servers_by_zone[zone],
                "resourceGroup": teardown.DNS_RESOURCE_GROUP,
                "tags": dict(teardown.ZONE_TAGS),
                "zoneType": "Public",
            }
            self.child_records[zone] = [
                {"id": f"{zone_id}/NS/@", "name": "@", "type": "Microsoft.Network/dnsZones/NS"},
                {
                    "id": f"{zone_id}/SOA/@",
                    "name": "@",
                    "type": "Microsoft.Network/dnsZones/SOA",
                },
                {
                    "id": f"{zone_id}/TXT/_acme-challenge",
                    "name": "_acme-challenge",
                    "type": "Microsoft.Network/dnsZones/TXT",
                },
            ]
            self.assignments[zone] = []
            for role_index, role_id in enumerate(
                (teardown.READER_ROLE_ID, teardown.DNS_ZONE_CONTRIBUTOR_ROLE_ID), start=1
            ):
                assignment_name = f"{index}{role_index}000000-0000-4000-8000-000000000000"
                assignment_name = assignment_name[:36]
                self.assignments[zone].append(
                    {
                        "id": (
                            f"{zone_id}/providers/Microsoft.Authorization/roleAssignments/"
                            f"{assignment_name}"
                        ),
                        "principalId": principals[zone],
                        "principalType": "ServicePrincipal",
                        "roleDefinitionId": teardown._role_definition_id(
                            teardown.EXPECTED_SUBSCRIPTION_ID, role_id
                        ),
                        "scope": zone_id,
                    }
                )
            self.locks[zone] = [
                {
                    "id": (
                        f"{zone_id}/providers/Microsoft.Authorization/locks/{teardown.LOCK_NAME}"
                    ),
                    "level": teardown.LOCK_LEVEL,
                    "name": teardown.LOCK_NAME,
                    "notes": teardown.LOCK_NOTES[zone],
                }
            ]

        for spec in teardown._parent_specs(inputs()):
            name = spec["name"]
            kind = spec["type"]
            record = {
                "etag": f"parent-record-etag-{len(self.parent_records) + 1}",
                "id": teardown._record_id(
                    teardown.EXPECTED_SUBSCRIPTION_ID, teardown.PARENT_ZONE, kind, name
                ),
                "name": name,
                "ttl": spec["ttl"],
                "type": f"Microsoft.Network/dnsZones/{kind}",
            }
            if kind == "A":
                record["aRecords"] = [{"ipv4Address": spec["ipv4"]}]
            elif kind == "CNAME":
                record["cnameRecord"] = {"cname": f"{spec['cname']}."}
            else:
                record["nsRecords"] = [
                    {"nsdname": value}
                    for value in servers_by_zone[spec["child"]]
                ]
            self.parent_records[(name, kind)] = record

    @staticmethod
    def _value(argv: list[str], option: str) -> str:
        return argv[argv.index(option) + 1]

    def __call__(self, raw_argv):
        argv = list(raw_argv)
        self.commands.append(argv)
        command = argv[1:]
        if command[:2] == ["account", "show"]:
            return json.dumps(self.account)
        if command[:2] == ["group", "show"]:
            name = self._value(argv, "--name")
            location = teardown.POC_LOCATION if name == teardown.POC_RESOURCE_GROUP else "eastus"
            return json.dumps(
                {
                    "id": teardown._resource_group_id(teardown.EXPECTED_SUBSCRIPTION_ID, name),
                    "location": location,
                    "name": name,
                }
            )
        if command[:2] == ["resource", "list"]:
            name = self._value(argv, "--name")
            child = self.children.get(name)
            if child is None:
                return "[]"
            return json.dumps(
                [{"id": child["id"], "name": name, "type": "Microsoft.Network/dnsZones"}]
            )
        if command[:4] == ["network", "dns", "zone", "show"]:
            name = self._value(argv, "--name")
            if name in self.children:
                return json.dumps(self.children[name])
            return json.dumps(
                {
                    "id": teardown._zone_id(
                        teardown.EXPECTED_SUBSCRIPTION_ID, teardown.PARENT_ZONE
                    ),
                    "name": teardown.PARENT_ZONE,
                    "resourceGroup": teardown.DNS_RESOURCE_GROUP,
                    "zoneType": "Public",
                }
            )
        if command[:4] == ["network", "dns", "record-set", "list"]:
            zone = self._value(argv, "--zone-name")
            if zone == teardown.PARENT_ZONE:
                return json.dumps(list(self.parent_records.values()))
            return json.dumps(self.child_records[zone])
        if command[:3] == ["role", "assignment", "list"]:
            scope = self._value(argv, "--scope")
            zone = scope.rsplit("/", 1)[-1]
            return json.dumps(self.assignments[zone])
        if command[:2] == ["lock", "list"]:
            zone = self._value(argv, "--resource-name")
            return json.dumps(self.locks[zone])

        if command[:3] == ["role", "assignment", "delete"]:
            target = self._value(argv, "--ids")
            for zone in list(self.assignments):
                self.assignments[zone] = [
                    record for record in self.assignments[zone] if record["id"] != target
                ]
            return ""
        if command[:2] == ["lock", "delete"]:
            target = self._value(argv, "--ids")
            for zone in list(self.locks):
                self.locks[zone] = [record for record in self.locks[zone] if record["id"] != target]
            first_zone = teardown.CHILD_ZONES[0]
            if (
                self.inject_child_record_after_first_lock_delete
                and not self.injected_child_record
                and first_zone in target
            ):
                self.child_records[first_zone].append(
                    {
                        "id": f"{self.children[first_zone]['id']}/TXT/unrelated",
                        "name": "unrelated",
                        "type": "Microsoft.Network/dnsZones/TXT",
                    }
                )
                self.injected_child_record = True
            return ""
        if command[:4] == ["network", "dns", "zone", "delete"]:
            target = self._value(argv, "--ids")
            zone = target.rsplit("/", 1)[-1]
            if self._value(argv, "--if-match") != self.children[zone]["etag"]:
                raise AssertionError("zone ETag mismatch")
            self.children.pop(zone)
            self.child_records.pop(zone)
            self.assignments.pop(zone)
            self.locks.pop(zone)
            return ""
        if command[:3] == ["network", "dns", "record-set"] and command[4] == "delete":
            kind = command[3].upper()
            name = self._value(argv, "--name")
            if self._value(argv, "--if-match") != self.parent_records[(name, kind)]["etag"]:
                raise AssertionError("record-set ETag mismatch")
            self.parent_records.pop((name, kind))
            return ""
        raise AssertionError(argv)

    @property
    def mutation_commands(self) -> list[list[str]]:
        return [
            command
            for command in self.commands
            if "delete" in command[1:]
        ]


class DnsAcmeTeardownTests(unittest.TestCase):
    def test_plan_is_read_only_and_exactly_bounded(self) -> None:
        azure = FakeAzure()
        plan = teardown.plan_teardown(inputs(), runner=azure)
        self.assertEqual(plan["status"], "POC_DNS_ACME_TEARDOWN_PLAN_READY")
        self.assertEqual(len(plan["actions"]), 17)
        self.assertRegex(plan["planSha256"], r"^[0-9a-f]{64}$")
        self.assertFalse(azure.mutation_commands)
        parent_zone_id = teardown._zone_id(
            teardown.EXPECTED_SUBSCRIPTION_ID, teardown.PARENT_ZONE
        )
        self.assertNotIn(parent_zone_id, {action["id"] for action in plan["actions"]})
        self.assertTrue(all("group" not in action["kind"].lower() for action in plan["actions"]))

        parent_record_command = next(
            command
            for command in azure.commands
            if command[1:5] == ["network", "dns", "record-set", "list"]
            and FakeAzure._value(command, "--zone-name") == teardown.PARENT_ZONE
        )
        query = FakeAzure._value(parent_record_command, "--query")
        self.assertIn("ttl:TTL", query)
        self.assertIn("aRecords:ARecords", query)
        self.assertIn("cnameRecord:CNAMERecord", query)
        self.assertIn("nsRecords:NSRecords", query)
        self.assertNotIn("ttl:ttl", query)

        role_list_commands = [
            command
            for command in azure.commands
            if command[1:4] == ["role", "assignment", "list"]
        ]
        self.assertEqual(len(role_list_commands), 2)
        for command in role_list_commands:
            self.assertNotIn("--include-inherited", command)
            self.assertEqual(FakeAzure._value(command, "--fill-principal-name"), "false")
            self.assertEqual(
                FakeAzure._value(command, "--fill-role-definition-name"), "false"
            )

    def test_apply_requires_matching_digest_and_exact_confirmation(self) -> None:
        azure = FakeAzure()
        plan = teardown.plan_teardown(inputs(), runner=azure)
        with self.assertRaisesRegex(teardown.DnsTeardownError, "confirmation"):
            teardown.apply_teardown(
                inputs(),
                approved_plan_sha256=plan["planSha256"],
                confirmation="delete",
                runner=azure,
            )
        self.assertFalse(azure.mutation_commands)

        with self.assertRaisesRegex(teardown.DnsTeardownError, "does not match"):
            teardown.apply_teardown(
                inputs(),
                approved_plan_sha256="0" * 64,
                confirmation=teardown.CONFIRMATION,
                runner=azure,
            )
        self.assertFalse(azure.mutation_commands)

    def test_apply_removes_only_planned_resources_and_verifies_absence(self) -> None:
        azure = FakeAzure()
        plan = teardown.plan_teardown(inputs(), runner=azure)
        result = teardown.apply_teardown(
            inputs(),
            approved_plan_sha256=plan["planSha256"],
            confirmation=teardown.CONFIRMATION,
            runner=azure,
        )
        self.assertEqual(result["status"], "POC_DNS_ACME_TEARDOWN_APPLIED")
        self.assertEqual(result["deletedActions"], 17)
        self.assertEqual(len(azure.mutation_commands), 17)
        self.assertFalse(azure.children)
        self.assertFalse(azure.parent_records)
        self.assertFalse(
            any(command[1:3] == ["group", "delete"] for command in azure.mutation_commands)
        )

    def test_wrong_subscription_tenant_or_group_fails_before_mutation(self) -> None:
        azure = FakeAzure()
        wrong = inputs()
        wrong = teardown.ExpectedInputs(
            **{**wrong.__dict__, "subscription_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
        )
        with self.assertRaisesRegex(teardown.DnsTeardownError, "outside"):
            teardown.plan_teardown(wrong, runner=azure)
        self.assertFalse(azure.commands)

        azure = FakeAzure()
        azure.account["tenantId"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        with self.assertRaisesRegex(teardown.DnsTeardownError, "tenant"):
            teardown.plan_teardown(inputs(), runner=azure)
        self.assertFalse(azure.mutation_commands)

    def test_record_tag_child_content_rbac_and_lock_drift_fail_closed(self) -> None:
        cases = []

        azure = FakeAzure()
        azure.parent_records[("sbc1", "A")]["aRecords"] = [{"ipv4Address": "20.10.0.99"}]
        cases.append((azure, "address drifted"))

        azure = FakeAzure()
        azure.children[teardown.CHILD_ZONES[0]]["tags"]["purpose"] = "unrelated"
        cases.append((azure, "ownership tags drifted"))

        azure = FakeAzure()
        zone = teardown.CHILD_ZONES[0]
        azure.child_records[zone].append(
            {
                "id": f"{azure.children[zone]['id']}/TXT/business-data",
                "name": "business-data",
                "type": "Microsoft.Network/dnsZones/TXT",
            }
        )
        cases.append((azure, "unexpected record set"))

        azure = FakeAzure()
        azure.assignments[teardown.CHILD_ZONES[0]][0]["principalId"] = SBC2_PRINCIPAL
        cases.append((azure, "unexpected direct RBAC"))

        azure = FakeAzure()
        azure.locks[teardown.CHILD_ZONES[0]][0]["notes"] = "unrelated"
        cases.append((azure, "lock identity drifted"))

        for azure, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(teardown.DnsTeardownError, message):
                    teardown.plan_teardown(inputs(), runner=azure)
                self.assertFalse(azure.mutation_commands)

    def test_child_zone_is_revalidated_after_lock_and_rbac_removal(self) -> None:
        azure = FakeAzure()
        plan = teardown.plan_teardown(inputs(), runner=azure)
        azure.inject_child_record_after_first_lock_delete = True
        with self.assertRaisesRegex(teardown.DnsTeardownError, "unexpected record set"):
            teardown.apply_teardown(
                inputs(),
                approved_plan_sha256=plan["planSha256"],
                confirmation=teardown.CONFIRMATION,
                runner=azure,
            )
        self.assertIn(teardown.CHILD_ZONES[0], azure.children)
        self.assertFalse(
            any(
                command[1:5] == ["network", "dns", "zone", "delete"]
                for command in azure.mutation_commands
            )
        )

    def test_partial_teardown_can_be_replanned_and_already_absent_is_safe(self) -> None:
        azure = FakeAzure()
        azure.parent_records.pop(("cp1-poc", "A"))
        azure.locks[teardown.CHILD_ZONES[0]] = []
        azure.assignments[teardown.CHILD_ZONES[1]] = azure.assignments[
            teardown.CHILD_ZONES[1]
        ][1:]
        plan = teardown.plan_teardown(inputs(), runner=azure)
        self.assertEqual(len(plan["actions"]), 14)
        self.assertFalse(azure.mutation_commands)

        azure.parent_records.clear()
        azure.children.clear()
        plan = teardown.plan_teardown(inputs(), runner=azure)
        self.assertEqual(plan["status"], "POC_DNS_ACME_ALREADY_ABSENT")
        self.assertEqual(plan["actions"], [])
        self.assertFalse(azure.mutation_commands)

    def test_stale_delegation_after_child_zone_loss_is_rejected(self) -> None:
        azure = FakeAzure()
        zone = teardown.CHILD_ZONES[0]
        azure.children.pop(zone)
        with self.assertRaisesRegex(teardown.DnsTeardownError, "cannot prove ownership"):
            teardown.plan_teardown(inputs(), runner=azure)
        self.assertFalse(azure.mutation_commands)

    def test_documentation_keeps_plan_first_and_shared_zone_safe(self) -> None:
        readme = (ROOT / "README.md").read_text()
        self.assertIn("teardown_dns_acme.py", readme)
        self.assertIn("defaults to read-only `plan` mode", readme)
        self.assertIn("never deletes `DNS_Zones`", readme)
        self.assertIn("planSha256", readme)


if __name__ == "__main__":
    unittest.main()
