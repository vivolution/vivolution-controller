from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import shutil
import stat
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT_PATH = ROOT / "direct-replacement-preflight.py"
TEMPLATE_PATH = ROOT / "direct-replacement.bicep"
PARAMETERS_PATH = ROOT / "direct-replacement.example.bicepparam"
MODULE_PATH = ROOT / "modules" / "linux-node.bicep"
README_PATH = ROOT / "direct-replacement-README.md"

SPEC = importlib.util.spec_from_file_location("direct_replacement_preflight", PREFLIGHT_PATH)
assert SPEC is not None and SPEC.loader is not None
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)

KEY_BLOB = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + b"d" * 32
KEY = "ssh-ed25519 " + base64.b64encode(KEY_BLOB).decode("ascii") + " test"
FINGERPRINT = (
    "SHA256:"
    + base64.b64encode(hashlib.sha256(KEY_BLOB).digest())
    .decode("ascii")
    .rstrip("=")
)
ADMIN = ["8.8.8.8/32"]
DEADLINE = "2026-09-03T00:00:00Z"
TEST_NOW = datetime(2026, 8, 31, 0, 0, 0, tzinfo=timezone.utc)
PUBLIC_IPS = {
    "viv-sbc-poc-cp1": "1.1.1.1",
    "viv-sbc-poc-sbc1": "8.8.4.4",
    "viv-sbc-poc-sbc2": "8.8.8.8",
    "viv-sbc-dr-sbc1-g3": "9.9.9.9",
    "viv-sbc-dr-sbc2-g3": "1.0.0.1",
}
DEADMAN_JOB_ID = "11111111-1111-4111-8111-111111111111"
SCHEDULER_HOST = "Jays-MacBook-Pro.local"


def parameter_document():
    values = dict(preflight.FIXED_VALUES)
    values.update(
        {
            "administratorSourcePrefixes": ADMIN,
            "parallelAcceptanceDeadlineUtc": DEADLINE,
            "sshPublicKey": KEY,
        }
    )
    return {
        "$schema": preflight.PARAMETER_SCHEMA,
        "contentVersion": "1.0.0.0",
        "parameters": {
            name: {"value": value} for name, value in sorted(values.items())
        },
    }


def rid(resource_type, name):
    return (
        "/subscriptions/{}/resourceGroups/{}/providers/{}/{}".format(
            preflight.EXPECTED_SUBSCRIPTION_ID,
            preflight.EXPECTED_RESOURCE_GROUP,
            resource_type,
            name,
        )
    )


def node_observation(node, *, include_disk=False, locked=True):
    nic_id = rid("Microsoft.Network/networkInterfaces", node + "-nic")
    nsg_id = rid("Microsoft.Network/networkSecurityGroups", node + "-nsg")
    public_ip_id = rid("Microsoft.Network/publicIPAddresses", node + "-pip")
    tags = (
        preflight._replacement_tags(node, DEADLINE)
        if node in preflight.EXPECTED_REPLACEMENT_VM_NAMES
        else {"existing": "baseline"}
    )
    vm = {
        "id": rid("Microsoft.Compute/virtualMachines", node),
        "location": "uaenorth",
        "name": node,
        "nicIds": [nic_id],
        "osDiskId": rid("Microsoft.Compute/disks", node + "-osdisk"),
        "osDiskName": node + "-osdisk",
        "provisioningState": "Succeeded",
    }
    record = {
        "name": node,
        "nic": {
            "enableAcceleratedNetworking": False,
            "enableIPForwarding": False,
            "id": nic_id,
            "ipConfigurations": [
                {
                    "name": "ipconfig1",
                    "primary": True,
                    "privateIPAddress": preflight.EXPECTED_NODE_PRIVATE_IPS[node],
                    "privateIPAllocationMethod": "Static",
                    "privateIPAddressVersion": "IPv4",
                    "publicIpId": rid(
                        "Microsoft.Network/publicIPAddresses", node + "-pip"
                    ),
                    "subnetId": preflight._expected_subnet_id(node),
                }
            ],
            "location": "uaenorth",
            "name": node + "-nic",
            "networkSecurityGroupId": rid(
                "Microsoft.Network/networkSecurityGroups", node + "-nsg"
            ),
            "provisioningState": "Succeeded",
        },
        "nsg": {
            "id": nsg_id,
            "location": "uaenorth",
            "name": node + "-nsg",
            "networkInterfaceIds": [nic_id],
            "provisioningState": "Succeeded",
            "subnetIds": [],
            "tags": tags,
        },
        "powerState": "PowerState/running",
        "publicIp": {
            "id": public_ip_id,
            "ipAddress": PUBLIC_IPS[node],
            "ipConfigurationId": nic_id + "/ipConfigurations/ipconfig1",
            "location": "uaenorth",
            "name": node + "-pip",
            "provisioningState": "Succeeded",
            "publicIPAllocationMethod": "Static",
            "publicIPAddressVersion": "IPv4",
            "skuName": "Standard",
            "skuTier": "Regional",
            "tags": tags,
        },
        "vm": vm,
    }
    if include_disk:
        record["disk"] = {
            "id": rid("Microsoft.Compute/disks", node + "-osdisk"),
            "managedBy": rid("Microsoft.Compute/virtualMachines", node),
            "name": node + "-osdisk",
            "networkAccessPolicy": "DenyAll" if locked else "AllowAll",
            "provisioningState": "Succeeded",
            "publicNetworkAccess": "Disabled" if locked else "Enabled",
            "tags": preflight._replacement_tags(node, DEADLINE) if locked else None,
        }
    return record


def live_observations(present_nodes=(), *, locked_nodes=None):
    present_nodes = set(present_nodes)
    locked_nodes = present_nodes if locked_nodes is None else set(locked_nodes)
    resources = []
    changes = []
    for node in preflight.EXPECTED_REPLACEMENT_VM_NAMES:
        for suffix, resource_type in (
            ("", "Microsoft.Compute/virtualMachines"),
            ("-nic", "Microsoft.Network/networkInterfaces"),
            ("-nsg", "Microsoft.Network/networkSecurityGroups"),
            ("-pip", "Microsoft.Network/publicIPAddresses"),
        ):
            name = node + suffix
            resource_id = rid(resource_type, name)
            changes.append(
                {
                    "changeType": "NoChange" if node in present_nodes else "Create",
                    "resourceId": resource_id,
                }
            )
            if node in present_nodes:
                resources.append(
                    {
                        "id": resource_id,
                        "location": "uaenorth",
                        "name": name,
                        "tags": preflight._replacement_tags(node, DEADLINE),
                        "type": resource_type,
                    }
                )
        if node in present_nodes:
            resources.append(
                {
                    "id": rid("Microsoft.Compute/disks", node + "-osdisk"),
                    "location": "uaenorth",
                    "managedBy": rid("Microsoft.Compute/virtualMachines", node),
                    "name": node + "-osdisk",
                    "tags": preflight._replacement_tags(node, DEADLINE),
                    "type": "Microsoft.Compute/disks",
                }
            )

    subnet_common = {
        "addressPrefixes": None,
        "defaultOutboundAccess": False,
        "delegations": [],
        "natGatewayId": None,
        "networkSecurityGroupId": None,
        "privateEndpointIds": [],
        "privateEndpointNetworkPolicies": "Enabled",
        "privateLinkServiceNetworkPolicies": "Enabled",
        "provisioningState": "Succeeded",
        "routeTableId": None,
        "serviceEndpointPolicyIds": [],
        "serviceEndpoints": [],
    }
    management_ipconfig = (
        rid("Microsoft.Network/networkInterfaces", "viv-sbc-poc-cp1-nic")
        + "/ipConfigurations/ipconfig1"
    )
    edge_ipconfigs = [
        rid("Microsoft.Network/networkInterfaces", node + "-nic")
        + "/ipConfigurations/ipconfig1"
        for node in preflight.EXPECTED_SYNTHETIC_VM_NAMES
    ] + [
        rid("Microsoft.Network/networkInterfaces", node + "-nic")
        + "/ipConfigurations/ipconfig1"
        for node in sorted(present_nodes)
    ]
    budget_notifications = {
        str(value): {
            "contactEmails": ["jaydevupadhyay@gmail.com"],
            "contactGroups": [],
            "contactRoles": [],
            "enabled": True,
            "operator": "GreaterThanOrEqualTo",
            "threshold": value,
            "thresholdType": "Actual",
        }
        for value in (75, 90, 100)
    }
    return {
        "account": {
            "id": preflight.EXPECTED_SUBSCRIPTION_ID,
            "state": "Enabled",
            "tenantId": preflight.EXPECTED_TENANT_ID,
        },
        "availabilitySet": {
            "faultDomains": 2,
            "id": rid(
                "Microsoft.Compute/availabilitySets",
                preflight.EXPECTED_AVAILABILITY_SET_NAME,
            ),
            "location": "uaenorth",
            "name": preflight.EXPECTED_AVAILABILITY_SET_NAME,
            "sku": "Aligned",
            "tags": preflight._required_common_tags(),
            "updateDomains": 5,
            "vmIds": [
                rid("Microsoft.Compute/virtualMachines", node)
                for node in (
                    *preflight.EXPECTED_SYNTHETIC_VM_NAMES,
                    *sorted(present_nodes),
                )
            ],
        },
        "budget": {
            "id": "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Consumption/budgets/{}".format(
                preflight.EXPECTED_SUBSCRIPTION_ID,
                preflight.EXPECTED_RESOURCE_GROUP,
                preflight.EXPECTED_BUDGET_NAME,
            ),
            "name": preflight.EXPECTED_BUDGET_NAME,
            "properties": {
                "amount": 100,
                "category": "Cost",
                "notifications": budget_notifications,
                "timeGrain": "Monthly",
            },
            "type": "Microsoft.Consumption/budgets",
        },
        "cost": {"amountUsd": "20.25", "currency": "USD"},
        "providers": [
            {"namespace": namespace, "registrationState": "Registered"}
            for namespace in preflight.EXPECTED_PROVIDER_NAMESPACES
        ],
        "resourceGroup": {
            "id": "/subscriptions/{}/resourceGroups/{}".format(
                preflight.EXPECTED_SUBSCRIPTION_ID,
                preflight.EXPECTED_RESOURCE_GROUP,
            ),
            "location": "uaenorth",
            "name": preflight.EXPECTED_RESOURCE_GROUP,
            "properties": {"provisioningState": "Succeeded"},
            "tags": preflight._required_common_tags(),
        },
        "resources": resources,
        "nodes": [
            node_observation("viv-sbc-poc-cp1"),
            node_observation("viv-sbc-poc-sbc1"),
            node_observation("viv-sbc-poc-sbc2"),
            *[
                node_observation(
                    node,
                    include_disk=True,
                    locked=node in locked_nodes,
                )
                for node in sorted(present_nodes)
            ],
        ],
        "vnet": {
            "addressPrefixes": ["10.20.0.0/16"],
            "ddosProtection": False,
            "dnsServers": [],
            "id": rid("Microsoft.Network/virtualNetworks", "viv-sbc-poc-vnet"),
            "location": "uaenorth",
            "name": "viv-sbc-poc-vnet",
            "peerings": [],
            "provisioningState": "Succeeded",
            "tags": preflight._required_common_tags(),
            "subnets": [
                {
                    **subnet_common,
                    "addressPrefix": "10.20.1.0/24",
                    "ipConfigurationIds": [management_ipconfig],
                    "name": "snet-management",
                },
                {
                    **subnet_common,
                    "addressPrefix": "10.20.2.0/24",
                    "ipConfigurationIds": edge_ipconfigs,
                    "name": "snet-edge",
                },
            ],
        },
        "whatIf": {"changes": changes, "status": "Succeeded"},
    }


def deadman_job(plan, *, enabled=True, created_at=None, payload=None, schedule=None):
    created = created_at or datetime(
        2026, 8, 31, 1, 3, 0, tzinfo=timezone.utc
    )
    deadline = datetime.strptime(DEADLINE, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    return {
        "agentId": preflight.OPENCLAW_AGENT_ID,
        "createdAtMs": preflight._canonical_millisecond(created),
        "declarationKey": "vivolution-direct-replacement-deadman:{}".format(
            plan["planSha256"]
        ),
        "deleteAfterRun": True,
        "delivery": preflight._expected_deadman_delivery(),
        "description": preflight._deadman_job_description(plan),
        "displayName": "Vivolution g3 replacement budget deadman",
        "enabled": enabled,
        "id": DEADMAN_JOB_ID,
        "name": preflight._deadman_job_name(plan),
        "payload": payload or preflight._expected_deadman_payload(plan),
        "schedule": schedule or {"at": DEADLINE, "kind": "at"},
        "sessionTarget": "isolated",
        "state": {
            "lastRunAtMs": None,
            "nextRunAtMs": preflight._canonical_millisecond(deadline),
            "runningAtMs": None,
        },
        "updatedAtMs": preflight._canonical_millisecond(created),
        "wakeMode": "now",
    }


def deadman_scheduler_runner(plan, *, job=None, status=None):
    live_job = job or deadman_job(plan)
    deadline = datetime.strptime(DEADLINE, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    live_status = status or {
        "enabled": True,
        "jobs": 1,
        "nextWakeAtMs": preflight._canonical_millisecond(deadline),
        "storage": "sqlite",
    }

    def runner(argv):
        if argv == [str(preflight.EXPECTED_OPENCLAW_CLI), "cron", "status"]:
            return json.dumps(live_status)
        if argv == [
            str(preflight.EXPECTED_OPENCLAW_CLI),
            "cron",
            "get",
            DEADMAN_JOB_ID,
        ]:
            return json.dumps(live_job)
        raise AssertionError(argv)

    return runner


class DirectReplacementPreflightTests(unittest.TestCase):
    def validate(self, value):
        return preflight.validate_parameters(
            value,
            approved_admin_cidrs=ADMIN,
            expected_ssh_fingerprint=FINGERPRINT,
            now=TEST_NOW,
        )

    def test_exact_reviewed_parameters_pass_without_disclosing_key(self):
        evidence = self.validate(parameter_document())
        self.assertEqual(evidence["status"], "DIRECT_REPLACEMENT_PARAMETERS_VALID")
        self.assertEqual(
            evidence["edgeRuntimeProfile"], "DIRECT_ROUTING_PRIVATE_PBX_POC"
        )
        self.assertEqual(evidence["edgeGeneration"], 3)
        self.assertEqual(
            evidence["replacementPrivateIpAddresses"],
            {"sbc1": "10.20.2.6", "sbc2": "10.20.2.7"},
        )
        self.assertEqual(
            evidence["replacementVmNames"],
            {"sbc1": "viv-sbc-dr-sbc1-g3", "sbc2": "viv-sbc-dr-sbc2-g3"},
        )
        self.assertNotIn(KEY, json.dumps(evidence, sort_keys=True))

    def test_parameter_names_and_wrappers_are_exact(self):
        missing = parameter_document()
        del missing["parameters"]["edgeGeneration"]
        with self.assertRaises(preflight.PreflightError):
            self.validate(missing)

        extra = parameter_document()
        extra["parameters"]["unsafe"] = {"value": True}
        with self.assertRaises(preflight.PreflightError):
            self.validate(extra)

        expression = parameter_document()
        expression["parameters"]["edgeGeneration"] = {
            "value": 3,
            "reference": "forbidden",
        }
        with self.assertRaises(preflight.PreflightError):
            self.validate(expression)

        unexpected_top_level = parameter_document()
        unexpected_top_level["variables"] = {}
        with self.assertRaises(preflight.PreflightError):
            self.validate(unexpected_top_level)

    def test_every_fixed_authority_is_fail_closed(self):
        mutations = {
            "targetSubscriptionId": "00000000-0000-0000-0000-000000000000",
            "targetResourceGroupName": "another-group",
            "existingVirtualNetworkName": "another-vnet",
            "existingEdgeSubnetName": "another-subnet",
            "existingAvailabilitySetName": "another-as",
            "edgeRuntimeProfile": "SYNTHETIC_PRIVATE",
            "edgeGeneration": 4,
            "sbc1NodeName": "viv-sbc-poc-sbc1",
            "sbc2NodeName": "viv-sbc-poc-sbc2",
            "sbc1PrivateIpAddress": "10.20.2.4",
            "sbc2PrivateIpAddress": "10.20.2.5",
            "cp1PrivatePrefix": "10.20.1.5/32",
            "microsoftSignalingSourcePrefixes": ["52.112.0.0/14"],
            "microsoftMediaSourcePrefixes": ["0.0.0.0/0"],
            "remoteTlsPort": 5060,
            "localPbxTlsListenerPort": 5061,
            "pbxMediaDestinationPortStart": 10000,
            "pbxMediaDestinationPortEnd": 60000,
            "rtpMediaPortCount": 45536,
            "tenantRtpMediaPortCount": 10000,
            "vmSize": "Standard_D8s_v5",
            "osDiskSizeGiB": 1024,
            "osDiskSku": "Premium_LRS",
            "enableTrustedLaunch": False,
            "adminUsername": "root",
            "imageVersion": "latest",
        }
        for name, candidate in mutations.items():
            with self.subTest(name=name):
                value = parameter_document()
                value["parameters"][name]["value"] = candidate
                with self.assertRaises(preflight.PreflightError):
                    self.validate(value)

    def test_admin_prefixes_are_exact_global_canonical_32s(self):
        for candidate in (
            ["0.0.0.0/0"],
            ["10.0.0.1/32"],
            ["8.8.8.8/32", "8.8.8.8/32"],
            ["9.9.9.9/32", "8.8.8.8/32"],
            [
                "1.0.0.1/32",
                "1.1.1.1/32",
                "8.8.4.4/32",
                "8.8.8.8/32",
                "9.9.9.9/32",
            ],
        ):
            with self.subTest(candidate=candidate):
                value = parameter_document()
                value["parameters"]["administratorSourcePrefixes"]["value"] = candidate
                with self.assertRaises(preflight.PreflightError):
                    self.validate(value)

        with self.assertRaises(preflight.PreflightError):
            preflight.validate_parameters(
                parameter_document(),
                approved_admin_cidrs=["9.9.9.9/32"],
                expected_ssh_fingerprint=FINGERPRINT,
                now=TEST_NOW,
            )

    def test_carrier_gateway_is_fixed_to_cp1_private_32_without_public_authority(self):
        evidence = self.validate(parameter_document())
        self.assertEqual(evidence["carrierGatewayPrivatePrefix"], "10.20.1.4/32")
        self.assertEqual(
            evidence["carrierGatewayPath"], "same-vnet-private-no-public-hairpin"
        )
        self.assertNotIn("carrierGatewayPublicPrefix", preflight.EXACT_PARAMETER_NAMES)

    def test_private_key_and_unapproved_public_key_are_rejected(self):
        value = parameter_document()
        value["parameters"]["sshPublicKey"]["value"] = (
            "-----BEGIN OPENSSH PRIVATE KEY-----"
        )
        with self.assertRaises(preflight.PreflightError):
            self.validate(value)

        with self.assertRaises(preflight.PreflightError):
            preflight.validate_parameters(
                parameter_document(),
                approved_admin_cidrs=ADMIN,
                expected_ssh_fingerprint="SHA256:" + "x" * 43,
                now=TEST_NOW,
            )

    def test_parallel_deadline_is_canonical_future_and_never_over_72_hours(self):
        for candidate in (
            "2026-08-31T00:00:00Z",
            "2026-09-03T00:00:01Z",
            "2026-09-03 00:00:00Z",
            "2026-09-03T00:00:00+00:00",
        ):
            value = parameter_document()
            value["parameters"]["parallelAcceptanceDeadlineUtc"]["value"] = candidate
            with self.subTest(candidate=candidate):
                with self.assertRaises(preflight.PreflightError):
                    self.validate(value)


class DirectReplacementLivePlanTests(unittest.TestCase):
    package_evidence = {
        "bicepCompilerVersion": preflight.EXPECTED_BICEP_VERSION,
        "compiledParametersSha256": "a" * 64,
        "compiledTemplateSha256": preflight.EXPECTED_COMPILED_TEMPLATE_SHA256,
        "edgeGeneration": 3,
        "edgeRuntimeProfile": "DIRECT_ROUTING_PRIVATE_PBX_POC",
        "parallelAcceptanceDeadlineUtc": DEADLINE,
    }
    observed_at = datetime(2026, 8, 31, 1, 2, 3, tzinfo=timezone.utc)

    def validate(self, observations):
        return preflight.validate_live_plan(
            observations,
            self.package_evidence,
            observed_at=self.observed_at,
        )

    def scheduler_authority(self, plan, now, *, job=None, status=None):
        runner = deadman_scheduler_runner(plan, job=job, status=status)
        receipt = preflight.build_deadman_scheduler_receipt(
            plan,
            job_id=DEADMAN_JOB_ID,
            now=now,
            scheduler_runner=runner,
            host_name=SCHEDULER_HOST,
        )
        return receipt, runner

    def test_empty_boundary_passes_with_budget_deadline_and_provider_what_if(self):
        plan = self.validate(live_observations())
        self.assertEqual(plan["status"], "DIRECT_REPLACEMENT_LIVE_PLAN_VALID")
        self.assertEqual(plan["compiledParametersSha256"], "a" * 64)
        self.assertEqual(plan["authority"]["providerValidationLevel"], "Provider")
        self.assertEqual(plan["budget"]["remainingBudgetUsd"], "79.75")
        self.assertEqual(plan["parallelAcceptance"]["maximumHours"], 72)
        self.assertEqual(
            plan["runtimeAuthority"],
            {
                "generation": 3,
                "profile": "DIRECT_ROUTING_PRIVATE_PBX_POC",
            },
        )
        self.assertEqual(
            plan["parallelAcceptance"]["deadlineUtc"], DEADLINE
        )
        self.assertEqual(plan["authorizationExpiresUtc"], "2026-08-31T01:17:03Z")
        self.assertRegex(plan["planSha256"], r"^[0-9a-f]{64}$")

    def test_live_create_plan_requires_one_hour_deadline_buffer(self):
        evidence = dict(self.package_evidence)
        evidence["parallelAcceptanceDeadlineUtc"] = "2026-08-31T01:32:03Z"
        with self.assertRaises(preflight.PreflightError):
            preflight.validate_live_plan(
                live_observations(),
                evidence,
                observed_at=self.observed_at,
            )

    def test_live_plan_rejects_generic_or_missing_runtime_authority(self):
        for profile in ("DIRECT_ROUTING", None):
            evidence = dict(self.package_evidence)
            if profile is None:
                del evidence["edgeRuntimeProfile"]
            else:
                evidence["edgeRuntimeProfile"] = profile
            with self.subTest(profile=profile):
                with self.assertRaises(preflight.PreflightError):
                    preflight.validate_live_plan(
                        live_observations(),
                        evidence,
                        observed_at=self.observed_at,
                    )

    def test_exact_partial_node_is_resumable_with_same_deployment_and_digest(self):
        node = preflight.EXPECTED_REPLACEMENT_VM_NAMES[0]
        plan = self.validate(live_observations([node]))
        self.assertEqual(
            plan["partialDeploymentResume"]["presentReplacementVmNames"], [node]
        )
        self.assertTrue(
            plan["partialDeploymentResume"][
                "resumeWithSameDeploymentNameAndParameterDigest"
            ]
        )

    def test_pending_disk_lockdown_is_explicit_and_locked_state_is_exact(self):
        node = preflight.EXPECTED_REPLACEMENT_VM_NAMES[0]
        pending = self.validate(live_observations([node], locked_nodes=[]))
        self.assertEqual(
            pending["partialDeploymentResume"]["diskLockdown"],
            {"lockedVmNames": [], "pendingVmNames": [node]},
        )
        locked = self.validate(live_observations([node]))
        self.assertEqual(
            locked["partialDeploymentResume"]["diskLockdown"],
            {"lockedVmNames": [node], "pendingVmNames": []},
        )
        interrupted = live_observations([node])
        interrupted["nodes"][3]["disk"]["tags"] = None
        next(
            item
            for item in interrupted["resources"]
            if item["type"] == "Microsoft.Compute/disks"
        )["tags"] = None
        resumed = self.validate(interrupted)
        self.assertEqual(
            resumed["partialDeploymentResume"]["diskLockdown"],
            {"lockedVmNames": [], "pendingVmNames": [node]},
        )

    def test_topology_provider_and_budget_drift_fail_closed(self):
        cases = []
        wrong_provider = live_observations()
        wrong_provider["providers"][0]["registrationState"] = "Registering"
        cases.append(wrong_provider)
        subnet_nsg = live_observations()
        subnet_nsg["vnet"]["subnets"][1]["networkSecurityGroupId"] = "unexpected"
        cases.append(subnet_nsg)
        subnet_route = live_observations()
        subnet_route["vnet"]["subnets"][1]["routeTableId"] = "unexpected"
        cases.append(subnet_route)
        subnet_nat = live_observations()
        subnet_nat["vnet"]["subnets"][1]["natGatewayId"] = "unexpected"
        cases.append(subnet_nat)
        subnet_delegation = live_observations()
        subnet_delegation["vnet"]["subnets"][1]["delegations"] = ["unexpected"]
        cases.append(subnet_delegation)
        default_outbound = live_observations()
        default_outbound["vnet"]["subnets"][1]["defaultOutboundAccess"] = True
        cases.append(default_outbound)
        bad_availability_set = live_observations()
        bad_availability_set["availabilitySet"]["faultDomains"] = 3
        cases.append(bad_availability_set)
        extra_availability_set_field = live_observations()
        extra_availability_set_field["availabilitySet"]["provisioningState"] = "Succeeded"
        cases.append(extra_availability_set_field)
        wrong_budget_scope = live_observations()
        wrong_budget_scope["budget"]["id"] = (
            "/subscriptions/{}/providers/Microsoft.Consumption/budgets/{}".format(
                preflight.EXPECTED_SUBSCRIPTION_ID,
                preflight.EXPECTED_BUDGET_NAME,
            )
        )
        cases.append(wrong_budget_scope)
        cp1_ip = live_observations()
        cp1_ip["nodes"][0]["nic"]["ipConfigurations"][0]["privateIPAddress"] = "10.20.1.5"
        cases.append(cp1_ip)
        predecessor_ip = live_observations()
        predecessor_ip["nodes"][1]["nic"]["ipConfigurations"][0]["privateIPAddress"] = "10.20.2.6"
        cases.append(predecessor_ip)
        partial = live_observations([preflight.EXPECTED_REPLACEMENT_VM_NAMES[0]])
        partial["nodes"][3]["vm"]["provisioningState"] = "Updating"
        cases.append(partial)
        replacement_ip = live_observations([preflight.EXPECTED_REPLACEMENT_VM_NAMES[0]])
        replacement_ip["nodes"][3]["nic"]["ipConfigurations"][0]["privateIPAllocationMethod"] = "Dynamic"
        cases.append(replacement_ip)
        failed_replacement_nsg = live_observations(
            [preflight.EXPECTED_REPLACEMENT_VM_NAMES[0]]
        )
        failed_replacement_nsg["nodes"][3]["nsg"]["provisioningState"] = "Failed"
        cases.append(failed_replacement_nsg)
        wrong_replacement_nsg_attachment = live_observations(
            [preflight.EXPECTED_REPLACEMENT_VM_NAMES[0]]
        )
        wrong_replacement_nsg_attachment["nodes"][3]["nsg"][
            "networkInterfaceIds"
        ] = []
        cases.append(wrong_replacement_nsg_attachment)
        failed_replacement_pip = live_observations(
            [preflight.EXPECTED_REPLACEMENT_VM_NAMES[0]]
        )
        failed_replacement_pip["nodes"][3]["publicIp"][
            "provisioningState"
        ] = "Failed"
        cases.append(failed_replacement_pip)
        dynamic_replacement_pip = live_observations(
            [preflight.EXPECTED_REPLACEMENT_VM_NAMES[0]]
        )
        dynamic_replacement_pip["nodes"][3]["publicIp"][
            "publicIPAllocationMethod"
        ] = "Dynamic"
        cases.append(dynamic_replacement_pip)
        private_replacement_pip = live_observations(
            [preflight.EXPECTED_REPLACEMENT_VM_NAMES[0]]
        )
        private_replacement_pip["nodes"][3]["publicIp"]["ipAddress"] = "10.20.2.6"
        cases.append(private_replacement_pip)
        ipv6_replacement_pip = live_observations(
            [preflight.EXPECTED_REPLACEMENT_VM_NAMES[0]]
        )
        ipv6_replacement_pip["nodes"][3]["publicIp"][
            "ipAddress"
        ] = "2606:4700:4700::1111"
        cases.append(ipv6_replacement_pip)
        wrong_replacement_pip_attachment = live_observations(
            [preflight.EXPECTED_REPLACEMENT_VM_NAMES[0]]
        )
        wrong_replacement_pip_attachment["nodes"][3]["publicIp"][
            "ipConfigurationId"
        ] = rid("Microsoft.Network/networkInterfaces", "wrong") + "/ipConfigurations/ipconfig1"
        cases.append(wrong_replacement_pip_attachment)
        disk_policy = live_observations([preflight.EXPECTED_REPLACEMENT_VM_NAMES[0]])
        disk_policy["nodes"][3]["disk"]["networkAccessPolicy"] = "AllowPrivate"
        cases.append(disk_policy)
        insufficient_headroom = live_observations()
        insufficient_headroom["cost"]["amountUsd"] = "95.00"
        cases.append(insufficient_headroom)
        for observations in cases:
            with self.subTest(observations=observations):
                with self.assertRaises(preflight.PreflightError):
                    self.validate(observations)

    def test_modify_delete_collision_and_incomplete_what_if_are_rejected(self):
        for mutation in ("Modify", "Delete", "Unsupported"):
            observations = live_observations()
            observations["whatIf"]["changes"][0]["changeType"] = mutation
            with self.subTest(mutation=mutation):
                with self.assertRaises(preflight.PreflightError):
                    self.validate(observations)

        missing_create = live_observations()
        missing_create["whatIf"]["changes"].pop()
        with self.assertRaises(preflight.PreflightError):
            self.validate(missing_create)

        outside = live_observations()
        outside["whatIf"]["changes"].append(
            {
                "changeType": "Create",
                "resourceId": rid("Microsoft.Network/virtualNetworks", "unsafe"),
            }
        )
        with self.assertRaises(preflight.PreflightError):
            self.validate(outside)

    def test_colliding_or_orphaned_partial_resources_are_rejected(self):
        collision = live_observations()
        collision["resources"].append(
            {
                "id": rid("Microsoft.Storage/storageAccounts", "viv-sbc-dr-sbc1-g3-bad"),
                "location": "uaenorth",
                "name": "viv-sbc-dr-sbc1-g3-bad",
                "tags": {},
                "type": "Microsoft.Storage/storageAccounts",
            }
        )
        with self.assertRaises(preflight.PreflightError):
            self.validate(collision)

        orphan = live_observations()
        node = preflight.EXPECTED_REPLACEMENT_VM_NAMES[0]
        orphan["resources"].append(
            {
                "id": rid("Microsoft.Compute/disks", node + "-osdisk"),
                "location": "uaenorth",
                "managedBy": rid("Microsoft.Compute/virtualMachines", node),
                "name": node + "-osdisk",
                "tags": preflight._replacement_tags(node, DEADLINE),
                "type": "Microsoft.Compute/disks",
            }
        )
        with self.assertRaises(preflight.PreflightError):
            self.validate(orphan)

        fragmented = live_observations()
        node = preflight.EXPECTED_REPLACEMENT_VM_NAMES[0]
        fragmented["resources"].append(
            {
                "id": rid("Microsoft.Network/publicIPAddresses", node + "-pip"),
                "location": "uaenorth",
                "name": node + "-pip",
                "tags": preflight._replacement_tags(node, DEADLINE),
                "type": "Microsoft.Network/publicIPAddresses",
            }
        )
        with self.assertRaises(preflight.PreflightError):
            self.validate(fragmented)

    def test_saved_plan_wrapper_binds_all_authority_and_locks_both_disks(self):
        saved = self.validate(live_observations())
        now = datetime(2026, 8, 31, 1, 5, 0, tzinfo=timezone.utc)
        receipt, scheduler_runner = self.scheduler_authority(saved, now)
        pending = live_observations(
            preflight.EXPECTED_REPLACEMENT_VM_NAMES, locked_nodes=[]
        )
        locked = live_observations(preflight.EXPECTED_REPLACEMENT_VM_NAMES)
        for observations in (pending, locked):
            for node in observations["nodes"][3:]:
                node["powerState"] = "PowerState/deallocated"
        commands = []

        def mutate(argv):
            commands.append(list(argv))
            return ""

        with mock.patch.object(
            preflight,
            "collect_live_observations",
            side_effect=[live_observations(), pending, locked],
        ):
            result = preflight.apply_saved_plan(
                PARAMETERS_PATH,
                self.package_evidence,
                saved,
                receipt,
                approved_plan_sha256=saved["planSha256"],
                expected_compiled_parameters_sha256="a" * 64,
                expected_compiled_template_sha256=preflight.EXPECTED_COMPILED_TEMPLATE_SHA256,
                expected_bicep_version=preflight.EXPECTED_BICEP_VERSION,
                expected_subscription_id=preflight.EXPECTED_SUBSCRIPTION_ID,
                expected_tenant_id=preflight.EXPECTED_TENANT_ID,
                now=now,
                mutation_runner=mutate,
                scheduler_runner=scheduler_runner,
                scheduler_host_name=SCHEDULER_HOST,
            )
        self.assertEqual(
            result["status"],
            "DIRECT_REPLACEMENT_CREATE_AND_DISK_LOCKDOWN_COMPLETE",
        )
        self.assertTrue(result["createExecuted"])
        create = [command for command in commands if command[1:4] == ["deployment", "sub", "create"]]
        self.assertEqual(len(create), 1)
        self.assertIn("--confirm-with-what-if", create[0])
        self.assertEqual(
            create[0][create[0].index("--validation-level") + 1], "Provider"
        )
        self.assertEqual(
            create[0][create[0].index("--subscription") + 1],
            preflight.EXPECTED_SUBSCRIPTION_ID,
        )
        updates = [command for command in commands if command[1:3] == ["disk", "update"]]
        tags = [command for command in commands if command[1:3] == ["tag", "create"]]
        self.assertEqual(len(updates), 2)
        self.assertEqual(len(tags), 2)
        for command in updates:
            self.assertIn("--ids", command)
            self.assertEqual(
                command[command.index("--public-network-access") + 1], "Disabled"
            )
            self.assertEqual(
                command[command.index("--network-access-policy") + 1], "DenyAll"
            )

    def test_saved_plan_wrapper_rejects_digest_expiry_or_fresh_what_if_drift(self):
        saved = self.validate(live_observations())
        now = datetime(2026, 8, 31, 1, 5, tzinfo=timezone.utc)
        receipt, scheduler_runner = self.scheduler_authority(saved, now)
        common = dict(
            expected_compiled_parameters_sha256="a" * 64,
            expected_compiled_template_sha256=preflight.EXPECTED_COMPILED_TEMPLATE_SHA256,
            expected_bicep_version=preflight.EXPECTED_BICEP_VERSION,
            expected_subscription_id=preflight.EXPECTED_SUBSCRIPTION_ID,
            expected_tenant_id=preflight.EXPECTED_TENANT_ID,
        )
        with self.assertRaises(preflight.PreflightError):
            preflight.validate_saved_plan(
                saved,
                self.package_evidence,
                approved_plan_sha256="0" * 64,
                now=datetime(2026, 8, 31, 1, 5, tzinfo=timezone.utc),
                **common,
            )
        extended_authorization = copy.deepcopy(saved)
        extended_authorization["authorizationExpiresUtc"] = "2026-09-02T23:59:59Z"
        extended_body = {
            key: extended_authorization[key]
            for key in sorted(extended_authorization)
            if key not in {"planSha256", "status"}
        }
        extended_authorization["planSha256"] = preflight._canonical_digest(
            extended_body
        )
        with self.assertRaises(preflight.PreflightError):
            preflight.validate_saved_plan(
                extended_authorization,
                self.package_evidence,
                approved_plan_sha256=extended_authorization["planSha256"],
                now=datetime(2026, 8, 31, 1, 5, tzinfo=timezone.utc),
                **common,
            )
        wrong_runtime = copy.deepcopy(saved)
        wrong_runtime["runtimeAuthority"]["profile"] = "DIRECT_ROUTING"
        wrong_body = {
            key: wrong_runtime[key]
            for key in sorted(wrong_runtime)
            if key not in {"planSha256", "status"}
        }
        wrong_runtime["planSha256"] = preflight._canonical_digest(wrong_body)
        with self.assertRaises(preflight.PreflightError):
            preflight.validate_saved_plan(
                wrong_runtime,
                self.package_evidence,
                approved_plan_sha256=wrong_runtime["planSha256"],
                now=datetime(2026, 8, 31, 1, 5, tzinfo=timezone.utc),
                **common,
            )
        with self.assertRaises(preflight.PreflightError):
            preflight.validate_saved_plan(
                saved,
                self.package_evidence,
                approved_plan_sha256=saved["planSha256"],
                now=datetime(2026, 8, 31, 1, 18, tzinfo=timezone.utc),
                **common,
            )
        drift = live_observations()
        drift["whatIf"]["changes"][0]["resourceId"] = rid(
            "Microsoft.Network/virtualNetworks", "unsafe"
        )
        with mock.patch.object(
            preflight, "collect_live_observations", return_value=drift
        ):
            with self.assertRaises(preflight.PreflightError):
                preflight.apply_saved_plan(
                    PARAMETERS_PATH,
                    self.package_evidence,
                    saved,
                    receipt,
                    approved_plan_sha256=saved["planSha256"],
                    now=now,
                    mutation_runner=lambda argv: self.fail(argv),
                    scheduler_runner=scheduler_runner,
                    scheduler_host_name=SCHEDULER_HOST,
                    **common,
                )

    def test_saved_plan_wrapper_resumes_disk_lockdown_without_redeploying(self):
        pending = live_observations(
            preflight.EXPECTED_REPLACEMENT_VM_NAMES, locked_nodes=[]
        )
        saved = self.validate(pending)
        now = datetime(2026, 8, 31, 1, 5, tzinfo=timezone.utc)
        receipt, scheduler_runner = self.scheduler_authority(saved, now)
        locked = live_observations(preflight.EXPECTED_REPLACEMENT_VM_NAMES)
        commands = []
        with mock.patch.object(
            preflight,
            "collect_live_observations",
            side_effect=[pending, pending, locked],
        ):
            result = preflight.apply_saved_plan(
                PARAMETERS_PATH,
                self.package_evidence,
                saved,
                receipt,
                approved_plan_sha256=saved["planSha256"],
                expected_compiled_parameters_sha256="a" * 64,
                expected_compiled_template_sha256=preflight.EXPECTED_COMPILED_TEMPLATE_SHA256,
                expected_bicep_version=preflight.EXPECTED_BICEP_VERSION,
                expected_subscription_id=preflight.EXPECTED_SUBSCRIPTION_ID,
                expected_tenant_id=preflight.EXPECTED_TENANT_ID,
                now=now,
                mutation_runner=lambda argv: commands.append(list(argv)) or "",
                scheduler_runner=scheduler_runner,
                scheduler_host_name=SCHEDULER_HOST,
            )
        self.assertFalse(result["createExecuted"])
        self.assertFalse(
            any(command[1:4] == ["deployment", "sub", "create"] for command in commands)
        )
        self.assertEqual(
            len([command for command in commands if command[1:3] == ["disk", "update"]]),
            2,
        )

    def test_deadman_job_embeds_exact_plan_program_and_never_executes_bundle_path(self):
        saved = self.validate(live_observations())
        command = preflight._deadman_command_contract(saved)
        self.assertEqual(command["argv"][:2], ["/opt/homebrew/bin/python3.13", "-c"])
        self.assertEqual(len(command["argv"]), 3)
        source = command["argv"][2]
        compile(source, "<embedded-deadman>", "exec")
        self.assertNotIn(str(preflight.EXPECTED_DEADMAN_BUNDLE_PATH), command["argv"])
        self.assertEqual(
            command["embeddedProgramSha256"],
            hashlib.sha256(source.encode("utf-8")).hexdigest(),
        )
        for expected in (
            'RUN_BUDGET_SECONDS = 840',
            'COMMAND_TIMEOUT_SECONDS = 45',
            'DIRECT_REPLACEMENT_DEADMAN_PROGRESS',
            'for resource_id in CONTRACT["replacementVmIds"]',
            '"status": "DIRECT_REPLACEMENT_DEADMAN_ENFORCED"',
            '/opt/homebrew/bin/az',
            '/opt/homebrew/bin/openclaw',
            '/opt/homebrew/bin/python3.13',
        ):
            self.assertIn(expected, source)
        self.assertNotIn(
            'for resource_id in CONTRACT["protectedPredecessorVmIds"]', source
        )
        payload = preflight._expected_deadman_payload(saved)
        self.assertEqual(payload["argv"], command["argv"])
        self.assertEqual(payload["timeoutSeconds"], 900)
        self.assertEqual(payload["noOutputTimeoutSeconds"], 300)

    def test_scheduler_receipt_is_fresh_live_external_and_exact(self):
        saved = self.validate(live_observations())
        now = datetime(2026, 8, 31, 1, 5, tzinfo=timezone.utc)
        receipt, runner = self.scheduler_authority(saved, now)
        self.assertEqual(
            receipt["status"],
            "DIRECT_REPLACEMENT_DEADMAN_SCHEDULER_RECEIPT_VALID",
        )
        self.assertEqual(receipt["job"]["id"], DEADMAN_JOB_ID)
        self.assertEqual(receipt["scheduler"]["gatewayHost"], SCHEDULER_HOST)
        self.assertEqual(receipt["command"]["argv"][1], "-c")
        self.assertNotIn("bundle", json.dumps(receipt, sort_keys=True).lower())
        validated = preflight.validate_deadman_scheduler_receipt(
            receipt,
            saved,
            now=now,
            scheduler_runner=runner,
            host_name=SCHEDULER_HOST,
        )
        self.assertEqual(validated, receipt)

    def test_scheduler_receipt_rejects_job_scheduler_host_and_freshness_drift(self):
        saved = self.validate(live_observations())
        now = datetime(2026, 8, 31, 1, 5, tzinfo=timezone.utc)
        bad_jobs = []
        bad_jobs.append(deadman_job(saved, enabled=False))
        wrong_schedule = {"at": "2026-09-02T23:59:59Z", "kind": "at"}
        bad_jobs.append(deadman_job(saved, schedule=wrong_schedule))
        wrong_payload = copy.deepcopy(preflight._expected_deadman_payload(saved))
        wrong_payload["argv"] = ["/bin/true"]
        bad_jobs.append(deadman_job(saved, payload=wrong_payload))
        bad_jobs.append(
            deadman_job(
                saved,
                created_at=datetime(2026, 8, 31, 1, 17, 4, tzinfo=timezone.utc),
            )
        )
        for bad_job in bad_jobs:
            with self.subTest(bad_job=bad_job):
                with self.assertRaises(preflight.PreflightError):
                    preflight.build_deadman_scheduler_receipt(
                        saved,
                        job_id=DEADMAN_JOB_ID,
                        now=now,
                        scheduler_runner=deadman_scheduler_runner(saved, job=bad_job),
                        host_name=SCHEDULER_HOST,
                    )

        disabled_status = {
            "enabled": False,
            "jobs": 1,
            "nextWakeAtMs": preflight._canonical_millisecond(
                datetime(2026, 9, 3, tzinfo=timezone.utc)
            ),
            "storage": "sqlite",
        }
        with self.assertRaises(preflight.PreflightError):
            self.scheduler_authority(saved, now, status=disabled_status)
        with self.assertRaises(preflight.PreflightError):
            preflight.build_deadman_scheduler_receipt(
                saved,
                job_id=DEADMAN_JOB_ID,
                now=now,
                scheduler_runner=deadman_scheduler_runner(saved),
                host_name=preflight.EXPECTED_REPLACEMENT_VM_NAMES[0] + ".local",
            )

        receipt, runner = self.scheduler_authority(saved, now)
        with self.assertRaises(preflight.PreflightError):
            preflight.validate_deadman_scheduler_receipt(
                receipt,
                saved,
                now=datetime(2026, 8, 31, 1, 10, 1, tzinfo=timezone.utc),
                scheduler_runner=runner,
                host_name=SCHEDULER_HOST,
            )

    def test_apply_requeries_live_job_at_mutation_boundary_and_refuses_drift(self):
        saved = self.validate(live_observations())
        now = datetime(2026, 8, 31, 1, 5, tzinfo=timezone.utc)
        receipt, _ = self.scheduler_authority(saved, now)
        enabled_job = deadman_job(saved)
        disabled_job = deadman_job(saved, enabled=False)
        status_calls = 0

        def drifting_scheduler(argv):
            nonlocal status_calls
            if argv == [str(preflight.EXPECTED_OPENCLAW_CLI), "cron", "status"]:
                status_calls += 1
                return json.dumps(
                    {
                        "enabled": True,
                        "jobs": 1,
                        "nextWakeAtMs": preflight._canonical_millisecond(
                            datetime(2026, 9, 3, tzinfo=timezone.utc)
                        ),
                        "storage": "sqlite",
                    }
                )
            if argv == [
                str(preflight.EXPECTED_OPENCLAW_CLI),
                "cron",
                "get",
                DEADMAN_JOB_ID,
            ]:
                return json.dumps(enabled_job if status_calls == 1 else disabled_job)
            raise AssertionError(argv)

        mutations = []
        with mock.patch.object(
            preflight,
            "collect_live_observations",
            return_value=live_observations(),
        ):
            with self.assertRaises(preflight.PreflightError):
                preflight.apply_saved_plan(
                    PARAMETERS_PATH,
                    self.package_evidence,
                    saved,
                    receipt,
                    approved_plan_sha256=saved["planSha256"],
                    expected_compiled_parameters_sha256="a" * 64,
                    expected_compiled_template_sha256=preflight.EXPECTED_COMPILED_TEMPLATE_SHA256,
                    expected_bicep_version=preflight.EXPECTED_BICEP_VERSION,
                    expected_subscription_id=preflight.EXPECTED_SUBSCRIPTION_ID,
                    expected_tenant_id=preflight.EXPECTED_TENANT_ID,
                    now=now,
                    mutation_runner=lambda argv: mutations.append(list(argv)) or "",
                    scheduler_runner=drifting_scheduler,
                    scheduler_host_name=SCHEDULER_HOST,
                )
        self.assertEqual(status_calls, 2)
        self.assertEqual(mutations, [])

    def test_post_deadline_disk_lockdown_recovery_never_creates(self):
        pending = live_observations(
            preflight.EXPECTED_REPLACEMENT_VM_NAMES, locked_nodes=[]
        )
        saved = self.validate(pending)
        locked = live_observations(preflight.EXPECTED_REPLACEMENT_VM_NAMES)
        for observations in (pending, locked):
            for node in observations["nodes"][3:]:
                node["powerState"] = "PowerState/deallocated"
        commands = []
        with mock.patch.object(
            preflight,
            "collect_live_observations",
            side_effect=[pending, locked],
        ):
            result = preflight.recover_disk_lockdown(
                PARAMETERS_PATH,
                self.package_evidence,
                saved,
                approved_plan_sha256=saved["planSha256"],
                expected_compiled_parameters_sha256="a" * 64,
                expected_compiled_template_sha256=preflight.EXPECTED_COMPILED_TEMPLATE_SHA256,
                expected_bicep_version=preflight.EXPECTED_BICEP_VERSION,
                expected_subscription_id=preflight.EXPECTED_SUBSCRIPTION_ID,
                expected_tenant_id=preflight.EXPECTED_TENANT_ID,
                now=datetime(2026, 9, 3, 0, 1, tzinfo=timezone.utc),
                mutation_runner=lambda argv: commands.append(list(argv)) or "",
            )
        self.assertEqual(
            result["status"],
            "DIRECT_REPLACEMENT_POST_DEADLINE_DISK_LOCKDOWN_COMPLETE",
        )
        self.assertFalse(
            any(command[1:4] == ["deployment", "sub", "create"] for command in commands)
        )
        self.assertEqual(
            len([command for command in commands if command[1:3] == ["disk", "update"]]),
            2,
        )

    def test_local_parameter_file_must_be_adjacent_ignored_named_and_owner_only(self):
        original_file = preflight.__file__
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                preflight.__file__ = str(root / "direct-replacement-preflight.py")
                local = root / "direct-replacement.local.bicepparam"
                local.write_text("using './direct-replacement.bicep'\n", encoding="utf-8")
                local.chmod(stat.S_IRUSR | stat.S_IWUSR)
                self.assertEqual(preflight.validate_local_parameter_path(local), local)
                local.chmod(0o644)
                with self.assertRaises(preflight.PreflightError):
                    preflight.validate_local_parameter_path(local)
                wrong = root / "wrong.local.bicepparam"
                wrong.write_text("", encoding="utf-8")
                wrong.chmod(0o600)
                with self.assertRaises(preflight.PreflightError):
                    preflight.validate_local_parameter_path(wrong)
        finally:
            preflight.__file__ = original_file


@unittest.skipUnless(shutil.which("az"), "Azure CLI with local Bicep is required")
class DirectReplacementCompiledPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parameters, cls.template = preflight.compile_bicep_package(
            PARAMETERS_PATH
        )

    def test_example_and_template_compile_offline(self):
        self.assertEqual(len(self.parameters["parameters"]), 37)
        self.assertEqual(
            preflight.validate_compiled_template(self.template),
            preflight.EXPECTED_COMPILED_TEMPLATE_SHA256,
        )

    def test_template_digest_and_compiler_are_pinned(self):
        changed = copy.deepcopy(self.template)
        changed["metadata"]["_generator"]["version"] = "future"
        with self.assertRaises(preflight.PreflightError):
            preflight.validate_compiled_template(changed)

        changed = copy.deepcopy(self.template)
        changed["outputs"]["unsafe"] = {"type": "string", "value": "drift"}
        with self.assertRaises(preflight.PreflightError):
            preflight.validate_compiled_template(changed)

    def test_reviewed_compiled_package_success_binds_both_digests(self):
        evidence = preflight.validate_compiled_package(
            parameter_document(),
            self.template,
            approved_admin_cidrs=ADMIN,
            expected_ssh_fingerprint=FINGERPRINT,
            now=TEST_NOW,
        )
        self.assertEqual(
            evidence["status"], "DIRECT_REPLACEMENT_COMPILED_PACKAGE_VALID"
        )
        self.assertEqual(
            evidence["compiledTemplateSha256"],
            preflight.EXPECTED_COMPILED_TEMPLATE_SHA256,
        )
        self.assertEqual(len(evidence["compiledParametersSha256"]), 64)

    def test_example_is_intentionally_rejected_until_authorities_are_replaced(self):
        with self.assertRaises(preflight.PreflightError):
            preflight.validate_compiled_package(
                self.parameters,
                self.template,
                approved_admin_cidrs=ADMIN,
                expected_ssh_fingerprint=FINGERPRINT,
                now=TEST_NOW,
            )


class DirectReplacementTemplateStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = TEMPLATE_PATH.read_text(encoding="utf-8")
        cls.module = MODULE_PATH.read_text(encoding="utf-8")

    def test_existing_boundary_is_subscription_and_resource_group_exact(self):
        self.assertIn("targetScope = 'subscription'", self.source)
        self.assertIn(
            "resourceGroup(targetSubscriptionId, targetResourceGroupName)", self.source
        )
        self.assertIn(
            "resource existingVnet 'Microsoft.Network/virtualNetworks@2023-11-01' existing",
            self.source,
        )
        self.assertIn(
            "resource existingEdgeSubnet 'Microsoft.Network/virtualNetworks/subnets@2023-11-01' existing",
            self.source,
        )
        self.assertIn(
            "resource existingEdgeAvailabilitySet 'Microsoft.Compute/availabilitySets@2024-03-01' existing",
            self.source,
        )
        self.assertEqual(self.source.count("scope: targetResourceGroup"), 4)
        self.assertNotIn("module network ", self.source)
        self.assertNotIn("module cp1 ", self.source)

    def test_runtime_authority_is_the_exact_private_pbx_poc_mode(self):
        self.assertIn("'DIRECT_ROUTING_PRIVATE_PBX_POC'", self.source)
        self.assertNotIn("  'DIRECT_ROUTING'\n", self.source)
        self.assertIn(
            "param edgeRuntimeProfile = 'DIRECT_ROUTING_PRIVATE_PBX_POC'",
            PARAMETERS_PATH.read_text(encoding="utf-8"),
        )

    def test_replacements_are_distinct_and_preserve_generation_two(self):
        for expected in (
            "viv-sbc-dr-sbc1-g3",
            "viv-sbc-dr-sbc2-g3",
            "10.20.2.6",
            "10.20.2.7",
            "parallel-preserve-generation-2",
        ):
            self.assertIn(expected, self.source)
        self.assertIn("'viv-sbc-poc-sbc1'", self.source)
        self.assertIn("'viv-sbc-poc-sbc2'", self.source)
        self.assertEqual(self.source.count("module sbc"), 2)
        self.assertEqual(self.source.count("'modules/linux-node.bicep'"), 2)
        self.assertEqual(
            self.source.count("availabilitySetId: existingEdgeAvailabilitySet.id"), 2
        )

    def test_low_cost_trusted_launch_debian_contract_is_exact(self):
        for expected in (
            "Standard_B2als_v2",
            "StandardSSD_LRS",
            "0.20260826.2582",
            "debian-13",
            "13-gen2",
        ):
            self.assertIn(expected, self.source)
        self.assertIn("param osDiskSizeGiB int", self.source)
        self.assertIn("param enableTrustedLaunch bool", self.source)
        self.assertIn("securityType: 'TrustedLaunch'", self.module)
        self.assertIn("secureBootEnabled: true", self.module)
        self.assertIn("vTpmEnabled: true", self.module)
        self.assertIn("sku: {\n    name: 'Standard'", self.module)
        self.assertIn("publicIPAllocationMethod: 'Static'", self.module)
        self.assertIn("publicIPAddressVersion: 'IPv4'", self.module)
        self.assertIn("disablePasswordAuthentication: true", self.module)

    def test_security_rules_cover_only_reviewed_authorities_then_deny(self):
        expected_rules = {
            "AllowAdminSsh",
            "AllowMicrosoftTls5061",
            "AllowMicrosoftMedia",
            "AllowCarrierGatewayTls15061",
            "AllowCarrierGatewayMediaInbound",
            "DenyAllInbound",
            "AllowAzureDhcpOutbound",
            "AllowAzureDnsUdpOutbound",
            "AllowAzureDnsTcpOutbound",
            "AllowAzureWireServerOutbound",
            "AllowAzureImdsOutbound",
            "AllowNtpOutbound",
            "AllowWebOutbound",
            "AllowControlPlaneOutbound",
            "AllowMicrosoftSignalingOutbound",
            "AllowMicrosoftMediaOutbound",
            "AllowCarrierGatewayTls5061",
            "AllowCarrierGatewayMediaOutbound",
            "DenyAllOutbound",
        }
        for name in expected_rules:
            self.assertEqual(self.source.count("name: '{}'".format(name)), 1)
        self.assertEqual(self.source.count("access: 'Allow'"), 17)
        self.assertEqual(self.source.count("access: 'Deny'"), 2)
        self.assertEqual(self.source.count("priority: 4096"), 2)
        self.assertGreater(
            self.source.index("name: 'DenyAllInbound'"),
            self.source.index("name: 'AllowCarrierGatewayMediaInbound'"),
        )
        self.assertGreater(
            self.source.index("name: 'DenyAllOutbound'"),
            self.source.index("name: 'AllowCarrierGatewayTls5061'"),
        )

    def test_microsoft_and_carrier_media_are_directionally_bounded(self):
        self.assertIn("sourcePortRanges: microsoftMediaProcessorPortRanges", self.source)
        self.assertIn("destinationPortRange: rtpMediaDestinationRange", self.source)
        self.assertIn("sourcePortRange: tenantRtpMediaDestinationRange", self.source)
        self.assertIn("destinationPortRanges: microsoftMediaProcessorPortRanges", self.source)
        self.assertEqual(self.source.count("sourceAddressPrefix: cp1PrivatePrefix"), 2)
        self.assertEqual(self.source.count("destinationAddressPrefix: cp1PrivatePrefix"), 3)
        self.assertNotIn("carrierGatewayPublicPrefix", self.source)
        self.assertIn("'10.20.1.4/32'", self.source)
        self.assertIn("same-vnet-private-no-public-hairpin", self.source)
        self.assertIn("sourcePortRange: pbxMediaDestinationRange", self.source)
        self.assertIn("destinationPortRange: pbxMediaDestinationRange", self.source)
        self.assertIn("destinationPortRange: string(localPbxTlsListenerPort)", self.source)
        self.assertEqual(
            self.source.count("destinationPortRange: string(remoteTlsPort)"), 3
        )
        self.assertNotIn("destinationPortRange: '10000-60000'", self.source)

    def test_platform_dns_ntp_web_and_control_plane_egress_are_explicit(self):
        for expected in (
            "168.63.129.16",
            "169.254.169.254",
            "162.159.200.1/32",
            "162.159.200.123/32",
            "destinationPortRange: '53'",
            "destinationPortRange: '123'",
            "destinationAddressPrefix: cp1PrivatePrefix",
        ):
            self.assertIn(expected, self.source)
        self.assertEqual(self.source.count("destinationAddressPrefix: 'Internet'"), 1)
        self.assertIn("'80'\n        '443'", self.source)

    def test_bounded_parallel_cost_and_predecessor_deallocation_are_declared(self):
        for expected in (
            "parallelAcceptanceWindowHours: '72'",
            "parallelAcceptanceDeadlineUtc: parallelAcceptanceDeadlineUtc",
            "predecessorDisposition: 'deallocate-after-final-acceptance'",
            "maximumIncrementalReplacementCostUsd: '7.80'",
            "deallocate-after-final-acceptance-and-no-later-than-plan-deadline",
        ):
            self.assertIn(expected, self.source)


class DirectReplacementWorkflowStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.preflight_source = PREFLIGHT_PATH.read_text(encoding="utf-8")
        cls.readme = README_PATH.read_text(encoding="utf-8")

    def test_only_guarded_wrapper_owns_create_and_disk_lockdown(self):
        for expected in (
            '"--confirm-with-what-if"',
            '"--validation-level", "Provider"',
            '"az", "disk", "update", "--ids"',
            '"--public-network-access", "Disabled"',
            '"--network-access-policy", "DenyAll"',
            '"az", "tag", "create", "--resource-id"',
            "DIRECT_REPLACEMENT_CREATE_AND_DISK_LOCKDOWN_COMPLETE",
        ):
            self.assertIn(expected, self.preflight_source)
        self.assertIn("--apply-plan deploy/.state/direct-replacement-live-plan.json", self.readme)
        self.assertIn("Direct `az deployment sub create` is outside this contract", self.readme)

    def test_readme_keeps_production_direct_routing_global_only(self):
        self.assertIn("profile `DIRECT_ROUTING_PRIVATE_PBX_POC`", self.readme)
        self.assertIn("Production `DIRECT_ROUTING` remains global-PBX only", self.readme)

    def test_cli_modes_accept_only_their_exact_authority_option_set(self):
        base = [
            str(PARAMETERS_PATH),
            "--approved-admin-cidr",
            ADMIN[0],
            "--expected-ssh-fingerprint",
            FINGERPRINT,
        ]
        valid_modes = (
            [],
            ["--live-plan"],
            [
                "--apply-plan",
                "deploy/.state/direct-replacement-live-plan.json",
                "--approved-plan-sha256",
                "a" * 64,
                "--deadman-scheduler-receipt",
                "deploy/.state/direct-replacement-deadman-scheduler-receipt.json",
                "--confirm-with-what-if",
            ],
            [
                "--prepare-deadman-bundle-plan",
                "deploy/.state/direct-replacement-live-plan.json",
                "--approved-plan-sha256",
                "a" * 64,
                "--deadman-bundle-output",
                "deploy/.state/direct-replacement-deadman-sealed.py",
            ],
            [
                "--issue-deadman-scheduler-receipt-plan",
                "deploy/.state/direct-replacement-live-plan.json",
                "--approved-plan-sha256",
                "a" * 64,
                "--openclaw-cron-job-id",
                DEADMAN_JOB_ID,
                "--deadman-scheduler-receipt-output",
                "deploy/.state/direct-replacement-deadman-scheduler-receipt.json",
            ],
            [
                "--recover-disk-lockdown-plan",
                "deploy/.state/direct-replacement-live-plan.json",
                "--approved-plan-sha256",
                "a" * 64,
                "--confirm-disk-lockdown-recovery",
            ],
        )
        for options in valid_modes:
            with self.subTest(options=options):
                preflight._validate_mode_specific_options(
                    preflight._parser().parse_args(base + options)
                )

        invalid_apply = valid_modes[2] + [
            "--deadman-bundle-output",
            "deploy/.state/direct-replacement-deadman-sealed.py",
        ]
        with self.assertRaises(preflight.PreflightError):
            preflight._validate_mode_specific_options(
                preflight._parser().parse_args(base + invalid_apply)
            )

    def test_interactive_create_timeout_cancels_and_fails_closed(self):
        timeout = subprocess.TimeoutExpired(["az", "deployment"], 7)
        with mock.patch.object(
            preflight.subprocess, "run", side_effect=timeout
        ) as run, mock.patch.object(
            preflight,
            "_deployment_terminal_state_after_cancel",
            return_value="Canceled",
        ) as cancel:
            with self.assertRaises(preflight.PreflightError):
                preflight._run_interactive(
                    ["az", "deployment", "sub", "create"], timeout_seconds=7
                )
        self.assertEqual(run.call_args.kwargs["timeout"], 7)
        cancel.assert_called_once_with()

    def test_timed_out_deployment_cancel_waits_for_terminal_state(self):
        completed = [
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 0, "Canceled\n", ""),
        ]
        with mock.patch.object(
            preflight.subprocess, "run", side_effect=completed
        ) as run:
            self.assertEqual(
                preflight._deployment_terminal_state_after_cancel(), "Canceled"
            )
        cancel_argv = run.call_args_list[0].args[0]
        show_argv = run.call_args_list[1].args[0]
        self.assertEqual(cancel_argv[0], "/opt/homebrew/bin/az")
        self.assertEqual(cancel_argv[1:4], ["deployment", "sub", "cancel"])
        self.assertIn(preflight.DEPLOYMENT_NAME, cancel_argv)
        self.assertEqual(show_argv[1:4], ["deployment", "sub", "show"])

    def test_cancel_retries_transient_show_failure_and_only_accepts_explicit_absence(self):
        transient_then_terminal = [
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 1, "", "ERROR: connection reset"),
            subprocess.CompletedProcess([], 0, "Canceled\n", ""),
        ]
        with mock.patch.object(
            preflight.subprocess, "run", side_effect=transient_then_terminal
        ) as run, mock.patch.object(preflight.time, "sleep"):
            self.assertEqual(
                preflight._deployment_terminal_state_after_cancel(), "Canceled"
            )
        self.assertEqual(run.call_count, 3)

        explicit_absence = (
            "ERROR: (DeploymentNotFound) Deployment could not be found.\n"
            "Code: DeploymentNotFound\n"
        )
        absent_results = [
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 1, "", explicit_absence),
        ]
        with mock.patch.object(
            preflight.subprocess, "run", side_effect=absent_results
        ):
            self.assertEqual(
                preflight._deployment_terminal_state_after_cancel(), "Absent"
            )
        self.assertTrue(preflight._explicit_deployment_not_found(explicit_absence))
        self.assertFalse(
            preflight._explicit_deployment_not_found(
                "ERROR: connection reset while reading DeploymentNotFound"
            )
        )

    def test_deadline_is_parameter_tag_plan_and_deallocation_authority(self):
        for expected in (
            "parallelAcceptanceDeadlineUtc",
            "--prepare-deadman-bundle-plan",
            "--issue-deadman-scheduler-receipt-plan",
            "--deadman-scheduler-receipt",
            "DIRECT_REPLACEMENT_DEADMAN_ENFORCED",
            '"vm", "deallocate", "--ids"',
            "/opt/homebrew/bin/python3.13",
            "/opt/homebrew/bin/openclaw",
            "telegram:-1004364314662",
        ):
            self.assertIn(expected, self.preflight_source + self.readme)
        self.assertIn("mandatory disarm receipt", self.readme)
        self.assertIn("there is no Azure-side redundant scheduler", self.readme)
        self.assertNotIn("--deadman-plan", self.preflight_source + self.readme)
        self.assertNotIn(
            "--confirm-deadman-deallocation", self.preflight_source + self.readme
        )
        for expected in (
            "CREATE_AUTHORIZATION_SAFETY_SECONDS = 120",
            "timeout=timeout_seconds",
            '"sub",\n        "cancel"',
            "did not reach a terminal state after cancellation",
        ):
            self.assertIn(expected, self.preflight_source)


if __name__ == "__main__":
    unittest.main()
