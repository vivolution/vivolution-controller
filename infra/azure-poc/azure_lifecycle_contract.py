"""Exact Azure lifecycle contract shared by the bounded POC guard/teardown.

This module contains only read-only discovery and validation helpers. Mutating
commands remain in the narrowly scoped caller that owns that operation.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Mapping, Sequence


EXPECTED_SUBSCRIPTION_ID = "a806949c-240f-4541-8c61-fd97f6d1f953"
EXPECTED_TENANT_ID = "efc3bcaa-8879-4366-a452-2b8efa76b16a"
POC_RESOURCE_GROUP = "rg-vivolution-sbc-poc-uaenorth"
PRESERVED_CP1_RESOURCE_GROUP = "rg-vivolution-cp1-uaenorth"
DNS_RESOURCE_GROUP = "DNS_Zones"
LOCATION = "uaenorth"
PARENT_ZONE = "voice.vivolution.ae"
BUDGET_NAME = "viv-sbc-poc-monthly-usd100"
BUDGET_AMOUNT = Decimal("100")
BUDGET_CONTACT_EMAIL = "jaydevupadhyay@gmail.com"
BUDGET_THRESHOLDS = (Decimal("75"), Decimal("90"), Decimal("100"))
PRESERVATION_LOCK_NAME = "preserve-qualified-cp1-during-poc"
PRESERVATION_LOCK_LEVEL = "CanNotDelete"
PRESERVATION_LOCK_NOTES = (
    "Preserve the qualified CP1 until replacement restore, rollback and cutover "
    "acceptance complete."
)
COMMON_TAGS = {
    "costProfile": "monthly-credit-lab",
    "environment": "poc",
    "managedBy": "bicep",
    "owner": "Vivolution Technologies LLC",
    "purpose": "SBC proof of concept",
    "region": LOCATION,
    "workload": "vivolution-sbc",
}
POC_PARENT_RECORD_NAMES = frozenset(
    {
        "*.sbc1",
        "*.sbc2",
        "_acme-challenge.sbc1",
        "_acme-challenge.sbc2",
        "acme-sbc1",
        "acme-sbc2",
        "cp1-poc",
        "sbc1",
        "sbc2",
    }
)
ACME_CHILD_ZONES = (
    "acme-sbc1.voice.vivolution.ae",
    "acme-sbc2.voice.vivolution.ae",
)
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


class LifecycleError(RuntimeError):
    """Raised when an Azure lifecycle boundary cannot be proven exactly."""


Runner = Callable[[Sequence[str]], str]


@dataclass(frozen=True)
class ResourceSpec:
    name: str
    resource_type: str
    tags: Mapping[str, str]
    managed_by_vm: str | None = None


def run(argv: Sequence[str]) -> str:
    result = subprocess.run(argv, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown Azure CLI error"
        raise LifecycleError(f"Azure CLI command failed: {detail}")
    return result.stdout


def parse_json(raw: str, label: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LifecycleError(f"Azure CLI returned malformed {label} JSON") from exc


def base_command(subscription_id: str, *parts: str) -> list[str]:
    return [
        "az",
        *parts,
        "--subscription",
        subscription_id,
        "--output",
        "json",
        "--only-show-errors",
    ]


def resource_group_id(subscription_id: str, name: str) -> str:
    return f"/subscriptions/{subscription_id}/resourceGroups/{name}"


def resource_id(subscription_id: str, resource_type: str, name: str) -> str:
    return (
        f"{resource_group_id(subscription_id, POC_RESOURCE_GROUP)}"
        f"/providers/{resource_type}/{name}"
    )


def zone_id(subscription_id: str, name: str) -> str:
    return (
        f"{resource_group_id(subscription_id, DNS_RESOURCE_GROUP)}"
        f"/providers/Microsoft.Network/dnsZones/{name}"
    )


def budget_id(subscription_id: str) -> str:
    return (
        f"{resource_group_id(subscription_id, POC_RESOURCE_GROUP)}"
        f"/providers/Microsoft.Consumption/budgets/{BUDGET_NAME}"
    )


def same_id(actual: Any, expected: str) -> bool:
    return isinstance(actual, str) and actual.lower() == expected.lower()


def validate_reviewed_ids(subscription_id: str, tenant_id: str) -> None:
    for value, label in (
        (subscription_id, "expected subscription ID"),
        (tenant_id, "expected tenant ID"),
    ):
        if UUID_RE.fullmatch(value) is None:
            raise LifecycleError(f"{label} must be a canonical lowercase UUID")
    if subscription_id != EXPECTED_SUBSCRIPTION_ID:
        raise LifecycleError("subscription ID is outside this reviewed POC lifecycle contract")
    if tenant_id != EXPECTED_TENANT_ID:
        raise LifecycleError("tenant ID is outside this reviewed POC lifecycle contract")


def validate_account(
    subscription_id: str,
    tenant_id: str,
    *,
    runner: Runner,
) -> None:
    validate_reviewed_ids(subscription_id, tenant_id)
    account = parse_json(
        runner(
            [
                "az",
                "account",
                "show",
                "--query",
                "{id:id,tenantId:tenantId}",
                "--output",
                "json",
                "--only-show-errors",
            ]
        ),
        "account",
    )
    if account != {"id": subscription_id, "tenantId": tenant_id}:
        raise LifecycleError("active Azure subscription or tenant is not the reviewed target")


def get_group(subscription_id: str, name: str, *, runner: Runner) -> dict[str, Any]:
    group = parse_json(
        runner(
            base_command(
                subscription_id,
                "group",
                "show",
                "--name",
                name,
                "--query",
                "{id:id,name:name,location:location,tags:tags,properties:properties}",
            )
        ),
        f"resource group {name}",
    )
    if not isinstance(group, dict):
        raise LifecycleError(f"resource group {name} is not an object")
    if group.get("name") != name or not same_id(
        group.get("id"), resource_group_id(subscription_id, name)
    ):
        raise LifecycleError(f"resource-group identity drifted for {name}")
    if str(group.get("location", "")).lower() != LOCATION:
        raise LifecycleError(f"resource-group location drifted for {name}")
    properties = group.get("properties")
    if not isinstance(properties, dict) or properties.get("provisioningState") != "Succeeded":
        raise LifecycleError(f"resource group {name} is not in Succeeded state")
    return group


def validate_poc_group(group: Mapping[str, Any]) -> None:
    if group.get("tags") != COMMON_TAGS:
        raise LifecycleError("POC resource-group ownership tags drifted")


def list_group_resources(subscription_id: str, *, runner: Runner) -> list[dict[str, Any]]:
    records = parse_json(
        runner(
            base_command(
                subscription_id,
                "resource",
                "list",
                "--resource-group",
                POC_RESOURCE_GROUP,
                "--query",
                (
                    "[].{id:id,name:name,type:type,location:location,tags:tags,"
                    "managedBy:managedBy}"
                ),
            )
        ),
        "POC resource inventory",
    )
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise LifecycleError("POC resource inventory is not a list of objects")
    return records


def validate_predeploy_empty_inventory(subscription_id: str, *, runner: Runner) -> None:
    records = list_group_resources(subscription_id, runner=runner)
    expected_budget_id = budget_id(subscription_id)
    budget_records = 0
    for record in records:
        if (
            same_id(record.get("id"), expected_budget_id)
            and str(record.get("type", "")).lower() == "microsoft.consumption/budgets"
            and record.get("name") == BUDGET_NAME
        ):
            budget_records += 1
            continue
        raise LifecycleError("POC resource group is not empty before deployment")
    if budget_records > 1:
        raise LifecycleError("POC resource inventory contains duplicate budget identities")


def _as_decimal(value: Any, label: str) -> Decimal:
    if isinstance(value, bool):
        raise LifecycleError(f"{label} is not numeric")
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise LifecycleError(f"{label} is not numeric") from exc


def _parse_date(value: Any, label: str) -> dt.date:
    if not isinstance(value, str):
        raise LifecycleError(f"{label} is not an ISO date")
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except ValueError as exc:
        raise LifecycleError(f"{label} is not an ISO date") from exc


def validate_budget(
    subscription_id: str,
    *,
    runner: Runner,
    today: dt.date | None = None,
) -> dict[str, Any]:
    expected_id = budget_id(subscription_id)
    record = parse_json(
        runner(
            [
                "az",
                "rest",
                "--method",
                "get",
                "--url",
                f"{expected_id}?api-version=2023-11-01",
                "--subscription",
                subscription_id,
                "--output",
                "json",
                "--only-show-errors",
            ]
        ),
        "POC budget",
    )
    if (
        not isinstance(record, dict)
        or record.get("name") != BUDGET_NAME
        or str(record.get("type", "")).lower() != "microsoft.consumption/budgets"
        or not same_id(record.get("id"), expected_id)
    ):
        raise LifecycleError("POC budget identity drifted")
    properties = record.get("properties")
    if not isinstance(properties, dict):
        raise LifecycleError("POC budget properties are missing")
    if (
        _as_decimal(properties.get("amount"), "POC budget amount") != BUDGET_AMOUNT
        or properties.get("category") != "Cost"
        or properties.get("timeGrain") != "Monthly"
    ):
        raise LifecycleError("POC budget amount/category/time grain drifted")

    period = properties.get("timePeriod")
    if not isinstance(period, dict):
        raise LifecycleError("POC budget time period is missing")
    start = _parse_date(period.get("startDate"), "POC budget startDate")
    end = _parse_date(period.get("endDate"), "POC budget endDate")
    current = today or dt.datetime.now(dt.timezone.utc).date()
    if start.day != 1 or start > current or end < current or end <= start:
        raise LifecycleError("POC budget is not active on a first-of-month boundary")

    notifications = properties.get("notifications")
    if not isinstance(notifications, dict) or len(notifications) != 3:
        raise LifecycleError("POC budget must have exactly three notifications")
    found: set[Decimal] = set()
    for notification in notifications.values():
        if not isinstance(notification, dict):
            raise LifecycleError("POC budget notification is not an object")
        threshold = _as_decimal(notification.get("threshold"), "budget threshold")
        if (
            threshold not in BUDGET_THRESHOLDS
            or threshold in found
            or notification.get("enabled") is not True
            or notification.get("operator") != "GreaterThanOrEqualTo"
            or notification.get("thresholdType") != "Actual"
            or notification.get("contactEmails") != [BUDGET_CONTACT_EMAIL]
            or notification.get("contactGroups") not in (None, [])
            or notification.get("contactRoles") not in (None, [])
        ):
            raise LifecycleError("POC budget notification contract drifted")
        found.add(threshold)
    if found != set(BUDGET_THRESHOLDS):
        raise LifecycleError("POC budget thresholds are not exactly 75/90/100")
    return {
        "amountUsd": int(BUDGET_AMOUNT),
        "id": expected_id,
        "thresholds": [int(value) for value in BUDGET_THRESHOLDS],
    }


def validate_preserved_cp1(
    subscription_id: str,
    *,
    runner: Runner,
) -> dict[str, str]:
    get_group(subscription_id, PRESERVED_CP1_RESOURCE_GROUP, runner=runner)
    expected_id = (
        f"{resource_group_id(subscription_id, PRESERVED_CP1_RESOURCE_GROUP)}"
        f"/providers/Microsoft.Authorization/locks/{PRESERVATION_LOCK_NAME}"
    )
    locks = parse_json(
        runner(
            base_command(
                subscription_id,
                "lock",
                "list",
                "--resource-group",
                PRESERVED_CP1_RESOURCE_GROUP,
                "--query",
                "[].{id:id,name:name,level:level,notes:notes}",
            )
        ),
        "preserved CP1 lock inventory",
    )
    if not isinstance(locks, list) or len(locks) != 1:
        raise LifecycleError("preserved CP1 resource group must have exactly one lock")
    lock = locks[0]
    if (
        not isinstance(lock, dict)
        or lock.get("name") != PRESERVATION_LOCK_NAME
        or lock.get("level") != PRESERVATION_LOCK_LEVEL
        or lock.get("notes") != PRESERVATION_LOCK_NOTES
        or not same_id(lock.get("id"), expected_id)
    ):
        raise LifecycleError("preserved CP1 management-lock contract drifted")
    return {"id": expected_id, "level": PRESERVATION_LOCK_LEVEL}


def validate_parent_dns_absent(
    subscription_id: str,
    *,
    runner: Runner,
) -> dict[str, Any]:
    parent = parse_json(
        runner(
            base_command(
                subscription_id,
                "network",
                "dns",
                "zone",
                "show",
                "--resource-group",
                DNS_RESOURCE_GROUP,
                "--name",
                PARENT_ZONE,
                "--query",
                "{id:id,name:name,zoneType:zoneType}",
            )
        ),
        "shared parent DNS zone",
    )
    if (
        not isinstance(parent, dict)
        or parent.get("name") != PARENT_ZONE
        or parent.get("zoneType") != "Public"
        or not same_id(parent.get("id"), zone_id(subscription_id, PARENT_ZONE))
    ):
        raise LifecycleError("shared parent DNS-zone identity drifted")

    records = parse_json(
        runner(
            base_command(
                subscription_id,
                "network",
                "dns",
                "record-set",
                "list",
                "--resource-group",
                DNS_RESOURCE_GROUP,
                "--zone-name",
                PARENT_ZONE,
                "--query",
                "[].{name:name,type:type}",
            )
        ),
        "shared parent DNS records",
    )
    if not isinstance(records, list):
        raise LifecycleError("shared parent DNS-record inventory is not a list")
    collisions = []
    for record in records:
        if not isinstance(record, dict):
            raise LifecycleError("shared parent DNS-record inventory contains a non-object")
        if record.get("name") in POC_PARENT_RECORD_NAMES:
            collisions.append(record)
    if collisions:
        raise LifecycleError("POC parent DNS names are not completely absent")

    for child_name in ACME_CHILD_ZONES:
        matches = parse_json(
            runner(
                base_command(
                    subscription_id,
                    "resource",
                    "list",
                    "--resource-group",
                    DNS_RESOURCE_GROUP,
                    "--name",
                    child_name,
                    "--resource-type",
                    "Microsoft.Network/dnsZones",
                    "--query",
                    "[].{id:id,name:name,type:type}",
                )
            ),
            f"ACME child-zone lookup for {child_name}",
        )
        if not isinstance(matches, list):
            raise LifecycleError(f"ACME child-zone lookup for {child_name} is not a list")
        if matches:
            raise LifecycleError("POC ACME child zones are not completely absent")
    return {
        "absentChildZones": list(ACME_CHILD_ZONES),
        "absentParentNames": sorted(POC_PARENT_RECORD_NAMES),
        "parentZoneId": zone_id(subscription_id, PARENT_ZONE),
    }


def validate_poc_group_unlocked(subscription_id: str, *, runner: Runner) -> None:
    locks = parse_json(
        runner(
            base_command(
                subscription_id,
                "lock",
                "list",
                "--resource-group",
                POC_RESOURCE_GROUP,
                "--query",
                "[].{id:id,name:name,level:level,notes:notes}",
            )
        ),
        "POC resource-group lock inventory",
    )
    if locks != []:
        raise LifecycleError("POC resource group has a direct or inherited management lock")


def expected_resource_specs() -> tuple[ResourceSpec, ...]:
    specs = [
        ResourceSpec("viv-sbc-poc-edge-as", "Microsoft.Compute/availabilitySets", COMMON_TAGS),
        ResourceSpec("viv-sbc-poc-vnet", "Microsoft.Network/virtualNetworks", COMMON_TAGS),
    ]
    roles = {
        "cp1": "control-plane",
        "sbc1": "session-border-controller",
        "sbc2": "session-border-controller",
    }
    for node, role in roles.items():
        base_name = f"viv-sbc-poc-{node}"
        tags = {**COMMON_TAGS, "nodeName": node, "nodeRole": role}
        specs.extend(
            (
                ResourceSpec(f"{base_name}-pip", "Microsoft.Network/publicIPAddresses", tags),
                ResourceSpec(f"{base_name}-nsg", "Microsoft.Network/networkSecurityGroups", tags),
                ResourceSpec(f"{base_name}-nic", "Microsoft.Network/networkInterfaces", tags),
                ResourceSpec(base_name, "Microsoft.Compute/virtualMachines", tags),
                ResourceSpec(
                    f"{base_name}-osdisk",
                    "Microsoft.Compute/disks",
                    tags,
                    managed_by_vm=base_name,
                ),
            )
        )
    return tuple(specs)


def validate_core_inventory(
    subscription_id: str,
    *,
    runner: Runner,
) -> list[dict[str, Any]]:
    records = list_group_resources(subscription_id, runner=runner)
    expected = {
        (spec.resource_type.lower(), spec.name): spec for spec in expected_resource_specs()
    }
    actual: dict[tuple[str, str], dict[str, Any]] = {}
    allowed_budget_id = budget_id(subscription_id)
    budget_records = 0
    for record in records:
        if same_id(record.get("id"), allowed_budget_id):
            if str(record.get("type", "")).lower() != "microsoft.consumption/budgets":
                raise LifecycleError("POC budget resource type drifted in group inventory")
            budget_records += 1
            continue
        key = (str(record.get("type", "")).lower(), str(record.get("name", "")))
        if key in actual:
            raise LifecycleError("POC resource inventory contains a duplicate identity")
        actual[key] = record
    if budget_records > 1:
        raise LifecycleError("POC resource inventory contains duplicate budget identities")
    if set(actual) != set(expected):
        raise LifecycleError("POC resource inventory is missing, extra, or renamed")

    evidence = []
    for key in sorted(expected):
        spec = expected[key]
        record = actual[key]
        expected_id = resource_id(subscription_id, spec.resource_type, spec.name)
        if (
            not same_id(record.get("id"), expected_id)
            or str(record.get("location", "")).lower() != LOCATION
            or record.get("tags") != spec.tags
        ):
            raise LifecycleError(f"identity/location/tags drifted for POC resource {spec.name}")
        if spec.managed_by_vm is not None:
            expected_vm_id = resource_id(
                subscription_id, "Microsoft.Compute/virtualMachines", spec.managed_by_vm
            )
            if not same_id(record.get("managedBy"), expected_vm_id):
                raise LifecycleError(f"OS disk {spec.name} is not attached to its exact VM")
        evidence.append(
            {
                "id": expected_id,
                "managedByVm": spec.managed_by_vm,
                "tags": dict(spec.tags),
            }
        )
    return evidence


def validate_vms_deallocated(subscription_id: str, *, runner: Runner) -> list[str]:
    names = ("viv-sbc-poc-cp1", "viv-sbc-poc-sbc1", "viv-sbc-poc-sbc2")
    for name in names:
        state = parse_json(
            runner(
                base_command(
                    subscription_id,
                    "vm",
                    "get-instance-view",
                    "--resource-group",
                    POC_RESOURCE_GROUP,
                    "--name",
                    name,
                    "--query",
                    "instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0]",
                )
            ),
            f"power state for {name}",
        )
        if state != "PowerState/deallocated":
            raise LifecycleError(f"VM {name} is not Azure-deallocated")
    return list(names)


def canonical_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
