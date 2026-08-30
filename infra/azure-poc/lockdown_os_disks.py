#!/usr/bin/env python3
"""Idempotently lock and ownership-tag the three POC OS disks.

Azure's virtual-machine API does not expose disk-level publicNetworkAccess or
networkAccessPolicy inside storageProfile.osDisk.managedDisk. Marketplace-image
OS disks are therefore locked immediately after VM creation and before host
configuration or qualification.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from typing import Any, Callable, Mapping, Sequence

import azure_lifecycle_contract as lifecycle


RESOURCE_GROUP = "rg-vivolution-sbc-poc-uaenorth"
LOCATION = "uaenorth"
DISK_TO_VM = {
    "viv-sbc-poc-cp1-osdisk": "viv-sbc-poc-cp1",
    "viv-sbc-poc-sbc1-osdisk": "viv-sbc-poc-sbc1",
    "viv-sbc-poc-sbc2-osdisk": "viv-sbc-poc-sbc2",
}
DISK_TAGS = {
    spec.name: dict(spec.tags)
    for spec in lifecycle.expected_resource_specs()
    if spec.resource_type == "Microsoft.Compute/disks"
}
SUBSCRIPTION_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


class DiskLockdownError(RuntimeError):
    pass


Runner = Callable[[Sequence[str]], str]


def _run(argv: Sequence[str]) -> str:
    result = subprocess.run(argv, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise DiskLockdownError(
            "Azure CLI command failed: {}".format(result.stderr.strip() or result.stdout.strip())
        )
    return result.stdout


def _json(raw: str, label: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DiskLockdownError(f"Azure CLI returned malformed {label} JSON") from exc


def _validate_disk(
    record: Mapping[str, Any], name: str, subscription_id: str
) -> dict[str, Any]:
    expected_vm = DISK_TO_VM[name]
    expected_managed_by = (
        f"/subscriptions/{subscription_id}/resourceGroups/{RESOURCE_GROUP}"
        f"/providers/Microsoft.Compute/virtualMachines/{expected_vm}"
    ).lower()
    actual = {
        "managedBy": record.get("managedBy"),
        "name": record.get("name"),
        "networkAccessPolicy": record.get("networkAccessPolicy"),
        "provisioningState": record.get("provisioningState"),
        "publicNetworkAccess": record.get("publicNetworkAccess"),
        "tags": record.get("tags"),
    }
    if actual["name"] != name:
        raise DiskLockdownError(f"disk identity drifted for {name}")
    if (
        not isinstance(actual["managedBy"], str)
        or actual["managedBy"].lower() != expected_managed_by
    ):
        raise DiskLockdownError(f"disk {name} is not attached to its exact POC VM")
    if actual["publicNetworkAccess"] != "Disabled":
        raise DiskLockdownError(f"disk {name} publicNetworkAccess is not Disabled")
    if actual["networkAccessPolicy"] != "DenyAll":
        raise DiskLockdownError(f"disk {name} networkAccessPolicy is not DenyAll")
    if actual["provisioningState"] != "Succeeded":
        raise DiskLockdownError(f"disk {name} provisioning did not succeed")
    if actual["tags"] != DISK_TAGS[name]:
        raise DiskLockdownError(f"disk {name} ownership tags drifted")
    return actual


def lock_down(subscription_id: str, *, runner: Runner = _run) -> dict[str, Any]:
    if SUBSCRIPTION_RE.fullmatch(subscription_id) is None:
        raise DiskLockdownError("expected subscription ID is not a canonical lowercase UUID")

    account = _json(
        runner(["az", "account", "show", "--query", "{id:id}", "--output", "json"]),
        "account",
    )
    if account != {"id": subscription_id}:
        raise DiskLockdownError(
            "active Azure subscription does not match the separately approved ID"
        )

    group = _json(
        runner(
            [
                "az",
                "group",
                "show",
                "--subscription",
                subscription_id,
                "--name",
                RESOURCE_GROUP,
                "--query",
                "{name:name,location:location}",
                "--output",
                "json",
            ]
        ),
        "resource group",
    )
    if group != {"location": LOCATION, "name": RESOURCE_GROUP}:
        raise DiskLockdownError("resource-group identity or location drifted")

    inventory = _json(
        runner(
            [
                "az",
                "disk",
                "list",
                "--subscription",
                subscription_id,
                "--resource-group",
                RESOURCE_GROUP,
                "--query",
                "[].name",
                "--output",
                "json",
            ]
        ),
        "disk inventory",
    )
    if not isinstance(inventory, list) or set(inventory) != set(DISK_TO_VM) or len(inventory) != 3:
        raise DiskLockdownError("resource group must contain exactly the three expected OS disks")

    evidence = []
    for name in sorted(DISK_TO_VM):
        runner(
            [
                "az",
                "disk",
                "update",
                "--subscription",
                subscription_id,
                "--resource-group",
                RESOURCE_GROUP,
                "--name",
                name,
                "--public-network-access",
                "Disabled",
                "--network-access-policy",
                "DenyAll",
                "--output",
                "none",
                "--only-show-errors",
            ]
        )
        disk_id = (
            f"/subscriptions/{subscription_id}/resourceGroups/{RESOURCE_GROUP}"
            f"/providers/Microsoft.Compute/disks/{name}"
        )
        tagged = _json(
            runner(
                [
                    "az",
                    "tag",
                    "create",
                    "--subscription",
                    subscription_id,
                    "--resource-id",
                    disk_id,
                    "--tags",
                    *[
                        f"{key}={value}"
                        for key, value in sorted(DISK_TAGS[name].items())
                    ],
                    "--query",
                    "properties.tags",
                    "--output",
                    "json",
                    "--only-show-errors",
                ]
            ),
            f"updated disk tags {name}",
        )
        if tagged != DISK_TAGS[name]:
            raise DiskLockdownError(f"disk {name} ownership tags drifted during replacement")
        record = _json(
            runner(
                [
                    "az",
                    "disk",
                    "show",
                    "--subscription",
                    subscription_id,
                    "--resource-group",
                    RESOURCE_GROUP,
                    "--name",
                    name,
                    "--query",
                    (
                        "{name:name,managedBy:managedBy,"
                        "publicNetworkAccess:publicNetworkAccess,"
                        "networkAccessPolicy:networkAccessPolicy,"
                        "provisioningState:provisioningState,tags:tags}"
                    ),
                    "--output",
                    "json",
                    "--only-show-errors",
                ]
            ),
            f"validated disk {name}",
        )
        if not isinstance(record, dict):
            raise DiskLockdownError(f"updated disk {name} is not an object")
        evidence.append(_validate_disk(record, name, subscription_id))

    return {
        "disks": evidence,
        "resourceGroup": RESOURCE_GROUP,
        "status": "POC_OS_DISKS_NETWORK_LOCKED",
        "subscriptionId": subscription_id,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-subscription-id", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        evidence = lock_down(args.expected_subscription_id)
    except DiskLockdownError as exc:
        print(f"POC_OS_DISKS_NETWORK_LOCKDOWN_REJECTED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
