#!/usr/bin/env python3
"""Idempotently lock and ownership-tag the three attached POC OS disks.

Azure's virtual-machine API does not expose disk-level publicNetworkAccess or
networkAccessPolicy inside storageProfile.osDisk.managedDisk. Marketplace-image
OS disks are therefore locked immediately after VM creation and before host
configuration or qualification. Azure reimage can replace an OS disk with a
derived name, so the exact current disk identities are resolved from the three
expected VM attachments before any disk is changed.
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
VM_TO_DISK_BASE = {
    "viv-sbc-poc-cp1": "viv-sbc-poc-cp1-osdisk",
    "viv-sbc-poc-sbc1": "viv-sbc-poc-sbc1-osdisk",
    "viv-sbc-poc-sbc2": "viv-sbc-poc-sbc2-osdisk",
}
DISK_TO_VM = {disk: vm for vm, disk in VM_TO_DISK_BASE.items()}
DISK_TAGS = {
    spec.name: dict(spec.tags)
    for spec in lifecycle.expected_resource_specs()
    if spec.resource_type == "Microsoft.Compute/disks"
}
SUBSCRIPTION_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
REIMAGE_DISK_NAME_RE = re.compile(r"^[0-9a-f]{32}(?:_[0-9a-f]{32})*$")


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


def _vm_id(subscription_id: str, vm_name: str) -> str:
    return (
        f"/subscriptions/{subscription_id}/resourceGroups/{RESOURCE_GROUP}"
        f"/providers/Microsoft.Compute/virtualMachines/{vm_name}"
    )


def _disk_id(subscription_id: str, disk_name: str) -> str:
    return (
        f"/subscriptions/{subscription_id}/resourceGroups/{RESOURCE_GROUP}"
        f"/providers/Microsoft.Compute/disks/{disk_name}"
    )


def _attached_disk_name_from_id(
    disk_id: Any, subscription_id: str, vm_name: str
) -> str:
    prefix = _disk_id(subscription_id, "")
    if (
        not isinstance(disk_id, str)
        or not disk_id.lower().startswith(prefix.lower())
        or len(disk_id) <= len(prefix)
    ):
        raise DiskLockdownError(f"VM {vm_name} OS-disk resource ID drifted")
    disk_name = disk_id[len(prefix) :]
    if "/" in disk_name or disk_id.lower() != _disk_id(
        subscription_id, disk_name
    ).lower():
        raise DiskLockdownError(f"VM {vm_name} OS-disk resource ID drifted")
    return disk_name


def _allowed_attached_disk_name(disk_name: str, base_name: str) -> bool:
    if disk_name == base_name:
        return True
    prefix = f"{base_name}_"
    return disk_name.startswith(prefix) and REIMAGE_DISK_NAME_RE.fullmatch(
        disk_name[len(prefix) :]
    ) is not None


def _resolve_vm_os_disks(
    subscription_id: str, *, runner: Runner
) -> dict[str, dict[str, str]]:
    attachments: dict[str, dict[str, str]] = {}
    for vm_name, base_name in sorted(VM_TO_DISK_BASE.items()):
        record = _json(
            runner(
                [
                    "az",
                    "vm",
                    "show",
                    "--subscription",
                    subscription_id,
                    "--resource-group",
                    RESOURCE_GROUP,
                    "--name",
                    vm_name,
                    "--query",
                    (
                        "{id:id,name:name,provisioningState:provisioningState,"
                        "osDiskId:storageProfile.osDisk.managedDisk.id,"
                        "osDiskName:storageProfile.osDisk.name}"
                    ),
                    "--output",
                    "json",
                    "--only-show-errors",
                ]
            ),
            f"VM OS-disk attachment {vm_name}",
        )
        if not isinstance(record, dict):
            raise DiskLockdownError(f"VM attachment {vm_name} is not an object")
        disk_id = record.get("osDiskId")
        if record.get("name") != vm_name or not isinstance(record.get("id"), str):
            raise DiskLockdownError(f"VM identity drifted for {vm_name}")
        if record["id"].lower() != _vm_id(subscription_id, vm_name).lower():
            raise DiskLockdownError(f"VM resource ID drifted for {vm_name}")
        if record.get("provisioningState") != "Succeeded":
            raise DiskLockdownError(f"VM {vm_name} provisioning did not succeed")
        if record.get("osDiskName") != base_name:
            raise DiskLockdownError(f"VM {vm_name} logical OS-disk name drifted")
        disk_name = _attached_disk_name_from_id(disk_id, subscription_id, vm_name)
        if not _allowed_attached_disk_name(disk_name, base_name):
            raise DiskLockdownError(
                f"VM {vm_name} OS disk is not its original or bounded reimage-derived identity"
            )
        attachments[vm_name] = {
            "baseName": base_name,
            "diskId": _disk_id(subscription_id, disk_name),
            "diskName": disk_name,
            "vmId": _vm_id(subscription_id, vm_name),
            "vmName": vm_name,
        }

    names = [attachment["diskName"] for attachment in attachments.values()]
    ids = [attachment["diskId"].lower() for attachment in attachments.values()]
    if len(set(names)) != 3 or len(set(ids)) != 3:
        raise DiskLockdownError("POC VMs do not have three distinct OS-disk attachments")
    return attachments


def _validate_disk_inventory(
    inventory: Any,
    attachments: Mapping[str, Mapping[str, str]],
) -> None:
    if not isinstance(inventory, list) or len(inventory) != 3:
        raise DiskLockdownError(
            "resource group must contain exactly the three attached POC OS disks"
        )

    expected_by_name = {
        attachment["diskName"]: attachment for attachment in attachments.values()
    }
    actual_names: set[str] = set()
    for record in inventory:
        if not isinstance(record, dict):
            raise DiskLockdownError("disk inventory contains a non-object record")
        name = record.get("name")
        disk_id = record.get("id")
        managed_by = record.get("managedBy")
        if not isinstance(name, str) or name in actual_names:
            raise DiskLockdownError("disk inventory contains a duplicate or invalid identity")
        actual_names.add(name)
        attachment = expected_by_name.get(name)
        if attachment is None:
            raise DiskLockdownError(
                "resource group contains an extra or unattached managed disk"
            )
        if not isinstance(disk_id, str) or disk_id.lower() != attachment["diskId"].lower():
            raise DiskLockdownError(f"disk inventory resource ID drifted for {name}")
        if (
            not isinstance(managed_by, str)
            or managed_by.lower() != attachment["vmId"].lower()
        ):
            raise DiskLockdownError(f"disk {name} is not attached to its exact POC VM")

    if actual_names != set(expected_by_name):
        raise DiskLockdownError(
            "resource group must contain exactly the three attached POC OS disks"
        )


def _read_disk_inventory(subscription_id: str, *, runner: Runner) -> Any:
    return _json(
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
                "[].{id:id,name:name,managedBy:managedBy}",
                "--output",
                "json",
                "--only-show-errors",
            ]
        ),
        "disk inventory",
    )


def _validate_disk(
    record: Mapping[str, Any], attachment: Mapping[str, str]
) -> dict[str, Any]:
    name = attachment["diskName"]
    actual = {
        "id": record.get("id"),
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
        not isinstance(actual["id"], str)
        or actual["id"].lower() != attachment["diskId"].lower()
    ):
        raise DiskLockdownError(f"disk resource ID drifted for {name}")
    if (
        not isinstance(actual["managedBy"], str)
        or actual["managedBy"].lower() != attachment["vmId"].lower()
    ):
        raise DiskLockdownError(f"disk {name} is not attached to its exact POC VM")
    if actual["publicNetworkAccess"] != "Disabled":
        raise DiskLockdownError(f"disk {name} publicNetworkAccess is not Disabled")
    if actual["networkAccessPolicy"] != "DenyAll":
        raise DiskLockdownError(f"disk {name} networkAccessPolicy is not DenyAll")
    if actual["provisioningState"] != "Succeeded":
        raise DiskLockdownError(f"disk {name} provisioning did not succeed")
    if actual["tags"] != DISK_TAGS[attachment["baseName"]]:
        raise DiskLockdownError(f"disk {name} ownership tags drifted")
    return actual


def _read_validated_disk(
    subscription_id: str,
    attachment: Mapping[str, str],
    *,
    runner: Runner,
) -> dict[str, Any]:
    name = attachment["diskName"]
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
                    "{name:name,managedBy:managedBy,id:id,"
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
    return _validate_disk(record, attachment)


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

    attachments = _resolve_vm_os_disks(subscription_id, runner=runner)
    inventory = _read_disk_inventory(subscription_id, runner=runner)
    _validate_disk_inventory(inventory, attachments)

    for vm_name in sorted(attachments):
        attachment = attachments[vm_name]
        name = attachment["diskName"]
        expected_tags = DISK_TAGS[attachment["baseName"]]
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
        tagged = _json(
            runner(
                [
                    "az",
                    "tag",
                    "create",
                    "--subscription",
                    subscription_id,
                    "--resource-id",
                    attachment["diskId"],
                    "--tags",
                    *[
                        f"{key}={value}"
                        for key, value in sorted(expected_tags.items())
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
        if tagged != expected_tags:
            raise DiskLockdownError(f"disk {name} ownership tags drifted during replacement")
        _read_validated_disk(subscription_id, attachment, runner=runner)

    final_attachments = _resolve_vm_os_disks(subscription_id, runner=runner)
    if final_attachments != attachments:
        raise DiskLockdownError("VM OS-disk attachments changed during lockdown")
    _validate_disk_inventory(
        _read_disk_inventory(subscription_id, runner=runner), final_attachments
    )
    evidence = [
        _read_validated_disk(subscription_id, final_attachments[vm_name], runner=runner)
        for vm_name in sorted(final_attachments)
    ]

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
