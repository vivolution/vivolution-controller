#!/usr/bin/env python3
"""Idempotently lock and ownership-tag the three attached POC OS disks.

Azure's virtual-machine API does not expose disk-level publicNetworkAccess or
networkAccessPolicy inside storageProfile.osDisk.managedDisk. Marketplace-image
OS disks are therefore locked immediately after VM creation and before host
configuration or qualification. Azure reimage can replace an OS disk with a
derived name, so the exact current disk identities are resolved from the three
expected VM attachments before any disk is changed.

The default mode applies the lockdown. ``--mode audit`` performs the same
stable attachment, inventory, ownership-tag, and network-policy proof without
issuing any mutating Azure command.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from typing import Any, Callable, Mapping, Sequence

import azure_lifecycle_contract as lifecycle


RESOURCE_GROUP = lifecycle.POC_RESOURCE_GROUP
LOCATION = lifecycle.LOCATION
VM_TO_DISK_BASE = lifecycle.VM_TO_OS_DISK_BASE
DISK_TO_VM = {disk: vm for vm, disk in VM_TO_DISK_BASE.items()}
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


def _resolve_vm_os_disks(
    subscription_id: str, *, runner: Runner
) -> dict[str, dict[str, str]]:
    try:
        return lifecycle.resolve_vm_os_disks(subscription_id, runner=runner)
    except lifecycle.LifecycleError as exc:
        raise DiskLockdownError(str(exc)) from exc


def _validate_disk_inventory(
    inventory: Any,
    attachments: Mapping[str, Mapping[str, str]],
) -> None:
    try:
        lifecycle.validate_os_disk_inventory(inventory, attachments)
    except lifecycle.LifecycleError as exc:
        raise DiskLockdownError(str(exc)) from exc


def _read_disk_inventory(subscription_id: str, *, runner: Runner) -> Any:
    try:
        return lifecycle.read_os_disk_inventory(subscription_id, runner=runner)
    except lifecycle.LifecycleError as exc:
        raise DiskLockdownError(str(exc)) from exc


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
    return {
        **actual,
        "baseName": attachment["baseName"],
        "vmId": attachment["vmId"],
        "vmName": attachment["vmName"],
    }


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


def _validate_scope(subscription_id: str, *, runner: Runner) -> None:
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


def audit(subscription_id: str, *, runner: Runner = _run) -> dict[str, Any]:
    """Read-only, race-detecting proof of the exact locked disk attachments."""

    _validate_scope(subscription_id, runner=runner)
    attachments = _resolve_vm_os_disks(subscription_id, runner=runner)
    _validate_disk_inventory(
        _read_disk_inventory(subscription_id, runner=runner), attachments
    )
    first = [
        _read_validated_disk(subscription_id, attachments[vm_name], runner=runner)
        for vm_name in sorted(attachments)
    ]

    final_attachments = _resolve_vm_os_disks(subscription_id, runner=runner)
    if final_attachments != attachments:
        raise DiskLockdownError("VM OS-disk attachments changed during audit")
    _validate_disk_inventory(
        _read_disk_inventory(subscription_id, runner=runner), final_attachments
    )
    final = [
        _read_validated_disk(subscription_id, final_attachments[vm_name], runner=runner)
        for vm_name in sorted(final_attachments)
    ]
    if final != first:
        raise DiskLockdownError("OS-disk state changed during audit")
    return {
        "disks": final,
        "resourceGroup": RESOURCE_GROUP,
        "status": "POC_OS_DISKS_AUDIT_PASSED",
        "subscriptionId": subscription_id,
    }


def lock_down(subscription_id: str, *, runner: Runner = _run) -> dict[str, Any]:
    _validate_scope(subscription_id, runner=runner)

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
    parser.add_argument("--mode", choices=("audit", "lockdown"), default="lockdown")
    parser.add_argument("--expected-subscription-id", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        evidence = (
            audit(args.expected_subscription_id)
            if args.mode == "audit"
            else lock_down(args.expected_subscription_id)
        )
    except DiskLockdownError as exc:
        rejection = (
            "POC_OS_DISKS_AUDIT_REJECTED"
            if args.mode == "audit"
            else "POC_OS_DISKS_NETWORK_LOCKDOWN_REJECTED"
        )
        print(f"{rejection}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
