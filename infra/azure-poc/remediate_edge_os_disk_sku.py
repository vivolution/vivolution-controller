#!/usr/bin/env python3
"""Plan or resume the exact two-node Edge OS-disk SKU correction.

The initial Azure deployment declared Standard SSDs for both Edge nodes, but
the attached reimage-derived disks are Premium SSDs.  Planning is read-only.
Applying requires the digest of that exact plan, an explicit acknowledgement,
and a protected durable journal.  Only one Edge is ever deallocated at a time;
the peer must remain healthy and complete a synthetic call before each outage.

An interrupted apply is resumed with the same command, plan digest, and
journal.  Every mutating phase is journalled before Azure is called.  A normal
failure after deallocation makes a bounded best-effort attempt to restart and
re-qualify the affected node without falsely advancing the journal.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import azure_lifecycle_contract as lifecycle


EXPECTED_SUBSCRIPTION_ID = lifecycle.EXPECTED_SUBSCRIPTION_ID
EXPECTED_TENANT_ID = lifecycle.EXPECTED_TENANT_ID
RESOURCE_GROUP = lifecycle.POC_RESOURCE_GROUP
LOCATION = lifecycle.LOCATION
AVAILABILITY_SET_NAME = "viv-sbc-poc-edge-as"
SOURCE_SKU = "Premium_LRS"
TARGET_SKU = "StandardSSD_LRS"
CONFIRMATION = "CONVERT-VIVOLUTION-SBC-POC-EDGE-OS-DISKS-TO-STANDARD-SSD"
API_VERSION = "infra.vivolution.ae/edge-os-disk-sku-remediation/v0.1"
PLAN_KIND = "EdgeOsDiskSkuRemediationPlan"
JOURNAL_KIND = "EdgeOsDiskSkuRemediationJournal"
JOURNAL_STATUS_IN_PROGRESS = "IN_PROGRESS"
JOURNAL_STATUS_COMPLETE = "COMPLETE"
PLAN_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
UUID_RE = lifecycle.UUID_RE
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FIXTURE_RESULT_RE = {
    role: re.compile(
        rf"^fixture test [0-9]{{8}}T[0-9]{{6}}Z-{role}-[0-9]+: PASS$"
    )
    for role in ("sbc1", "sbc2")
}
REQUIRED_UNITS = (
    "nftables.service",
    "ntpsec.service",
    "opensips.service",
    "rtpengine-daemon.service",
    "ssh.service",
    "vivolution-edge-certificate.timer",
)
PHASES = (
    "PENDING",
    "BASELINED",
    "DEALLOCATE_REQUESTED",
    "DEALLOCATED",
    "OUTAGE_PEER_QUALIFIED",
    "SKU_UPDATE_REQUESTED",
    "SKU_UPDATED",
    "START_REQUESTED",
    "STARTED",
    "QUALIFIED",
)
PHASE_INDEX = {phase: index for index, phase in enumerate(PHASES)}
JOURNAL_MAX_BYTES = 2 * 1024 * 1024
FIXED_APPLY_LOCK_PATH = (
    Path(__file__).resolve().parents[2]
    / "deploy/.state/edge-os-disk-sku-remediation.lock"
)


class DiskSkuRemediationError(RuntimeError):
    """The exact correction contract could not be proved or resumed safely."""


class _RemediationSignal(BaseException):
    def __init__(self, signum: int):
        super().__init__(f"received signal {signum}")
        self.signum = signum


AzureRunner = Callable[[Sequence[str]], str]
RemoteRunner = Callable[[str, Sequence[str], bool], str]
Sleeper = Callable[[float], None]


@dataclass(frozen=True)
class NodeSpec:
    role: str
    vm_name: str
    vm_size: str
    logical_disk_name: str
    disk_size_gib: int
    nic_name: str
    public_ip_name: str
    public_ip: str
    private_ip: str


NODE_SPECS = (
    NodeSpec(
        role="sbc2",
        vm_name="viv-sbc-poc-sbc2",
        vm_size="Standard_B2als_v2",
        logical_disk_name="viv-sbc-poc-sbc2-osdisk",
        disk_size_gib=32,
        nic_name="viv-sbc-poc-sbc2-nic",
        public_ip_name="viv-sbc-poc-sbc2-pip",
        public_ip="20.216.14.173",
        private_ip="10.20.2.5",
    ),
    NodeSpec(
        role="sbc1",
        vm_name="viv-sbc-poc-sbc1",
        vm_size="Standard_B2als_v2",
        logical_disk_name="viv-sbc-poc-sbc1-osdisk",
        disk_size_gib=32,
        nic_name="viv-sbc-poc-sbc1-nic",
        public_ip_name="viv-sbc-poc-sbc1-pip",
        public_ip="20.46.45.96",
        private_ip="10.20.2.4",
    ),
)
SPEC_BY_ROLE = {spec.role: spec for spec in NODE_SPECS}
NODE_ORDER = tuple(spec.role for spec in NODE_SPECS)
FIXTURE_CONTROLLER_PUBLIC_IP = "40.123.208.212"


def _run_azure(argv: Sequence[str]) -> str:
    result = subprocess.run(argv, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown Azure CLI error"
        raise DiskSkuRemediationError(f"Azure CLI command failed: {detail}")
    return result.stdout


class SshRemoteRunner:
    """Execute fixed argv over the inventory's ordinary SSH security boundary."""

    def __init__(self, private_key: Path, known_hosts: Path, *, user: str = "cpadmin"):
        self.private_key = private_key.resolve(strict=True)
        self.known_hosts = known_hosts.resolve(strict=True)
        self.user = user
        self._validate_file(self.private_key, "SSH private key", require_private=True)
        self._validate_file(self.known_hosts, "SSH known-hosts file", require_private=False)

    @staticmethod
    def _validate_file(path: Path, label: str, *, require_private: bool) -> None:
        if '"' in str(path) or "\n" in str(path) or "\r" in str(path):
            raise DiskSkuRemediationError(f"{label} path cannot be quoted safely")
        value = path.lstat()
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
            raise DiskSkuRemediationError(f"{label} must be a single-link regular file")
        if value.st_uid != os.getuid():
            raise DiskSkuRemediationError(f"{label} is not owned by the runner user")
        forbidden = 0o077 if require_private else 0o022
        if stat.S_IMODE(value.st_mode) & forbidden:
            raise DiskSkuRemediationError(f"{label} permissions are too broad")

    def __call__(self, endpoint: str, argv: Sequence[str], become: bool) -> str:
        hosts = {
            "cp1": FIXTURE_CONTROLLER_PUBLIC_IP,
            **{spec.role: spec.public_ip for spec in NODE_SPECS},
        }
        if endpoint not in hosts:
            raise DiskSkuRemediationError("remote endpoint is outside the fixed POC fleet")
        if not argv or any(not isinstance(item, str) or not item for item in argv):
            raise DiskSkuRemediationError("remote argv is empty or invalid")
        remote_argv = list(argv)
        if become:
            remote_argv = ["/usr/bin/sudo", "-n", "--", *remote_argv]
        command = [
            "/usr/bin/ssh",
            "-F",
            "/dev/null",
            "-i",
            str(self.private_key),
            "-p",
            "22",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f'UserKnownHostsFile="{self.known_hosts}"',
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=10",
            "-o",
            "ServerAliveCountMax=3",
            f"{self.user}@{hosts[endpoint]}",
            "--",
            *remote_argv,
        ]
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=240,
            )
        except subprocess.TimeoutExpired as exc:
            raise DiskSkuRemediationError(
                f"remote command timed out on {endpoint}"
            ) from exc
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "unknown SSH error"
            raise DiskSkuRemediationError(
                f"remote command failed on {endpoint}: {detail}"
            )
        return result.stdout


def _json(raw: str, label: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DiskSkuRemediationError(f"malformed {label} JSON") from exc


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _same_id(actual: Any, expected: str) -> bool:
    return isinstance(actual, str) and actual.lower() == expected.lower()


def _resource_id(subscription_id: str, resource_type: str, name: str) -> str:
    return lifecycle.resource_id(subscription_id, resource_type, name)


def _base(subscription_id: str, *parts: str) -> list[str]:
    return [
        "az",
        *parts,
        "--subscription",
        subscription_id,
        "--output",
        "json",
        "--only-show-errors",
    ]


def _validate_inputs(subscription_id: str, tenant_id: str) -> None:
    if subscription_id != EXPECTED_SUBSCRIPTION_ID or UUID_RE.fullmatch(subscription_id) is None:
        raise DiskSkuRemediationError("subscription ID is outside the reviewed POC contract")
    if tenant_id != EXPECTED_TENANT_ID or UUID_RE.fullmatch(tenant_id) is None:
        raise DiskSkuRemediationError("tenant ID is outside the reviewed POC contract")


def _validate_scope(
    subscription_id: str, tenant_id: str, *, runner: AzureRunner
) -> None:
    _validate_inputs(subscription_id, tenant_id)
    account = _json(
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
        "Azure account",
    )
    if account != {"id": subscription_id, "tenantId": tenant_id}:
        raise DiskSkuRemediationError("active Azure account differs from the approved scope")
    group = _json(
        runner(
            _base(
                subscription_id,
                "group",
                "show",
                "--name",
                RESOURCE_GROUP,
                "--query",
                "{id:id,name:name,location:location,provisioningState:properties.provisioningState}",
            )
        ),
        "resource group",
    )
    expected_id = f"/subscriptions/{subscription_id}/resourceGroups/{RESOURCE_GROUP}"
    if (
        not isinstance(group, dict)
        or not _same_id(group.get("id"), expected_id)
        or group.get("name") != RESOURCE_GROUP
        or str(group.get("location", "")).lower() != LOCATION
        or group.get("provisioningState") != "Succeeded"
    ):
        raise DiskSkuRemediationError("resource-group identity or state drifted")


def _power_state(statuses: Any, role: str) -> str:
    if not isinstance(statuses, list):
        raise DiskSkuRemediationError(f"{role} instance statuses are not a list")
    codes = [item.get("code") for item in statuses if isinstance(item, dict)]
    power = [code for code in codes if isinstance(code, str) and code.startswith("PowerState/")]
    if len(power) != 1 or "ProvisioningState/succeeded" not in codes:
        raise DiskSkuRemediationError(f"{role} instance state is incomplete or ambiguous")
    return power[0]


def _read_control(spec: NodeSpec, subscription_id: str, *, runner: AzureRunner) -> dict[str, Any]:
    vm = _json(
        runner(
            _base(
                subscription_id,
                "vm",
                "show",
                "--resource-group",
                RESOURCE_GROUP,
                "--name",
                spec.vm_name,
                "--query",
                (
                    "{id:id,name:name,location:location,vmSize:hardwareProfile.vmSize,"
                    "availabilitySetId:availabilitySet.id,identityType:identity.type,"
                    "identityPrincipalId:identity.principalId,"
                    "osDiskName:storageProfile.osDisk.name,"
                    "osDiskId:storageProfile.osDisk.managedDisk.id,"
                    "networkInterfaces:networkProfile.networkInterfaces[]."
                    "{id:id,primary:primary,deleteOption:deleteOption},"
                    "provisioningState:provisioningState}"
                ),
            )
        ),
        f"{spec.role} VM",
    )
    statuses = _json(
        runner(
            _base(
                subscription_id,
                "vm",
                "get-instance-view",
                "--resource-group",
                RESOURCE_GROUP,
                "--name",
                spec.vm_name,
                "--query",
                "instanceView.statuses[].{code:code}",
            )
        ),
        f"{spec.role} instance view",
    )
    if not isinstance(vm, dict):
        raise DiskSkuRemediationError(f"{spec.role} VM record is not an object")
    disk_id = vm.get("osDiskId")
    try:
        disk_name = lifecycle.attached_os_disk_name_from_id(
            disk_id, subscription_id, spec.vm_name
        )
    except lifecycle.LifecycleError as exc:
        raise DiskSkuRemediationError(str(exc)) from exc
    if not lifecycle.allowed_attached_os_disk_name(disk_name, spec.logical_disk_name):
        raise DiskSkuRemediationError(f"{spec.role} attached disk identity is unbounded")

    disk = _json(
        runner(
            _base(
                subscription_id,
                "disk",
                "show",
                "--resource-group",
                RESOURCE_GROUP,
                "--name",
                disk_name,
                "--query",
                (
                    "{id:id,name:name,uniqueId:uniqueId,location:location,diskSizeGiB:diskSizeGB,"
                    "sku:sku.name,managedBy:managedBy,"
                    "securityType:securityProfile.securityType,"
                    "encryptionType:encryption.type,"
                    "publicNetworkAccess:publicNetworkAccess,"
                    "networkAccessPolicy:networkAccessPolicy,"
                    "provisioningState:provisioningState}"
                ),
            )
        ),
        f"{spec.role} disk",
    )
    nic = _json(
        runner(
            _base(
                subscription_id,
                "network",
                "nic",
                "show",
                "--resource-group",
                RESOURCE_GROUP,
                "--name",
                spec.nic_name,
                "--query",
                (
                    "{id:id,name:name,location:location,vmId:virtualMachine.id,"
                    "provisioningState:provisioningState,"
                    "ipConfigurations:ipConfigurations[]."
                    "{name:name,primary:primary,privateIpAddress:privateIPAddress,"
                    "privateIpAllocationMethod:privateIPAllocationMethod,"
                    "publicIpId:publicIPAddress.id}}"
                ),
            )
        ),
        f"{spec.role} NIC",
    )
    public_ip = _json(
        runner(
            _base(
                subscription_id,
                "network",
                "public-ip",
                "show",
                "--resource-group",
                RESOURCE_GROUP,
                "--name",
                spec.public_ip_name,
                "--query",
                (
                    "{id:id,name:name,location:location,ipAddress:ipAddress,"
                    "allocationMethod:publicIPAllocationMethod,sku:sku.name,"
                    "tier:sku.tier,provisioningState:provisioningState}"
                ),
            )
        ),
        f"{spec.role} public IP",
    )
    control = {
        "disk": disk,
        "nic": nic,
        "powerState": _power_state(statuses, spec.role),
        "publicIp": public_ip,
        "vm": vm,
    }
    _validate_control(spec, subscription_id, control)
    return control


def _validate_control(spec: NodeSpec, subscription_id: str, value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {"disk", "nic", "powerState", "publicIp", "vm"}:
        raise DiskSkuRemediationError(f"{spec.role} control snapshot has unexpected shape")
    vm, disk, nic, public_ip = (
        value["vm"],
        value["disk"],
        value["nic"],
        value["publicIp"],
    )
    if not all(isinstance(item, dict) for item in (vm, disk, nic, public_ip)):
        raise DiskSkuRemediationError(f"{spec.role} Azure records are not objects")
    expected_vm_id = _resource_id(
        subscription_id, "Microsoft.Compute/virtualMachines", spec.vm_name
    )
    expected_nic_id = _resource_id(
        subscription_id, "Microsoft.Network/networkInterfaces", spec.nic_name
    )
    expected_pip_id = _resource_id(
        subscription_id, "Microsoft.Network/publicIPAddresses", spec.public_ip_name
    )
    expected_as_id = _resource_id(
        subscription_id, "Microsoft.Compute/availabilitySets", AVAILABILITY_SET_NAME
    )
    if (
        not _same_id(vm.get("id"), expected_vm_id)
        or vm.get("name") != spec.vm_name
        or str(vm.get("location", "")).lower() != LOCATION
        or vm.get("vmSize") != spec.vm_size
        or not _same_id(vm.get("availabilitySetId"), expected_as_id)
        or vm.get("identityType") != "SystemAssigned"
        or UUID_RE.fullmatch(str(vm.get("identityPrincipalId", ""))) is None
        or vm.get("osDiskName") != spec.logical_disk_name
        or vm.get("provisioningState") != "Succeeded"
    ):
        raise DiskSkuRemediationError(f"{spec.role} VM identity or provisioning drifted")
    interfaces = vm.get("networkInterfaces")
    if (
        not isinstance(interfaces, list)
        or len(interfaces) != 1
        or not isinstance(interfaces[0], dict)
        or not _same_id(interfaces[0].get("id"), expected_nic_id)
        or interfaces[0].get("primary") is not True
    ):
        raise DiskSkuRemediationError(f"{spec.role} VM NIC attachment drifted")
    disk_id = vm.get("osDiskId")
    try:
        actual_disk_name = lifecycle.attached_os_disk_name_from_id(
            disk_id, subscription_id, spec.vm_name
        )
    except lifecycle.LifecycleError as exc:
        raise DiskSkuRemediationError(str(exc)) from exc
    expected_disk_id = _resource_id(
        subscription_id, "Microsoft.Compute/disks", actual_disk_name
    )
    if (
        not lifecycle.allowed_attached_os_disk_name(actual_disk_name, spec.logical_disk_name)
        or disk.get("name") != actual_disk_name
        or not _same_id(disk.get("id"), expected_disk_id)
        or UUID_RE.fullmatch(str(disk.get("uniqueId", ""))) is None
        or not _same_id(disk.get("managedBy"), expected_vm_id)
        or str(disk.get("location", "")).lower() != LOCATION
        or disk.get("diskSizeGiB") != spec.disk_size_gib
        or disk.get("sku") not in {SOURCE_SKU, TARGET_SKU}
        or disk.get("securityType") != "TrustedLaunch"
        or disk.get("encryptionType") != "EncryptionAtRestWithPlatformKey"
        or disk.get("publicNetworkAccess") != "Disabled"
        or disk.get("networkAccessPolicy") != "DenyAll"
        or disk.get("provisioningState") != "Succeeded"
    ):
        raise DiskSkuRemediationError(f"{spec.role} attached OS disk drifted")
    configs = nic.get("ipConfigurations")
    if (
        not _same_id(nic.get("id"), expected_nic_id)
        or nic.get("name") != spec.nic_name
        or str(nic.get("location", "")).lower() != LOCATION
        or not _same_id(nic.get("vmId"), expected_vm_id)
        or nic.get("provisioningState") != "Succeeded"
        or not isinstance(configs, list)
        or len(configs) != 1
        or configs[0].get("name") != "ipconfig1"
        or configs[0].get("primary") is not True
        or configs[0].get("privateIpAddress") != spec.private_ip
        or configs[0].get("privateIpAllocationMethod") != "Static"
        or not _same_id(configs[0].get("publicIpId"), expected_pip_id)
    ):
        raise DiskSkuRemediationError(f"{spec.role} NIC or private-IP identity drifted")
    if (
        not _same_id(public_ip.get("id"), expected_pip_id)
        or public_ip.get("name") != spec.public_ip_name
        or str(public_ip.get("location", "")).lower() != LOCATION
        or public_ip.get("ipAddress") != spec.public_ip
        or public_ip.get("allocationMethod") != "Static"
        or public_ip.get("sku") != "Standard"
        or public_ip.get("tier") != "Regional"
        or public_ip.get("provisioningState") != "Succeeded"
    ):
        raise DiskSkuRemediationError(f"{spec.role} public-IP identity drifted")


def _probe_remote(role: str, *, runner: RemoteRunner) -> dict[str, Any]:
    spec = SPEC_BY_ROLE[role]
    hostname = runner(role, ["/bin/hostname"], False).strip()
    boot_id = runner(
        role, ["/usr/bin/cat", "/proc/sys/kernel/random/boot_id"], False
    ).strip()
    status_value = _json(
        runner(role, ["/usr/local/sbin/vivolution-edge-runtime", "status"], True),
        f"{role} runtime status",
    )
    health = _json(
        runner(role, ["/usr/local/sbin/vivolution-edge-runtime", "health"], True),
        f"{role} runtime health",
    )
    hashes_raw = runner(
        role,
        [
            "/usr/bin/sha256sum",
            "/etc/vivolution-edge/node-facts.json",
            "/var/lib/vivolution-edge/runtime/runtime-authority.json",
        ],
        True,
    )
    hashes: dict[str, str] = {}
    for line in hashes_raw.splitlines():
        fields = line.split()
        if len(fields) != 2 or SHA256_RE.fullmatch(fields[0]) is None:
            raise DiskSkuRemediationError(f"{role} immutable identity hash output drifted")
        hashes[fields[1]] = fields[0]
    units = {
        unit: runner(role, ["/usr/bin/systemctl", "is-active", unit], True).strip()
        for unit in REQUIRED_UNITS
    }
    value = {
        "bootId": boot_id,
        "health": health,
        "hostname": hostname,
        "identitySha256": hashes,
        "status": status_value,
        "units": units,
    }
    _validate_remote(spec, value)
    return value


def _validate_remote(spec: NodeSpec, value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {
        "bootId",
        "health",
        "hostname",
        "identitySha256",
        "status",
        "units",
    }:
        raise DiskSkuRemediationError(f"{spec.role} remote snapshot has unexpected shape")
    if value["hostname"] != spec.vm_name or UUID_RE.fullmatch(str(value["bootId"])) is None:
        raise DiskSkuRemediationError(f"{spec.role} hostname or boot identity drifted")
    hashes = value["identitySha256"]
    expected_hash_paths = {
        "/etc/vivolution-edge/node-facts.json",
        "/var/lib/vivolution-edge/runtime/runtime-authority.json",
    }
    if (
        not isinstance(hashes, dict)
        or set(hashes) != expected_hash_paths
        or any(SHA256_RE.fullmatch(str(item)) is None for item in hashes.values())
    ):
        raise DiskSkuRemediationError(f"{spec.role} immutable identity hashes drifted")
    status_value, health = value["status"], value["health"]
    if (
        not isinstance(status_value, dict)
        or set(status_value) != {
            "active",
            "apiVersion",
            "highestSeenSequence",
            "journalPresent",
            "kind",
            "lastEvidenceDigest",
            "previous",
        }
        or status_value.get("apiVersion") != "edge.vivolution.ae/runtime/v0.1"
        or status_value.get("kind") != "EdgeRuntimeStatus"
        or status_value.get("journalPresent") is not False
        or not isinstance(status_value.get("active"), dict)
        or status_value["active"].get("kind") != "CANDIDATE"
    ):
        raise DiskSkuRemediationError(f"{spec.role} runtime status is not committed and journal-free")
    if (
        not isinstance(health, dict)
        or set(health) != {
            "active",
            "apiVersion",
            "highestSeenSequence",
            "kind",
            "runtimeChecks",
        }
        or health.get("apiVersion") != "edge.vivolution.ae/runtime/v0.1"
        or health.get("kind") != "EdgeRuntimeHealth"
        or health.get("active") != status_value.get("active")
        or health.get("highestSeenSequence") != status_value.get("highestSeenSequence")
        or not isinstance(health.get("runtimeChecks"), list)
        or not health["runtimeChecks"]
        or any(
            not isinstance(check, dict) or check.get("status") != "PASSED"
            for check in health["runtimeChecks"]
        )
    ):
        raise DiskSkuRemediationError(f"{spec.role} protected runtime health failed")
    if value["units"] != {unit: "active" for unit in REQUIRED_UNITS}:
        raise DiskSkuRemediationError(f"{spec.role} required units are not all active")


def _same_control_identity(current: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    left = json.loads(json.dumps(current))
    right = json.loads(json.dumps(expected))
    for value in (left, right):
        value["powerState"] = "IGNORED"
        value["disk"]["sku"] = "IGNORED"
    return left == right


def _same_remote_identity(current: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    left = json.loads(json.dumps(current))
    right = json.loads(json.dumps(expected))
    left["bootId"] = "IGNORED"
    right["bootId"] = "IGNORED"
    return left == right


def plan_remediation(
    subscription_id: str,
    tenant_id: str,
    *,
    azure_runner: AzureRunner = _run_azure,
    remote_runner: RemoteRunner,
) -> dict[str, Any]:
    """Return one race-detecting, non-mutating exact correction plan."""

    _validate_scope(subscription_id, tenant_id, runner=azure_runner)
    nodes: dict[str, Any] = {}
    principals: set[str] = set()
    for spec in NODE_SPECS:
        control = _read_control(spec, subscription_id, runner=azure_runner)
        if control["powerState"] != "PowerState/running":
            raise DiskSkuRemediationError(f"{spec.role} must be running while planning")
        remote = _probe_remote(spec.role, runner=remote_runner)
        principal = control["vm"]["identityPrincipalId"]
        if principal in principals:
            raise DiskSkuRemediationError("Edge system-assigned identities are not distinct")
        principals.add(principal)
        nodes[spec.role] = {"control": control, "remote": remote}
    actions = [
        {
            "action": "CONVERT_ATTACHED_OS_DISK_SKU",
            "diskId": nodes[spec.role]["control"]["disk"]["id"],
            "fromSku": SOURCE_SKU,
            "role": spec.role,
            "toSku": TARGET_SKU,
            "vmId": nodes[spec.role]["control"]["vm"]["id"],
        }
        for spec in NODE_SPECS
        if nodes[spec.role]["control"]["disk"]["sku"] == SOURCE_SKU
    ]
    body = {
        "actions": actions,
        "apiVersion": API_VERSION,
        "kind": PLAN_KIND,
        "nodeOrder": list(NODE_ORDER),
        "nodes": nodes,
        "scope": {
            "location": LOCATION,
            "resourceGroup": RESOURCE_GROUP,
            "subscriptionId": subscription_id,
            "tenantId": tenant_id,
        },
        "status": (
            "POC_EDGE_OS_DISK_SKU_REMEDIATION_REQUIRED"
            if actions
            else "POC_EDGE_OS_DISK_SKU_ALREADY_COMPLIANT"
        ),
    }
    plan = {**body, "planSha256": _digest(body)}

    # A second complete read rejects attachment, identity, or runtime races.
    for spec in NODE_SPECS:
        control = _read_control(spec, subscription_id, runner=azure_runner)
        remote = _probe_remote(spec.role, runner=remote_runner)
        if control != nodes[spec.role]["control"] or remote != nodes[spec.role]["remote"]:
            raise DiskSkuRemediationError(f"{spec.role} changed while the plan was built")
    return plan


def _journal_without_digest(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "selfSha256"}


def _with_journal_digest(value: Mapping[str, Any]) -> dict[str, Any]:
    body = _journal_without_digest(value)
    return {**body, "selfSha256": _digest(body)}


def _secure_parent(path: Path) -> None:
    parent = path.parent
    value = parent.lstat()
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.getuid():
        raise DiskSkuRemediationError("journal parent must be a runner-owned directory")
    if stat.S_IMODE(value.st_mode) & 0o077:
        raise DiskSkuRemediationError("journal parent must have mode 0700 or stricter")


@contextlib.contextmanager
def _exclusive_apply_lock(path: Path):
    """Hold one fleet-wide lock independent of the caller's journal name."""
    path = path.resolve(strict=False)
    _secure_parent(path)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    locked = False
    try:
        value = os.fstat(descriptor)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_nlink != 1
            or value.st_uid != os.getuid()
            or stat.S_IMODE(value.st_mode) != 0o600
        ):
            raise DiskSkuRemediationError(
                "fleet remediation lock is linked, misowned, or mis-modeed"
            )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except BlockingIOError as exc:
            raise DiskSkuRemediationError(
                "another Edge OS-disk remediation process holds the fleet lock"
            ) from exc
        yield
    finally:
        try:
            if locked:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


@contextlib.contextmanager
def _recoverable_interrupts():
    """Convert ordinary termination signals into the recovery path."""
    previous: dict[int, Any] = {}

    def handler(signum: int, _frame: Any) -> None:
        raise _RemediationSignal(signum)

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, handler)
        yield
    finally:
        for signum, prior in previous.items():
            signal.signal(signum, prior)


def _load_journal(path: Path) -> dict[str, Any] | None:
    _secure_parent(path)
    try:
        value = path.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_nlink != 1
        or value.st_uid != os.getuid()
        or stat.S_IMODE(value.st_mode) != 0o600
        or value.st_size <= 0
        or value.st_size > JOURNAL_MAX_BYTES
    ):
        raise DiskSkuRemediationError("journal is linked, misowned, mis-modeed, or oversized")
    raw = path.read_bytes()
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DiskSkuRemediationError("journal is malformed JSON") from exc
    if not isinstance(decoded, dict) or raw != _canonical_bytes(decoded):
        raise DiskSkuRemediationError("journal is not canonical JSON")
    _validate_journal(decoded)
    return decoded


def _validate_plan(plan: Any) -> None:
    if not isinstance(plan, dict) or set(plan) != {
        "actions",
        "apiVersion",
        "kind",
        "nodeOrder",
        "nodes",
        "planSha256",
        "scope",
        "status",
    }:
        raise DiskSkuRemediationError("journal plan shape is invalid")
    body = {key: item for key, item in plan.items() if key != "planSha256"}
    if (
        plan.get("apiVersion") != API_VERSION
        or plan.get("kind") != PLAN_KIND
        or plan.get("nodeOrder") != list(NODE_ORDER)
        or plan.get("scope")
        != {
            "location": LOCATION,
            "resourceGroup": RESOURCE_GROUP,
            "subscriptionId": EXPECTED_SUBSCRIPTION_ID,
            "tenantId": EXPECTED_TENANT_ID,
        }
        or plan.get("planSha256") != _digest(body)
        or set(plan.get("nodes", {})) != set(NODE_ORDER)
    ):
        raise DiskSkuRemediationError("journal plan authority or digest is invalid")
    for spec in NODE_SPECS:
        snapshot = plan["nodes"].get(spec.role)
        if not isinstance(snapshot, dict) or set(snapshot) != {"control", "remote"}:
            raise DiskSkuRemediationError(f"journal plan lacks exact {spec.role} snapshot")
        _validate_control(spec, EXPECTED_SUBSCRIPTION_ID, snapshot["control"])
        _validate_remote(spec, snapshot["remote"])
    expected_actions = [
        {
            "action": "CONVERT_ATTACHED_OS_DISK_SKU",
            "diskId": plan["nodes"][spec.role]["control"]["disk"]["id"],
            "fromSku": SOURCE_SKU,
            "role": spec.role,
            "toSku": TARGET_SKU,
            "vmId": plan["nodes"][spec.role]["control"]["vm"]["id"],
        }
        for spec in NODE_SPECS
        if plan["nodes"][spec.role]["control"]["disk"]["sku"] == SOURCE_SKU
    ]
    if plan.get("actions") != expected_actions:
        raise DiskSkuRemediationError("journal plan actions differ from exact disk drift")


def _validate_journal(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != {
        "acknowledgement",
        "apiVersion",
        "kind",
        "nodes",
        "plan",
        "planSha256",
        "selfSha256",
        "status",
    }:
        raise DiskSkuRemediationError("journal shape is invalid")
    if (
        value.get("apiVersion") != API_VERSION
        or value.get("kind") != JOURNAL_KIND
        or value.get("acknowledgement") != CONFIRMATION
        or value.get("status") not in {JOURNAL_STATUS_IN_PROGRESS, JOURNAL_STATUS_COMPLETE}
        or value.get("selfSha256") != _digest(_journal_without_digest(value))
    ):
        raise DiskSkuRemediationError("journal authority or self-digest is invalid")
    _validate_plan(value.get("plan"))
    if value.get("planSha256") != value["plan"]["planSha256"]:
        raise DiskSkuRemediationError("journal plan digest binding is invalid")
    nodes = value.get("nodes")
    if not isinstance(nodes, dict) or set(nodes) != set(NODE_ORDER):
        raise DiskSkuRemediationError("journal node set is invalid")
    for role in NODE_ORDER:
        record = nodes[role]
        if not isinstance(record, dict) or set(record) != {
            "outagePeerCall",
            "peerCall",
            "phase",
            "postCall",
            "postControl",
            "postRemote",
        }:
            raise DiskSkuRemediationError(f"{role} journal record shape is invalid")
        if record["phase"] not in PHASES:
            raise DiskSkuRemediationError(f"{role} journal phase is invalid")
        if record["phase"] == "QUALIFIED":
            if not all(
                record[key] is not None
                for key in (
                    "outagePeerCall",
                    "peerCall",
                    "postCall",
                    "postControl",
                    "postRemote",
                )
            ):
                raise DiskSkuRemediationError(f"{role} qualified journal evidence is incomplete")
        elif record["postCall"] is not None or record["postControl"] is not None or record["postRemote"] is not None:
            raise DiskSkuRemediationError(f"{role} unqualified journal contains final evidence")
        if PHASE_INDEX[record["phase"]] >= PHASE_INDEX["OUTAGE_PEER_QUALIFIED"]:
            if record["peerCall"] is None or record["outagePeerCall"] is None:
                raise DiskSkuRemediationError(
                    f"{role} progressed without both durable peer-call proofs"
                )
        elif record["outagePeerCall"] is not None:
            raise DiskSkuRemediationError(
                f"{role} has outage-call evidence before deallocation"
            )
    phases = [nodes[role]["phase"] for role in NODE_ORDER]
    if phases[0] != "QUALIFIED" and phases[1] != "PENDING":
        raise DiskSkuRemediationError("SBC1 progressed before SBC2 qualification")
    complete = all(phase == "QUALIFIED" for phase in phases)
    if (value["status"] == JOURNAL_STATUS_COMPLETE) != complete:
        raise DiskSkuRemediationError("journal completion status conflicts with node phases")


def _atomic_write_journal(path: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    _secure_parent(path)
    final = _with_journal_digest(value)
    _validate_journal(final)
    data = _canonical_bytes(final)
    if len(data) > JOURNAL_MAX_BYTES:
        raise DiskSkuRemediationError("journal exceeds its fixed size bound")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return final


def _begin_journal(path: Path, plan: Mapping[str, Any]) -> dict[str, Any]:
    if _load_journal(path) is not None:
        raise DiskSkuRemediationError("journal appeared while beginning the correction")
    nodes = {
        role: {
            "outagePeerCall": None,
            "peerCall": None,
            "phase": "PENDING",
            "postCall": None,
            "postControl": None,
            "postRemote": None,
        }
        for role in NODE_ORDER
    }
    value = {
        "acknowledgement": CONFIRMATION,
        "apiVersion": API_VERSION,
        "kind": JOURNAL_KIND,
        "nodes": nodes,
        "plan": dict(plan),
        "planSha256": plan["planSha256"],
        "status": JOURNAL_STATUS_IN_PROGRESS,
    }
    return _atomic_write_journal(path, value)


def _transition(
    path: Path,
    journal: Mapping[str, Any],
    role: str,
    phase: str,
    **evidence: Any,
) -> dict[str, Any]:
    current = journal["nodes"][role]["phase"]
    if phase not in PHASES or PHASE_INDEX[phase] != PHASE_INDEX[current] + 1:
        raise DiskSkuRemediationError(f"forbidden journal transition {current} -> {phase}")
    updated = json.loads(json.dumps(journal))
    updated["nodes"][role]["phase"] = phase
    for key, item in evidence.items():
        if key not in {
            "outagePeerCall",
            "peerCall",
            "postCall",
            "postControl",
            "postRemote",
        }:
            raise DiskSkuRemediationError("unsupported journal evidence field")
        updated["nodes"][role][key] = item
    if all(updated["nodes"][item]["phase"] == "QUALIFIED" for item in NODE_ORDER):
        updated["status"] = JOURNAL_STATUS_COMPLETE
    return _atomic_write_journal(path, updated)


def _fixture_call(role: str, *, runner: RemoteRunner) -> str:
    runner(
        "cp1", ["/usr/local/libexec/vivolution-voice-fixture-readiness"], True
    )
    result = runner(
        "cp1",
        [
            "/usr/bin/timeout",
            "--signal=TERM",
            "--kill-after=10s",
            "180s",
            "/usr/local/sbin/vivolution-voice-fixture-test",
            role,
        ],
        True,
    ).strip()
    if FIXTURE_RESULT_RE[role].fullmatch(result) is None:
        raise DiskSkuRemediationError(f"{role} did not complete one exact synthetic call")
    return result


def _mutate(azure_runner: AzureRunner, subscription_id: str, *parts: str) -> None:
    azure_runner(
        [
            "az",
            *parts,
            "--subscription",
            subscription_id,
            "--output",
            "none",
            "--only-show-errors",
        ]
    )


def _wait_control(
    spec: NodeSpec,
    subscription_id: str,
    *,
    azure_runner: AzureRunner,
    predicate: Callable[[Mapping[str, Any]], bool],
    label: str,
    sleeper: Sleeper,
    attempts: int = 60,
) -> dict[str, Any]:
    error: Exception | None = None
    for _ in range(attempts):
        try:
            current = _read_control(spec, subscription_id, runner=azure_runner)
            if predicate(current):
                return current
        except DiskSkuRemediationError as exc:
            error = exc
        sleeper(5)
    raise DiskSkuRemediationError(f"{spec.role} did not reach {label}: {error}")


def _wait_remote(
    role: str,
    *,
    remote_runner: RemoteRunner,
    sleeper: Sleeper,
    attempts: int = 60,
) -> dict[str, Any]:
    error: Exception | None = None
    for _ in range(attempts):
        try:
            return _probe_remote(role, runner=remote_runner)
        except DiskSkuRemediationError as exc:
            error = exc
            sleeper(5)
    raise DiskSkuRemediationError(f"{role} SSH/runtime recovery timed out: {error}")


def _expected_remote(journal: Mapping[str, Any], role: str) -> Mapping[str, Any]:
    record = journal["nodes"][role]
    return record["postRemote"] or journal["plan"]["nodes"][role]["remote"]


def _validate_live_identity(
    role: str,
    control: Mapping[str, Any],
    remote: Mapping[str, Any] | None,
    journal: Mapping[str, Any],
    *,
    require_running: bool,
) -> None:
    expected_control = journal["plan"]["nodes"][role]["control"]
    if not _same_control_identity(control, expected_control):
        raise DiskSkuRemediationError(f"{role} Azure identity changed after plan approval")
    if require_running and control["powerState"] != "PowerState/running":
        raise DiskSkuRemediationError(f"{role} is not running")
    if remote is not None and not _same_remote_identity(remote, _expected_remote(journal, role)):
        raise DiskSkuRemediationError(f"{role} immutable runtime identity changed")


def _best_effort_start(
    spec: NodeSpec,
    subscription_id: str,
    journal: Mapping[str, Any],
    *,
    azure_runner: AzureRunner,
    remote_runner: RemoteRunner,
    sleeper: Sleeper,
) -> str:
    """Recover availability without advancing the durable correction phase."""
    try:
        control = _wait_control(
            spec,
            subscription_id,
            azure_runner=azure_runner,
            predicate=lambda item: item["powerState"]
            in {
                "PowerState/deallocated",
                "PowerState/running",
                "PowerState/stopped",
            },
            label="a stable state during recovery",
            sleeper=sleeper,
            attempts=24,
        )
        if not _same_control_identity(
            control, journal["plan"]["nodes"][spec.role]["control"]
        ):
            return "RECOVERY_REFUSED_IDENTITY_DRIFT"
        if control["powerState"] != "PowerState/running":
            _mutate(
                azure_runner,
                subscription_id,
                "vm",
                "start",
                "--ids",
                journal["plan"]["nodes"][spec.role]["control"]["vm"]["id"],
            )
            control = _wait_control(
                spec,
                subscription_id,
                azure_runner=azure_runner,
                predicate=lambda item: item["powerState"] == "PowerState/running",
                label="running during recovery",
                sleeper=sleeper,
            )
        remote = _wait_remote(spec.role, remote_runner=remote_runner, sleeper=sleeper)
        _validate_live_identity(
            spec.role, control, remote, journal, require_running=True
        )
        return "RECOVERED_RUNNING_HEALTHY"
    except BaseException as exc:  # best effort must preserve the original failure
        return f"RECOVERY_FAILED:{type(exc).__name__}"


def _apply_node(
    role: str,
    subscription_id: str,
    journal_path: Path,
    journal: dict[str, Any],
    *,
    azure_runner: AzureRunner,
    remote_runner: RemoteRunner,
    sleeper: Sleeper,
) -> dict[str, Any]:
    spec = SPEC_BY_ROLE[role]
    peer = "sbc2" if role == "sbc1" else "sbc1"
    phase = journal["nodes"][role]["phase"]
    if phase == "QUALIFIED":
        return journal

    peer_control = _read_control(SPEC_BY_ROLE[peer], subscription_id, runner=azure_runner)
    peer_remote = _probe_remote(peer, runner=remote_runner)
    _validate_live_identity(peer, peer_control, peer_remote, journal, require_running=True)
    peer_call = _fixture_call(peer, runner=remote_runner)

    control = _read_control(spec, subscription_id, runner=azure_runner)
    _validate_live_identity(role, control, None, journal, require_running=False)
    if phase == "PENDING":
        if control["powerState"] != "PowerState/running":
            raise DiskSkuRemediationError(f"{role} was not running before its correction")
        remote = _probe_remote(role, runner=remote_runner)
        _validate_live_identity(role, control, remote, journal, require_running=True)
        journal = _transition(
            journal_path,
            journal,
            role,
            "BASELINED",
            peerCall=peer_call,
        )
        phase = "BASELINED"
    if phase == "BASELINED":
        journal = _transition(
            journal_path,
            journal,
            role,
            "DEALLOCATE_REQUESTED",
        )
        phase = "DEALLOCATE_REQUESTED"

    # A prior ordinary failure may have restarted this exact VM without
    # advancing the phase.  Re-deallocation is safe only after the fresh peer
    # health and call proof above.
    if PHASE_INDEX[phase] <= PHASE_INDEX["SKU_UPDATE_REQUESTED"]:
        control = _read_control(spec, subscription_id, runner=azure_runner)
        if control["powerState"] != "PowerState/deallocated":
            _mutate(
                azure_runner,
                subscription_id,
                "vm",
                "deallocate",
                "--ids",
                journal["plan"]["nodes"][role]["control"]["vm"]["id"],
            )
        control = _wait_control(
            spec,
            subscription_id,
            azure_runner=azure_runner,
            predicate=lambda item: item["powerState"] == "PowerState/deallocated",
            label="Azure-deallocated",
            sleeper=sleeper,
        )
        _validate_live_identity(role, control, None, journal, require_running=False)
        if phase == "DEALLOCATE_REQUESTED":
            journal = _transition(journal_path, journal, role, "DEALLOCATED")
            phase = "DEALLOCATED"
        if phase == "DEALLOCATED":
            # Prove a complete new call through the still-running peer while
            # this node is observably Azure-deallocated, not merely just
            # before the outage began.
            outage_call = _fixture_call(peer, runner=remote_runner)
            journal = _transition(
                journal_path,
                journal,
                role,
                "OUTAGE_PEER_QUALIFIED",
                outagePeerCall=outage_call,
            )
            phase = "OUTAGE_PEER_QUALIFIED"
        if phase == "OUTAGE_PEER_QUALIFIED":
            journal = _transition(journal_path, journal, role, "SKU_UPDATE_REQUESTED")
            phase = "SKU_UPDATE_REQUESTED"
        if control["disk"]["sku"] == SOURCE_SKU:
            _mutate(
                azure_runner,
                subscription_id,
                "disk",
                "update",
                "--ids",
                journal["plan"]["nodes"][role]["control"]["disk"]["id"],
                "--sku",
                TARGET_SKU,
            )
        control = _wait_control(
            spec,
            subscription_id,
            azure_runner=azure_runner,
            predicate=lambda item: (
                item["powerState"] == "PowerState/deallocated"
                and item["disk"]["sku"] == TARGET_SKU
            ),
            label="deallocated with Standard SSD",
            sleeper=sleeper,
        )
        _validate_live_identity(role, control, None, journal, require_running=False)
        if phase == "SKU_UPDATE_REQUESTED":
            journal = _transition(journal_path, journal, role, "SKU_UPDATED")
            phase = "SKU_UPDATED"

    if phase == "SKU_UPDATED":
        journal = _transition(journal_path, journal, role, "START_REQUESTED")
        phase = "START_REQUESTED"
    if phase == "START_REQUESTED":
        control = _read_control(spec, subscription_id, runner=azure_runner)
        if control["disk"]["sku"] != TARGET_SKU:
            raise DiskSkuRemediationError(f"{role} disk SKU regressed before start")
        if control["powerState"] != "PowerState/running":
            _mutate(
                azure_runner,
                subscription_id,
                "vm",
                "start",
                "--ids",
                journal["plan"]["nodes"][role]["control"]["vm"]["id"],
            )
        control = _wait_control(
            spec,
            subscription_id,
            azure_runner=azure_runner,
            predicate=lambda item: item["powerState"] == "PowerState/running",
            label="running",
            sleeper=sleeper,
        )
        journal = _transition(journal_path, journal, role, "STARTED")
        phase = "STARTED"
    if phase == "STARTED":
        remote = _wait_remote(role, remote_runner=remote_runner, sleeper=sleeper)
        _validate_live_identity(role, control, remote, journal, require_running=True)
        original_boot = journal["plan"]["nodes"][role]["remote"]["bootId"]
        if remote["bootId"] == original_boot:
            raise DiskSkuRemediationError(f"{role} boot ID did not change across deallocation")
        if control["disk"]["sku"] != TARGET_SKU:
            raise DiskSkuRemediationError(f"{role} final disk SKU is not Standard SSD")
        post_call = _fixture_call(role, runner=remote_runner)
        # The peer is re-proved before the node can be marked qualified.
        final_peer_control = _read_control(
            SPEC_BY_ROLE[peer], subscription_id, runner=azure_runner
        )
        final_peer_remote = _probe_remote(peer, runner=remote_runner)
        _validate_live_identity(
            peer, final_peer_control, final_peer_remote, journal, require_running=True
        )
        journal = _transition(
            journal_path,
            journal,
            role,
            "QUALIFIED",
            postCall=post_call,
            postControl=control,
            postRemote=remote,
        )
    return journal


def _verify_final_fleet(
    subscription_id: str,
    journal: Mapping[str, Any],
    *,
    azure_runner: AzureRunner,
    remote_runner: RemoteRunner,
) -> None:
    for spec in NODE_SPECS:
        control = _read_control(spec, subscription_id, runner=azure_runner)
        remote = _probe_remote(spec.role, runner=remote_runner)
        _validate_live_identity(
            spec.role, control, remote, journal, require_running=True
        )
        if control["disk"]["sku"] != TARGET_SKU:
            raise DiskSkuRemediationError(f"{spec.role} final SKU verification failed")


def _apply_remediation_under_lock(
    subscription_id: str,
    tenant_id: str,
    *,
    approved_plan_sha256: str,
    confirmation: str,
    journal_path: Path,
    azure_runner: AzureRunner = _run_azure,
    remote_runner: RemoteRunner,
    sleeper: Sleeper = time.sleep,
) -> dict[str, Any]:
    if PLAN_DIGEST_RE.fullmatch(approved_plan_sha256) is None:
        raise DiskSkuRemediationError("approved plan SHA-256 is not canonical")
    if confirmation != CONFIRMATION:
        raise DiskSkuRemediationError("exact disk-SKU correction acknowledgement is absent")
    _validate_scope(subscription_id, tenant_id, runner=azure_runner)
    journal_path = journal_path.resolve(strict=False)
    journal = _load_journal(journal_path)
    if journal is None:
        plan = plan_remediation(
            subscription_id,
            tenant_id,
            azure_runner=azure_runner,
            remote_runner=remote_runner,
        )
        if plan["planSha256"] != approved_plan_sha256:
            raise DiskSkuRemediationError(
                "approved plan digest differs from freshly validated fleet state"
            )
        if not plan["actions"]:
            raise DiskSkuRemediationError("both Edge disks are already Standard SSDs")
        if [action["role"] for action in plan["actions"]] != list(NODE_ORDER):
            raise DiskSkuRemediationError(
                "fresh apply refuses a mixed Premium/Standard fleet without its original journal"
            )
        journal = _begin_journal(journal_path, plan)
    elif journal["planSha256"] != approved_plan_sha256:
        raise DiskSkuRemediationError("approved plan digest differs from durable journal")

    if journal["status"] == JOURNAL_STATUS_COMPLETE:
        _verify_final_fleet(
            subscription_id,
            journal,
            azure_runner=azure_runner,
            remote_runner=remote_runner,
        )
        return {
            "journal": str(journal_path),
            "planSha256": approved_plan_sha256,
            "status": "POC_EDGE_OS_DISK_SKU_REMEDIATION_ALREADY_COMPLETE",
        }

    active_role = next(
        role for role in NODE_ORDER if journal["nodes"][role]["phase"] != "QUALIFIED"
    )
    try:
        for role in NODE_ORDER:
            if journal["nodes"][role]["phase"] != "QUALIFIED":
                active_role = role
                journal = _apply_node(
                    role,
                    subscription_id,
                    journal_path,
                    journal,
                    azure_runner=azure_runner,
                    remote_runner=remote_runner,
                    sleeper=sleeper,
                )
    except (Exception, KeyboardInterrupt, _RemediationSignal) as exc:
        recovery = _best_effort_start(
            SPEC_BY_ROLE[active_role],
            subscription_id,
            journal,
            azure_runner=azure_runner,
            remote_runner=remote_runner,
            sleeper=sleeper,
        )
        if isinstance(exc, DiskSkuRemediationError):
            raise DiskSkuRemediationError(f"{exc}; availability recovery={recovery}") from exc
        if isinstance(exc, (KeyboardInterrupt, _RemediationSignal)):
            raise DiskSkuRemediationError(
                f"disk correction interrupted; availability recovery={recovery}"
            ) from exc
        raise DiskSkuRemediationError(
            f"unexpected correction failure; availability recovery={recovery}"
        ) from exc

    final = _load_journal(journal_path)
    if final is None or final["status"] != JOURNAL_STATUS_COMPLETE:
        raise DiskSkuRemediationError("durable correction did not reach COMPLETE")
    _verify_final_fleet(
        subscription_id,
        final,
        azure_runner=azure_runner,
        remote_runner=remote_runner,
    )
    return {
        "journal": str(journal_path),
        "nodeOrder": list(NODE_ORDER),
        "planSha256": approved_plan_sha256,
        "status": "POC_EDGE_OS_DISK_SKU_REMEDIATION_APPLIED",
    }


def apply_remediation(
    subscription_id: str,
    tenant_id: str,
    *,
    approved_plan_sha256: str,
    confirmation: str,
    journal_path: Path,
    azure_runner: AzureRunner = _run_azure,
    remote_runner: RemoteRunner,
    sleeper: Sleeper = time.sleep,
    lock_path: Path = FIXED_APPLY_LOCK_PATH,
) -> dict[str, Any]:
    with _exclusive_apply_lock(lock_path):
        with _recoverable_interrupts():
            return _apply_remediation_under_lock(
                subscription_id,
                tenant_id,
                approved_plan_sha256=approved_plan_sha256,
                confirmation=confirmation,
                journal_path=journal_path,
                azure_runner=azure_runner,
                remote_runner=remote_runner,
                sleeper=sleeper,
            )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "apply"), default="plan")
    parser.add_argument("--expected-subscription-id", required=True)
    parser.add_argument("--expected-tenant-id", required=True)
    parser.add_argument("--ssh-private-key", required=True, type=Path)
    parser.add_argument("--known-hosts", required=True, type=Path)
    parser.add_argument("--journal", type=Path)
    parser.add_argument("--approved-plan-sha256")
    parser.add_argument("--confirmation")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        remote = SshRemoteRunner(args.ssh_private_key, args.known_hosts)
        if args.mode == "plan":
            if any(
                value is not None
                for value in (
                    args.journal,
                    args.approved_plan_sha256,
                    args.confirmation,
                )
            ):
                raise DiskSkuRemediationError("plan mode refuses apply-only arguments")
            with _exclusive_apply_lock(FIXED_APPLY_LOCK_PATH):
                evidence = plan_remediation(
                    args.expected_subscription_id,
                    args.expected_tenant_id,
                    remote_runner=remote,
                )
        else:
            if (
                args.journal is None
                or args.approved_plan_sha256 is None
                or args.confirmation is None
            ):
                raise DiskSkuRemediationError(
                    "apply mode requires journal, plan digest, and acknowledgement"
                )
            evidence = apply_remediation(
                args.expected_subscription_id,
                args.expected_tenant_id,
                approved_plan_sha256=args.approved_plan_sha256,
                confirmation=args.confirmation,
                journal_path=args.journal,
                remote_runner=remote,
            )
    except DiskSkuRemediationError as exc:
        print(f"POC_EDGE_OS_DISK_SKU_REMEDIATION_REJECTED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
