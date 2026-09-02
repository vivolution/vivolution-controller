#!/usr/bin/env python3
"""Plan or reconcile the root Direct Routing private-PBX DNS authority.

Planning is read-only. Applying can delete only stale ``_acme-challenge`` TXT
sets from the three exact isolated child zones, requires a freshly validated
plan digest and exact confirmation, and is safe to resume after interruption.
No root-zone record, DNS zone, role, VM, resource group, or preserved
``voice.vivolution.ae`` authority is ever a reconciliation mutation target.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import root_direct_dns_acme_contract as contract


CONFIRMATION = "RECONCILE-VIVOLUTION-ROOT-DIRECT-DNS-ACME-AUTHORITY"
RECEIPT_API_VERSION = "infra.vivolution.ae/carrier-acme-rbac-receipt/v0.1"
RECEIPT_KIND = "CarrierAcmeRbacReceipt"
RECEIPT_STATUS = "CARRIER_ACME_RBAC_RECEIPT_ISSUED"
RECEIPT_MIN_LIFETIME_SECONDS = 60
RECEIPT_MAX_LIFETIME_SECONDS = 3600
SIGNING_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _actions(discovery: Mapping[str, Any]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for child in discovery["observed"]["childZones"]:
        challenge = child["challenge"]
        if challenge is not None:
            result.append(
                {
                    "etag": challenge["etag"],
                    "id": challenge["id"],
                    "kind": "DELETE_STALE_ACME_CHALLENGE_TXT",
                    "name": challenge["name"],
                    "zone": child["name"],
                }
            )
    return result


def _stable_authority(discovery: Mapping[str, Any]) -> dict[str, Any]:
    authority = discovery["authority"]
    children = []
    for item in authority["childZones"]:
        stable = dict(item)
        stable.pop("etag", None)
        children.append(stable)
    return {
        "childZones": children,
        "customRoleDefinition": authority["customRoleDefinition"],
        "parentRecords": authority["parentRecords"],
        "virtualMachines": [
            {key: value for key, value in vm.items() if key != "powerState"}
            for vm in authority["virtualMachines"]
        ],
    }


def plan(
    inputs: contract.ExpectedInputs,
    *,
    runner: contract.Runner = contract.run,
) -> dict[str, Any]:
    discovery = contract.discover(
        inputs, runner=runner, require_complete=True, include_vms=True
    )
    actions = _actions(discovery)
    if actions and any(
        vm["powerState"] != "PowerState/deallocated"
        for vm in discovery["authority"]["virtualMachines"]
    ):
        raise contract.RootDirectDnsError(
            "CP1 and both generation-3 SBCs must be Azure-deallocated while stale challenge authority remains"
        )
    base = {
        "actions": actions,
        "authority": discovery["authority"],
        "observed": discovery["observed"],
        "preserved": discovery["preserved"],
        "scope": discovery["scope"],
    }
    result = dict(base)
    result["planSha256"] = contract.canonical_json_sha256(base)
    result["status"] = (
        "ROOT_DIRECT_DNS_ACME_AUTHORITY_RECONCILIATION_PLAN_READY"
        if actions
        else "ROOT_DIRECT_DNS_ACME_AUTHORITY_RECONCILED"
    )
    return result


def apply(
    inputs: contract.ExpectedInputs,
    *,
    approved_plan_sha256: str,
    confirmation: str,
    runner: contract.Runner = contract.run,
) -> dict[str, Any]:
    if contract.DIGEST_RE.fullmatch(approved_plan_sha256) is None:
        raise contract.RootDirectDnsError(
            "approved plan SHA-256 must be 64 lowercase hexadecimal characters"
        )
    if confirmation != CONFIRMATION:
        raise contract.RootDirectDnsError("exact reconciliation confirmation is required")
    approved = plan(inputs, runner=runner)
    if approved["planSha256"] != approved_plan_sha256:
        raise contract.RootDirectDnsError(
            "approved plan digest does not match freshly validated Azure state"
        )
    stable = _stable_authority(approved)
    for index, action in enumerate(approved["actions"]):
        boundary = plan(inputs, runner=runner)
        if (
            boundary["scope"] != approved["scope"]
            or boundary["preserved"] != approved["preserved"]
            or _stable_authority(boundary) != stable
            or boundary["actions"] != approved["actions"][index:]
        ):
            raise contract.RootDirectDnsError(
                "authority changed during reconciliation; generate and review a new plan"
            )
        contract.delete_txt(action, inputs.subscription_id, runner)
    final = plan(inputs, runner=runner)
    if (
        final["status"] != "ROOT_DIRECT_DNS_ACME_AUTHORITY_RECONCILED"
        or final["actions"]
        or final["scope"] != approved["scope"]
        or final["preserved"] != approved["preserved"]
        or _stable_authority(final) != stable
    ):
        raise contract.RootDirectDnsError("root Direct DNS reconciliation postcondition failed")
    return {
        "appliedActions": len(approved["actions"]),
        "appliedPlanSha256": approved_plan_sha256,
        "postconditionPlanSha256": final["planSha256"],
        "scope": approved["scope"],
        "status": "ROOT_DIRECT_DNS_ACME_AUTHORITY_RECONCILIATION_APPLIED",
    }


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _receipt_source(
    reconciliation: Mapping[str, Any], inputs: contract.ExpectedInputs
) -> dict[str, str]:
    base_fields = ("actions", "authority", "observed", "preserved", "scope")
    if any(field not in reconciliation for field in base_fields):
        raise contract.RootDirectDnsError(
            "carrier RBAC receipt source is missing reconciliation evidence"
        )
    canonical_discovery = {field: reconciliation[field] for field in base_fields}
    discovery_digest = contract.canonical_json_sha256(canonical_discovery)
    if (
        reconciliation.get("status")
        != "ROOT_DIRECT_DNS_ACME_AUTHORITY_RECONCILED"
        or reconciliation.get("actions") != []
        or reconciliation.get("planSha256") != discovery_digest
    ):
        raise contract.RootDirectDnsError(
            "carrier RBAC receipt requires a fully reconciled fresh discovery"
        )

    scope = reconciliation.get("scope")
    authority = reconciliation.get("authority")
    observed = reconciliation.get("observed")
    if not all(isinstance(value, Mapping) for value in (scope, authority, observed)):
        raise contract.RootDirectDnsError(
            "carrier RBAC receipt source has malformed authority evidence"
        )
    if (
        scope.get("subscriptionId") != inputs.subscription_id
        or scope.get("tenantId") != inputs.tenant_id
        or scope.get("dnsResourceGroup") != contract.DNS_RESOURCE_GROUP
        or scope.get("childZones") != list(contract.CHILD_ZONES)
        or scope.get("profile") != "DIRECT_ROUTING_PRIVATE_PBX_POC"
    ):
        raise contract.RootDirectDnsError(
            "carrier RBAC receipt source crosses its reviewed Azure scope"
        )

    expected_role = {
        "actions": sorted(contract.ROLE_ACTIONS),
        "description": contract.ROLE_DESCRIPTION,
        "id": contract.role_definition_id(inputs.subscription_id),
        "name": contract.ROLE_GUID,
        "roleName": contract.ROLE_NAME,
    }
    if authority.get("customRoleDefinition") != expected_role:
        raise contract.RootDirectDnsError(
            "carrier RBAC receipt source has custom-role drift"
        )

    children = authority.get("childZones")
    observations = observed.get("childZones")
    if (
        not isinstance(children, list)
        or len(children) != 3
        or not isinstance(observations, list)
        or len(observations) != 3
        or any(
            not isinstance(item, Mapping)
            or item.get("challenge") is not None
            or item.get("exists") is not True
            or item.get("roleAssignmentPresent") is not True
            for item in observations
        )
    ):
        raise contract.RootDirectDnsError(
            "carrier RBAC receipt requires exact zones with no stale TXT"
        )
    by_name = {
        str(item.get("name")): item
        for item in children
        if isinstance(item, Mapping)
    }
    if set(by_name) != set(contract.CHILD_ZONES):
        raise contract.RootDirectDnsError(
            "carrier RBAC receipt child-zone inventory drifted"
        )
    zone = "acme-carrier.vivolution.ae"
    zone_id = contract.zone_id(inputs.subscription_id, zone)
    carrier = by_name[zone]
    assignment = carrier.get("assignment")
    expected_assignment_prefix = (
        zone_id + "/providers/Microsoft.Authorization/roleAssignments/"
    )
    assignment_id = assignment.get("id") if isinstance(assignment, Mapping) else None
    if (
        carrier.get("id") != zone_id
        or carrier.get("principalId") != inputs.cp1_principal_id
        or not isinstance(assignment, Mapping)
        or set(assignment) != {"id", "principalId", "scope"}
        or assignment.get("principalId") != inputs.cp1_principal_id
        or assignment.get("scope") != zone_id
        or not isinstance(assignment_id, str)
        or not assignment_id.startswith(expected_assignment_prefix)
        or contract.UUID_RE.fullmatch(assignment_id.rsplit("/", 1)[-1]) is None
    ):
        raise contract.RootDirectDnsError(
            "carrier RBAC receipt CP1 assignment is not exact"
        )

    virtual_machines = authority.get("virtualMachines")
    if not isinstance(virtual_machines, list):
        raise contract.RootDirectDnsError(
            "carrier RBAC receipt CP1 inventory is malformed"
        )
    carrier_vms = [
        item
        for item in virtual_machines
        if isinstance(item, Mapping)
        and item.get("name") == contract.VM_NAMES["carrier"]
    ]
    if (
        len(carrier_vms) != 1
        or carrier_vms[0].get("principalId") != inputs.cp1_principal_id
    ):
        raise contract.RootDirectDnsError(
            "carrier RBAC receipt CP1 managed-identity binding drifted"
        )
    return {
        "assignmentId": assignment_id,
        "authorityDiscoverySha256": discovery_digest,
        "roleDefinitionId": expected_role["id"],
        "zone": zone,
        "zoneResourceId": zone_id,
    }


def build_carrier_rbac_receipt(
    reconciliation: Mapping[str, Any],
    inputs: contract.ExpectedInputs,
    *,
    signing_seed: bytes,
    signing_key_id: str,
    lifetime_seconds: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    if len(signing_seed) != 32:
        raise contract.RootDirectDnsError(
            "carrier RBAC receipt signing seed must be exactly 32 bytes"
        )
    if SIGNING_KEY_ID_RE.fullmatch(signing_key_id) is None:
        raise contract.RootDirectDnsError(
            "carrier RBAC receipt signing key ID is invalid"
        )
    if not (
        RECEIPT_MIN_LIFETIME_SECONDS
        <= lifetime_seconds
        <= RECEIPT_MAX_LIFETIME_SECONDS
    ):
        raise contract.RootDirectDnsError(
            "carrier RBAC receipt lifetime exceeds its short bound"
        )
    issued_at = now or datetime.now(timezone.utc)
    if issued_at.tzinfo is None:
        raise contract.RootDirectDnsError(
            "carrier RBAC receipt issue time must be timezone-aware"
        )
    issued_at = issued_at.astimezone(timezone.utc).replace(microsecond=0)
    expires_at = issued_at + timedelta(seconds=lifetime_seconds)
    source = _receipt_source(reconciliation, inputs)

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(signing_seed)
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    payload = {
        **source,
        "cp1PrincipalId": inputs.cp1_principal_id,
        "dnsResourceGroup": contract.DNS_RESOURCE_GROUP,
        "expiresAt": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "humanSubscriptionAdministrationEvaluated": False,
        "issuedAt": issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "roleActions": sorted(contract.ROLE_ACTIONS),
        "roleDefinitionGuid": contract.ROLE_GUID,
        "roleDescription": contract.ROLE_DESCRIPTION,
        "roleName": contract.ROLE_NAME,
        "signingKeyId": signing_key_id,
        "signingPublicKeySha256": hashlib.sha256(public_der).hexdigest(),
        "subscriptionId": inputs.subscription_id,
        "tenantId": inputs.tenant_id,
    }
    encoded_payload = _canonical_bytes(payload)
    signed = {
        "apiVersion": RECEIPT_API_VERSION,
        "kind": RECEIPT_KIND,
        "payload": payload,
        "payloadSha256": hashlib.sha256(encoded_payload).hexdigest(),
        "signatureAlgorithm": "Ed25519",
    }
    signature = private_key.sign(_canonical_bytes(signed))
    return {**signed, "signature": base64.b64encode(signature).decode("ascii")}


def _read_signing_seed(path: Path) -> bytes:
    if not path.is_absolute():
        raise contract.RootDirectDnsError(
            "carrier RBAC signing seed path must be absolute"
        )
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise contract.RootDirectDnsError(
            "carrier RBAC signing seed is unavailable"
        ) from exc
    if resolved.is_relative_to(PROJECT_ROOT.resolve()):
        raise contract.RootDirectDnsError(
            "carrier RBAC signing seed must remain outside Git"
        )
    descriptor = os.open(
        resolved, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        record = os.fstat(descriptor)
        if (
            not stat.S_ISREG(record.st_mode)
            or record.st_nlink != 1
            or record.st_uid != os.getuid()
            or stat.S_IMODE(record.st_mode) not in {0o400, 0o600}
            or record.st_size != 32
        ):
            raise contract.RootDirectDnsError(
                "carrier RBAC signing seed is not exact owner-only state"
            )
        value = os.read(descriptor, 33)
        if len(value) != 32 or os.read(descriptor, 1):
            raise contract.RootDirectDnsError(
                "carrier RBAC signing seed changed during its bounded read"
            )
        return value
    finally:
        os.close(descriptor)


def _write_owner_file(path: Path, content: bytes, label: str) -> str:
    if not path.is_absolute():
        raise contract.RootDirectDnsError(
            f"carrier RBAC {label} output path must be absolute"
        )
    parent = path.parent.resolve(strict=True)
    parent_record = parent.stat()
    if (
        not stat.S_ISDIR(parent_record.st_mode)
        or parent_record.st_uid != os.getuid()
        or stat.S_IMODE(parent_record.st_mode) & 0o022
    ):
        raise contract.RootDirectDnsError(
            f"carrier RBAC {label} output directory is not owner-controlled"
        )
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None and (
        stat.S_ISLNK(existing.st_mode)
        or not stat.S_ISREG(existing.st_mode)
        or existing.st_nlink != 1
        or existing.st_uid != os.getuid()
        or stat.S_IMODE(existing.st_mode) != 0o600
    ):
        raise contract.RootDirectDnsError(
            f"existing carrier RBAC {label} output is unsafe"
        )
    temporary = parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
        parent_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except OSError as exc:
        raise contract.RootDirectDnsError(
            f"carrier RBAC {label} could not be published atomically"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return hashlib.sha256(content).hexdigest()


def _write_receipt(path: Path, receipt: Mapping[str, Any]) -> str:
    return _write_owner_file(
        path,
        _canonical_bytes(receipt) + b"\n",
        "receipt",
    )


def _signing_public_key_pem(signing_seed: bytes) -> bytes:
    if len(signing_seed) != 32:
        raise contract.RootDirectDnsError(
            "carrier RBAC receipt signing seed must be exactly 32 bytes"
        )
    return (
        ed25519.Ed25519PrivateKey.from_private_bytes(signing_seed)
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def issue_carrier_rbac_receipt(
    inputs: contract.ExpectedInputs,
    *,
    signing_seed_path: Path,
    signing_key_id: str,
    output_path: Path,
    public_key_output_path: Path,
    lifetime_seconds: int,
    runner: contract.Runner = contract.run,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not output_path.is_absolute() or not public_key_output_path.is_absolute():
        raise contract.RootDirectDnsError(
            "carrier RBAC receipt outputs must be absolute paths"
        )
    seed_identity = signing_seed_path.resolve(strict=True)
    output_identities = (
        output_path.parent.resolve(strict=True) / output_path.name,
        public_key_output_path.parent.resolve(strict=True)
        / public_key_output_path.name,
    )
    if (
        len({seed_identity, *output_identities}) != 3
        or any(
            selected.is_relative_to(PROJECT_ROOT.resolve())
            for selected in output_identities
        )
    ):
        raise contract.RootDirectDnsError(
            "carrier RBAC seed, receipt, and public-key paths must be distinct and outside Git"
        )
    reconciliation = plan(inputs, runner=runner)
    signing_seed = _read_signing_seed(signing_seed_path)
    receipt = build_carrier_rbac_receipt(
        reconciliation,
        inputs,
        signing_seed=signing_seed,
        signing_key_id=signing_key_id,
        lifetime_seconds=lifetime_seconds,
        now=now,
    )
    public_key_pem = _signing_public_key_pem(signing_seed)
    public_key_sha256 = _write_owner_file(
        public_key_output_path,
        public_key_pem,
        "signer public key",
    )
    receipt_sha256 = _write_receipt(output_path, receipt)
    return {
        "expiresAt": receipt["payload"]["expiresAt"],
        "outputPath": str(output_path),
        "receiptSha256": receipt_sha256,
        "signingKeyId": signing_key_id,
        "signingPublicKeyOutputPath": str(public_key_output_path),
        "signingPublicKeyPemSha256": public_key_sha256,
        "signingPublicKeySha256": receipt["payload"]["signingPublicKeySha256"],
        "status": RECEIPT_STATUS,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode", choices=("plan", "apply", "carrier-rbac-receipt"), default="plan"
    )
    parser.add_argument("--expected-subscription-id", required=True)
    parser.add_argument("--expected-tenant-id", required=True)
    parser.add_argument("--expected-carrier-public-ipv4", required=True)
    parser.add_argument("--expected-sbc1-public-ipv4", required=True)
    parser.add_argument("--expected-sbc2-public-ipv4", required=True)
    parser.add_argument("--expected-cp1-principal-id", required=True)
    parser.add_argument("--expected-sbc1-principal-id", required=True)
    parser.add_argument("--expected-sbc2-principal-id", required=True)
    parser.add_argument("--approved-plan-sha256")
    parser.add_argument("--confirmation")
    parser.add_argument("--receipt-signing-seed", type=Path)
    parser.add_argument("--receipt-signing-key-id")
    parser.add_argument("--receipt-output", type=Path)
    parser.add_argument("--receipt-public-key-output", type=Path)
    parser.add_argument(
        "--receipt-lifetime-seconds",
        type=int,
        default=900,
    )
    return parser


def _inputs(args: argparse.Namespace) -> contract.ExpectedInputs:
    return contract.ExpectedInputs(
        subscription_id=args.expected_subscription_id,
        tenant_id=args.expected_tenant_id,
        carrier_public_ipv4=args.expected_carrier_public_ipv4,
        sbc1_public_ipv4=args.expected_sbc1_public_ipv4,
        sbc2_public_ipv4=args.expected_sbc2_public_ipv4,
        cp1_principal_id=args.expected_cp1_principal_id,
        sbc1_principal_id=args.expected_sbc1_principal_id,
        sbc2_principal_id=args.expected_sbc2_principal_id,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        inputs = _inputs(args)
        receipt_arguments = (
            args.receipt_signing_seed,
            args.receipt_signing_key_id,
            args.receipt_output,
            args.receipt_public_key_output,
        )
        if args.mode == "plan":
            if (
                args.approved_plan_sha256 is not None
                or args.confirmation is not None
                or any(value is not None for value in receipt_arguments)
            ):
                raise contract.RootDirectDnsError(
                    "plan mode refuses apply or receipt arguments"
                )
            evidence = plan(inputs)
        elif args.mode == "apply":
            if args.approved_plan_sha256 is None or args.confirmation is None:
                raise contract.RootDirectDnsError(
                    "apply mode requires a plan digest and confirmation"
                )
            if any(value is not None for value in receipt_arguments):
                raise contract.RootDirectDnsError(
                    "apply mode refuses receipt arguments"
                )
            evidence = apply(
                inputs,
                approved_plan_sha256=args.approved_plan_sha256,
                confirmation=args.confirmation,
            )
        else:
            if args.approved_plan_sha256 is not None or args.confirmation is not None:
                raise contract.RootDirectDnsError(
                    "receipt mode is read-only and refuses apply arguments"
                )
            if any(value is None for value in receipt_arguments):
                raise contract.RootDirectDnsError(
                    "receipt mode requires seed, key ID, and output paths"
                )
            evidence = issue_carrier_rbac_receipt(
                inputs,
                signing_seed_path=args.receipt_signing_seed,
                signing_key_id=args.receipt_signing_key_id,
                output_path=args.receipt_output,
                public_key_output_path=args.receipt_public_key_output,
                lifetime_seconds=args.receipt_lifetime_seconds,
            )
    except contract.RootDirectDnsError as exc:
        print(f"ROOT_DIRECT_DNS_ACME_AUTHORITY_REJECTED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
