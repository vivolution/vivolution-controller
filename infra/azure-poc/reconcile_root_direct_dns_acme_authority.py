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
import json
import sys
from typing import Any, Mapping, Sequence

import root_direct_dns_acme_contract as contract


CONFIRMATION = "RECONCILE-VIVOLUTION-ROOT-DIRECT-DNS-ACME-AUTHORITY"


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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "apply"), default="plan")
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
        if args.mode == "plan":
            if args.approved_plan_sha256 is not None or args.confirmation is not None:
                raise contract.RootDirectDnsError(
                    "plan mode refuses apply-only approval arguments"
                )
            evidence = plan(inputs)
        else:
            if args.approved_plan_sha256 is None or args.confirmation is None:
                raise contract.RootDirectDnsError(
                    "apply mode requires a plan digest and confirmation"
                )
            evidence = apply(
                inputs,
                approved_plan_sha256=args.approved_plan_sha256,
                confirmation=args.confirmation,
            )
    except contract.RootDirectDnsError as exc:
        print(f"ROOT_DIRECT_DNS_ACME_AUTHORITY_REJECTED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
