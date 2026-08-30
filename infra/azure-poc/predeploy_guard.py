#!/usr/bin/env python3
"""Read-only, fail-closed admission guard for the Azure SBC POC deployment."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from typing import Sequence

import azure_lifecycle_contract as contract


def guard_predeploy(
    subscription_id: str,
    tenant_id: str,
    *,
    runner: contract.Runner = contract.run,
    today: dt.date | None = None,
) -> dict[str, object]:
    """Prove the exact empty, budgeted, preservation-locked create boundary."""
    contract.validate_account(subscription_id, tenant_id, runner=runner)
    group = contract.get_group(
        subscription_id, contract.POC_RESOURCE_GROUP, runner=runner
    )
    contract.validate_poc_group(group)
    contract.validate_predeploy_empty_inventory(subscription_id, runner=runner)
    contract.validate_poc_group_unlocked(subscription_id, runner=runner)
    budget = contract.validate_budget(subscription_id, runner=runner, today=today)
    preserved_cp1 = contract.validate_preserved_cp1(subscription_id, runner=runner)
    dns = contract.validate_parent_dns_absent(subscription_id, runner=runner)

    evidence: dict[str, object] = {
        "budget": budget,
        "dns": dns,
        "pocResourceGroup": {
            "id": contract.resource_group_id(
                subscription_id, contract.POC_RESOURCE_GROUP
            ),
            "location": contract.LOCATION,
            "resources": [],
            "tags": contract.COMMON_TAGS,
        },
        "preservedCp1Lock": preserved_cp1,
        "subscriptionId": subscription_id,
        "tenantId": tenant_id,
    }
    return {
        **evidence,
        "evidenceSha256": contract.canonical_digest(evidence),
        "status": "POC_PREDEPLOY_GUARD_PASSED",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-subscription-id", required=True)
    parser.add_argument("--expected-tenant-id", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        evidence = guard_predeploy(
            args.expected_subscription_id,
            args.expected_tenant_id,
        )
    except contract.LifecycleError as exc:
        print(f"POC_PREDEPLOY_GUARD_REJECTED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
