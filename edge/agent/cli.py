#!/usr/bin/env python3
"""Local command-line boundary for the protected Edge metadata lifecycle."""

from __future__ import annotations

import argparse
import base64
import binascii
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Sequence

from edge.schema import manifest_tool

from .security_core import (
    MAX_ENVELOPE_BYTES,
    AgentError,
    LocalContext,
    PinnedKeyring,
    abort_pending,
    commit_pending_after_health,
    inspect_protected_state,
    verify_and_stage,
)


def _add_context_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--scope", required=True, choices=("CLUSTER", "TENANT"))
    parser.add_argument("--cluster-id", required=True)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--generation", required=True, type=int)
    parser.add_argument("--slot", required=True, choices=("A", "B"))
    parser.add_argument("--customer-account-id")
    parser.add_argument("--m365-tenant-id")
    parser.add_argument("--tenant-context-id")
    parser.add_argument("--service-instance-id")
    parser.add_argument("--allocation-id")
    parser.add_argument("--tenant-listener-port", type=int)
    parser.add_argument("--tenant-media-port-start", type=int)
    parser.add_argument("--tenant-media-port-end", type=int)
    parser.add_argument("--pbx-media-destination-port-start", type=int)
    parser.add_argument("--pbx-media-destination-port-end", type=int)
    parser.add_argument("--cluster-media-port-start", type=int)
    parser.add_argument("--cluster-media-port-end", type=int)
    parser.add_argument(
        "--expected-advertised-public-ip",
        help="immutable public IPv4 authorized for ACTIVE tenant media",
    )
    parser.add_argument(
        "--authorized-pbx-source-cidr",
        action="append",
        help="repeat in canonical sorted order for each tenant PBX source CIDR",
    )
    parser.add_argument(
        "--authorized-microsoft-source-cidr",
        action="append",
        help="repeat in canonical sorted order for each cluster Microsoft source CIDR",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify/stage protected Edge metadata, or explicitly commit/abort "
            "the exact pending candidate; no command applies configuration."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    stage = subparsers.add_parser("verify-and-stage")
    stage.add_argument("envelope", help="signed envelope file, or - for stdin")
    _add_context_arguments(stage)
    stage.add_argument(
        "--pinned-key",
        action="append",
        required=True,
        metavar="KEY_ID=BASE64_RAW_PUBLIC_KEY",
        help="repeatable explicit key-id allowlist entry",
    )
    stage.add_argument("--now", help="fixed whole-second UTC time for reproducible checks")

    commit = subparsers.add_parser(
        "commit-pending",
        help=(
            "promote the exact pending candidate only from immutable signed "
            "local-health success evidence"
        ),
    )
    _add_context_arguments(commit)
    commit.add_argument("--sequence", required=True, type=int)
    commit.add_argument("--manifest-digest", required=True)
    commit.add_argument(
        "--runtime-evidence-digest",
        required=True,
        help=(
            "digest of the fixed-path immutable root runtime success evidence; "
            "caller-controlled evidence paths are never accepted"
        ),
    )

    abort = subparsers.add_parser(
        "abort-pending",
        help="discard the exact pending candidate while preserving active LKG/highest-seen",
    )
    _add_context_arguments(abort)
    abort.add_argument("--sequence", required=True, type=int)
    abort.add_argument("--manifest-digest", required=True)
    status = subparsers.add_parser(
        "status",
        help="inspect the validated protected metadata without exposing artifacts",
    )
    _add_context_arguments(status)
    return parser


def _read_bounded(path_value: str) -> bytes:
    if path_value == "-":
        raw = sys.stdin.buffer.read(MAX_ENVELOPE_BYTES + 1)
    else:
        with Path(path_value).open("rb") as source:
            raw = source.read(MAX_ENVELOPE_BYTES + 1)
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise ValueError("envelope exceeds the {} byte limit".format(MAX_ENVELOPE_BYTES))
    return raw


def _parse_pins(values: Sequence[str]) -> PinnedKeyring:
    pins: Dict[str, bytes] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("--pinned-key must use KEY_ID=BASE64_RAW_PUBLIC_KEY")
        key_id, encoded = value.split("=", 1)
        if key_id in pins:
            raise ValueError("duplicate --pinned-key id {!r}".format(key_id))
        try:
            public_bytes = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("pinned key {!r} is not canonical base64".format(key_id)) from exc
        if base64.b64encode(public_bytes).decode("ascii") != encoded:
            raise ValueError("pinned key {!r} is not canonical base64".format(key_id))
        pins[key_id] = public_bytes
    return PinnedKeyring(pins)


def _parse_now(value: Optional[str]) -> Optional[datetime]:
    if value is None:
        return None
    errors = []
    parsed = manifest_tool.parse_utc_timestamp(value, "--now", errors)
    if parsed is None:
        raise ValueError("; ".join(errors))
    return parsed.astimezone(timezone.utc)


def _context_from_args(args: argparse.Namespace) -> LocalContext:
    return LocalContext(
        scope=args.scope,
        cluster_id=args.cluster_id,
        node_id=args.node_id,
        generation=args.generation,
        slot=args.slot,
        customer_account_id=args.customer_account_id,
        m365_tenant_id=args.m365_tenant_id,
        tenant_context_id=args.tenant_context_id,
        service_instance_id=args.service_instance_id,
        allocation_id=args.allocation_id,
        tenant_listener_port=args.tenant_listener_port,
        tenant_media_port_start=args.tenant_media_port_start,
        tenant_media_port_end=args.tenant_media_port_end,
        pbx_media_destination_port_start=args.pbx_media_destination_port_start,
        pbx_media_destination_port_end=args.pbx_media_destination_port_end,
        cluster_media_port_start=args.cluster_media_port_start,
        cluster_media_port_end=args.cluster_media_port_end,
        expected_advertised_public_ip=args.expected_advertised_public_ip,
        authorized_pbx_source_cidrs=tuple(args.authorized_pbx_source_cidr or ()),
        authorized_microsoft_source_cidrs=tuple(
            args.authorized_microsoft_source_cidr or ()
        ),
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        context = _context_from_args(args)
        if args.command == "verify-and-stage":
            result = verify_and_stage(
                _read_bounded(args.envelope),
                local_context=context,
                keyring=_parse_pins(args.pinned_key),
                state_directory=args.state_dir,
                now=_parse_now(args.now),
            )
        elif args.command == "commit-pending":
            result = commit_pending_after_health(
                local_context=context,
                state_directory=args.state_dir,
                sequence=args.sequence,
                manifest_digest=args.manifest_digest,
                runtime_evidence_digest=args.runtime_evidence_digest,
            )
        elif args.command == "abort-pending":
            result = abort_pending(
                local_context=context,
                state_directory=args.state_dir,
                sequence=args.sequence,
                manifest_digest=args.manifest_digest,
            )
        else:
            result = inspect_protected_state(
                local_context=context,
                state_directory=args.state_dir,
            )
        evidence = result if isinstance(result, dict) else result.evidence()
        print(manifest_tool.canonical_json_bytes(evidence).decode("utf-8"))
        return 0
    except (AgentError, OSError, UnicodeError, ValueError) as exc:
        print("ERROR: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
