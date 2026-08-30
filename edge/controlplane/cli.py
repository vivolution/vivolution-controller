#!/usr/bin/env python3
"""CLI for the bounded CP1 first-tenant materializer."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from edge.compiler.core import NodeFacts
from edge.schema import manifest_tool

from .core import (
    ControlPlaneError,
    FirstTenantProfile,
    generate_private_seed,
    materialize_first_tenant,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    generate = commands.add_parser("generate-key", help="atomically create a raw Ed25519 seed")
    generate.add_argument("private_seed", type=Path)
    generate.add_argument("--key-id", required=True)

    materialize = commands.add_parser("materialize", help="create a new signed node release")
    materialize.add_argument("profile", type=Path)
    materialize.add_argument("node_facts", type=Path)
    materialize.add_argument("private_seed", type=Path)
    materialize.add_argument("output_dir", type=Path)
    materialize.add_argument("--key-id", required=True)
    materialize.add_argument(
        "--issued-at",
        help="whole-second UTC timestamp; defaults to the current UTC second",
    )
    return parser


def _issued_at(value: Optional[str]) -> datetime:
    if value is None:
        return datetime.now(timezone.utc).replace(microsecond=0)
    errors: list[str] = []
    parsed = manifest_tool.parse_utc_timestamp(value, "--issued-at", errors)
    if parsed is None:
        raise ControlPlaneError("; ".join(errors))
    return parsed


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "generate-key":
            metadata = generate_private_seed(args.private_seed, key_id=args.key_id)
            sys.stdout.buffer.write(manifest_tool.canonical_json_bytes(metadata) + b"\n")
            return 0

        profile = FirstTenantProfile.from_mapping(manifest_tool.load_json(args.profile))
        facts = NodeFacts.from_mapping(manifest_tool.load_json(args.node_facts))
        release = materialize_first_tenant(
            profile,
            facts,
            private_seed_path=args.private_seed,
            key_id=args.key_id,
            issued_at=_issued_at(args.issued_at),
        )
        release.write_new_directory(args.output_dir)
        sys.stdout.buffer.write(manifest_tool.canonical_json_bytes(dict(release.evidence)) + b"\n")
        return 0
    except (
        ControlPlaneError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        manifest_tool.ContractError,
        manifest_tool.DuplicateKeyError,
        ValueError,
    ) as exc:
        print("ERROR: {}".format(exc), file=sys.stderr)
        return 1
