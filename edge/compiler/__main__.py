#!/usr/bin/env python3
"""Compile one verifier-approved first-tenant candidate into a new directory."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from edge.compiler.core import (
    CompileError,
    NodeFacts,
    VerificationReceipt,
    compile_tenant_bundle,
)
from edge.schema import manifest_tool


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("envelope", type=Path)
    parser.add_argument("node_facts", type=Path)
    parser.add_argument("verification_receipt", type=Path)
    parser.add_argument("output_dir", type=Path)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    try:
        envelope = manifest_tool.load_json(args.envelope)
        facts = NodeFacts.from_mapping(manifest_tool.load_json(args.node_facts))
        receipt = VerificationReceipt.from_mapping(
            manifest_tool.load_json(args.verification_receipt)
        )
        bundle = compile_tenant_bundle(envelope, facts, receipt)
        bundle.write_new_directory(args.output_dir)
        sys.stdout.buffer.write(bundle.evidence)
        return 0
    except (
        CompileError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        manifest_tool.DuplicateKeyError,
        ValueError,
    ) as exc:
        print("ERROR: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
