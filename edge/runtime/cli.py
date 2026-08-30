#!/usr/bin/env python3
"""Fixed-path CLI for the privileged Edge runtime helper."""

from __future__ import annotations

import argparse
import grp
import os
import sys
from typing import Optional, Sequence

from edge.runtime.contracts import RuntimeContractError, canonical_bytes
from edge.runtime.core import (
    ApplyFailed,
    CommandRunner,
    RuntimeErrorBase,
    RuntimeIdentity,
    RuntimeLayout,
    RuntimeManager,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vivolution-edge-runtime",
        description=(
            "Apply or roll back one verifier-approved, compiler-produced Edge "
            "candidate using fixed root-owned paths."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    activate = commands.add_parser("activate")
    activate.add_argument("--sequence", required=True, type=int)
    activate.add_argument("--manifest-digest", required=True)
    rollback = commands.add_parser("rollback")
    rollback.add_argument("--sequence", required=True, type=int)
    rollback.add_argument("--manifest-digest", required=True)
    commands.add_parser("recover")
    commands.add_parser("health")
    commands.add_parser("status")
    return parser


def _identity() -> RuntimeIdentity:
    if os.geteuid() != 0:
        raise RuntimeErrorBase("the fixed runtime helper must execute as root")
    try:
        opensips_gid = grp.getgrnam("opensips").gr_gid
        rtpengine_gid = grp.getgrnam("rtpengine").gr_gid
        agent_gid = grp.getgrnam("vivolution-edge-agent").gr_gid
    except KeyError as exc:
        raise RuntimeErrorBase("required unprivileged service group is absent: {}".format(exc)) from exc
    return RuntimeIdentity(0, 0, opensips_gid, rtpengine_gid, agent_gid)


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        manager = RuntimeManager(RuntimeLayout.production(), _identity(), CommandRunner())
        if arguments.command == "activate":
            result = manager.activate(arguments.sequence, arguments.manifest_digest)
        elif arguments.command == "rollback":
            result = manager.rollback(arguments.sequence, arguments.manifest_digest)
        elif arguments.command == "recover":
            result = manager.recover()
        elif arguments.command == "health":
            result = manager.health()
        else:
            result = manager.status()
    except ApplyFailed as exc:
        sys.stdout.buffer.write(canonical_bytes(exc.evidence))
        print("runtime transaction failed: {}".format(exc), file=sys.stderr)
        return 1
    except (RuntimeErrorBase, RuntimeContractError, OSError, ValueError) as exc:
        print("runtime request rejected: {}".format(exc), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
