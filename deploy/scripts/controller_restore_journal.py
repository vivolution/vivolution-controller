#!/usr/bin/python3
"""Crash-safe journal and topology reconciliation for CP1 replacement restore."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


API_VERSION = "vivolution.io/controller-restore-journal/v1"
PRODUCTION_PATH = Path(
    "/var/lib/vivolution/backups/cp1-restore-transaction-v1.json"
)
MAX_JOURNAL_BYTES = 16_384
DATABASE_RE = re.compile(r"^[a-z][a-z0-9_]{1,62}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

PHASE_IMPORT_STARTED = "IMPORT_STARTED"
PHASE_PREPARED = "PREPARED"
PHASE_SWAP_STARTED = "SWAP_STARTED"
PHASE_SELECTED = "SELECTED"
PHASE_READINESS_VERIFIED = "READINESS_VERIFIED"
PHASE_ROLLBACK_STARTED = "ROLLBACK_STARTED"
PHASE_ROLLED_BACK = "ROLLED_BACK"
PHASE_COMPLETE = "COMPLETE"

PHASES = {
    PHASE_IMPORT_STARTED,
    PHASE_PREPARED,
    PHASE_SWAP_STARTED,
    PHASE_SELECTED,
    PHASE_READINESS_VERIFIED,
    PHASE_ROLLBACK_STARTED,
    PHASE_ROLLED_BACK,
    PHASE_COMPLETE,
}

ALLOWED_TRANSITIONS: Mapping[str | None, frozenset[str]] = {
    None: frozenset({PHASE_IMPORT_STARTED}),
    PHASE_IMPORT_STARTED: frozenset({PHASE_PREPARED}),
    PHASE_PREPARED: frozenset({PHASE_SWAP_STARTED}),
    PHASE_SWAP_STARTED: frozenset({PHASE_SELECTED}),
    PHASE_SELECTED: frozenset(
        {PHASE_READINESS_VERIFIED, PHASE_ROLLBACK_STARTED}
    ),
    PHASE_READINESS_VERIFIED: frozenset({PHASE_COMPLETE}),
    PHASE_ROLLBACK_STARTED: frozenset({PHASE_ROLLED_BACK}),
    PHASE_ROLLED_BACK: frozenset(),
    PHASE_COMPLETE: frozenset(),
}


class RestoreJournalError(RuntimeError):
    """Raised when the durable restore state is unsafe or inconsistent."""


@dataclass(frozen=True)
class RestoreIdentity:
    expected_sha256: str
    main_database: str
    import_database: str
    previous_database: str
    failed_database: str

    def __post_init__(self) -> None:
        if not SHA256_RE.fullmatch(self.expected_sha256):
            raise RestoreJournalError("expected SHA-256 must be lowercase hexadecimal")
        names = (
            self.main_database,
            self.import_database,
            self.previous_database,
            self.failed_database,
        )
        if any(not DATABASE_RE.fullmatch(name) for name in names):
            raise RestoreJournalError("database identity differs from the fixed format")
        if len(set(names)) != len(names):
            raise RestoreJournalError("restore database identities must be distinct")
        token = self.expected_sha256[:16]
        if self.main_database != "vivolution":
            raise RestoreJournalError("the service database must be vivolution")
        if self.import_database != f"vivolution_import_{token}":
            raise RestoreJournalError("import database is not digest-bound")
        if self.previous_database != f"vivolution_preimport_{token}":
            raise RestoreJournalError("previous database is not digest-bound")
        if self.failed_database != f"vivolution_failedimport_{token}":
            raise RestoreJournalError("failed database is not digest-bound")

    @property
    def token(self) -> str:
        return self.expected_sha256[:16]

    @property
    def relevant_databases(self) -> frozenset[str]:
        return frozenset(
            {
                self.main_database,
                self.import_database,
                self.previous_database,
                self.failed_database,
            }
        )

    def journal(self, phase: str) -> dict[str, Any]:
        if phase not in PHASES:
            raise RestoreJournalError("unsupported restore journal phase")
        return {
            "apiVersion": API_VERSION,
            "databaseNames": {
                "failed": self.failed_database,
                "import": self.import_database,
                "main": self.main_database,
                "previous": self.previous_database,
            },
            "expectedSha256": self.expected_sha256,
            "phase": phase,
            "token": self.token,
        }


def _validate_journal(value: Any, identity: RestoreIdentity) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RestoreJournalError("restore journal must be a JSON object")
    expected = identity.journal(value.get("phase", ""))
    if value != expected:
        raise RestoreJournalError("restore journal differs from its exact identity")
    return value


def reconcile_action(
    journal: Mapping[str, Any] | None,
    observed_databases: Sequence[str] | set[str] | frozenset[str],
    identity: RestoreIdentity,
) -> str:
    """Return the only safe next action for a journal/database snapshot."""

    observed = frozenset(observed_databases)
    if any(not DATABASE_RE.fullmatch(name) for name in observed):
        raise RestoreJournalError("observed database name differs from fixed format")
    relevant = observed & identity.relevant_databases
    main_only = frozenset({identity.main_database})
    importing = frozenset({identity.main_database, identity.import_database})
    selected = frozenset({identity.main_database, identity.previous_database})
    rolled_back = frozenset({identity.main_database, identity.failed_database})

    if journal is None:
        if relevant == main_only:
            return "START"
        raise RestoreJournalError(
            "deterministic restore databases exist without a durable journal"
        )

    checked = _validate_journal(dict(journal), identity)
    phase = checked["phase"]
    expected: dict[str, str]

    if phase == PHASE_IMPORT_STARTED:
        expected = {
            "|".join(sorted(main_only)): "BEGIN_IMPORT",
            "|".join(sorted(importing)): "RESTART_IMPORT",
        }
    elif phase == PHASE_PREPARED:
        expected = {"|".join(sorted(importing)): "RESUME_PREPARED"}
    elif phase == PHASE_SWAP_STARTED:
        expected = {
            "|".join(sorted(importing)): "RESUME_SWAP",
            "|".join(sorted(selected)): "RESUME_SELECTED_AFTER_SWAP",
        }
    elif phase == PHASE_SELECTED:
        expected = {"|".join(sorted(selected)): "RESUME_READINESS"}
    elif phase == PHASE_READINESS_VERIFIED:
        expected = {"|".join(sorted(selected)): "FINALIZE_COMPLETE"}
    elif phase == PHASE_ROLLBACK_STARTED:
        expected = {
            "|".join(sorted(selected)): "RESUME_ROLLBACK",
            "|".join(sorted(rolled_back)): "FINALIZE_ROLLBACK",
        }
    elif phase == PHASE_ROLLED_BACK:
        expected = {"|".join(sorted(rolled_back)): "ROLLED_BACK"}
    elif phase == PHASE_COMPLETE:
        expected = {"|".join(sorted(selected)): "COMPLETE"}
    else:  # pragma: no cover - _validate_journal rejects this first.
        raise RestoreJournalError("unsupported restore journal phase")

    key = "|".join(sorted(relevant))
    try:
        return expected[key]
    except KeyError as exc:
        raise RestoreJournalError(
            f"journal phase {phase} conflicts with observed database topology"
        ) from exc


def _open_parent(path: Path, production: bool) -> tuple[int, str]:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise RestoreJournalError("secure directory operations are unavailable")
    if production:
        if os.geteuid() != 0:
            raise RestoreJournalError("production journal operations require root")
        if path != PRODUCTION_PATH:
            raise RestoreJournalError("production journal path is fixed")
    parent = path.parent
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd = os.open(parent, flags)
    metadata = os.fstat(directory_fd)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(directory_fd)
        raise RestoreJournalError("journal parent is not a directory")
    if production:
        if metadata.st_uid != 0 or metadata.st_gid != 0:
            os.close(directory_fd)
            raise RestoreJournalError("journal parent must be root-owned")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            os.close(directory_fd)
            raise RestoreJournalError("journal parent must not be group/world writable")
    return directory_fd, path.name


def load_journal(
    path: Path, identity: RestoreIdentity, *, production: bool
) -> dict[str, Any] | None:
    directory_fd, name = _open_parent(path, production)
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, dir_fd=directory_fd)
        except FileNotFoundError:
            return None
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise RestoreJournalError("restore journal must be a single-link regular file")
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                raise RestoreJournalError("restore journal mode must be 0600")
            if production and (metadata.st_uid != 0 or metadata.st_gid != 0):
                raise RestoreJournalError("restore journal must be root-owned")
            if metadata.st_size < 2 or metadata.st_size > MAX_JOURNAL_BYTES:
                raise RestoreJournalError("restore journal size is outside its bound")
            payload = b""
            while len(payload) <= MAX_JOURNAL_BYTES:
                chunk = os.read(descriptor, MAX_JOURNAL_BYTES + 1 - len(payload))
                if not chunk:
                    break
                payload += chunk
            if len(payload) > MAX_JOURNAL_BYTES:
                raise RestoreJournalError("restore journal exceeds its size bound")
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_fd)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RestoreJournalError("restore journal is not canonical JSON") from exc
    return _validate_journal(value, identity)


def _atomic_write(path: Path, value: Mapping[str, Any], *, production: bool) -> None:
    directory_fd, name = _open_parent(path, production)
    temporary = f".{name}.tmp-{os.getpid()}"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_NOFOLLOW
    )
    descriptor = -1
    try:
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        os.fchmod(descriptor, 0o600)
        if production:
            os.fchown(descriptor, 0, 0)
        payload = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii") + b"\n"
        os.write(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)


def transition(
    path: Path,
    identity: RestoreIdentity,
    next_phase: str,
    *,
    production: bool,
) -> None:
    if next_phase not in PHASES:
        raise RestoreJournalError("unsupported restore journal phase")
    current = load_journal(path, identity, production=production)
    current_phase = None if current is None else current["phase"]
    if next_phase not in ALLOWED_TRANSITIONS[current_phase]:
        raise RestoreJournalError(
            f"restore journal transition {current_phase!r} -> {next_phase!r} is forbidden"
        )
    _atomic_write(path, identity.journal(next_phase), production=production)


def clear_journal(
    path: Path,
    identity: RestoreIdentity,
    expected_phase: str,
    *,
    production: bool,
) -> None:
    if expected_phase not in {
        PHASE_IMPORT_STARTED,
        PHASE_PREPARED,
        PHASE_SWAP_STARTED,
    }:
        raise RestoreJournalError("journal clearing is limited to pre-selection phases")
    current = load_journal(path, identity, production=production)
    if current is None or current["phase"] != expected_phase:
        raise RestoreJournalError("journal phase changed before bounded clear")
    directory_fd, name = _open_parent(path, production)
    try:
        os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _identity_from_args(args: argparse.Namespace) -> RestoreIdentity:
    return RestoreIdentity(
        expected_sha256=args.expected_sha256,
        main_database=args.main_database,
        import_database=args.import_database,
        previous_database=args.previous_database,
        failed_database=args.failed_database,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", required=True, type=Path)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--main-database", required=True)
    parser.add_argument("--import-database", required=True)
    parser.add_argument("--previous-database", required=True)
    parser.add_argument("--failed-database", required=True)
    parser.add_argument("--production", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("--observed", default="")
    transition_parser = subparsers.add_parser("transition")
    transition_parser.add_argument("--phase", required=True, choices=sorted(PHASES))
    clear_parser = subparsers.add_parser("clear")
    clear_parser.add_argument(
        "--phase",
        required=True,
        choices=sorted(
            {PHASE_IMPORT_STARTED, PHASE_PREPARED, PHASE_SWAP_STARTED}
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    identity = _identity_from_args(args)
    try:
        if args.command == "inspect":
            observed = [] if not args.observed else args.observed.split(",")
            journal = load_journal(args.journal, identity, production=args.production)
            action = reconcile_action(journal, observed, identity)
            result = {
                "action": action,
                "journalPresent": journal is not None,
                "phase": None if journal is None else journal["phase"],
            }
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0
        if args.command == "clear":
            clear_journal(
                args.journal,
                identity,
                args.phase,
                production=args.production,
            )
            print(json.dumps({"cleared": args.phase}, sort_keys=True, separators=(",", ":")))
            return 0
        transition(
            args.journal,
            identity,
            args.phase,
            production=args.production,
        )
        print(json.dumps({"phase": args.phase}, sort_keys=True, separators=(",", ":")))
        return 0
    except RestoreJournalError as exc:
        print(f"controller restore journal rejected: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
