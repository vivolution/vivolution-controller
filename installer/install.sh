#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
if [ -n "${VIVO_INSTALLER_PYTHON:-}" ]; then
    PYTHON_BIN=$VIVO_INSTALLER_PYTHON
elif command -v python3.12 >/dev/null 2>&1; then
    PYTHON_BIN=python3.12
else
    PYTHON_BIN=python3
fi

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    printf 'Vivolution Turnkey Installer requires Python 3.12: %s was not found.\n' \
        "$PYTHON_BIN" >&2
    exit 2
fi

if ! "$PYTHON_BIN" -c \
    'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)'
then
    printf 'Vivolution Turnkey Installer requires Python 3.12 exactly.\n' >&2
    exit 2
fi

if [ "$#" -eq 0 ]; then
    set -- menu
fi

# A curl pipe consumes standard input. Reopen the controlling TTY so the same
# permanent one-liner can safely display menus and collect interactive answers.
if [ ! -t 0 ] && [ -c /dev/tty ] && (: </dev/tty) 2>/dev/null; then
    exec "$PYTHON_BIN" "$SCRIPT_DIR/vivo_cp_installer.py" "$@" </dev/tty
fi
exec "$PYTHON_BIN" "$SCRIPT_DIR/vivo_cp_installer.py" "$@"
