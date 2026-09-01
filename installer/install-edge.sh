#!/bin/sh
set -eu

vivo_edge_usage() {
  /usr/bin/printf '%s\n' \
    'Usage: sudo ./installer/install-edge.sh [--verify-only|--check-host-os|--dry-run]' \
    '' \
    'Installs the provider-neutral Edge enrollment client on fresh Ubuntu 24.04.' \
    'Interactive install asks only for the Controller Shared URL and hidden grant.'
}

vivo_edge_mode=install
case "${1-}" in
  '') ;;
  --verify-only) vivo_edge_mode=verify ;;
  --check-host-os) vivo_edge_mode=os-check ;;
  --dry-run) vivo_edge_mode=dry-run ;;
  -h|--help) vivo_edge_usage; exit 0 ;;
  *) vivo_edge_usage >&2; exit 64 ;;
esac
[ "$#" -le 1 ] || { vivo_edge_usage >&2; exit 64; }

vivo_edge_script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
vivo_edge_repo_root=$(CDPATH='' cd -- "$vivo_edge_script_dir/.." && pwd -P)
vivo_edge_release_source="$vivo_edge_repo_root/edge/enrollment"
vivo_edge_release_defaults="$vivo_edge_repo_root/deploy/roles/edge_enrollment_install/defaults/main.yml"
vivo_edge_local_playbook="$vivo_edge_repo_root/deploy/playbooks/install-edge-enrollment-local.yml"
vivo_edge_ansible_config="$vivo_edge_repo_root/installer/ansible/ansible.cfg"

for vivo_edge_required in \
  "$vivo_edge_release_source/release.py" \
  "$vivo_edge_release_defaults" \
  "$vivo_edge_local_playbook" \
  "$vivo_edge_ansible_config"; do
  [ -f "$vivo_edge_required" ] && [ ! -L "$vivo_edge_required" ] || {
    /usr/bin/printf 'ERROR: enrollment-client source bundle is incomplete\n' >&2
    exit 1
  }
done

command -v /usr/bin/python3 >/dev/null 2>&1 || {
  /usr/bin/printf 'ERROR: /usr/bin/python3 is required\n' >&2
  exit 1
}

vivo_edge_actual_digest=$(
  /usr/bin/python3 "$vivo_edge_release_source/release.py" "$vivo_edge_release_source"
)
vivo_edge_expected_digest=$(
  /usr/bin/sed -n 's/^edge_enrollment_release_digest: \(sha256:[0-9a-f][0-9a-f]*\)$/\1/p' \
    "$vivo_edge_release_defaults"
)
case "$vivo_edge_expected_digest" in
  sha256:????????????????????????????????????????????????????????????????) ;;
  *) /usr/bin/printf 'ERROR: pinned Edge release digest is invalid\n' >&2; exit 1 ;;
esac
[ "$vivo_edge_actual_digest" = "$vivo_edge_expected_digest" ] || {
  /usr/bin/printf 'ERROR: Edge source bundle differs from its pinned digest\n' >&2
  exit 1
}

if [ "$vivo_edge_mode" = verify ]; then
  /usr/bin/printf 'VERIFIED %s\n' "$vivo_edge_actual_digest"
  exit 0
fi

if [ "$vivo_edge_mode" = dry-run ]; then
  /usr/bin/printf '%s\n' \
    "VERIFIED $vivo_edge_actual_digest" \
    'DRY RUN: would install native dependencies and the hardened Edge enrollment service' \
    'DRY RUN: would then prompt for Controller Shared URL and hidden one-time grant'
  exit 0
fi

[ "$(/usr/bin/id -u)" -eq 0 ] || {
  /usr/bin/printf 'ERROR: run this installer with sudo\n' >&2
  exit 1
}

if ! /usr/bin/python3 - <<'PY'
import os
import stat

source = "/etc/os-release"
try:
    source_metadata = os.lstat(source)
    read_path = source
    if stat.S_ISLNK(source_metadata.st_mode):
        if os.readlink(source) != "../usr/lib/os-release":
            raise OSError("non-canonical os-release link")
        read_path = "/usr/lib/os-release"
    elif not stat.S_ISREG(source_metadata.st_mode):
        raise OSError("os-release is not a regular file")

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(read_path, flags)
    try:
        opened_metadata = os.fstat(descriptor)
        if not stat.S_ISREG(opened_metadata.st_mode) or opened_metadata.st_size > 65536:
            raise OSError("os-release target is unsafe")
        if opened_metadata.st_uid != 0 or opened_metadata.st_mode & 0o022:
            raise OSError("os-release ownership or mode is unsafe")
        chunks = []
        remaining = 65537
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > 65536 or b"\x00" in content:
            raise OSError("os-release is too large")
    finally:
        os.close(descriptor)
    values = {}
    for line in content.decode("utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            key = key.strip()
            if key in values:
                raise OSError("duplicate os-release key")
            values[key] = value.strip().strip("\"'")
    if values.get("ID", "").lower() != "ubuntu" or values.get("VERSION_ID") != "24.04":
        raise OSError("unsupported operating system")
except (OSError, UnicodeError):
    raise SystemExit(1)
PY
then
  /usr/bin/printf 'ERROR: this turnkey entrypoint requires fresh Ubuntu 24.04 LTS\n' >&2
  exit 1
fi
if [ "$vivo_edge_mode" = os-check ]; then
  /usr/bin/printf 'Host OS verified: ubuntu 24.04\n'
  exit 0
fi
case "$(/usr/bin/uname -m)" in
  x86_64|aarch64) ;;
  *) /usr/bin/printf 'ERROR: supported architectures are amd64 and arm64\n' >&2; exit 1 ;;
esac

/usr/bin/apt-get update
/usr/bin/apt-get install --yes --no-install-recommends \
  ansible-core ca-certificates python3 python3-cryptography

/usr/bin/env \
  ANSIBLE_CONFIG="$vivo_edge_ansible_config" \
  ANSIBLE_NOCOLOR=1 \
  /usr/bin/ansible-playbook \
  --inventory localhost, \
  --connection local \
  "$vivo_edge_local_playbook"

/usr/local/bin/vivolution-edge-join enroll
