#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SSH_KEY="${VIVO_LAB_SSH_KEY:-$HOME/.ssh/vivo_cp1_lab_ed25519}"
SSH_PORT="${VIVO_LAB_SSH_PORT:-2222}"
KNOWN_HOSTS="${VIVO_LAB_KNOWN_HOSTS:-$SCRIPT_DIR/generated/known_hosts}"
KNOWN_HOSTS_OPTION="UserKnownHostsFile=\"$KNOWN_HOSTS\""
EXPECTED_HOSTNAME="${VIVO_LAB_EXPECTED_HOSTNAME:-vivo-cp1-lab}"
EXPECTED_DISK_BYTES="${VIVO_LAB_EXPECTED_DISK_BYTES:-68719476736}"

case "$SSH_PORT" in
    ''|*[!0-9]*)
        printf 'Invalid VIVO_LAB_SSH_PORT: %s\n' "$SSH_PORT" >&2
        exit 1
        ;;
esac
if [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
    printf 'VIVO_LAB_SSH_PORT is outside 1..65535: %s\n' "$SSH_PORT" >&2
    exit 1
fi
case "$EXPECTED_HOSTNAME" in
    ''|*[!A-Za-z0-9.-]*)
        printf 'Invalid expected hostname: %s\n' "$EXPECTED_HOSTNAME" >&2
        exit 1
        ;;
esac
case "$EXPECTED_DISK_BYTES" in
    ''|*[!0-9]*)
        printf 'Invalid expected disk byte count: %s\n' "$EXPECTED_DISK_BYTES" >&2
        exit 1
        ;;
esac

[ -f "$SSH_KEY" ] || {
    printf 'SSH key not found: %s\n' "$SSH_KEY" >&2
    exit 1
}
if [ -L "$KNOWN_HOSTS" ]; then
    printf 'Refusing a symlinked known-hosts file: %s\n' "$KNOWN_HOSTS" >&2
    exit 1
fi
if [ -e "$KNOWN_HOSTS" ] && [ ! -f "$KNOWN_HOSTS" ]; then
    printf 'Known-hosts path is not a regular file: %s\n' "$KNOWN_HOSTS" >&2
    exit 1
fi
KNOWN_HOSTS_DIR="$(dirname -- "$KNOWN_HOSTS")"
if [ -L "$KNOWN_HOSTS_DIR" ]; then
    printf 'Refusing a symlinked known-hosts directory: %s\n' "$KNOWN_HOSTS_DIR" >&2
    exit 1
fi
install -d -m 0700 "$KNOWN_HOSTS_DIR"

# Break any stale hardlink before using the rebuild driver's pinned host key.
known_hosts_temp="$(mktemp "$KNOWN_HOSTS_DIR/.known-hosts.XXXXXX")"
trap 'rm -f -- "$known_hosts_temp"' EXIT HUP INT TERM
if [ -f "$KNOWN_HOSTS" ]; then
    cp -- "$KNOWN_HOSTS" "$known_hosts_temp"
fi
chmod 0600 "$known_hosts_temp"
mv -f -- "$known_hosts_temp" "$KNOWN_HOSTS"
trap - EXIT HUP INT TERM

ssh \
    -i "$SSH_KEY" \
    -p "$SSH_PORT" \
    -o BatchMode=yes \
    -o ConnectTimeout=10 \
    -o ConnectionAttempts=1 \
    -o ControlMaster=no \
    -o ControlPath=none \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=yes \
    -o "$KNOWN_HOSTS_OPTION" \
    cpadmin@127.0.0.1 \
    sh -s -- "$EXPECTED_HOSTNAME" "$EXPECTED_DISK_BYTES" <<'REMOTE_VERIFY'
set -eu

expected_hostname="$1"
expected_disk_bytes="$2"

printf '## identity\n'
id

printf '## os\n'
cat /etc/os-release
uname -a
[ "$(dpkg --print-architecture)" = arm64 ]

printf '## hostname\n'
actual_hostname="$(hostname)"
printf '%s\n' "$actual_hostname"
[ "$actual_hostname" = "$expected_hostname" ]

printf '## marker\n'
cat /etc/vivolution-lab-image
grep -Fx 'profile=local-lab' /etc/vivolution-lab-image >/dev/null
grep -Fx 'created_by=vivolution-sbc-lab-installer' /etc/vivolution-lab-image >/dev/null

printf '## sudo\n'
sudo -n true
printf 'ok\n'

printf '## services\n'
systemctl is-active ssh qemu-guest-agent

printf '## resources\n'
nproc
[ "$(nproc)" -ge 2 ]
free -h
findmnt /
df -hT /
actual_disk_bytes="$(sudo blockdev --getsize64 /dev/vda)"
printf 'system_disk_bytes=%s\n' "$actual_disk_bytes"
[ "$actual_disk_bytes" = "$expected_disk_bytes" ]

printf '## ssh policy\n'
sshd_policy="$(sudo sshd -T)"
printf '%s\n' "$sshd_policy" | awk '$1 ~ /^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|x11forwarding|allowagentforwarding|allowtcpforwarding|maxauthtries)$/ {print}'
printf '%s\n' "$sshd_policy" | grep -Fx 'permitrootlogin no' >/dev/null
printf '%s\n' "$sshd_policy" | grep -Fx 'passwordauthentication no' >/dev/null
printf '%s\n' "$sshd_policy" | grep -Fx 'kbdinteractiveauthentication no' >/dev/null
printf '%s\n' "$sshd_policy" | grep -Fx 'pubkeyauthentication yes' >/dev/null
printf '%s\n' "$sshd_policy" | grep -Fx 'x11forwarding no' >/dev/null
printf '%s\n' "$sshd_policy" | grep -Fx 'allowagentforwarding no' >/dev/null
printf '%s\n' "$sshd_policy" | grep -Fx 'allowtcpforwarding no' >/dev/null
printf '%s\n' "$sshd_policy" | grep -Fx 'maxauthtries 3' >/dev/null

printf '## failures\n'
failed_units="$(systemctl --failed --no-legend --plain)"
printf '%s\n' "$failed_units"
[ -z "$failed_units" ]
REMOTE_VERIFY
