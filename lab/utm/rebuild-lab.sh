#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_DIR="$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)"
GENERATED_DIR="$SCRIPT_DIR/generated"
UTMCTL="/Applications/UTM.app/Contents/MacOS/utmctl"
EXPECTED_UTM_VERSION="4.7.5"
EXPECTED_UTM_BUILD="118"
WORKING_VM_NAME="vivo-cp1-lab"
WORKING_VM_ID="81C7DE36-9421-4E1C-AC4E-48336131D1EC"
REBUILD_VM_NAME="vivo-cp1-lab-rebuild"
REBUILD_MARKER="vivolution-cp1-disposable-rebuild-v1"
UTM_DOCUMENTS_DIR="$HOME/Library/Containers/com.utmapp.UTM/Data/Documents"
UEFI_VARS_TEMPLATE="/Applications/UTM.app/Contents/Resources/qemu/edk2-arm-vars.fd"
EXPECTED_UEFI_VARS_SHA256="7b0a7f26192011e6e98c770694269b40f8b70620ca58fc4973a232fb223600d5"
REBUILD_STATE="$GENERATED_DIR/rebuild-vm-id"
REBUILD_KNOWN_HOSTS="$GENERATED_DIR/known_hosts-rebuild"
REBUILD_KNOWN_HOSTS_OPTION="UserKnownHostsFile=\"$REBUILD_KNOWN_HOSTS\""
SSH_KEY="${VIVO_LAB_SSH_KEY:-$HOME/.ssh/vivo_cp1_lab_ed25519}"
ISO_PATH="${1:-$HOME/Downloads/debian-13.6.0-arm64-netinst.iso}"
EXPECTED_ISO_SHA512="43eef37fe589c8995f713c2d731604494f4353dfcc9c6f7dc4abdedab1e8f313a68bd1eb1ae299f4fb8995cbc1306c7348dc20d3dbd95ad1b613131611506bb8"
SSH_HOST_PORT=2223
PORTAL_HOST_PORT=8081
REBUILD_MAC="B6:D3:46:43:95:AD"
INSTALL_TIMEOUT_SECONDS="${VIVO_LAB_INSTALL_TIMEOUT_SECONDS:-7200}"
BOOT_TIMEOUT_SECONDS="${VIVO_LAB_BOOT_TIMEOUT_SECONDS:-600}"
SSH_KEYSCAN_PENALTY_DRAIN_SECONDS=20

usage() {
    printf '%s\n' \
        'Usage: lab/utm/rebuild-lab.sh [verified-debian-arm64-netinst.iso]' \
        '' \
        'Creates or safely replaces only the managed vivo-cp1-lab-rebuild VM.' \
        'The protected vivo-cp1-lab VM must already be stopped and is never stopped,' \
        'reconfigured, started, or deleted by this workflow.'
}

uuid_is_valid() {
    case "$1" in
        ????????-????-????-????-????????????)
            case "$1" in
                *[!0-9A-Fa-f-]*) return 1 ;;
                *) return 0 ;;
            esac
            ;;
        *) return 1 ;;
    esac
}

if [ "$#" -eq 1 ] && { [ "$1" = -h ] || [ "$1" = --help ]; }; then
    usage
    exit 0
fi
if [ "$#" -gt 1 ]; then
    usage >&2
    exit 2
fi

for command_name in awk chmod cmp codesign date grep install lsof mktemp mv osascript rm shasum sleep ssh ssh-keygen ssh-keyscan stat xxd; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf 'Missing required command: %s\n' "$command_name" >&2
        exit 1
    }
done
[ -x "$UTMCTL" ] || {
    printf 'UTM control tool not found: %s\n' "$UTMCTL" >&2
    exit 1
}
[ -f "$ISO_PATH" ] || {
    printf 'Debian ISO not found: %s\n' "$ISO_PATH" >&2
    exit 1
}
if [ ! -f "$SSH_KEY" ] || [ -L "$SSH_KEY" ]; then
    printf 'SSH private key is missing, not regular, or symlinked: %s\n' "$SSH_KEY" >&2
    exit 1
fi
actual_iso_sha512="$(shasum -a 512 "$ISO_PATH" | awk '{print $1}')"
if [ "$actual_iso_sha512" != "$EXPECTED_ISO_SHA512" ]; then
    printf 'Debian ISO SHA-512 verification failed before cloning.\n' >&2
    exit 1
fi

case "$INSTALL_TIMEOUT_SECONDS" in
    ''|*[!0-9]*)
        printf 'Install and boot timeouts must be positive integer seconds.\n' >&2
        exit 1
        ;;
esac
case "$BOOT_TIMEOUT_SECONDS" in
    ''|*[!0-9]*)
        printf 'Install and boot timeouts must be positive integer seconds.\n' >&2
        exit 1
        ;;
esac
if [ "$INSTALL_TIMEOUT_SECONDS" -lt 1 ] || \
   [ "$BOOT_TIMEOUT_SECONDS" -le "$SSH_KEYSCAN_PENALTY_DRAIN_SECONDS" ]; then
    printf 'Install timeout must be positive and boot timeout must exceed %s seconds.\n' \
        "$SSH_KEYSCAN_PENALTY_DRAIN_SECONDS" >&2
    exit 1
fi

if [ "$REBUILD_VM_NAME" = "$WORKING_VM_NAME" ]; then
    printf 'Internal safety error: rebuild and working VM names collide.\n' >&2
    exit 1
fi
if [ "$SSH_HOST_PORT" -eq 2222 ] || [ "$PORTAL_HOST_PORT" -eq 8080 ]; then
    printf 'Internal safety error: rebuild ports collide with working-lab forwards.\n' >&2
    exit 1
fi
if lsof -nP -iTCP:"$SSH_HOST_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    printf 'Host TCP port %s is already in use; refusing to start a rebuild.\n' "$SSH_HOST_PORT" >&2
    exit 1
fi
if lsof -nP -iTCP:"$PORTAL_HOST_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    printf 'Host TCP port %s is already in use; refusing to start a rebuild.\n' "$PORTAL_HOST_PORT" >&2
    exit 1
fi

if [ -L "$GENERATED_DIR" ]; then
    printf 'Refusing a symlinked generated directory: %s\n' "$GENERATED_DIR" >&2
    exit 1
fi
install -d -m 0700 "$GENERATED_DIR"
if [ -L "$REBUILD_STATE" ]; then
    printf 'Refusing a symlinked rebuild state file: %s\n' "$REBUILD_STATE" >&2
    exit 1
fi
previous_rebuild_id=""
if [ -e "$REBUILD_STATE" ]; then
    if [ ! -f "$REBUILD_STATE" ]; then
        printf 'Rebuild state path is not a regular file: %s\n' "$REBUILD_STATE" >&2
        exit 1
    fi
    IFS= read -r previous_rebuild_id < "$REBUILD_STATE"
    if ! uuid_is_valid "$previous_rebuild_id"; then
        printf 'Recorded rebuild UUID is invalid; refusing automatic replacement.\n' >&2
        exit 1
    fi
    if [ "$previous_rebuild_id" = "$WORKING_VM_ID" ]; then
        printf 'Recorded rebuild UUID equals the protected working VM UUID; refusing.\n' >&2
        exit 1
    fi
fi

printf 'Preparing exact disposable clone %s from stopped source %s.\n' "$REBUILD_VM_NAME" "$WORKING_VM_NAME"
if [ -n "$previous_rebuild_id" ]; then
    rebuild_vm_id="$(osascript "$SCRIPT_DIR/prepare-rebuild-clone.applescript" "$previous_rebuild_id")"
else
    rebuild_vm_id="$(osascript "$SCRIPT_DIR/prepare-rebuild-clone.applescript")"
fi
if ! uuid_is_valid "$rebuild_vm_id"; then
    printf 'UTM returned an invalid rebuild UUID: %s\n' "$rebuild_vm_id" >&2
    exit 1
fi
if [ "$rebuild_vm_id" = "$WORKING_VM_ID" ]; then
    printf 'UTM returned the protected working VM UUID; refusing.\n' >&2
    exit 1
fi

# Persist the clone identity before any later staging/configuration check can
# fail, so a partial run remains safely recognizable on the next invocation.
state_temp="$(mktemp "$GENERATED_DIR/.rebuild-vm-id.XXXXXX")"
trap 'rm -f -- "$state_temp"' EXIT HUP INT TERM
chmod 0600 "$state_temp"
printf '%s\n' "$rebuild_vm_id" > "$state_temp"
mv -f -- "$state_temp" "$REBUILD_STATE"
trap - EXIT HUP INT TERM

rebuild_bundle_matches=0
working_bundle_matches=0
REBUILD_VM_BUNDLE=""
WORKING_VM_BUNDLE=""
for bundle_candidate in "$UTM_DOCUMENTS_DIR"/*.utm; do
    [ -d "$bundle_candidate" ] || continue
    [ ! -L "$bundle_candidate" ] || continue
    candidate_config="$bundle_candidate/config.plist"
    [ -f "$candidate_config" ] || continue
    [ ! -L "$candidate_config" ] || continue
    candidate_id="$(/usr/libexec/PlistBuddy -c 'Print :Information:UUID' "$candidate_config" 2>/dev/null || true)"
    if [ "$candidate_id" = "$WORKING_VM_ID" ]; then
        candidate_name="$(/usr/libexec/PlistBuddy -c 'Print :Information:Name' "$candidate_config" 2>/dev/null || true)"
        if [ "$candidate_name" != "$WORKING_VM_NAME" ]; then
            printf 'Protected UUID resolved to the wrong VM name: %s\n' "$candidate_name" >&2
            exit 1
        fi
        working_bundle_matches=$((working_bundle_matches + 1))
        WORKING_VM_BUNDLE="$bundle_candidate"
    fi
    if [ "$candidate_id" = "$rebuild_vm_id" ]; then
        candidate_name="$(/usr/libexec/PlistBuddy -c 'Print :Information:Name' "$candidate_config" 2>/dev/null || true)"
        if [ "$candidate_name" != "$REBUILD_VM_NAME" ]; then
            printf 'Disposable UUID resolved to the wrong VM name: %s\n' "$candidate_name" >&2
            exit 1
        fi
        rebuild_bundle_matches=$((rebuild_bundle_matches + 1))
        REBUILD_VM_BUNDLE="$bundle_candidate"
    fi
done
if [ "$rebuild_bundle_matches" -ne 1 ]; then
    printf 'Expected exactly one local UTM bundle for disposable UUID %s; found %s.\n' \
        "$rebuild_vm_id" "$rebuild_bundle_matches" >&2
    exit 1
fi
if [ "$working_bundle_matches" -ne 1 ]; then
    printf 'Expected exactly one local UTM bundle for protected UUID %s; found %s.\n' \
        "$WORKING_VM_ID" "$working_bundle_matches" >&2
    exit 1
fi
if [ "$REBUILD_VM_BUNDLE" = "$WORKING_VM_BUNDLE" ]; then
    printf 'Disposable and protected UUIDs resolved to the same UTM bundle; refusing.\n' >&2
    exit 1
fi
if [ "$("$UTMCTL" status "$rebuild_vm_id")" != stopped ]; then
    printf 'Disposable rebuild VM is no longer stopped; refusing firmware reset.\n' >&2
    exit 1
fi
if [ "$("$UTMCTL" status "$WORKING_VM_ID")" != stopped ]; then
    printf 'Protected working VM is no longer stopped; refusing firmware reset.\n' >&2
    exit 1
fi

reset_disposable_uefi_vars() {
    # UTM clones the source VM's per-VM UEFI variable store along with its
    # disk. Reset it only after the fresh disk and ISO are configured, so no
    # inherited BootOrder can bypass the installer on the first boot.
    rebuild_config="$REBUILD_VM_BUNDLE/config.plist"
    if [ ! -f "$rebuild_config" ] || [ -L "$rebuild_config" ]; then
        printf 'Disposable rebuild configuration is missing or symlinked.\n' >&2
        exit 1
    fi
    current_rebuild_id="$(/usr/libexec/PlistBuddy -c 'Print :Information:UUID' "$rebuild_config" 2>/dev/null || true)"
    current_rebuild_name="$(/usr/libexec/PlistBuddy -c 'Print :Information:Name' "$rebuild_config" 2>/dev/null || true)"
    current_rebuild_notes="$(/usr/libexec/PlistBuddy -c 'Print :Information:Notes' "$rebuild_config" 2>/dev/null || true)"
    current_rebuild_backend="$(/usr/libexec/PlistBuddy -c 'Print :Backend' "$rebuild_config" 2>/dev/null || true)"
    current_rebuild_arch="$(/usr/libexec/PlistBuddy -c 'Print :System:Architecture' "$rebuild_config" 2>/dev/null || true)"
    current_rebuild_uefi="$(/usr/libexec/PlistBuddy -c 'Print :QEMU:UEFIBoot' "$rebuild_config" 2>/dev/null || true)"
    if [ "$current_rebuild_id" != "$rebuild_vm_id" ] || \
       [ "$current_rebuild_name" != "$REBUILD_VM_NAME" ] || \
       [ "$current_rebuild_notes" != "$REBUILD_MARKER" ] || \
       [ "$current_rebuild_backend" != QEMU ] || \
       [ "$current_rebuild_arch" != aarch64 ] || \
       [ "$current_rebuild_uefi" != true ]; then
        printf 'Disposable rebuild identity, marker, backend, architecture or UEFI mode changed; refusing firmware reset.\n' >&2
        exit 1
    fi
    if [ "$("$UTMCTL" status "$rebuild_vm_id")" != stopped ]; then
        printf 'Disposable rebuild VM is not stopped; refusing firmware reset.\n' >&2
        exit 1
    fi
    if [ "$("$UTMCTL" status "$WORKING_VM_ID")" != stopped ]; then
        printf 'Protected working VM is not stopped; refusing firmware reset.\n' >&2
        exit 1
    fi
    if [ ! -d "$REBUILD_VM_BUNDLE/Data" ] || [ -L "$REBUILD_VM_BUNDLE/Data" ]; then
        printf 'Disposable rebuild Data path is missing or symlinked.\n' >&2
        exit 1
    fi
    if [ ! -f "$UEFI_VARS_TEMPLATE" ] || [ -L "$UEFI_VARS_TEMPLATE" ]; then
        printf 'UTM ARM64 UEFI variable template is missing or symlinked: %s\n' "$UEFI_VARS_TEMPLATE" >&2
        exit 1
    fi
    actual_utm_version="$(/usr/bin/defaults read /Applications/UTM.app/Contents/Info CFBundleShortVersionString 2>/dev/null || true)"
    actual_utm_build="$(/usr/bin/defaults read /Applications/UTM.app/Contents/Info CFBundleVersion 2>/dev/null || true)"
    if [ "$actual_utm_version" != "$EXPECTED_UTM_VERSION" ] || [ "$actual_utm_build" != "$EXPECTED_UTM_BUILD" ]; then
        printf 'UTM version changed; requalify its firmware template before rebuilding.\n' >&2
        exit 1
    fi
    if ! codesign --verify --deep --strict /Applications/UTM.app >/dev/null 2>&1; then
        printf 'UTM code-signature verification failed; refusing firmware reset.\n' >&2
        exit 1
    fi
    actual_uefi_sha256="$(shasum -a 256 "$UEFI_VARS_TEMPLATE" | awk '{print $1}')"
    if [ "$actual_uefi_sha256" != "$EXPECTED_UEFI_VARS_SHA256" ]; then
        printf 'UTM ARM64 UEFI template digest changed; requalify it before rebuilding.\n' >&2
        exit 1
    fi

    rebuild_efi_vars="$REBUILD_VM_BUNDLE/Data/efi_vars.fd"
    working_efi_vars="$WORKING_VM_BUNDLE/Data/efi_vars.fd"
    if [ ! -f "$rebuild_efi_vars" ] || [ -L "$rebuild_efi_vars" ]; then
        printf 'Disposable UEFI variable store is missing or symlinked.\n' >&2
        exit 1
    fi
    if [ ! -f "$working_efi_vars" ] || [ -L "$working_efi_vars" ]; then
        printf 'Protected UEFI variable store is missing or symlinked.\n' >&2
        exit 1
    fi
    if [ "$(stat -f '%d:%i' "$rebuild_efi_vars")" = "$(stat -f '%d:%i' "$working_efi_vars")" ]; then
        printf 'Disposable and protected UEFI stores are the same filesystem object; refusing.\n' >&2
        exit 1
    fi
    if lsof "$rebuild_efi_vars" >/dev/null 2>&1; then
        printf 'Disposable UEFI variable store is open by a process; refusing reset.\n' >&2
        exit 1
    fi
    working_efi_identity="$(stat -f '%d:%i:%l' "$working_efi_vars")"
    working_efi_sha256="$(shasum -a 256 "$working_efi_vars" | awk '{print $1}')"
    for efi_image in "$UEFI_VARS_TEMPLATE" "$rebuild_efi_vars" "$working_efi_vars"; do
        if [ "$(xxd -p -l 4 "$efi_image")" != 514649fb ]; then
            printf 'UEFI variable image is not qcow2: %s\n' "$efi_image" >&2
            exit 1
        fi
        if [ "$(xxd -p -s 24 -l 8 "$efi_image")" != 0000000004000000 ]; then
            printf 'UEFI variable image virtual size is not 64 MiB: %s\n' "$efi_image" >&2
            exit 1
        fi
    done

    efi_temp="$(mktemp "$REBUILD_VM_BUNDLE/Data/.efi-vars.XXXXXX")"
    trap 'rm -f -- "$efi_temp"' EXIT HUP INT TERM
    install -m 0644 "$UEFI_VARS_TEMPLATE" "$efi_temp"
    if ! cmp -s "$UEFI_VARS_TEMPLATE" "$efi_temp"; then
        printf 'Staged UEFI variable template failed byte comparison.\n' >&2
        exit 1
    fi

    # Re-check the mutable target immediately before the same-directory atomic
    # replacement. The protected UEFI store is read for validation only.
    if [ "$("$UTMCTL" status "$rebuild_vm_id")" != stopped ] || \
       [ ! -f "$rebuild_efi_vars" ] || [ -L "$rebuild_efi_vars" ]; then
        printf 'Disposable VM or UEFI target changed before atomic reset; refusing.\n' >&2
        exit 1
    fi
    mv -f -- "$efi_temp" "$rebuild_efi_vars"
    trap - EXIT HUP INT TERM
    if ! cmp -s "$UEFI_VARS_TEMPLATE" "$rebuild_efi_vars"; then
        printf 'Disposable UEFI variable reset failed byte comparison.\n' >&2
        exit 1
    fi
    if [ "$(stat -f '%d:%i:%l' "$working_efi_vars")" != "$working_efi_identity" ] || \
       [ "$(shasum -a 256 "$working_efi_vars" | awk '{print $1}')" != "$working_efi_sha256" ]; then
        printf 'Protected UEFI variable store changed during disposable reset; aborting.\n' >&2
        exit 1
    fi
    printf 'Reset pinned stock UEFI variables only for disposable UUID %s.\n' "$rebuild_vm_id"
}

VIVO_LAB_VM_NAME="$REBUILD_VM_NAME" \
VIVO_LAB_EXPECTED_VM_ID="$rebuild_vm_id" \
VIVO_LAB_VM_BUNDLE="$REBUILD_VM_BUNDLE" \
    "$SCRIPT_DIR/build-installer.sh" "$ISO_PATH"

unattended_iso="$SCRIPT_DIR/generated/debian-13.6.0-arm64-vivo-preseed.iso"
[ -f "$unattended_iso" ] || {
    printf 'Checksum-derived unattended ISO was not created.\n' >&2
    exit 1
}
osascript "$SCRIPT_DIR/configure-install.applescript" \
    "$REBUILD_VM_NAME" \
    "$rebuild_vm_id" \
    "$unattended_iso" \
    "$SSH_HOST_PORT" \
    "$PORTAL_HOST_PORT" \
    "$REBUILD_MAC" \
    fresh-64g

# UTM saves the configuration atomically while stopped. Prove that the clone
# now has one fresh qcow2 at the requested virtual size.
set -- "$REBUILD_VM_BUNDLE"/Data/*.qcow2
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    printf 'Expected exactly one qcow2 system disk in the disposable VM bundle.\n' >&2
    exit 1
fi
system_disk="$1"
disk_magic="$(xxd -p -l 4 "$system_disk")"
if [ "$disk_magic" != 514649fb ]; then
    printf 'Disposable system disk is not qcow2.\n' >&2
    exit 1
fi
disk_virtual_size_hex="$(xxd -p -s 24 -l 8 "$system_disk")"
if [ "$disk_virtual_size_hex" != 0000001000000000 ]; then
    printf 'Disposable system disk virtual size is not 64 GiB.\n' >&2
    exit 1
fi

# Reset the clone firmware only after UTM has committed the fresh disk and ISO,
# then start immediately through the UUID-guarded helper.
reset_disposable_uefi_vars

printf 'Starting unattended UEFI ISO installation on disposable UUID %s.\n' "$rebuild_vm_id"
osascript "$SCRIPT_DIR/start-unattended-install.applescript" "$REBUILD_VM_NAME" "$rebuild_vm_id"

install_deadline="$(($(date +%s) + INSTALL_TIMEOUT_SECONDS))"
saw_installer_running=false
while :; do
    rebuild_status="$("$UTMCTL" status "$rebuild_vm_id")"
    case "$rebuild_status" in
        starting|started|pausing|paused|resuming|stopping)
            saw_installer_running=true
            ;;
        stopped)
            if [ "$saw_installer_running" = true ]; then
                break
            fi
            ;;
        *)
            printf 'Unexpected UTM status for %s: %s\n' "$REBUILD_VM_NAME" "$rebuild_status" >&2
            exit 1
            ;;
    esac
    if [ "$(date +%s)" -ge "$install_deadline" ]; then
        printf 'Timed out waiting for the disposable installer to power off.\n' >&2
        exit 1
    fi
    sleep 5
done

printf 'Installer powered off; removing only unattended installer media.\n'
osascript "$SCRIPT_DIR/finalize-install.applescript" \
    "$REBUILD_VM_NAME" \
    "$rebuild_vm_id" \
    "$SSH_HOST_PORT" \
    "$PORTAL_HOST_PORT" \
    "$REBUILD_MAC"

if [ -L "$REBUILD_KNOWN_HOSTS" ]; then
    printf 'Refusing a symlinked rebuild known-hosts file: %s\n' "$REBUILD_KNOWN_HOSTS" >&2
    exit 1
fi
if [ -e "$REBUILD_KNOWN_HOSTS" ] && [ ! -f "$REBUILD_KNOWN_HOSTS" ]; then
    printf 'Rebuild known-hosts path is not a regular file: %s\n' "$REBUILD_KNOWN_HOSTS" >&2
    exit 1
fi
umask 077
known_hosts_temp="$(mktemp "$GENERATED_DIR/.known-hosts-rebuild.XXXXXX")"
trap 'rm -f -- "$known_hosts_temp"' EXIT HUP INT TERM
chmod 0600 "$known_hosts_temp"
mv -f -- "$known_hosts_temp" "$REBUILD_KNOWN_HOSTS"
trap - EXIT HUP INT TERM

osascript "$SCRIPT_DIR/start-unattended-install.applescript" "$REBUILD_VM_NAME" "$rebuild_vm_id"

boot_deadline="$(($(date +%s) + BOOT_TIMEOUT_SECONDS))"
scan_temp="$(mktemp "$GENERATED_DIR/.known-hosts-rebuild-scan.XXXXXX")"
trap 'rm -f -- "$scan_temp"' EXIT HUP INT TERM
chmod 0600 "$scan_temp"
while :; do
    if [ "$(date +%s)" -ge "$boot_deadline" ]; then
        printf 'Timed out waiting for an SSH host key on 127.0.0.1:%s.\n' "$SSH_HOST_PORT" >&2
        exit 1
    fi
    if ssh-keyscan -T 5 -p "$SSH_HOST_PORT" -t ed25519 127.0.0.1 2>/dev/null \
        | awk -v expected="[127.0.0.1]:$SSH_HOST_PORT" \
            '$1 == expected && $2 == "ssh-ed25519" && NF == 3 { print; matches++ }
             END { if (matches != 1) exit 1 }' \
        > "$scan_temp" && \
       ssh-keygen -lf "$scan_temp" >/dev/null 2>&1; then
        chmod 0600 "$scan_temp"
        mv -f -- "$scan_temp" "$REBUILD_KNOWN_HOSTS"
        break
    fi
    rebuild_status="$("$UTMCTL" status "$rebuild_vm_id")"
    if [ "$rebuild_status" = stopped ]; then
        printf 'Disposable rebuild VM stopped before SSH became ready.\n' >&2
        exit 1
    fi
    if [ "$(date +%s)" -ge "$boot_deadline" ]; then
        printf 'Timed out waiting for an SSH host key on 127.0.0.1:%s.\n' "$SSH_HOST_PORT" >&2
        exit 1
    fi
    sleep 5
done
trap - EXIT HUP INT TERM

# Debian 13 OpenSSH enables PerSourcePenalties. ssh-keyscan intentionally
# disconnects before authentication and can accumulate the default noauth
# penalty while the new guest is still booting. Stop scanning once the host
# key is pinned and let that penalty window drain before the real login.
remaining_boot_seconds="$((boot_deadline - $(date +%s)))"
if [ "$remaining_boot_seconds" -le "$SSH_KEYSCAN_PENALTY_DRAIN_SECONDS" ]; then
    printf 'Insufficient boot deadline remains to drain the SSH noauth penalty.\n' >&2
    exit 1
fi
sleep "$SSH_KEYSCAN_PENALTY_DRAIN_SECONDS"
while :; do
    if [ "$(date +%s)" -ge "$boot_deadline" ]; then
        printf 'Timed out waiting for authenticated SSH on 127.0.0.1:%s.\n' "$SSH_HOST_PORT" >&2
        exit 1
    fi
    if ssh \
        -F /dev/null \
        -i "$SSH_KEY" \
        -p "$SSH_HOST_PORT" \
        -o BatchMode=yes \
        -o ConnectTimeout=5 \
        -o ConnectionAttempts=1 \
        -o ControlMaster=no \
        -o ControlPath=none \
        -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=yes \
        -o "$REBUILD_KNOWN_HOSTS_OPTION" \
        cpadmin@127.0.0.1 true >/dev/null 2>&1; then
        if [ "$(date +%s)" -lt "$boot_deadline" ]; then
            break
        fi
        printf 'Authenticated SSH completed after the boot deadline.\n' >&2
        exit 1
    fi
    rebuild_status="$("$UTMCTL" status "$rebuild_vm_id")"
    if [ "$rebuild_status" = stopped ]; then
        printf 'Disposable rebuild VM stopped before authenticated SSH became ready.\n' >&2
        exit 1
    fi
    if [ "$(date +%s)" -ge "$boot_deadline" ]; then
        printf 'Timed out waiting for authenticated SSH on 127.0.0.1:%s.\n' "$SSH_HOST_PORT" >&2
        exit 1
    fi
    sleep 5
done

VIVO_LAB_SSH_PORT="$SSH_HOST_PORT" \
VIVO_LAB_KNOWN_HOSTS="$REBUILD_KNOWN_HOSTS" \
VIVO_LAB_EXPECTED_HOSTNAME="vivo-cp1-lab" \
VIVO_LAB_EXPECTED_DISK_BYTES="68719476736" \
    "$SCRIPT_DIR/verify-base.sh"

if [ "$("$UTMCTL" status "$WORKING_VM_NAME")" != stopped ]; then
    printf 'Warning: the protected working VM is no longer stopped; this workflow did not start it.\n' >&2
fi

printf 'Clean rebuild base qualification passed for %s (%s).\n' "$REBUILD_VM_NAME" "$rebuild_vm_id"
printf 'Rebuild-only Ansible inventory: %s\n' "$PROJECT_DIR/deploy/inventories/rebuild/hosts.yml"
