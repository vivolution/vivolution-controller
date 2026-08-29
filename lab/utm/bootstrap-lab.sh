#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
GENERATED_DIR="$SCRIPT_DIR/generated"
UTMCTL="/Applications/UTM.app/Contents/MacOS/utmctl"
EXPECTED_UTM_VERSION="4.7.5"
EXPECTED_UTM_BUILD="118"
PRIMARY_VM_NAME="vivo-cp1-lab"
PRIMARY_MARKER="vivolution-cp1-primary-lab-v1"
UTM_DOCUMENTS_DIR="$HOME/Library/Containers/com.utmapp.UTM/Data/Documents"
UEFI_VARS_TEMPLATE="/Applications/UTM.app/Contents/Resources/qemu/edk2-arm-vars.fd"
EXPECTED_UEFI_VARS_SHA256="7b0a7f26192011e6e98c770694269b40f8b70620ca58fc4973a232fb223600d5"
PRIMARY_STATE="$GENERATED_DIR/primary-vm-id"
PRIMARY_KNOWN_HOSTS="$GENERATED_DIR/known_hosts"
PRIMARY_KNOWN_HOSTS_OPTION="UserKnownHostsFile=\"$PRIMARY_KNOWN_HOSTS\""
SSH_KEY="${VIVO_LAB_SSH_KEY:-$HOME/.ssh/vivo_cp1_lab_ed25519}"
ISO_PATH="${1:-$HOME/Downloads/debian-13.6.0-arm64-netinst.iso}"
EXPECTED_ISO_SHA512="43eef37fe589c8995f713c2d731604494f4353dfcc9c6f7dc4abdedab1e8f313a68bd1eb1ae299f4fb8995cbc1306c7348dc20d3dbd95ad1b613131611506bb8"
SSH_HOST_PORT=2222
PORTAL_HOST_PORT=8080
PRIMARY_MAC="B6:D3:46:43:95:AC"
INSTALL_TIMEOUT_SECONDS="${VIVO_LAB_INSTALL_TIMEOUT_SECONDS:-7200}"
BOOT_TIMEOUT_SECONDS="${VIVO_LAB_BOOT_TIMEOUT_SECONDS:-600}"
SSH_KEYSCAN_PENALTY_DRAIN_SECONDS=20

usage() {
    printf '%s\n' \
        'Usage: lab/utm/bootstrap-lab.sh [verified-debian-arm64-netinst.iso]' \
        '' \
        'Creates vivo-cp1-lab from zero only when the UTM registry and local' \
        'UTM Documents directory contain no virtual machines. Existing VMs are' \
        'never stopped, changed, or deleted by this workflow.'
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

verify_primary_serial() {
    serial_config="$PRIMARY_VM_BUNDLE/config.plist"
    [ -f "$serial_config" ] && [ ! -L "$serial_config" ] || {
        printf 'Primary VM configuration is missing or symlinked.\n' >&2
        return 1
    }
    serial_mode="$(/usr/libexec/PlistBuddy -c 'Print :Serial:0:Mode' \
        "$serial_config" 2>/dev/null || true)"
    serial_target="$(/usr/libexec/PlistBuddy -c 'Print :Serial:0:Target' \
        "$serial_config" 2>/dev/null || true)"
    if [ "$serial_mode" != Ptty ] || [ "$serial_target" != Auto ] || \
       /usr/libexec/PlistBuddy -c 'Print :Serial:1' "$serial_config" \
           >/dev/null 2>&1; then
        printf 'Primary VM must persist exactly one automatic PTTY serial device.\n' >&2
        return 1
    fi
}

if [ "$#" -eq 1 ] && { [ "$1" = -h ] || [ "$1" = --help ]; }; then
    usage
    exit 0
fi
if [ "$#" -gt 1 ]; then
    usage >&2
    exit 2
fi

for command_name in awk chmod cmp codesign date grep install lsof mktemp mv \
    osascript rm shasum sleep ssh ssh-keygen ssh-keyscan stat xxd; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf 'Missing required command: %s\n' "$command_name" >&2
        exit 1
    }
done
[ -x "$UTMCTL" ] || {
    printf 'UTM control tool not found: %s\n' "$UTMCTL" >&2
    exit 1
}
[ -f "$ISO_PATH" ] && [ ! -L "$ISO_PATH" ] || {
    printf 'Debian ISO is missing, not regular, or symlinked: %s\n' "$ISO_PATH" >&2
    exit 1
}
if [ ! -f "$SSH_KEY" ] || [ -L "$SSH_KEY" ]; then
    printf 'SSH private key is missing, not regular, or symlinked: %s\n' "$SSH_KEY" >&2
    exit 1
fi
actual_iso_sha512="$(shasum -a 512 "$ISO_PATH" | awk '{print $1}')"
if [ "$actual_iso_sha512" != "$EXPECTED_ISO_SHA512" ]; then
    printf 'Debian ISO SHA-512 verification failed before VM creation.\n' >&2
    exit 1
fi

case "$INSTALL_TIMEOUT_SECONDS" in
    ''|0|0*|??????*|*[!0-9]*)
        printf 'Install timeout must be a bounded positive decimal integer.\n' >&2
        exit 1
        ;;
esac
case "$BOOT_TIMEOUT_SECONDS" in
    ''|0|0*|?????*|*[!0-9]*)
        printf 'Boot timeout must be a bounded positive decimal integer.\n' >&2
        exit 1
        ;;
esac
if [ "$INSTALL_TIMEOUT_SECONDS" -lt 1 ] || \
   [ "$BOOT_TIMEOUT_SECONDS" -le "$SSH_KEYSCAN_PENALTY_DRAIN_SECONDS" ]; then
    printf 'Install timeout must be positive and boot timeout must exceed %s seconds.\n' \
        "$SSH_KEYSCAN_PENALTY_DRAIN_SECONDS" >&2
    exit 1
fi

actual_utm_version="$(/usr/bin/defaults read /Applications/UTM.app/Contents/Info CFBundleShortVersionString 2>/dev/null || true)"
actual_utm_build="$(/usr/bin/defaults read /Applications/UTM.app/Contents/Info CFBundleVersion 2>/dev/null || true)"
if [ "$actual_utm_version" != "$EXPECTED_UTM_VERSION" ] || \
   [ "$actual_utm_build" != "$EXPECTED_UTM_BUILD" ]; then
    printf 'UTM version changed; requalify the bootstrap before creating a VM.\n' >&2
    exit 1
fi
if ! codesign --verify --deep --strict /Applications/UTM.app >/dev/null 2>&1; then
    printf 'UTM code-signature verification failed; refusing VM creation.\n' >&2
    exit 1
fi
if [ ! -f "$UEFI_VARS_TEMPLATE" ] || [ -L "$UEFI_VARS_TEMPLATE" ]; then
    printf 'UTM ARM64 UEFI template is missing or symlinked: %s\n' \
        "$UEFI_VARS_TEMPLATE" >&2
    exit 1
fi
actual_uefi_sha256="$(shasum -a 256 "$UEFI_VARS_TEMPLATE" | awk '{print $1}')"
if [ "$actual_uefi_sha256" != "$EXPECTED_UEFI_VARS_SHA256" ]; then
    printf 'UTM ARM64 UEFI template digest changed; requalify it before creating a VM.\n' >&2
    exit 1
fi

if lsof -nP -iTCP:"$SSH_HOST_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    printf 'Host TCP port %s is already in use; refusing bootstrap.\n' \
        "$SSH_HOST_PORT" >&2
    exit 1
fi
if lsof -nP -iTCP:"$PORTAL_HOST_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    printf 'Host TCP port %s is already in use; refusing bootstrap.\n' \
        "$PORTAL_HOST_PORT" >&2
    exit 1
fi

if [ -L "$GENERATED_DIR" ]; then
    printf 'Refusing a symlinked generated directory: %s\n' "$GENERATED_DIR" >&2
    exit 1
fi
install -d -m 0700 "$GENERATED_DIR"
for state_path in "$PRIMARY_STATE" "$PRIMARY_KNOWN_HOSTS"; do
    if [ -L "$state_path" ] || { [ -e "$state_path" ] && [ ! -f "$state_path" ]; }; then
        printf 'Managed state path is symlinked or non-regular: %s\n' "$state_path" >&2
        exit 1
    fi
done

registered_vm_count="$("$UTMCTL" list | awk 'NR > 1 && NF { count++ } END { print count + 0 }')"
bundle_count=0
for bundle_candidate in "$UTM_DOCUMENTS_DIR"/*.utm; do
    [ -e "$bundle_candidate" ] || continue
    bundle_count=$((bundle_count + 1))
done

case "$registered_vm_count:$bundle_count" in
    0:0)
        printf 'Creating a fresh managed UTM VM from the pinned ARM64 profile.\n'
        primary_vm_id="$(osascript "$SCRIPT_DIR/create-primary.applescript")"
        ;;
    1:1)
        # Recover only the narrow interruption window after UTM created the
        # marked, stopped, pre-staging primary but before its UUID was saved.
        # Later partial states contain installer media or run and are refused.
        primary_vm_id=""
        recovery_bundle=""
        for bundle_candidate in "$UTM_DOCUMENTS_DIR"/*.utm; do
            [ -d "$bundle_candidate" ] && [ ! -L "$bundle_candidate" ] || continue
            recovery_config="$bundle_candidate/config.plist"
            [ -f "$recovery_config" ] && [ ! -L "$recovery_config" ] || continue
            recovery_name="$(/usr/libexec/PlistBuddy -c 'Print :Information:Name' \
                "$recovery_config" 2>/dev/null || true)"
            recovery_notes="$(/usr/libexec/PlistBuddy -c 'Print :Information:Notes' \
                "$recovery_config" 2>/dev/null || true)"
            recovery_id="$(/usr/libexec/PlistBuddy -c 'Print :Information:UUID' \
                "$recovery_config" 2>/dev/null || true)"
            if [ "$recovery_name" = "$PRIMARY_VM_NAME" ] && \
               [ "$recovery_notes" = "$PRIMARY_MARKER" ] && \
               uuid_is_valid "$recovery_id" && \
               [ "$("$UTMCTL" status "$recovery_id")" = stopped ]; then
                primary_vm_id="$recovery_id"
                recovery_bundle="$bundle_candidate"
            fi
        done
        [ -n "$primary_vm_id" ] || {
            printf 'The one existing UTM VM is not an exact stopped pre-staging primary; refusing recovery.\n' >&2
            exit 1
        }
        if [ -f "$PRIMARY_STATE" ]; then
            IFS= read -r recorded_primary_id < "$PRIMARY_STATE"
            if ! uuid_is_valid "$recorded_primary_id"; then
                printf 'Existing primary state is invalid; refusing recovery.\n' >&2
                exit 1
            fi
            if [ "$recorded_primary_id" = "$primary_vm_id" ]; then
                printf 'The existing primary is already recorded; seedless bootstrap will not reinstall it.\n' >&2
                exit 1
            fi
        fi
        set -- "$recovery_bundle"/Data/*.qcow2
        if [ "$#" -ne 1 ] || [ ! -f "$1" ] || [ -L "$1" ] || \
           [ "$(stat -f '%z' "$1")" -gt 1048576 ]; then
            printf 'Existing primary disk is not an untouched pre-staging qcow2; refusing recovery.\n' >&2
            exit 1
        fi
        printf 'Recovering exact pre-staging primary UUID %s.\n' "$primary_vm_id"
        ;;
    *)
        printf 'UTM is not empty or contains unregistered/ambiguous bundles; refusing seedless bootstrap.\n' >&2
        exit 1
        ;;
esac
if ! uuid_is_valid "$primary_vm_id"; then
    printf 'UTM returned or exposed an invalid primary UUID: %s\n' "$primary_vm_id" >&2
    exit 1
fi

# Record ownership immediately. A later failure leaves a precisely identified
# managed VM for inspection, but this workflow never deletes it automatically.
state_temp="$(mktemp "$GENERATED_DIR/.primary-vm-id.XXXXXX")"
trap 'rm -f -- "$state_temp"' EXIT HUP INT TERM
chmod 0600 "$state_temp"
printf '%s\n' "$primary_vm_id" > "$state_temp"
mv -f -- "$state_temp" "$PRIMARY_STATE"
trap - EXIT HUP INT TERM

primary_bundle_matches=0
PRIMARY_VM_BUNDLE=""
for bundle_candidate in "$UTM_DOCUMENTS_DIR"/*.utm; do
    [ -d "$bundle_candidate" ] || continue
    [ ! -L "$bundle_candidate" ] || continue
    candidate_config="$bundle_candidate/config.plist"
    [ -f "$candidate_config" ] && [ ! -L "$candidate_config" ] || continue
    candidate_id="$(/usr/libexec/PlistBuddy -c 'Print :Information:UUID' "$candidate_config" 2>/dev/null || true)"
    if [ "$candidate_id" = "$primary_vm_id" ]; then
        candidate_name="$(/usr/libexec/PlistBuddy -c 'Print :Information:Name' "$candidate_config" 2>/dev/null || true)"
        candidate_notes="$(/usr/libexec/PlistBuddy -c 'Print :Information:Notes' "$candidate_config" 2>/dev/null || true)"
        if [ "$candidate_name" != "$PRIMARY_VM_NAME" ] || \
           [ "$candidate_notes" != "$PRIMARY_MARKER" ]; then
            printf 'Primary UUID resolved to an unexpected name or marker.\n' >&2
            exit 1
        fi
        primary_bundle_matches=$((primary_bundle_matches + 1))
        PRIMARY_VM_BUNDLE="$bundle_candidate"
    fi
done
if [ "$primary_bundle_matches" -ne 1 ]; then
    printf 'Expected exactly one UTM bundle for primary UUID %s; found %s.\n' \
        "$primary_vm_id" "$primary_bundle_matches" >&2
    exit 1
fi
if [ "$("$UTMCTL" status "$primary_vm_id")" != stopped ]; then
    printf 'New primary VM is not stopped; refusing installer staging.\n' >&2
    exit 1
fi
osascript "$SCRIPT_DIR/verify-primary-created.applescript" "$primary_vm_id" \
    >/dev/null

VIVO_LAB_VM_NAME="$PRIMARY_VM_NAME" \
VIVO_LAB_EXPECTED_VM_ID="$primary_vm_id" \
VIVO_LAB_VM_BUNDLE="$PRIMARY_VM_BUNDLE" \
    "$SCRIPT_DIR/build-installer.sh" "$ISO_PATH"

unattended_iso="$GENERATED_DIR/debian-13.6.0-arm64-vivo-preseed.iso"
[ -f "$unattended_iso" ] && [ ! -L "$unattended_iso" ] || {
    printf 'Checksum-derived unattended ISO was not created safely.\n' >&2
    exit 1
}
osascript "$SCRIPT_DIR/configure-primary-install.applescript" \
    "$PRIMARY_VM_NAME" \
    "$primary_vm_id" \
    "$unattended_iso" \
    "$SSH_HOST_PORT" \
    "$PORTAL_HOST_PORT" \
    "$PRIMARY_MAC"
verify_primary_serial

set -- "$PRIMARY_VM_BUNDLE"/Data/*.qcow2
if [ "$#" -ne 1 ] || [ ! -f "$1" ] || [ -L "$1" ]; then
    printf 'Expected exactly one regular qcow2 system disk in the primary VM bundle.\n' >&2
    exit 1
fi
system_disk="$1"
if [ "$(xxd -p -l 4 "$system_disk")" != 514649fb ]; then
    printf 'Primary system disk is not qcow2.\n' >&2
    exit 1
fi
if [ "$(xxd -p -s 24 -l 8 "$system_disk")" != 0000001000000000 ]; then
    printf 'Primary system disk virtual size is not 64 GiB.\n' >&2
    exit 1
fi

primary_efi_vars="$PRIMARY_VM_BUNDLE/Data/efi_vars.fd"
if [ ! -f "$primary_efi_vars" ] || [ -L "$primary_efi_vars" ]; then
    printf 'Primary UEFI variable store is missing or symlinked.\n' >&2
    exit 1
fi
if lsof "$primary_efi_vars" >/dev/null 2>&1; then
    printf 'Primary UEFI variable store is open by a process; refusing reset.\n' >&2
    exit 1
fi
for efi_image in "$UEFI_VARS_TEMPLATE" "$primary_efi_vars"; do
    if [ "$(xxd -p -l 4 "$efi_image")" != 514649fb ] || \
       [ "$(xxd -p -s 24 -l 8 "$efi_image")" != 0000000004000000 ]; then
        printf 'UEFI image is not the expected 64 MiB qcow2: %s\n' "$efi_image" >&2
        exit 1
    fi
done
efi_temp="$(mktemp "$PRIMARY_VM_BUNDLE/Data/.efi-vars.XXXXXX")"
trap 'rm -f -- "$efi_temp"' EXIT HUP INT TERM
install -m 0644 "$UEFI_VARS_TEMPLATE" "$efi_temp"
cmp -s "$UEFI_VARS_TEMPLATE" "$efi_temp" || {
    printf 'Staged UEFI variable template failed byte comparison.\n' >&2
    exit 1
}
if [ "$("$UTMCTL" status "$primary_vm_id")" != stopped ] || \
   [ ! -f "$primary_efi_vars" ] || [ -L "$primary_efi_vars" ]; then
    printf 'Primary VM or UEFI target changed before atomic reset; refusing.\n' >&2
    exit 1
fi
mv -f -- "$efi_temp" "$primary_efi_vars"
trap - EXIT HUP INT TERM
cmp -s "$UEFI_VARS_TEMPLATE" "$primary_efi_vars" || {
    printf 'Primary UEFI variable reset failed byte comparison.\n' >&2
    exit 1
}

printf 'Starting unattended UEFI installation on primary UUID %s.\n' "$primary_vm_id"
osascript "$SCRIPT_DIR/start-primary.applescript" \
    "$PRIMARY_VM_NAME" "$primary_vm_id" installer
install_deadline="$(($(date +%s) + INSTALL_TIMEOUT_SECONDS))"
saw_installer_running=false
while :; do
    primary_status="$("$UTMCTL" status "$primary_vm_id")"
    case "$primary_status" in
        starting|started|pausing|paused|resuming|stopping)
            saw_installer_running=true
            ;;
        stopped)
            if [ "$saw_installer_running" = true ]; then
                break
            fi
            ;;
        *)
            printf 'Unexpected UTM status during install: %s\n' "$primary_status" >&2
            exit 1
            ;;
    esac
    if [ "$(date +%s)" -ge "$install_deadline" ]; then
        printf 'Timed out waiting for the primary installer to power off.\n' >&2
        exit 1
    fi
    sleep 5
done

printf 'Installer powered off; removing only the unattended installer media.\n'
osascript "$SCRIPT_DIR/finalize-primary-install.applescript" \
    "$PRIMARY_VM_NAME" \
    "$primary_vm_id" \
    "$SSH_HOST_PORT" \
    "$PORTAL_HOST_PORT" \
    "$PRIMARY_MAC"
verify_primary_serial

umask 077
known_hosts_temp="$(mktemp "$GENERATED_DIR/.known-hosts.XXXXXX")"
trap 'rm -f -- "$known_hosts_temp"' EXIT HUP INT TERM
chmod 0600 "$known_hosts_temp"
mv -f -- "$known_hosts_temp" "$PRIMARY_KNOWN_HOSTS"
trap - EXIT HUP INT TERM

osascript "$SCRIPT_DIR/start-primary.applescript" \
    "$PRIMARY_VM_NAME" "$primary_vm_id" installed
boot_deadline="$(($(date +%s) + BOOT_TIMEOUT_SECONDS))"
scan_temp="$(mktemp "$GENERATED_DIR/.known-hosts-scan.XXXXXX")"
trap 'rm -f -- "$scan_temp"' EXIT HUP INT TERM
chmod 0600 "$scan_temp"
while :; do
    if [ "$(date +%s)" -ge "$boot_deadline" ]; then
        printf 'Timed out waiting for an SSH host key on 127.0.0.1:%s.\n' \
            "$SSH_HOST_PORT" >&2
        exit 1
    fi
    if ssh-keyscan -T 5 -p "$SSH_HOST_PORT" -t ed25519 127.0.0.1 2>/dev/null \
        | awk -v expected="[127.0.0.1]:$SSH_HOST_PORT" \
            '$1 == expected && $2 == "ssh-ed25519" && NF == 3 { print; matches++ }
             END { if (matches != 1) exit 1 }' \
        > "$scan_temp" && ssh-keygen -lf "$scan_temp" >/dev/null 2>&1; then
        chmod 0600 "$scan_temp"
        mv -f -- "$scan_temp" "$PRIMARY_KNOWN_HOSTS"
        break
    fi
    primary_status="$("$UTMCTL" status "$primary_vm_id")"
    if [ "$primary_status" = stopped ]; then
        printf 'Primary VM stopped before SSH became ready.\n' >&2
        exit 1
    fi
    sleep 5
done
trap - EXIT HUP INT TERM

remaining_boot_seconds="$((boot_deadline - $(date +%s)))"
if [ "$remaining_boot_seconds" -le "$SSH_KEYSCAN_PENALTY_DRAIN_SECONDS" ]; then
    printf 'Insufficient boot deadline remains to drain the SSH noauth penalty.\n' >&2
    exit 1
fi
sleep "$SSH_KEYSCAN_PENALTY_DRAIN_SECONDS"
while :; do
    if [ "$(date +%s)" -ge "$boot_deadline" ]; then
        printf 'Timed out waiting for authenticated SSH on 127.0.0.1:%s.\n' \
            "$SSH_HOST_PORT" >&2
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
        -o "$PRIMARY_KNOWN_HOSTS_OPTION" \
        cpadmin@127.0.0.1 true >/dev/null 2>&1; then
        break
    fi
    primary_status="$("$UTMCTL" status "$primary_vm_id")"
    if [ "$primary_status" = stopped ]; then
        printf 'Primary VM stopped before authenticated SSH became ready.\n' >&2
        exit 1
    fi
    sleep 5
done

VIVO_LAB_SSH_PORT="$SSH_HOST_PORT" \
VIVO_LAB_KNOWN_HOSTS="$PRIMARY_KNOWN_HOSTS" \
VIVO_LAB_EXPECTED_HOSTNAME="$PRIMARY_VM_NAME" \
VIVO_LAB_EXPECTED_DISK_BYTES="68719476736" \
    "$SCRIPT_DIR/verify-base.sh"

printf 'Seedless base qualification passed for %s (%s).\n' \
    "$PRIMARY_VM_NAME" "$primary_vm_id"
printf 'Primary Ansible inventory: %s\n' \
    "$SCRIPT_DIR/../../deploy/inventories/lab/hosts.yml"
