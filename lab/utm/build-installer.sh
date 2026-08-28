#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
ISO_PATH="${1:-$HOME/Downloads/debian-13.6.0-arm64-netinst.iso}"
SSH_KEY="${VIVO_LAB_SSH_KEY:-$HOME/.ssh/vivo_cp1_lab_ed25519}"
OUT_DIR="$SCRIPT_DIR/generated"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vivo-cp1-installer.XXXXXX")"
EXPECTED_ISO_SHA512="43eef37fe589c8995f713c2d731604494f4353dfcc9c6f7dc4abdedab1e8f313a68bd1eb1ae299f4fb8995cbc1306c7348dc20d3dbd95ad1b613131611506bb8"
UTMCTL="/Applications/UTM.app/Contents/MacOS/utmctl"
WORKING_VM_ID="81C7DE36-9421-4E1C-AC4E-48336131D1EC"
REBUILD_VM_NAME="vivo-cp1-lab-rebuild"
REBUILD_MARKER="vivolution-cp1-disposable-rebuild-v1"
VM_NAME="${VIVO_LAB_VM_NAME:-}"
EXPECTED_VM_ID="${VIVO_LAB_EXPECTED_VM_ID:-}"
VM_BUNDLE="${VIVO_LAB_VM_BUNDLE:-$HOME/Library/Containers/com.utmapp.UTM/Data/Documents/$VM_NAME.utm}"
CUSTOM_ISO_BASENAME="debian-13.6.0-arm64-vivo-preseed.iso"
CUSTOM_ISO="$OUT_DIR/$CUSTOM_ISO_BASENAME"

cleanup() {
    rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT HUP INT TERM

atomic_install() {
    source_file="$1"
    destination_file="$2"
    destination_mode="$3"
    destination_dir="$(dirname -- "$destination_file")"
    temporary_file="$(mktemp "$destination_dir/.installer-output.XXXXXX")"
    install -m "$destination_mode" "$source_file" "$temporary_file"
    mv -f -- "$temporary_file" "$destination_file"
}

for command_name in awk bsdtar cat chmod cmp cp dirname grep gzip install mkdir mktemp mv python3 rm shasum sed ssh-keygen tr xorriso; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf 'Missing required command: %s\n' "$command_name" >&2
        exit 1
    }
done

case "$VM_NAME" in
    ''|*/*)
        printf 'Invalid UTM VM name: %s\n' "$VM_NAME" >&2
        exit 1
        ;;
esac

if [ -z "$EXPECTED_VM_ID" ]; then
    printf 'VIVO_LAB_EXPECTED_VM_ID is required; installer staging has no working-VM default.\n' >&2
    exit 1
fi

case "$EXPECTED_VM_ID" in
    "$WORKING_VM_ID")
        printf 'Refusing to stage unattended installer assets in the protected working VM.\n' >&2
        exit 1
        ;;
    ????????-????-????-????-????????????) ;;
    *)
        printf 'Invalid expected UTM VM UUID: %s\n' "$EXPECTED_VM_ID" >&2
        exit 1
        ;;
esac
case "$EXPECTED_VM_ID" in
    *[!0-9A-Fa-f-]*)
        printf 'Invalid expected UTM VM UUID: %s\n' "$EXPECTED_VM_ID" >&2
        exit 1
        ;;
esac
if [ "$VM_NAME" != "$REBUILD_VM_NAME" ]; then
    printf 'Installer staging is restricted to the exact disposable rebuild VM name.\n' >&2
    exit 1
fi

[ -f "$ISO_PATH" ] || {
    printf 'Debian ISO not found: %s\n' "$ISO_PATH" >&2
    exit 1
}
if [ -L "$OUT_DIR" ]; then
    printf 'Refusing a symlinked generated directory: %s\n' "$OUT_DIR" >&2
    exit 1
fi
for generated_output in \
    "$OUT_DIR/vmlinuz" \
    "$OUT_DIR/initrd-preseed.gz" \
    "$CUSTOM_ISO" \
    "$OUT_DIR/SHA512SUMS" \
    "$OUT_DIR/SSH_KEY_FINGERPRINT"; do
    if [ -L "$generated_output" ] || { [ -e "$generated_output" ] && [ ! -f "$generated_output" ]; }; then
        printf 'Refusing a symlinked or non-regular generated output: %s\n' "$generated_output" >&2
        exit 1
    fi
done

actual_iso_sha512="$(shasum -a 512 "$ISO_PATH" | awk '{print $1}')"
if [ "$actual_iso_sha512" != "$EXPECTED_ISO_SHA512" ]; then
    printf 'Debian ISO SHA-512 verification failed.\n' >&2
    exit 1
fi

if [ -L "$SSH_KEY" ] || [ -L "$SSH_KEY.pub" ]; then
    printf 'Refusing a symlinked installer SSH key path.\n' >&2
    exit 1
fi

if [ ! -f "$SSH_KEY" ]; then
    umask 077
    ssh-keygen -q -t ed25519 -N '' \
        -C 'vivo-cp1-lab@vivolution-sbc' \
        -f "$SSH_KEY"
fi

if [ ! -f "$SSH_KEY.pub" ]; then
    ssh-keygen -y -f "$SSH_KEY" > "$SSH_KEY.pub"
    chmod 0644 "$SSH_KEY.pub"
fi

mkdir -p "$OUT_DIR" "$WORK_DIR/inject" "$WORK_DIR/output"
bsdtar -xOf "$ISO_PATH" install.a64/vmlinuz > "$WORK_DIR/output/vmlinuz"
bsdtar -xOf "$ISO_PATH" install.a64/initrd.gz > "$WORK_DIR/output/initrd-original.gz"

cp "$SCRIPT_DIR/preseed.cfg" "$WORK_DIR/inject/preseed.cfg"
public_key="$(tr -d '\r\n' < "$SSH_KEY.pub")"
sed "s|@@SSH_PUBLIC_KEY@@|$public_key|" \
    "$SCRIPT_DIR/late.sh.in" > "$WORK_DIR/inject/late.sh"
chmod 0644 "$WORK_DIR/inject/preseed.cfg"
chmod 0755 "$WORK_DIR/inject/late.sh"
if grep -q '@@SSH_PUBLIC_KEY@@' "$WORK_DIR/inject/late.sh"; then
    printf 'SSH public-key substitution failed.\n' >&2
    exit 1
fi

python3 "$SCRIPT_DIR/inject-initrd.py" \
    "$WORK_DIR/output/initrd-original.gz" \
    "$WORK_DIR/inject/preseed.cfg" \
    "$WORK_DIR/inject/late.sh" \
    "$WORK_DIR/output/initrd-preseed.gz"

gzip -t "$WORK_DIR/output/initrd-preseed.gz"
gzip -dc "$WORK_DIR/output/initrd-preseed.gz" \
    | bsdtar -xOf - preseed.cfg > "$WORK_DIR/output/verified-preseed.cfg"
gzip -dc "$WORK_DIR/output/initrd-preseed.gz" \
    | bsdtar -xOf - late.sh > "$WORK_DIR/output/verified-late.sh"
cmp -s "$WORK_DIR/inject/preseed.cfg" "$WORK_DIR/output/verified-preseed.cfg" || {
    printf 'Injected preseed content failed archive verification.\n' >&2
    exit 1
}
cmp -s "$WORK_DIR/inject/late.sh" "$WORK_DIR/output/verified-late.sh" || {
    printf 'Injected late-command content failed archive verification.\n' >&2
    exit 1
}

# Reuse Debian's signed UEFI boot layout while replacing only the installer
# initrd and top-level GRUB menu. The zero-timeout menu boots the embedded
# preseed through Debian's normal ISO path, avoiding UTM/QEMU external-kernel
# sandbox limitations.
xorriso \
    -indev "$ISO_PATH" \
    -outdev "$WORK_DIR/output/$CUSTOM_ISO_BASENAME" \
    -boot_image any replay \
    -map "$WORK_DIR/output/initrd-preseed.gz" /install.a64/initrd.gz \
    -map "$SCRIPT_DIR/grub-unattended.cfg" /boot/grub/grub.cfg \
    -commit \
    -end

bsdtar -xOf "$WORK_DIR/output/$CUSTOM_ISO_BASENAME" install.a64/initrd.gz \
    > "$WORK_DIR/output/verified-initrd.gz"
bsdtar -xOf "$WORK_DIR/output/$CUSTOM_ISO_BASENAME" boot/grub/grub.cfg \
    > "$WORK_DIR/output/verified-grub.cfg"
cmp -s "$WORK_DIR/output/initrd-preseed.gz" "$WORK_DIR/output/verified-initrd.gz" || {
    printf 'Custom ISO does not contain the qualified installer initrd.\n' >&2
    exit 1
}
cmp -s "$SCRIPT_DIR/grub-unattended.cfg" "$WORK_DIR/output/verified-grub.cfg" || {
    printf 'Custom ISO does not contain the unattended GRUB policy.\n' >&2
    exit 1
}

kernel_sha512="$(shasum -a 512 "$WORK_DIR/output/vmlinuz" | awk '{print $1}')"
initrd_sha512="$(shasum -a 512 "$WORK_DIR/output/initrd-preseed.gz" | awk '{print $1}')"
custom_iso_sha512="$(shasum -a 512 "$WORK_DIR/output/$CUSTOM_ISO_BASENAME" | awk '{print $1}')"
{
    printf '%s  %s\n' "$actual_iso_sha512" "$ISO_PATH"
    printf '%s  %s\n' "$kernel_sha512" "$OUT_DIR/vmlinuz"
    printf '%s  %s\n' "$initrd_sha512" "$OUT_DIR/initrd-preseed.gz"
    printf '%s  %s\n' "$custom_iso_sha512" "$CUSTOM_ISO"
} > "$WORK_DIR/output/SHA512SUMS"
ssh-keygen -lf "$SSH_KEY.pub" > "$WORK_DIR/output/SSH_KEY_FINGERPRINT"

# Rename fully built files over any prior regular files. This never writes
# through a stale hardlink or symlink at a generated destination.
atomic_install "$WORK_DIR/output/vmlinuz" "$OUT_DIR/vmlinuz" 0644
atomic_install "$WORK_DIR/output/initrd-preseed.gz" "$OUT_DIR/initrd-preseed.gz" 0644
atomic_install "$WORK_DIR/output/$CUSTOM_ISO_BASENAME" "$CUSTOM_ISO" 0644
atomic_install "$WORK_DIR/output/SHA512SUMS" "$OUT_DIR/SHA512SUMS" 0644
atomic_install "$WORK_DIR/output/SSH_KEY_FINGERPRINT" "$OUT_DIR/SSH_KEY_FINGERPRINT" 0644

[ -x "$UTMCTL" ] || {
    printf 'UTM control tool not found: %s\n' "$UTMCTL" >&2
    exit 1
}

if [ "$("$UTMCTL" status "$VM_NAME")" != "stopped" ]; then
    printf 'Refusing to stage installer assets while %s is not stopped.\n' "$VM_NAME" >&2
    exit 1
fi

if [ -L "$VM_BUNDLE" ] || [ ! -d "$VM_BUNDLE" ]; then
    printf 'Expected a non-symlink UTM bundle directory: %s\n' "$VM_BUNDLE" >&2
    exit 1
fi

CONFIG_PLIST="$VM_BUNDLE/config.plist"
if [ -L "$CONFIG_PLIST" ] || [ ! -f "$CONFIG_PLIST" ]; then
    printf 'Expected a non-symlink UTM configuration file: %s\n' "$CONFIG_PLIST" >&2
    exit 1
fi

actual_vm_id="$(/usr/libexec/PlistBuddy -c 'Print :Information:UUID' "$CONFIG_PLIST" 2>/dev/null || true)"
actual_vm_name="$(/usr/libexec/PlistBuddy -c 'Print :Information:Name' "$CONFIG_PLIST" 2>/dev/null || true)"
if [ "$actual_vm_id" != "$EXPECTED_VM_ID" ] || [ "$actual_vm_name" != "$VM_NAME" ]; then
    printf 'UTM bundle identity mismatch; refusing to stage installer assets.\n' >&2
    exit 1
fi
actual_vm_notes="$(/usr/libexec/PlistBuddy -c 'Print :Information:Notes' "$CONFIG_PLIST" 2>/dev/null || true)"
if [ "$actual_vm_notes" != "$REBUILD_MARKER" ]; then
    printf 'Disposable rebuild marker mismatch; refusing to stage installer assets.\n' >&2
    exit 1
fi

printf 'Built unattended installer assets in %s\n' "$OUT_DIR"
printf 'Built checksum-derived unattended ISO: %s\n' "$CUSTOM_ISO"
printf 'Validated disposable target identity: %s (%s)\n' "$VM_NAME" "$EXPECTED_VM_ID"
printf 'SSH key: %s\n' "$SSH_KEY"
cat "$OUT_DIR/SSH_KEY_FINGERPRINT"
