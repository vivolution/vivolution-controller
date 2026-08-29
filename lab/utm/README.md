# Local CP1 UTM lab

This directory builds Debian 13 ARM64 base VMs used to qualify the CP1 deployment kit before the final x86-64 Azure acceptance test. The working VM and the destructive-test VM are deliberately separate.

## Protected source shape

- UTM/QEMU VM: `vivo-cp1-lab`
- a UUID created by UTM and recorded in ignored `generated/primary-vm-id`
- ownership marker `vivolution-cp1-primary-lab-v1`
- 2 vCPU, 3072 MiB RAM
- 64 GiB sparse VirtIO disk (host storage is consumed only as data is written)
- QEMU user-mode networking with host-only forwards for SSH
  (`127.0.0.1:2222 -> guest:22`) and the lab portal
  (`127.0.0.1:8080 -> guest:8080`)
- Debian 13.6 ARM64 netinst ISO
- `cpadmin` with key-only SSH and passwordless sudo in this disposable lab only

The clean-rebuild target has a fixed, separate shape:

- exact UTM name: `vivo-cp1-lab-rebuild`
- a UUID created by UTM and recorded in ignored `generated/rebuild-vm-id`
- fresh 64 GiB sparse qcow2 created through UTM's configuration API
- fresh per-VM UEFI variables copied atomically from UTM's stock ARM64 template
- host forwards `127.0.0.1:2223 -> guest:22` and
  `127.0.0.1:8081 -> guest:8080`
- dedicated known-hosts file `generated/known_hosts-rebuild`

The password previously sent in Telegram is never used. The installer generates an unrecoverable random local password solely to keep the account valid for public-key authentication, then disables SSH password authentication.

The local UTM profile uses QEMU user-mode networking's fixed private values
(`10.0.2.15/24`, gateway `10.0.2.2`, DNS `10.0.2.3`) so a DHCP timeout cannot
pause an unattended rebuild. Debian creates a locked `cpadmin` placeholder
because Debian 13 requires a normal user when root login is disabled; the late
hardening step sets an unrecoverable random local password, ensures sudo-group
membership, installs only the lab SSH public key, and disables SSH password
authentication.

The build injects `preseed.cfg` and the key-only account setup before the
original Debian initramfs trailer, preserves every original archive byte before
that point, and recompresses the result as one deterministic gzip member. This
removes ambiguity from host-side archive inspection and makes the injected
files directly verifiable with standard `bsdtar`; it does not rely on proving
whether the earlier valid multi-member initramfs was unpacked by the guest. The
builder then uses `xorriso` to derive a new ISO from the checksum-verified
official image. Only `/install.a64/initrd.gz` and the top-level GRUB menu are replaced.
Debian's original UEFI boot layout is replayed, and the new zero-timeout entry
starts the automated installer. There is no HTTP preseed server, GRUB
keystroke timing, shared password, or menu interaction.

Generated kernels, initrds, the derived ISO, checksums and host keys are
excluded from version control. The builder proves that the injected files are
root-owned with exact modes/content in the single newc archive, then reads the
injected initrd and GRUB policy back from the derived ISO and compares them
byte-for-byte before UTM is allowed to attach it. The dedicated private SSH key remains in
`~/.ssh/vivo_cp1_lab_ed25519`.

## Seedless primary bootstrap

`bootstrap-lab.sh` creates the protected primary from a truly empty UTM state;
it does not require a template, clone, exported bundle, or old VM UUID. It first
requires both UTM's registry and local Documents directory to contain zero VMs,
then uses UTM 4.7.5's supported AppleScript configuration API to create the
fixed profile above. It never deletes, stops, imports, or modifies an existing
VM. The normal creation path requires both UTM's registry and local Documents
directory to contain zero VMs. The sole exception is recovery of one exact,
stopped, marker-owned VM interrupted before staging, as described below; no
other existing VM is changed.

The workflow pins UTM's version, build, code signature, stock ARM64 firmware
digest, and the official Debian ISO checksum. It builds and verifies the
derived unattended ISO, persists the UTM-generated UUID before later changes,
attaches the ISO to the one fresh disk, resets only the new VM's UEFI variables
to the pinned stock template, waits for installer poweroff, removes the ISO,
and starts the installed system. It then captures exactly one ED25519 host key,
waits out Debian's SSH no-auth penalty window, authenticates with the dedicated
key, and runs the base assertions.

From an empty UTM registry and Documents directory:

```bash
cd "/Users/jay/Projects/Active/Vivolution SBC"
lab/utm/bootstrap-lab.sh
```

The generated UUID is returned and recorded before configuration validation.
If creation is interrupted even earlier, a rerun can adopt only one exact,
stopped, marker-owned VM whose qcow2 is still untouched and whose UUID is not
already the recorded primary. Once the UUID is recorded, later failures remain
for inspection and require an explicit operator cleanup or recovery decision;
the script never reinstalls an already recorded VM. A successful run leaves the
primary running on `127.0.0.1:2222` and pins its host key in
`generated/known_hosts`, ready for `deploy/inventories/lab/hosts.yml`.

## Safe clean-rebuild qualification

The rebuild workflow never stops, starts, reconfigures, or deletes
`vivo-cp1-lab`. It requires that protected VM to already be stopped, clones it
under the exact disposable name, and then replaces only the clone's copied
firmware-variable store with UTM's validated stock ARM64 template and its
copied system disk with a fresh 64 GiB sparse qcow2 through UTM's AppleScript
configuration API. The protected UUID is loaded from the seedless bootstrap's
`generated/primary-vm-id`; both replacements require the exact UUID, exact name,
managed-disposable marker and stopped state. It attaches the checksum-derived
unattended Debian ISO even when a previous finalization removed all removable
media, waits for the installer poweroff, finalizes the clone, boots it, and
runs the base assertions.

The firmware reset occurs after UTM commits the fresh disk and installer ISO
and immediately before the clone's first boot. UTM's version, build, code
signature and stock ARM64 template digest are pinned for UTM 4.7.5; an upgrade
fails closed until the template is reviewed and requalified. The workflow also
proves that no process has the disposable store open and that the protected
VM's `efi_vars.fd` inode, link count and digest remain unchanged. The protected
store is validated but never written.

The rebuild installer build, configure, start, and finalize helpers have no
working-VM default, and the builder requires the protected UUID separately from
the disposable target UUID. Invoke them only through the guarded rebuild
driver:

```bash
cd "/Users/jay/Projects/Active/Vivolution SBC"
chmod 0755 lab/utm/rebuild-lab.sh
lab/utm/rebuild-lab.sh
```

An existing same-name VM is deleted only when all of these match: the exact
name, the ignored recorded UUID, the managed-disposable configuration marker,
and stopped state. An unknown same-name VM or UUID mismatch is refused. The
only no-state recovery is a stopped, marked raw clone whose system-drive id
still matches the source, covering interruption between clone completion and
the atomic state-file write. The workflow never stops a VM on the user's
behalf.

The clean guest is available to Ansible through
`deploy/inventories/rebuild/hosts.yml`. Its guest hostname and internal HTTPS
port remain `vivo-cp1-lab` and `8080`; only the host-side forwards differ from
the working VM.

After the first boot, the driver scans exactly one ED25519 host key from the
clone's loopback-only SSH forward, validates and atomically pins it, disables
SSH connection sharing for the base check, and then authenticates with strict
host-key checking. This prevents a stale control socket from bypassing creation
of the rebuild-specific known-hosts evidence used by Ansible and reboot tests.
Host-key capture and authentication are separate phases because Debian 13's
OpenSSH applies per-source penalties to unauthenticated probes. The driver
stops scanning after the key is pinned, drains the penalty window, and quotes
the absolute known-hosts path so the space in the project directory cannot be
misparsed by OpenSSH or Ansible.

## Historical functional record — 2026-08-27 (superseded)

UTM 4.7.5 build 118 and Debian 13.6 ARM64 completed two clean rebuild
qualification cycles. The first clean cycle exposed a PgBouncer first-boot
ordering defect; the deployment role was corrected to apply its generated
authentication state before controller activation, and the complete suite then
passed after repair. Its retained evidence is
`deploy/evidence/20260827T180455Z-19848`.

The final cycle ran the corrected rebuild driver from a fresh sparse disk and
stock pinned UEFI-variable template, passed strict SSH host-key pinning, and
passed the then-current functional suite from the untouched OS. The first
deployment succeeded without recovery and Ansible reported zero changes on the
immediate second deployment. Its retained evidence is
`deploy/evidence/20260827T183743Z-74252`.

The August 28 audit later proved that the old `changed=0` check hid PostgreSQL
SCRAM changes and that these records lacked the release/security provenance and
vulnerability gate now required. They remain bounded functional evidence; they
do not qualify the current release, Azure AMD64, Azure Database for PostgreSQL,
public TLS, enrollment/PKI, the Edge Agent, or the SIP/media data plane.
