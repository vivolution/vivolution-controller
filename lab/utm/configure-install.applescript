property workingVmId : "81C7DE36-9421-4E1C-AC4E-48336131D1EC"
property rebuildVmName : "vivo-cp1-lab-rebuild"
property rebuildMarker : "vivolution-cp1-disposable-rebuild-v1"
property freshDiskSizeMiB : 65536
property guestIpAddress : "10.0.2.15"

on run argv
    if (count of argv) is 7 then
        set vmName to item 1 of argv
        set expectedVmId to item 2 of argv
        set isoPath to item 3 of argv
        set hostSshPort to (item 4 of argv) as integer
        set hostPortalPort to (item 5 of argv) as integer
        set macAddress to item 6 of argv
        set diskMode to item 7 of argv
    else
        error "usage: osascript configure-install.applescript vm-name vm-uuid unattended-iso ssh-port portal-port mac preserve|fresh-64g"
    end if

    if hostSshPort is less than 1 or hostSshPort is greater than 65535 then error "invalid SSH host port"
    if hostPortalPort is less than 1 or hostPortalPort is greater than 65535 then error "invalid portal host port"
    if hostSshPort is hostPortalPort then error "host forwards must use distinct ports"
    if diskMode is not "preserve" and diskMode is not "fresh-64g" then error "disk mode must be preserve or fresh-64g"
    if vmName is not rebuildVmName then error "configuration is restricted to the exact disposable rebuild VM name"
    if expectedVmId is workingVmId then error "refusing to configure the protected working VM"
    if diskMode is "fresh-64g" then
        if vmName is not rebuildVmName then error "fresh-disk mode is restricted to the exact disposable rebuild VM name"
        if expectedVmId is workingVmId then error "refusing to replace the protected working VM disk"
    end if

    set isoFile to POSIX file isoPath

    tell application "UTM"
        set auto terminate to false
        set vmMatches to every virtual machine whose name is vmName
        if (count of vmMatches) is not 1 then error "expected exactly one stopped UTM VM named " & vmName
        set vm to item 1 of vmMatches
        if id of vm is not expectedVmId then error "UTM VM UUID mismatch for " & vmName
        if status of vm is not stopped then error vmName & " must be stopped before configuration"
        if backend of vm is not qemu then error vmName & " must use the QEMU backend"

        set cfg to configuration of vm
        if architecture of cfg is not "aarch64" then error vmName & " must use the aarch64 architecture"
        if notes of cfg is not rebuildMarker then error "disposable rebuild VM marker mismatch"
        set currentSystemDrives to {}
        repeat with driveConfig in drives of cfg
            if removable of driveConfig is false then set end of currentSystemDrives to contents of driveConfig
        end repeat
        if (count of currentSystemDrives) is not 1 then error vmName & " must have exactly one system disk before configuration"
        set priorSystemDiskId to id of item 1 of currentSystemDrives

        set name of cfg to vmName
        set memory of cfg to 3072
        set cpu cores of cfg to 2

        if diskMode is "fresh-64g" then
            -- Omitting an id/source asks UTM to create a new sparse qcow2. The
            -- cloned system disk is dropped only from the disposable VM config.
            set drives of cfg to {{removable:false, interface:VirtIO, guest size:freshDiskSizeMiB, raw:false}, {removable:true, interface:USB, source:isoFile}}
        else
            -- Finalization removes removable media, so never assume an ISO is
            -- at a fixed drive index. Preserve the one system disk and re-add it.
            set drives of cfg to {item 1 of currentSystemDrives, {removable:true, interface:USB, source:isoFile}}
        end if

        set network interfaces of cfg to {{index:0, hardware:"virtio-net-pci", mode:emulated, address:macAddress, port forwards:{¬
            {«class PrTl»:«constant NtPrTcPp», host address:"127.0.0.1", host port:hostSshPort, guest address:guestIpAddress, guest port:22}, ¬
            {«class PrTl»:«constant NtPrTcPp», host address:"127.0.0.1", host port:hostPortalPort, guest address:guestIpAddress, guest port:8080}}}}
        set «class SrPt» of cfg to {{interface:ptty}}
        set qemu additional arguments of cfg to {}

        update configuration vm with cfg

        -- UTM persists the update asynchronously. Re-read until the scripting
        -- view catches up with the already-written config.plist.
        repeat 20 times
            set verifiedCfg to configuration of vm
            set verifiedArguments to qemu additional arguments of verifiedCfg
            if (count of verifiedArguments) is 0 then exit repeat
            delay 0.25
        end repeat
        set verifiedSystemDrives to {}
        set verifiedRemovableDrives to {}
        repeat with driveConfig in drives of verifiedCfg
            if removable of driveConfig is true then
                set end of verifiedRemovableDrives to contents of driveConfig
            else
                set end of verifiedSystemDrives to contents of driveConfig
            end if
        end repeat
        if (count of verifiedSystemDrives) is not 1 then error "configuration did not leave exactly one system disk"
        if (count of verifiedRemovableDrives) is not 1 then error "configuration did not attach exactly one installer ISO"
        if (count of verifiedArguments) is not 0 then error "unexpected direct-kernel arguments remain"

        set verifiedSystemDisk to item 1 of verifiedSystemDrives
        if diskMode is "fresh-64g" then
            if id of verifiedSystemDisk is priorSystemDiskId then error "UTM retained the cloned system disk instead of creating a fresh disk"
        else
            if id of verifiedSystemDisk is not priorSystemDiskId then error "preserve mode unexpectedly replaced the system disk"
        end if

        return {name of vm, id of vm, status of vm, id of verifiedSystemDisk}
    end tell
end run
