property primaryVmName : "vivo-cp1-lab"
property primaryMarker : "vivolution-cp1-primary-lab-v1"
property primarySshPort : 2222
property primaryPortalPort : 8080
property primaryMacAddress : "B6:D3:46:43:95:AC"
property guestIpAddress : "10.0.2.15"

on uuidIsValid(candidate)
    if (count of candidate) is not 36 then return false
    repeat with hyphenPosition in {9, 14, 19, 24}
        if character hyphenPosition of candidate is not "-" then return false
    end repeat

    set hexadecimalCharacters to "0123456789abcdefABCDEF"
    repeat with characterPosition from 1 to 36
        set candidateCharacter to character characterPosition of candidate
        if candidateCharacter is not "-" and hexadecimalCharacters does not contain candidateCharacter then return false
    end repeat
    return true
end uuidIsValid

on run argv
    if (count of argv) is 5 then
        set vmName to item 1 of argv
        set expectedVmId to item 2 of argv
        set hostSshPort to (item 3 of argv) as integer
        set hostPortalPort to (item 4 of argv) as integer
        set macAddress to item 5 of argv
    else
        error "usage: osascript finalize-primary-install.applescript vm-name vm-uuid ssh-port portal-port mac"
    end if

    if vmName is not primaryVmName then error "finalization is restricted to the exact primary VM name"
    if my uuidIsValid(expectedVmId) is false then error "invalid expected primary VM UUID"
    if hostSshPort is not primarySshPort then error "primary SSH host port must be 2222"
    if hostPortalPort is not primaryPortalPort then error "primary portal host port must be 8080"
    if macAddress is not primaryMacAddress then error "primary VM MAC address mismatch"

    tell application "UTM"
        set auto terminate to false
        set vmMatches to every virtual machine whose name is vmName
        if (count of vmMatches) is not 1 then error "expected exactly one stopped primary UTM VM named " & vmName
        set vm to item 1 of vmMatches
        if id of vm is not expectedVmId then error "primary UTM VM UUID mismatch"
        if status of vm is not stopped then error vmName & " must be stopped before finalization"
        if backend of vm is not qemu then error vmName & " must use the QEMU backend"

        set cfg to configuration of vm
        if name of cfg is not vmName then error "primary configuration name mismatch"
        if notes of cfg is not primaryMarker then error "primary VM marker mismatch"
        if architecture of cfg is not "aarch64" then error "primary VM architecture mismatch"
        if machine of cfg is not "virt" then error "primary QEMU machine mismatch"
        if directory share mode of cfg is not none then error "primary VM directory sharing is enabled"

        set currentSystemDrives to {}
        set currentRemovableDrives to {}
        repeat with driveConfig in drives of cfg
            if removable of driveConfig is true then
                set end of currentRemovableDrives to contents of driveConfig
            else
                set end of currentSystemDrives to contents of driveConfig
            end if
        end repeat
        if (count of currentSystemDrives) is not 1 then error vmName & " must have exactly one system disk before finalization"
        if (count of currentRemovableDrives) is not 1 then error vmName & " must have exactly one installer ISO before finalization"
        set preservedSystemDisk to item 1 of currentSystemDrives
        set preservedSystemDiskId to id of preservedSystemDisk
        if interface of preservedSystemDisk is not VirtIO then error "primary system disk must use VirtIO"
        if interface of item 1 of currentRemovableDrives is not USB then error "primary installer ISO must use USB"

        set name of cfg to vmName
        set memory of cfg to 3072
        set cpu cores of cfg to 2
        set hypervisor of cfg to true
        set uefi of cfg to true
        set directory share mode of cfg to none
        set drives of cfg to {preservedSystemDisk}
        set network interfaces of cfg to {{index:0, hardware:"virtio-net-pci", mode:emulated, address:macAddress, port forwards:{¬
            {«class PrTl»:«constant NtPrTcPp», host address:"127.0.0.1", host port:hostSshPort, guest address:guestIpAddress, guest port:22}, ¬
            {«class PrTl»:«constant NtPrTcPp», host address:"127.0.0.1", host port:hostPortalPort, guest address:guestIpAddress, guest port:8080}}}}
        set «class SrPt» of cfg to {{interface:ptty}}
        set qemu additional arguments of cfg to {}

        update configuration vm with cfg

        repeat 40 times
            set verifiedCfg to configuration of vm
            set persistenceReady to name of verifiedCfg is vmName and memory of verifiedCfg is 3072 and cpu cores of verifiedCfg is 2 and (count of qemu additional arguments of verifiedCfg) is 0
            if persistenceReady then
                set readySystemDrives to {}
                set readyRemovableDrives to {}
                repeat with driveConfig in drives of verifiedCfg
                    if removable of driveConfig is true then
                        set end of readyRemovableDrives to contents of driveConfig
                    else
                        set end of readySystemDrives to contents of driveConfig
                    end if
                end repeat
                if (count of readySystemDrives) is 1 and (count of readyRemovableDrives) is 0 then exit repeat
            end if
            delay 0.25
        end repeat

        if id of vm is not expectedVmId then error "primary VM UUID changed during finalization"
        if name of vm is not vmName then error "primary VM name changed during finalization"
        if status of vm is not stopped then error "primary VM left the stopped state during finalization"
        if backend of vm is not qemu then error "primary VM backend changed during finalization"
        if name of verifiedCfg is not vmName then error "primary configuration name was not persisted"
        if notes of verifiedCfg is not primaryMarker then error "primary marker was not persisted"
        if architecture of verifiedCfg is not "aarch64" then error "primary architecture changed during finalization"
        if machine of verifiedCfg is not "virt" then error "primary machine changed during finalization"
        if memory of verifiedCfg is not 3072 then error "primary memory setting was not persisted"
        if cpu cores of verifiedCfg is not 2 then error "primary CPU setting was not persisted"
        if hypervisor of verifiedCfg is not true then error "primary hypervisor setting was not persisted"
        if uefi of verifiedCfg is not true then error "primary UEFI setting was not persisted"
        if directory share mode of verifiedCfg is not none then error "primary directory sharing was enabled during finalization"
        if (count of qemu additional arguments of verifiedCfg) is not 0 then error "unexpected QEMU additional arguments remain after finalization"

        set verifiedSystemDrives to {}
        set verifiedRemovableDrives to {}
        repeat with driveConfig in drives of verifiedCfg
            if removable of driveConfig is true then
                set end of verifiedRemovableDrives to contents of driveConfig
            else
                set end of verifiedSystemDrives to contents of driveConfig
            end if
        end repeat
        if (count of verifiedSystemDrives) is not 1 then error "finalization did not preserve exactly one system disk"
        if id of item 1 of verifiedSystemDrives is not preservedSystemDiskId then error "finalization changed the primary system disk identity"
        if interface of item 1 of verifiedSystemDrives is not VirtIO then error "primary system disk interface changed"
        if (count of verifiedRemovableDrives) is not 0 then error "installer media remains after finalization"

        set verifiedNetworks to network interfaces of verifiedCfg
        if (count of verifiedNetworks) is not 1 then error "finalization did not persist exactly one network interface"
        set verifiedNetwork to item 1 of verifiedNetworks
        if hardware of verifiedNetwork is not "virtio-net-pci" then error "primary network hardware mismatch after finalization"
        if mode of verifiedNetwork is not emulated then error "primary network mode mismatch after finalization"
        if address of verifiedNetwork is not macAddress then error "primary network MAC mismatch after finalization"
        set verifiedForwards to port forwards of verifiedNetwork
        if (count of verifiedForwards) is not 2 then error "finalization did not persist exactly two host forwards"
        if «class PrTl» of item 1 of verifiedForwards is not «constant NtPrTcPp» then error "SSH forward is not TCP"
        if host address of item 1 of verifiedForwards is not "127.0.0.1" then error "SSH forward is not loopback-only"
        if host port of item 1 of verifiedForwards is not hostSshPort then error "SSH host forward mismatch after finalization"
        if guest address of item 1 of verifiedForwards is not guestIpAddress then error "SSH guest address mismatch after finalization"
        if guest port of item 1 of verifiedForwards is not 22 then error "SSH guest port mismatch after finalization"
        if «class PrTl» of item 2 of verifiedForwards is not «constant NtPrTcPp» then error "portal forward is not TCP"
        if host address of item 2 of verifiedForwards is not "127.0.0.1" then error "portal forward is not loopback-only"
        if host port of item 2 of verifiedForwards is not hostPortalPort then error "portal host forward mismatch after finalization"
        if guest address of item 2 of verifiedForwards is not guestIpAddress then error "portal guest address mismatch after finalization"
        if guest port of item 2 of verifiedForwards is not 8080 then error "portal guest port mismatch after finalization"

        return {name of vm, id of vm, status of vm, preservedSystemDiskId}
    end tell
end run
