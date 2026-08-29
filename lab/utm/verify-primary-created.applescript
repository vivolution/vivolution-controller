property primaryVmName : "vivo-cp1-lab"
property primaryMarker : "vivolution-cp1-primary-lab-v1"
property primaryArchitecture : "aarch64"
property primaryMemoryMiB : 3072
property primaryCpuCores : 2
property primaryMacAddress : "B6:D3:46:43:95:AC"
property guestIpAddress : "10.0.2.15"
property hostSshPort : 2222
property hostPortalPort : 8080

on uuidIsValid(candidateValue)
    try
        set candidateText to candidateValue as text
        if (count characters of candidateText) is not 36 then return false
        repeat with characterIndex from 1 to 36
            set candidateCharacter to character characterIndex of candidateText
            if characterIndex is in {9, 14, 19, 24} then
                if candidateCharacter is not "-" then return false
            else if "0123456789abcdefABCDEF" does not contain candidateCharacter then
                return false
            end if
        end repeat
        return true
    on error
        return false
    end try
end uuidIsValid

on run argv
    if (count of argv) is not 1 then error "usage: osascript verify-primary-created.applescript primary-uuid"
    set expectedVmId to item 1 of argv
    if not my uuidIsValid(expectedVmId) then error "invalid expected primary VM UUID"

    tell application "UTM"
        set auto terminate to false
        if (count of virtual machines) is not 1 then error "UTM registry must contain exactly one VM during primary verification"
        set exactMatches to every virtual machine whose name is primaryVmName
        if (count of exactMatches) is not 1 then error "UTM did not retain exactly one primary VM with the required name"
        set verifiedVm to item 1 of exactMatches

        if id of verifiedVm is not expectedVmId then error "primary VM UUID mismatch after creation"
        if status of verifiedVm is not stopped then error "new primary VM is not stopped"
        if backend of verifiedVm is not qemu then error "new primary VM does not use the QEMU backend"

        set verifiedCfg to configuration of verifiedVm
        if name of verifiedCfg is not primaryVmName then error "primary VM configuration name mismatch"
        if notes of verifiedCfg is not primaryMarker then error "primary VM ownership marker mismatch"
        if architecture of verifiedCfg is not primaryArchitecture then error "primary VM architecture mismatch"
        if machine of verifiedCfg is not "virt" then error "primary VM machine type mismatch"
        if memory of verifiedCfg is not primaryMemoryMiB then error "primary VM memory mismatch"
        if cpu cores of verifiedCfg is not primaryCpuCores then error "primary VM CPU count mismatch"
        if hypervisor of verifiedCfg is not true then error "primary VM hypervisor acceleration is disabled"
        if uefi of verifiedCfg is not true then error "primary VM UEFI boot is disabled"
        if directory share mode of verifiedCfg is not none then error "primary VM directory sharing is enabled"

        set systemDrives to {}
        set removableDrives to {}
        repeat with driveCfg in drives of verifiedCfg
            if removable of driveCfg is true then
                set end of removableDrives to contents of driveCfg
            else
                set end of systemDrives to contents of driveCfg
            end if
        end repeat
        if (count of systemDrives) is not 1 then error "primary VM does not have exactly one system disk"
        if (count of removableDrives) is not 0 then error "primary VM unexpectedly has removable media before staging"
        if interface of item 1 of systemDrives is not VirtIO then error "primary VM system disk is not attached through VirtIO"

        set verifiedNetworks to network interfaces of verifiedCfg
        if (count of verifiedNetworks) is not 1 then error "primary VM does not have exactly one network interface"
        set verifiedNetwork to item 1 of verifiedNetworks
        if hardware of verifiedNetwork is not "virtio-net-pci" then error "primary VM network hardware mismatch"
        if mode of verifiedNetwork is not emulated then error "primary VM network is not QEMU user-mode networking"
        if address of verifiedNetwork is not primaryMacAddress then error "primary VM network MAC mismatch"

        set verifiedForwards to port forwards of verifiedNetwork
        if (count of verifiedForwards) is not 2 then error "primary VM does not have exactly two port forwards"
        if «class PrTl» of item 1 of verifiedForwards is not «constant NtPrTcPp» then error "primary VM SSH forward is not TCP"
        if host address of item 1 of verifiedForwards is not "127.0.0.1" then error "primary VM SSH forward is not bound to loopback"
        if host port of item 1 of verifiedForwards is not hostSshPort then error "primary VM SSH host port mismatch"
        if guest address of item 1 of verifiedForwards is not guestIpAddress then error "primary VM SSH guest address mismatch"
        if guest port of item 1 of verifiedForwards is not 22 then error "primary VM SSH guest port mismatch"
        if «class PrTl» of item 2 of verifiedForwards is not «constant NtPrTcPp» then error "primary VM portal forward is not TCP"
        if host address of item 2 of verifiedForwards is not "127.0.0.1" then error "primary VM portal forward is not bound to loopback"
        if host port of item 2 of verifiedForwards is not hostPortalPort then error "primary VM portal host port mismatch"
        if guest address of item 2 of verifiedForwards is not guestIpAddress then error "primary VM portal guest address mismatch"
        if guest port of item 2 of verifiedForwards is not 8080 then error "primary VM portal guest port mismatch"

        set verifiedSerials to «class SrPt» of verifiedCfg
        if (count of verifiedSerials) is not 1 then error "primary VM does not have exactly one serial device"
        if interface of item 1 of verifiedSerials is not ptty then error "primary VM serial device is not a PTTY"
        if (count of displays of verifiedCfg) is not 0 then error "primary VM unexpectedly has a display device"
        if (count of qemu additional arguments of verifiedCfg) is not 0 then error "primary VM has unexpected additional QEMU arguments"

        return expectedVmId
    end tell
end run
