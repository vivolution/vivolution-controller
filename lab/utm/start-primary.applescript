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
    if (count of argv) is 3 then
        set vmName to item 1 of argv
        set expectedVmId to item 2 of argv
        set bootMode to item 3 of argv
    else
        error "usage: osascript start-primary.applescript vm-name vm-uuid installer|installed"
    end if

    if vmName is not primaryVmName then error "start is restricted to the exact primary VM name"
    if my uuidIsValid(expectedVmId) is false then error "invalid expected primary VM UUID"
    if bootMode is not "installer" and bootMode is not "installed" then error "boot mode must be installer or installed"

    tell application "UTM"
        set auto terminate to false
        set vmMatches to every virtual machine whose name is vmName
        if (count of vmMatches) is not 1 then error "expected exactly one stopped primary UTM VM named " & vmName
        set vm to item 1 of vmMatches
        if id of vm is not expectedVmId then error "primary UTM VM UUID mismatch"
        if status of vm is not stopped then error vmName & " must be stopped before start"
        if backend of vm is not qemu then error vmName & " must use the QEMU backend"

        set cfg to configuration of vm
        if name of cfg is not vmName then error "primary configuration name mismatch"
        if notes of cfg is not primaryMarker then error "primary VM marker mismatch"
        if architecture of cfg is not "aarch64" then error "primary VM architecture mismatch"
        if machine of cfg is not "virt" then error "primary QEMU machine mismatch"
        if memory of cfg is not 3072 then error "primary VM memory mismatch"
        if cpu cores of cfg is not 2 then error "primary VM CPU count mismatch"
        if hypervisor of cfg is not true then error "primary VM hypervisor is disabled"
        if uefi of cfg is not true then error "primary VM UEFI is disabled"
        if directory share mode of cfg is not none then error "primary VM directory sharing is enabled"
        if (count of qemu additional arguments of cfg) is not 0 then error "unexpected QEMU additional arguments remain"

        set systemDrives to {}
        set removableDrives to {}
        repeat with driveConfig in drives of cfg
            if removable of driveConfig is true then
                set end of removableDrives to contents of driveConfig
            else
                set end of systemDrives to contents of driveConfig
            end if
        end repeat
        if (count of systemDrives) is not 1 then error "primary VM must have exactly one system disk before installer start"
        if interface of item 1 of systemDrives is not VirtIO then error "primary system disk must use VirtIO"
        if bootMode is "installer" then
            if (count of removableDrives) is not 1 then error "primary VM must have exactly one installer ISO before installer start"
            if interface of item 1 of removableDrives is not USB then error "primary installer ISO must use USB"
        else
            if (count of removableDrives) is not 0 then error "installed primary VM must not retain removable media"
        end if

        set configuredNetworks to network interfaces of cfg
        if (count of configuredNetworks) is not 1 then error "primary VM must have exactly one network interface"
        set configuredNetwork to item 1 of configuredNetworks
        if hardware of configuredNetwork is not "virtio-net-pci" then error "primary network hardware mismatch"
        if mode of configuredNetwork is not emulated then error "primary network mode mismatch"
        if address of configuredNetwork is not primaryMacAddress then error "primary network MAC mismatch"
        set configuredForwards to port forwards of configuredNetwork
        if (count of configuredForwards) is not 2 then error "primary VM must have exactly two host forwards"
        if «class PrTl» of item 1 of configuredForwards is not «constant NtPrTcPp» then error "SSH forward is not TCP"
        if host address of item 1 of configuredForwards is not "127.0.0.1" then error "SSH forward is not loopback-only"
        if host port of item 1 of configuredForwards is not primarySshPort then error "SSH host forward mismatch"
        if guest address of item 1 of configuredForwards is not guestIpAddress then error "SSH guest address mismatch"
        if guest port of item 1 of configuredForwards is not 22 then error "SSH guest port mismatch"
        if «class PrTl» of item 2 of configuredForwards is not «constant NtPrTcPp» then error "portal forward is not TCP"
        if host address of item 2 of configuredForwards is not "127.0.0.1" then error "portal forward is not loopback-only"
        if host port of item 2 of configuredForwards is not primaryPortalPort then error "portal host forward mismatch"
        if guest address of item 2 of configuredForwards is not guestIpAddress then error "portal guest address mismatch"
        if guest port of item 2 of configuredForwards is not 8080 then error "portal guest port mismatch"

        start vm
        repeat 40 times
            if status of vm is not stopped then exit repeat
            delay 0.25
        end repeat
        if status of vm is stopped then error "primary VM did not leave the stopped state"
        if id of vm is not expectedVmId then error "primary VM UUID changed during start"
        if name of vm is not vmName then error "primary VM name changed during start"

        return {name of vm, id of vm, status of vm}
    end tell
end run
