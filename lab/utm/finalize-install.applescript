property rebuildVmName : "vivo-cp1-lab-rebuild"
property rebuildMarker : "vivolution-cp1-disposable-rebuild-v1"
property guestIpAddress : "10.0.2.15"

on run argv
    if (count of argv) is 5 then
        set vmName to item 1 of argv
        set expectedVmId to item 2 of argv
        set hostSshPort to (item 3 of argv) as integer
        set hostPortalPort to (item 4 of argv) as integer
        set macAddress to item 5 of argv
    else
        error "usage: osascript finalize-install.applescript vm-name vm-uuid ssh-port portal-port mac"
    end if

    if vmName is not rebuildVmName then error "finalization is restricted to the exact disposable rebuild VM name"
    if hostSshPort is less than 1 or hostSshPort is greater than 65535 then error "invalid SSH host port"
    if hostPortalPort is less than 1 or hostPortalPort is greater than 65535 then error "invalid portal host port"

    tell application "UTM"
        set auto terminate to false
        set vmMatches to every virtual machine whose name is vmName
        if (count of vmMatches) is not 1 then error "expected exactly one stopped UTM VM named " & vmName
        set vm to item 1 of vmMatches
        if id of vm is not expectedVmId then error "UTM VM UUID mismatch for " & vmName
        if status of vm is not stopped then error vmName & " must be stopped before finalization"

        set cfg to configuration of vm
        if notes of cfg is not rebuildMarker then error "disposable rebuild VM marker mismatch"
        set qemu additional arguments of cfg to {}
        set network interfaces of cfg to {{index:0, hardware:"virtio-net-pci", mode:emulated, address:macAddress, port forwards:{¬
            {«class PrTl»:«constant NtPrTcPp», host address:"127.0.0.1", host port:hostSshPort, guest address:guestIpAddress, guest port:22}, ¬
            {«class PrTl»:«constant NtPrTcPp», host address:"127.0.0.1", host port:hostPortalPort, guest address:guestIpAddress, guest port:8080}}}}

        -- Remove installer media by its immutable removable property. Drive
        -- order is deliberately irrelevant, and the system disk is preserved.
        set keptSystemDrives to {}
        repeat with driveConfig in drives of cfg
            if removable of driveConfig is false then set end of keptSystemDrives to contents of driveConfig
        end repeat
        if (count of keptSystemDrives) is not 1 then error vmName & " must have exactly one system disk before finalization"
        set keptSystemDiskId to id of item 1 of keptSystemDrives
        set drives of cfg to keptSystemDrives

        update configuration vm with cfg

        set verifiedCfg to configuration of vm
        if (count of qemu additional arguments of verifiedCfg) is not 0 then error "direct-kernel arguments remain after finalization"
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
        if id of item 1 of verifiedSystemDrives is not keptSystemDiskId then error "finalization changed the system disk identity"
        if (count of verifiedRemovableDrives) is not 0 then error "installer media remains after finalization"

        set verifiedNetworks to network interfaces of verifiedCfg
        if (count of verifiedNetworks) is not 1 then error "finalization did not save exactly one network interface"
        set verifiedNetwork to item 1 of verifiedNetworks
        if hardware of verifiedNetwork is not "virtio-net-pci" then error "network hardware mismatch after finalization"
        if mode of verifiedNetwork is not emulated then error "network mode is not QEMU emulated user networking"
        if address of verifiedNetwork is not macAddress then error "network MAC mismatch after finalization"
        set verifiedForwards to port forwards of verifiedNetwork
        if (count of verifiedForwards) is not 2 then error "finalization did not save exactly two host forwards"
        if «class PrTl» of item 1 of verifiedForwards is not «constant NtPrTcPp» then error "SSH forward is not TCP"
        if host address of item 1 of verifiedForwards is not "127.0.0.1" then error "SSH forward is not bound to loopback"
        if host port of item 1 of verifiedForwards is not hostSshPort then error "SSH host forward mismatch after finalization"
        if guest address of item 1 of verifiedForwards is not guestIpAddress then error "SSH guest address mismatch after finalization"
        if guest port of item 1 of verifiedForwards is not 22 then error "SSH guest forward mismatch after finalization"
        if «class PrTl» of item 2 of verifiedForwards is not «constant NtPrTcPp» then error "portal forward is not TCP"
        if host address of item 2 of verifiedForwards is not "127.0.0.1" then error "portal forward is not bound to loopback"
        if host port of item 2 of verifiedForwards is not hostPortalPort then error "portal host forward mismatch after finalization"
        if guest address of item 2 of verifiedForwards is not guestIpAddress then error "portal guest address mismatch after finalization"
        if guest port of item 2 of verifiedForwards is not 8080 then error "portal guest forward mismatch after finalization"

        return {name of vm, id of vm, status of vm, keptSystemDiskId}
    end tell
end run
