property primaryVmName : "vivo-cp1-lab"
property primaryMarker : "vivolution-cp1-primary-lab-v1"
property primaryArchitecture : "aarch64"
property primaryMemoryMiB : 3072
property primaryCpuCores : 2
property primaryDiskSizeMiB : 65536
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
    if (count of argv) is not 0 then error "usage: osascript create-primary.applescript"

    tell application "UTM"
        set auto terminate to false

        if (count of virtual machines) is not 0 then error "UTM registry must be empty before creating the primary CP1 lab VM"

        set primaryVm to make new virtual machine with properties {backend:qemu, configuration:{name:primaryVmName, notes:primaryMarker, architecture:primaryArchitecture, machine:"virt", memory:primaryMemoryMiB, cpu cores:primaryCpuCores, hypervisor:true, uefi:true, directory share mode:none, drives:{{removable:false, interface:VirtIO, guest size:primaryDiskSizeMiB, raw:false}}, network interfaces:{{index:0, hardware:"virtio-net-pci", mode:emulated, address:primaryMacAddress, port forwards:{{«class PrTl»:«constant NtPrTcPp», host address:"127.0.0.1", host port:hostSshPort, guest address:guestIpAddress, guest port:22}, {«class PrTl»:«constant NtPrTcPp», host address:"127.0.0.1", host port:hostPortalPort, guest address:guestIpAddress, guest port:8080}}}}, «class SrPt»:{{index:0, interface:ptty}}, displays:{}, qemu additional arguments:{}}}
        set primaryVmId to id of primaryVm
        if not my uuidIsValid(primaryVmId) then error "UTM returned an invalid primary VM UUID"

        -- Return the generated identity immediately. All configuration checks
        -- run only after the shell driver has persisted this UUID, closing the
        -- failure window between UTM creation and ownership recording.
        return primaryVmId
    end tell
end run
