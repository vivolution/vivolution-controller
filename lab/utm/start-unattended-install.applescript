property rebuildVmName : "vivo-cp1-lab-rebuild"
property rebuildMarker : "vivolution-cp1-disposable-rebuild-v1"

on run argv
    if (count of argv) is 2 then
        set vmName to item 1 of argv
        set expectedVmId to item 2 of argv
    else
        error "usage: osascript start-unattended-install.applescript vm-name vm-uuid"
    end if

    if vmName is not rebuildVmName then error "start is restricted to the exact disposable rebuild VM name"
    tell application "UTM"
        set auto terminate to false
        set vmMatches to every virtual machine whose name is vmName
        if (count of vmMatches) is not 1 then error "expected exactly one stopped UTM VM named " & vmName
        set vm to item 1 of vmMatches
        if id of vm is not expectedVmId then error "UTM VM UUID mismatch for " & vmName
        if status of vm is not stopped then error vmName & " must be stopped before start"
        set cfg to configuration of vm
        if notes of cfg is not rebuildMarker then error "disposable rebuild VM marker mismatch"
        start vm

        return {name of vm, id of vm, status of vm}
    end tell
end run
