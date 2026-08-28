property workingVmName : "vivo-cp1-lab"
property workingVmId : "81C7DE36-9421-4E1C-AC4E-48336131D1EC"
property rebuildVmName : "vivo-cp1-lab-rebuild"
property rebuildMarker : "vivolution-cp1-disposable-rebuild-v1"

on run argv
    if (count of argv) is greater than 1 then error "usage: osascript prepare-rebuild-clone.applescript [previous-rebuild-uuid]"
    if (count of argv) is 1 then
        set previousRebuildId to item 1 of argv
    else
        set previousRebuildId to ""
    end if
    if previousRebuildId is workingVmId then error "the disposable UUID must never equal the protected working VM UUID"

    tell application "UTM"
        set auto terminate to false

        set sourceMatches to every virtual machine whose name is workingVmName
        if (count of sourceMatches) is not 1 then error "expected exactly one protected working VM named " & workingVmName
        set sourceVm to item 1 of sourceMatches
        if id of sourceVm is not workingVmId then error "protected working VM UUID mismatch"
        if status of sourceVm is not stopped then error workingVmName & " must already be stopped; this workflow will never stop it"
        if backend of sourceVm is not qemu then error "protected working VM must use the QEMU backend"

        set sourceCfg to configuration of sourceVm
        if architecture of sourceCfg is not "aarch64" then error "protected working VM must use the aarch64 architecture"
        set sourceSystemDrives to {}
        repeat with driveConfig in drives of sourceCfg
            if removable of driveConfig is false then set end of sourceSystemDrives to contents of driveConfig
        end repeat
        if (count of sourceSystemDrives) is not 1 then error "protected working VM must have exactly one system disk"
        set protectedSystemDiskId to id of item 1 of sourceSystemDrives

        set targetMatches to every virtual machine whose name is rebuildVmName
        if (count of targetMatches) is greater than 1 then error "refusing ambiguous duplicate VMs named " & rebuildVmName
        if (count of targetMatches) is 1 then
            set oldTargetVm to item 1 of targetMatches
            if id of oldTargetVm is workingVmId then error "refusing to delete the protected working VM"
            if status of oldTargetVm is not stopped then error rebuildVmName & " must be stopped before replacement"
            set oldTargetCfg to configuration of oldTargetVm
            if notes of oldTargetCfg is not rebuildMarker then error "existing rebuild VM lacks the managed-disposable marker"

            if previousRebuildId is "" or id of oldTargetVm is not previousRebuildId then
                -- Recover only the narrow crash window after UTM completed a
                -- marked clone but before the driver persisted its new UUID. A
                -- raw clone retains the source drive id; a configured rebuild
                -- does not, so unknown same-name VMs are still refused.
                if previousRebuildId is not "" then
                    set recordedIdMatches to every virtual machine whose id is previousRebuildId
                    if (count of recordedIdMatches) is not 0 then error "recorded disposable UUID belongs to another registered VM; refusing recovery"
                end if
                set orphanSystemDrives to {}
                repeat with driveConfig in drives of oldTargetCfg
                    if removable of driveConfig is false then set end of orphanSystemDrives to contents of driveConfig
                end repeat
                if (count of orphanSystemDrives) is not 1 then error "unrecorded rebuild VM is not a raw managed clone; refusing to delete it"
                if id of item 1 of orphanSystemDrives is not protectedSystemDiskId then error "unrecorded rebuild VM is not a raw managed clone; refusing to delete it"
            end if

            delete oldTargetVm
            repeat 60 times
                if (count of (every virtual machine whose name is rebuildVmName)) is 0 then exit repeat
                delay 0.5
            end repeat
            if (count of (every virtual machine whose name is rebuildVmName)) is not 0 then error "timed out deleting the prior disposable rebuild VM"
        else if previousRebuildId is not "" then
            -- A stale state file is harmless when no same-name VM exists.
            set previousRebuildId to ""
        end if

        -- UTM duplicates the stopped source into a different VM bundle. Only
        -- the clone configuration is renamed and marked as disposable.
        duplicate sourceVm with properties {configuration:{name:rebuildVmName, notes:rebuildMarker}}
        repeat 60 times
            set newTargetMatches to every virtual machine whose name is rebuildVmName
            if (count of newTargetMatches) is 1 then exit repeat
            delay 0.5
        end repeat
        set newTargetMatches to every virtual machine whose name is rebuildVmName
        if (count of newTargetMatches) is not 1 then error "UTM did not create one exact-name disposable clone"
        set rebuildVm to item 1 of newTargetMatches

        if id of rebuildVm is workingVmId then error "UTM returned the protected working VM instead of a clone"
        if status of rebuildVm is not stopped then error "new disposable clone is not stopped"
        set rebuildCfg to configuration of rebuildVm
        if notes of rebuildCfg is not rebuildMarker then error "new disposable clone marker was not saved"

        -- Re-read the protected source after duplication and prove that UTM
        -- retained its VM identity and system-drive identity.
        set sourceAfterMatches to every virtual machine whose name is workingVmName
        if (count of sourceAfterMatches) is not 1 then error "protected working VM disappeared during clone"
        set sourceAfterVm to item 1 of sourceAfterMatches
        if id of sourceAfterVm is not workingVmId then error "protected working VM identity changed during clone"
        set sourceAfterCfg to configuration of sourceAfterVm
        set sourceAfterSystemDrives to {}
        repeat with driveConfig in drives of sourceAfterCfg
            if removable of driveConfig is false then set end of sourceAfterSystemDrives to contents of driveConfig
        end repeat
        if (count of sourceAfterSystemDrives) is not 1 then error "protected working VM system-drive count changed during clone"
        if id of item 1 of sourceAfterSystemDrives is not protectedSystemDiskId then error "protected working VM system-drive identity changed during clone"

        set exactTargetMatches to every virtual machine whose name is rebuildVmName
        if (count of exactTargetMatches) is not 1 then error "exact disposable clone name is not unique"
        return id of rebuildVm
    end tell
end run
