#!/usr/bin/env fish

set patterns \
  "/mnt/BTRFSdrive/EpicGames/*/Engine/Binaries/ThirdParty/DbgHelp/dbghelp.dll" \
  "/mnt/MyDrives/NTFSdrive/EpicGames/*/Engine/Binaries/ThirdParty/DbgHelp/dbghelp.dll" \
  "/mnt/MyDrives/NTFSdrive/SteamLibrary/steamapps/common/*/Engine/Binaries/ThirdParty/DbgHelp/dbghelp.dll"

for pattern in $patterns
    for file in $pattern
        if test -f "$file"
            rm -- "$file"
        end
    end
end
