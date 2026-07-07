#!/usr/bin/env bash

patterns=(
  "/mnt/BTRFSdrive/EpicGames/*/Engine/Binaries/ThirdParty/DbgHelp/dbghelp.dll"
  "/mnt/MyDrives/NTFSdrive/EpicGames/*/Engine/Binaries/ThirdParty/DbgHelp/dbghelp.dll"
  "/mnt/MyDrives/NTFSdrive/SteamLibrary/steamapps/common/*/Engine/Binaries/ThirdParty/DbgHelp/dbghelp.dll"
)

for pattern in "${patterns[@]}"; do
  for file in $pattern; do
    [ -f "$file" ] || continue
    rm -- "$file"
  done
done
