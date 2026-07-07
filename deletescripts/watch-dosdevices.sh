#!/usr/bin/env bash

roots=(
  "/mnt/BTRFSdrive/Steam/steamapps/compatdata"
  "/mnt/BTRFSdrive/EpicGames/Prefixes"
)

for root in "${roots[@]}"; do
  [ -d "$root" ] || continue

  find "$root" -type d -path '*/pfx/dosdevices' -print0 |
  while IFS= read -r -d '' dir; do
    inotifywait -m -e create -e moved_to --format '%f' "$dir" | while read -r f; do
      case "$f" in
        z:|Z:) rm -- "$dir/$f" ;;
      esac
    done &
  done
done

wait
