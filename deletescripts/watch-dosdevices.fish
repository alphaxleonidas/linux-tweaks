#!/usr/bin/env fish

set roots \
    /mnt/BTRFSdrive/Steam/steamapps/compatdata \
    /mnt/BTRFSdrive/EpicGames/Prefixes

for root in $roots
    if not test -d "$root"
        continue
    end

    find "$root" -type d -path '*/pfx/dosdevices' -print0 | \
    while read -lz dir
        inotifywait -m -e create -e moved_to --format '%f' "$dir" | while read f
            switch $f
                case 'z:' 'Z:'
                    rm -- "$dir/$f"
            end
        end &
    end
end

wait
