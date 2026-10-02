#!/bin/bash

# ----------------------------------------------------------------------
# Nautilus script: vt-scan
# Purpose: Scan selected files/folders with VirusTotal, show stats,
#          open reports in background tabs (optional), and upload missing files.
# Usage:   Right-click on files/folders -> Scripts -> vt-scan
#          or run directly: ./vt-scan.sh [OPTIONS] [FILE...]
#          Run ./vt-scan.sh --help for all options.
# ----------------------------------------------------------------------

# #!/data/data/com.termux/files/usr/bin/bash # uncomment this shebang for termux

export VT_SCAN_RUNNING=1

# ----------------------------- Paths ------------------------------------

CONFIG_DIR="$HOME/.vtscan"
LOG_DIR="$CONFIG_DIR/logs"
CONFIG_FILE="$CONFIG_DIR/config"
KEY_FILE_1="$CONFIG_DIR/api_key1"
KEY_FILE_2="$CONFIG_DIR/api_key2"
KEY_FILE_3="$CONFIG_DIR/api_key3"
KEY_FILE_4="$CONFIG_DIR/api_key4"
LEGACY_KEY_FILE="$HOME/.vt_api_key"

mkdir -p "$CONFIG_DIR" "$LOG_DIR" 2>/dev/null

# Migrate a pre-existing single key from the old location, once.
if [[ -f "$LEGACY_KEY_FILE" && ! -f "$KEY_FILE_1" ]]; then
    cp "$LEGACY_KEY_FILE" "$KEY_FILE_1" 2>/dev/null
    chmod 600 "$KEY_FILE_1" 2>/dev/null
fi

TMP_RESPONSE="/tmp/vt_response_$$.json"
trap 'rm -f "$TMP_RESPONSE"' EXIT

# ----------------------------- Defaults ----------------------------------
# These are the built-in fallbacks. They get overridden by ~/.vtscan/config
# (if present) and then by any CLI flags, in that order.

TAB_COUNT=0
PAUSE_AFTER=20
MISSING_FILES=()
REPORT_URLS=()
UPLOADED_REPORT_URLS=()
UPLOADED_PATHS=()
UPLOADED_SHAS=()
UPLOADED_DIRS=()
UPLOADED_BASES=()
MALWARE_PATHS=()
MALWARE_SHAS=()
MALWARE_STATS=()
MALWARE_URLS=()
MALWARE_DIRS=()
MALWARE_BASES=()

MAX_UPLOAD_BYTES=$((650 * 1024 * 1024))   # VirusTotal hard limit
DIRECT_UPLOAD_LIMIT=$((32 * 1024 * 1024)) # above this, VT requires the upload_url flow

CFG_OPEN_BROWSER_SCAN=false      # open report pages during the scan loop
CFG_UPLOAD_MISSING=false         # upload missing files as soon as they're found
CFG_OPEN_BROWSER_UPLOAD_LIVE=false  # open browser for on-the-fly uploads
CFG_OPEN_BROWSER_UPLOAD_BATCH=false # open browser for the end-of-run batch upload
CFG_ALLOW_LARGE_UPLOADS=true     # allow the >32MB upload_url path at all
CFG_NOTIFY=false                 # desktop notification on successful upload
CFG_SKIP_PROMPTS=false           # if true, never ask - just use these values

# Values actually used this run (start as copies of the config defaults,
# may be overridden by prompts or CLI flags below).
OPEN_BROWSER_SCAN="$CFG_OPEN_BROWSER_SCAN"
UPLOAD_MISSING="$CFG_UPLOAD_MISSING"
OPEN_BROWSER_UPLOAD_LIVE="$CFG_OPEN_BROWSER_UPLOAD_LIVE"
OPEN_BROWSER_UPLOAD_BATCH="$CFG_OPEN_BROWSER_UPLOAD_BATCH"
ALLOW_LARGE_UPLOADS="$CFG_ALLOW_LARGE_UPLOADS"
NOTIFY="$CFG_NOTIFY"
SKIP_PROMPTS="$CFG_SKIP_PROMPTS"

CLI_ALLOW_LARGE=""   # "" = not set on CLI, "true"/"false" = forced
CLI_NOTIFY=""
FORCE_ASK=false
FORCE_USE_CONFIG=false
WRITE_CONFIG_MODE=false

# ----------------------------- Help ---------------------------------------

print_help() {
    cat <<'EOF'
vt-scan.sh - Scan files with VirusTotal from Nautilus or the terminal.

USAGE:
  vt-scan.sh [OPTIONS] [FILE...]

  With no FILE arguments: scans the current directory, or (when launched
  from Nautilus) whatever is selected in the file manager. Multiple files
  and/or folders can be passed and are scanned one after another, e.g.:
      vt-scan.sh /path/to/one /path/to/two /path/to/three

OPTIONS:
  -h, --help              Show this help and exit.

  --reset-key             (Re)enter the primary VirusTotal API key.
  --reset-key2            (Re)enter the secondary API key. Used automatically
                           when the primary key gets rate-limited (HTTP 429).
  --reset-key3            (Re)enter the tertiary API key. Used automatically
                           when both the primary and secondary keys are
                           rate-limited.
  --reset-key4            (Re)enter the quaternary API key. Used automatically
                           when the primary, secondary, and tertiary keys are
                           all rate-limited.

  --write-config, --config
                           Ask every setting below, save the answers to
                           ~/.vtscan/config as the new defaults, then exit
                           without scanning anything.
  --use-config            Skip all setting prompts for this run and use
                           whatever is saved in ~/.vtscan/config (same
                           effect as "skip prompts" in the config, but
                           just for this run).
  --ask                   Always show the setting prompts for this run,
                           even if the saved config has "skip prompts" on.

  --allow-large-uploads   Allow uploading files that require VirusTotal's
                           large-file (>32MB) upload path. Overrides config.
  --no-large-uploads      Skip files that would need the large-file upload
                           path (they're still reported as "missing").
                           Overrides config.

  --notify                Show a desktop notification after each successful
                           upload. Overrides config.
  --no-notify             Don't show desktop notifications. Overrides config.

CONFIG & LOGS:
  Settings live in ~/.vtscan/config (created with --write-config, or the
  first time you answer "yes" to "save these as defaults?").
  Every run is logged to its own timestamped file under ~/.vtscan/logs/.

EXAMPLES:
  vt-scan.sh                       Scan the current directory, with prompts.
  vt-scan.sh file1 file2 dir/      Scan several files/folders in one run.
  vt-scan.sh --use-config          Scan using saved defaults, no prompts.
  vt-scan.sh --no-large-uploads file.iso   Skip it if it needs a big upload.
  vt-scan.sh --reset-key2          Set/replace the secondary API key.
EOF
}

# ----------------------------- API key helpers ----------------------------

save_api_key() {
    local slot="$1" file="$2" label="$3"
    local key
    read -rp "Enter your $label VirusTotal API key: " key
    if [[ -z "$key" ]]; then
        echo "Error: API key cannot be empty." >&2
        exit 1
    fi
    echo "$key" > "$file"
    chmod 600 "$file"
    echo "$label API key saved to $file"
}

# Build the ordered list of usable API keys.
load_api_keys() {
    API_KEYS=()
    for f in "$KEY_FILE_1" "$KEY_FILE_2" "$KEY_FILE_3" "$KEY_FILE_4"; do
        if [[ -f "$f" ]]; then
            local k
            k=$(<"$f")
            [[ -n "$k" ]] && API_KEYS+=("$k")
        fi
    done
    if [[ ${#API_KEYS[@]} -eq 0 ]]; then
        echo "No API key found. Let's set up your VirusTotal API key(s)." >&2
        save_api_key 1 "$KEY_FILE_1" "primary"
        API_KEYS+=("$(<"$KEY_FILE_1")")

        local add_secondary
        read -rp "Add a secondary API key now (used automatically if the primary gets rate-limited)? (y/N): " add_secondary
        if [[ "$add_secondary" =~ ^[Yy]$ ]]; then
            save_api_key 2 "$KEY_FILE_2" "secondary"
            API_KEYS+=("$(<"$KEY_FILE_2")")

            local add_tertiary
            read -rp "Add a tertiary API key as well (used if both primary and secondary are rate-limited)? (y/N): " add_tertiary
            if [[ "$add_tertiary" =~ ^[Yy]$ ]]; then
                save_api_key 3 "$KEY_FILE_3" "tertiary"
                API_KEYS+=("$(<"$KEY_FILE_3")")

                local add_quaternary
                read -rp "Add a quaternary API key too (used if all three others are rate-limited)? (y/N): " add_quaternary
                if [[ "$add_quaternary" =~ ^[Yy]$ ]]; then
                    save_api_key 4 "$KEY_FILE_4" "quaternary"
                    API_KEYS+=("$(<"$KEY_FILE_4")")
                fi
            fi
        fi
    fi
}

CURRENT_KEY_IDX=0
current_api_key() { echo "${API_KEYS[$CURRENT_KEY_IDX]}"; }

rotate_key() {
    if (( CURRENT_KEY_IDX + 1 < ${#API_KEYS[@]} )); then
        ((CURRENT_KEY_IDX++))
        echo "   🔑 Current key rate-limited - switching to backup key #$((CURRENT_KEY_IDX + 1))." >&2
        return 0
    fi
    return 1
}

# Generic authenticated VirusTotal request with automatic key rotation and
# bounded retry on HTTP 429. Prints the final HTTP status code on stdout;
# the response body is written to $outfile.
#   vt_request METHOD URL OUTFILE [extra curl args...]
vt_request() {
    local method="$1" url="$2" outfile="$3"
    shift 3
    local http_code rounds=0 max_rounds=3
    while true; do
        http_code=$(curl -s -o "$outfile" -w "%{http_code}" -X "$method" \
            -H "x-apikey: $(current_api_key)" "$@" "$url")
        if [[ "$http_code" == "429" ]]; then
            if rotate_key; then
                continue
            fi
            ((rounds++))
            if (( rounds >= max_rounds )); then
                echo "   ⏳ Still rate-limited on every key after $rounds attempt(s). Giving up on this request." >&2
                break
            fi
            echo "   ⏳ All API keys are rate-limited. Waiting 60 seconds before retrying..." >&2
            sleep 60
            CURRENT_KEY_IDX=0
            continue
        fi
        break
    done
    printf '%s' "$http_code"
}

# ----------------------------- Config helpers ------------------------------

# source-load the config file safely (only known CFG_* vars, one per line
# in KEY=VALUE form - we don't `source` it directly to avoid executing
# arbitrary content if the file ever got corrupted/tampered).
load_config() {
    [[ -f "$CONFIG_FILE" ]] || return 0
    while IFS='=' read -r key value; do
        [[ -z "$key" || "$key" == \#* ]] && continue
        case "$key" in
            CFG_OPEN_BROWSER_SCAN|CFG_UPLOAD_MISSING|CFG_OPEN_BROWSER_UPLOAD_LIVE|\
            CFG_OPEN_BROWSER_UPLOAD_BATCH|CFG_ALLOW_LARGE_UPLOADS|CFG_NOTIFY|CFG_SKIP_PROMPTS)
                printf -v "$key" '%s' "$value"
                ;;
        esac
    done < "$CONFIG_FILE"
}

write_config() {
    cat > "$CONFIG_FILE" <<EOF
# vt-scan config - generated $(date '+%Y-%m-%d %H:%M:%S')
CFG_OPEN_BROWSER_SCAN=$OPEN_BROWSER_SCAN
CFG_UPLOAD_MISSING=$UPLOAD_MISSING
CFG_OPEN_BROWSER_UPLOAD_LIVE=$OPEN_BROWSER_UPLOAD_LIVE
CFG_OPEN_BROWSER_UPLOAD_BATCH=$OPEN_BROWSER_UPLOAD_BATCH
CFG_ALLOW_LARGE_UPLOADS=$ALLOW_LARGE_UPLOADS
CFG_NOTIFY=$NOTIFY
CFG_SKIP_PROMPTS=$SKIP_PROMPTS
EOF
    chmod 600 "$CONFIG_FILE"
    echo "Saved settings to $CONFIG_FILE" >&2
}

# Ask a y/n question; $2 is the default ("true"/"false") shown as the
# capital letter. Writes "true"/"false" into the variable named by $3.
prompt_yn() {
    local prompt="$1" default="$2" varname="$3" hint ans
    if [[ "$default" == "true" ]]; then hint="Y/n"; else hint="y/N"; fi
    read -rp "$prompt ($hint): " ans
    if [[ -z "$ans" ]]; then
        printf -v "$varname" '%s' "$default"
        return
    fi
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        printf -v "$varname" '%s' "true"
    else
        printf -v "$varname" '%s' "false"
    fi
}

run_setting_prompts() {
    prompt_yn "Upload files with no VirusTotal report as they're found" "$UPLOAD_MISSING" UPLOAD_MISSING
    prompt_yn "Open uploaded files' report in the browser (on-the-fly uploads)" "$OPEN_BROWSER_UPLOAD_LIVE" OPEN_BROWSER_UPLOAD_LIVE
    prompt_yn "Open reports in browser during the scan" "$OPEN_BROWSER_SCAN" OPEN_BROWSER_SCAN
    prompt_yn "Allow uploading large files (>32MB, needs VirusTotal's slower upload path)" "$ALLOW_LARGE_UPLOADS" ALLOW_LARGE_UPLOADS
    prompt_yn "Show a desktop notification after each successful upload" "$NOTIFY" NOTIFY
}

# ----------------------------- Misc helpers -------------------------------

open_url_background() {
    local url="$1"
    if command -v xdotool &>/dev/null; then
        local current_win
        current_win=$(xdotool getwindowfocus 2>/dev/null)
        if [[ -z "$current_win" ]]; then
            current_win=$(xdotool getactivewindow 2>/dev/null)
        fi
        (xdg-open "$url" &) 2>/dev/null
        sleep 1
        if [[ -n "$current_win" ]]; then
            xdotool windowactivate "$current_win" 2>/dev/null
            sleep 0.2
            xdotool windowactivate "$current_win" 2>/dev/null
        fi
        return
    fi
    (xdg-open "$url" &) 2>/dev/null
}

uri_to_path() {
    local uri="$1"
    local path="${uri#file://}"
    # Decode every %XX escape, not just %20 - Nautilus URI-encodes any
    # character outside a small safe set, so accented letters, &, #, etc.
    # need the same treatment as spaces.
    printf '%b' "${path//%/\\x}"
}

# Percent-encode a filesystem path for use inside a file:// URL. Needed
# because paths routinely contain spaces (and other characters) that a
# literal file://<path> URL breaks on - browsers/file managers won't
# resolve "file:///a b/c" correctly, but they will resolve "file:///a%20b/c".
path_to_file_uri() {
    local LC_ALL=C
    local path="$1" out="" c i len=${#1}
    for (( i=0; i<len; i++ )); do
        c="${path:i:1}"
        case "$c" in
            [a-zA-Z0-9./_-]) out+="$c" ;;
            *)
                printf -v hex '%02X' "'$c"
                out+="%$hex"
                ;;
        esac
    done
    printf '%s' "$out"
}

extract_stats() {
    local json_file="$1"
    if command -v jq &>/dev/null; then
        jq -r '.data.attributes.last_analysis_stats |
            "malicious: \(.malicious // 0)\nsuspicious: \(.suspicious // 0)\nundetected: \(.undetected // 0)\nharmless: \(.harmless // 0)\ntimeout: \(.timeout // 0)"' "$json_file" 2>/dev/null
    else
        local malicious suspicious undetected harmless timeout
        malicious=$(grep -o '"malicious":[[:space:]]*[0-9]*' "$json_file" 2>/dev/null | grep -o '[0-9]*$' | head -1)
        suspicious=$(grep -o '"suspicious":[[:space:]]*[0-9]*' "$json_file" 2>/dev/null | grep -o '[0-9]*$' | head -1)
        undetected=$(grep -o '"undetected":[[:space:]]*[0-9]*' "$json_file" 2>/dev/null | grep -o '[0-9]*$' | head -1)
        harmless=$(grep -o '"harmless":[[:space:]]*[0-9]*' "$json_file" 2>/dev/null | grep -o '[0-9]*$' | head -1)
        timeout=$(grep -o '"timeout":[[:space:]]*[0-9]*' "$json_file" 2>/dev/null | grep -o '[0-9]*$' | head -1)
        echo "malicious: ${malicious:-0}"
        echo "suspicious: ${suspicious:-0}"
        echo "undetected: ${undetected:-0}"
        echo "harmless: ${harmless:-0}"
        echo "timeout: ${timeout:-0}"
    fi
}

get_file_size() {
    local file="$1"
    if command -v stat &>/dev/null; then
        if stat -c '%s' "$file" 2>/dev/null; then
            return
        elif stat -f '%z' "$file" 2>/dev/null; then
            return
        fi
    fi
    wc -c < "$file" 2>/dev/null | tr -d ' '
}

# ----------------------------- Upload ---------------------------------------

# upload_file FILE SHA OPEN_BROWSER_FLAG
upload_file() {
    local file="$1" sha="$2" open_flag="${3:-false}"
    if [[ -z "$sha" ]]; then
        sha=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
        if [[ -z "$sha" ]]; then
            echo "   ⚠️  Could not compute hash for '$file' - skipping upload." >&2
            return 1
        fi
    fi

    local filesize
    filesize=$(get_file_size "$file")
    if [[ -z "$filesize" ]]; then
        echo "   ⚠️  Could not determine file size for '$file' - skipping." >&2
        return 1
    fi
    if [[ "$filesize" -gt "$MAX_UPLOAD_BYTES" ]]; then
        local size_mb=$(( filesize / 1024 / 1024 ))
        echo "   ⚠️  File too large (${size_mb}MB) - VirusTotal's hard limit is 650MB. Skipping upload." >&2
        return 1
    fi
    if [[ "$filesize" -gt "$DIRECT_UPLOAD_LIMIT" && "$ALLOW_LARGE_UPLOADS" != "true" ]]; then
        local size_mb=$(( filesize / 1024 / 1024 ))
        echo "   ⚠️  Skipping upload of '$(basename "$file")' (${size_mb}MB) - large-file uploads are disabled." >&2
        echo "      Re-run with --allow-large-uploads (or change it in --write-config) to allow this." >&2
        return 1
    fi

    local upload_response="/tmp/vt_upload_$$.json"
    local http_code

    if [[ "$filesize" -le "$DIRECT_UPLOAD_LIMIT" ]]; then
        # ---- Direct upload (<=32 MB) ----
        echo "   ⬆️  Uploading (direct): $(basename "$file")" >&2
        http_code=$(vt_request POST "https://www.virustotal.com/api/v3/files" "$upload_response" \
            -F "file=@$file")
    else
        # ---- Two-step upload via upload_url (>32 MB and <=650 MB) ----
        echo "   ⬆️  Uploading (large file via upload_url): $(basename "$file")" >&2

        local upload_url_response="/tmp/vt_upload_url_$$.json"
        http_code=$(vt_request GET "https://www.virustotal.com/api/v3/files/upload_url" "$upload_url_response")
        if [[ "$http_code" != "200" ]]; then
            echo "   ❌ Failed to get an upload URL (HTTP $http_code)." >&2
            rm -f "$upload_url_response"
            return 1
        fi

        local upload_url
        if command -v jq &>/dev/null; then
            upload_url=$(jq -r '.data' "$upload_url_response" 2>/dev/null)
        else
            upload_url=$(grep -o '"data":"[^"]*"' "$upload_url_response" 2>/dev/null | head -1 | cut -d'"' -f4)
        fi
        rm -f "$upload_url_response"
        if [[ -z "$upload_url" || "$upload_url" == "null" ]]; then
            echo "   ❌ Could not extract the upload URL from VirusTotal's response." >&2
            return 1
        fi

        # NOTE: this special URL must be POSTed to as multipart form data,
        # exactly like the direct-upload endpoint - it is NOT a raw PUT
        # target. Sending a PUT here is what produced the earlier "HTTP 303"
        # failures: the endpoint replies with a redirect that a plain PUT
        # doesn't follow, so curl reports the 303 itself as if it were the
        # final result, even though the bytes were already sent over the
        # wire (hence "it looked like it uploaded, then failed at the end").
        # It also turns out this URL is NOT pre-authorized on its own - VT
        # returned "401 X-Apikey header is missing" without it, so the key
        # has to be sent here too, same as every other VT API call. Routed
        # through vt_request so a rate-limit here also rotates keys.
        http_code=$(vt_request POST "$upload_url" "$upload_response" -L -F "file=@$file")
    fi

    if [[ "$http_code" == "200" ]]; then
        local url="https://www.virustotal.com/gui/file/$sha"
        echo "   ✅ Upload successful: $url" >&2
        UPLOADED_REPORT_URLS+=("$url")
        UPLOADED_PATHS+=("$file")
        UPLOADED_SHAS+=("$sha")
        UPLOADED_DIRS+=("$(dirname "$file")")
        UPLOADED_BASES+=("$(basename "$file")")
        if [[ "$open_flag" == "true" ]]; then
            echo "   Opening upload result page..." >&2
            open_url_background "$url"
        fi
        if [[ "$NOTIFY" == "true" ]] && command -v notify-send &>/dev/null; then
            notify-send -t 5000 "VirusTotal Upload" "Uploaded: $(basename "$file")" 2>/dev/null
        fi
    elif [[ "$http_code" == "413" ]]; then
        echo "   ❌ Upload failed: file too large (413). VirusTotal's limit is 650MB." >&2
    elif [[ "$http_code" == "303" ]]; then
        echo "   ❌ Upload failed (HTTP 303 - unexpected redirect). If this keeps happening the upload_url" >&2
        echo "      VirusTotal issued may have expired mid-transfer for a very large/slow upload; try again." >&2
    else
        echo "   ❌ Upload failed (HTTP $http_code)." >&2
        cat "$upload_response" >&2 2>/dev/null
    fi
    rm -f "$upload_response"
    return 0
}

# Re-fetch and print the current VirusTotal report for a file that was
# uploaded this run. Any malicious/suspicious result found here is folded
# into the same MALWARE_* arrays process_file() uses, so it shows up in the
# end-of-run malware summary too. On success, the report URL is appended to
# the global UPLOADED_VIEW_URLS array so the caller can offer to open it.
print_uploaded_result() {
    local file="$1" sha="$2" dir_path="$3" base_name="$4"
    local resp="/tmp/vt_view_$$_${RANDOM}.json"
    local http_code
    http_code=$(vt_request GET "https://www.virustotal.com/api/v3/files/$sha" "$resp")

    echo "➜ Processing: $file" >&2
    echo "   SHA256: $sha" >&2

    if [[ "$http_code" == "200" ]]; then
        local stats_raw malicious_count suspicious_count report_url
        stats_raw=$(extract_stats "$resp")
        malicious_count=$(echo "$stats_raw" | awk -F': ' '/^malicious:/{print $2}')
        suspicious_count=$(echo "$stats_raw" | awk -F': ' '/^suspicious:/{print $2}')
        malicious_count=${malicious_count:-0}
        suspicious_count=${suspicious_count:-0}
        report_url="https://www.virustotal.com/gui/file/$sha"

        echo "   📊 Stats:" >&2
        echo "$stats_raw" | sed -e 's/malicious:/☠️ malicious:/' \
                                 -e 's/suspicious:/⚠️ suspicious:/' \
                                 -e 's/undetected:/✅ undetected:/' \
                                 -e 's/harmless:/😇 harmless:/' \
                                 -e 's/timeout:/⏰ timeout:/' | sed 's/^/      /' >&2
        echo "   🔗 Report: $report_url" >&2
        echo "   📂 Open Folder: file://$(path_to_file_uri "$dir_path")/" >&2
        echo "   📄 File: $base_name" >&2

        if [[ "$malicious_count" -gt 0 || "$suspicious_count" -gt 0 ]]; then
            MALWARE_PATHS+=("$file")
            MALWARE_SHAS+=("$sha")
            MALWARE_STATS+=("$stats_raw")
            MALWARE_URLS+=("$report_url")
            MALWARE_DIRS+=("$dir_path")
            MALWARE_BASES+=("$base_name")
        fi
        UPLOADED_VIEW_URLS+=("$report_url")
    else
        echo "   ⏳ No results yet (HTTP $http_code) - VirusTotal may still be analyzing this upload." >&2
        echo "   📂 Open Folder: file://$(path_to_file_uri "$dir_path")/" >&2
        echo "   📄 File: $base_name" >&2
    fi
    rm -f "$resp"
    echo >&2
}

# ----------------------------- Scan a single file ---------------------------

process_file() {
    local file="$1"
    local sha
    sha=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
    if [[ -z "$sha" ]]; then
        echo "⚠️  Could not compute hash for '$file' - skipping." >&2
        return
    fi

    local abs_path dir_path base_name
    abs_path=$(realpath "$file")
    dir_path=$(dirname "$abs_path")
    base_name=$(basename "$abs_path")

    echo "➜ Processing: $abs_path" >&2
    echo "   SHA256: $sha" >&2

    local http_code
    http_code=$(vt_request GET "https://www.virustotal.com/api/v3/files/$sha" "$TMP_RESPONSE")

    if [[ "$http_code" == "200" ]]; then
        local report_url="https://www.virustotal.com/gui/file/$sha"
        REPORT_URLS+=("$report_url")

        local stats_raw malicious_count suspicious_count
        stats_raw=$(extract_stats "$TMP_RESPONSE")
        malicious_count=$(echo "$stats_raw" | awk -F': ' '/^malicious:/{print $2}')
        suspicious_count=$(echo "$stats_raw" | awk -F': ' '/^suspicious:/{print $2}')
        malicious_count=${malicious_count:-0}
        suspicious_count=${suspicious_count:-0}

        echo "   📊 Stats:" >&2
        echo "$stats_raw" | sed -e 's/malicious:/☠️ malicious:/' \
                                            -e 's/suspicious:/⚠️ suspicious:/' \
                                            -e 's/undetected:/✅ undetected:/' \
                                            -e 's/harmless:/😇 harmless:/' \
                                            -e 's/timeout:/⏰ timeout:/' | sed 's/^/      /' >&2
        echo "   🔗 Report: $report_url" >&2

        if [[ "$malicious_count" -gt 0 || "$suspicious_count" -gt 0 ]]; then
            MALWARE_PATHS+=("$abs_path")
            MALWARE_SHAS+=("$sha")
            MALWARE_STATS+=("$stats_raw")
            MALWARE_URLS+=("$report_url")
            MALWARE_DIRS+=("$dir_path")
            MALWARE_BASES+=("$base_name")
        fi

        if [[ "$OPEN_BROWSER_SCAN" == "true" ]]; then
            echo "   Opening browser tab in background..." >&2
            open_url_background "$report_url"
            ((TAB_COUNT++))
        else
            echo "   (Browser opening disabled)" >&2
        fi

        echo "   📂 Open Folder: file://$(path_to_file_uri "$dir_path")/" >&2
        echo "   📄 File: $base_name" >&2

        if [[ "$OPEN_BROWSER_SCAN" == "true" ]] && (( TAB_COUNT % PAUSE_AFTER == 0 )); then
            local cont
            read -rp "Opened $TAB_COUNT tabs. Continue opening? (Y/n): " cont
            cont="${cont:-y}"
            if [[ ! "$cont" =~ ^[Yy]$ ]]; then
                OPEN_BROWSER_SCAN=false
                echo "   🔒 Further browser opening disabled." >&2
            fi
        fi

    elif [[ "$http_code" == "404" ]]; then
        echo "   ❌ No report found for this hash." >&2
        echo "   📂 Open Folder: file://$(path_to_file_uri "$dir_path")/" >&2
        echo "   📄 File: $base_name" >&2

        if [[ "$UPLOAD_MISSING" == "true" ]]; then
            upload_file "$abs_path" "$sha" "$OPEN_BROWSER_UPLOAD_LIVE"
        else
            echo "   💡 Will be offered for upload at the end of the scan." >&2
            MISSING_FILES+=("$abs_path")
        fi
    else
        echo "   ⚠️  Unexpected HTTP status $http_code - check your API key(s) or network." >&2
        echo "   📂 Open Folder: file://$(path_to_file_uri "$dir_path")/" >&2
        echo "   📄 File: $base_name" >&2
    fi
}

# ----------------------------- Argument parsing -----------------------------

POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            print_help
            exit 0
            ;;
        --reset-key)
            save_api_key 1 "$KEY_FILE_1" "primary"
            exit 0
            ;;
        --reset-key2)
            save_api_key 2 "$KEY_FILE_2" "secondary"
            exit 0
            ;;
        --reset-key3)
            save_api_key 3 "$KEY_FILE_3" "tertiary"
            exit 0
            ;;
        --reset-key4)
            save_api_key 4 "$KEY_FILE_4" "quaternary"
            exit 0
            ;;
        --write-config|--config)
            WRITE_CONFIG_MODE=true
            shift
            ;;
        --use-config)
            FORCE_USE_CONFIG=true
            shift
            ;;
        --ask)
            FORCE_ASK=true
            shift
            ;;
        --allow-large-uploads)
            CLI_ALLOW_LARGE=true
            shift
            ;;
        --no-large-uploads)
            CLI_ALLOW_LARGE=false
            shift
            ;;
        --notify)
            CLI_NOTIFY=true
            shift
            ;;
        --no-notify)
            CLI_NOTIFY=false
            shift
            ;;
        --)
            shift
            while [[ $# -gt 0 ]]; do POSITIONAL+=("$1"); shift; done
            ;;
        -*)
            echo "Unknown option: $1" >&2
            print_help
            exit 1
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done
set -- "${POSITIONAL[@]}"

# ----------------------------- Logging --------------------------------------
# From here on, everything printed (stdout+stderr) is also written to a
# per-run logfile so you can review past scans later.

LOG_FILE="$LOG_DIR/scan_$(date '+%Y%m%d-%H%M%S').log"
# Extremely unlikely, but don't clobber a log from the same second.
[[ -e "$LOG_FILE" ]] && LOG_FILE="$LOG_DIR/scan_$(date '+%Y%m%d-%H%M%S')_$$.log"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "Logging this run to: file://$(path_to_file_uri "$LOG_FILE")" >&2

# ----------------------------- Load config, then apply prompts/flags --------

load_config
OPEN_BROWSER_SCAN="$CFG_OPEN_BROWSER_SCAN"
UPLOAD_MISSING="$CFG_UPLOAD_MISSING"
OPEN_BROWSER_UPLOAD_LIVE="$CFG_OPEN_BROWSER_UPLOAD_LIVE"
OPEN_BROWSER_UPLOAD_BATCH="$CFG_OPEN_BROWSER_UPLOAD_BATCH"
ALLOW_LARGE_UPLOADS="$CFG_ALLOW_LARGE_UPLOADS"
NOTIFY="$CFG_NOTIFY"
SKIP_PROMPTS="$CFG_SKIP_PROMPTS"

if [[ "$WRITE_CONFIG_MODE" == "true" ]]; then
    echo "Answer the questions below to set your saved defaults." >&2
    run_setting_prompts
    prompt_yn "Skip these prompts entirely on future runs (always use this saved config)" "$SKIP_PROMPTS" SKIP_PROMPTS
    write_config
    exit 0
fi

# Set up API key(s) first (only prompts if none are saved yet) so a
# brand-new install asks for keys before it asks about scan preferences.
load_api_keys

if [[ "$FORCE_USE_CONFIG" == "true" ]]; then
    : # use loaded config values as-is, no prompts
elif [[ "$SKIP_PROMPTS" == "true" && "$FORCE_ASK" != "true" ]]; then
    : # config says don't ask
else
    run_setting_prompts
fi

# CLI flags always win over both config and prompts.
[[ -n "$CLI_ALLOW_LARGE" ]] && ALLOW_LARGE_UPLOADS="$CLI_ALLOW_LARGE"
[[ -n "$CLI_NOTIFY" ]] && NOTIFY="$CLI_NOTIFY"

# ----------------------------- Gather files ---------------------------------

FILES_TO_SCAN=()
ALL_FILES=()

if [[ $# -gt 0 ]]; then
    # Terminal use: scan every path given, in order (files and/or folders).
    for arg in "$@"; do
        if [[ -e "$arg" ]]; then
            FILES_TO_SCAN+=("$arg")
        else
            echo "Error: '$arg' does not exist - skipping." >&2
        fi
    done
elif [[ -n "$NAUTILUS_SCRIPT_SELECTED_FILE_PATHS" ]]; then
    while IFS= read -r item; do
        [[ -n "$item" ]] && FILES_TO_SCAN+=("$item")
    done <<< "$NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"
elif [[ -n "$NAUTILUS_SCRIPT_CURRENT_URI" ]]; then
    current_path=$(uri_to_path "$NAUTILUS_SCRIPT_CURRENT_URI")
    FILES_TO_SCAN+=("$current_path")
else
    FILES_TO_SCAN+=(".")
fi

if [[ ${#FILES_TO_SCAN[@]} -eq 0 ]]; then
    echo "No files or folders to scan." >&2
    exit 1
fi

echo "Collecting files..." >&2

for item in "${FILES_TO_SCAN[@]}"; do
    if [[ -d "$item" ]]; then
        while IFS= read -r -d '' file; do
            ALL_FILES+=("$file")
        done < <(find "$item" -type f -print0 2>/dev/null)
    elif [[ -f "$item" ]]; then
        ALL_FILES+=("$item")
    else
        echo "Warning: '$item' is not a regular file or directory." >&2
    fi
done

total_files=${#ALL_FILES[@]}
if [[ $total_files -eq 0 ]]; then
    echo "No regular files found to scan." >&2
    exit 1
fi

echo "Found $total_files files to scan." >&2
read -rp "Do you want to proceed? (Y/n): " answer
answer="${answer:-y}"
if [[ ! "$answer" =~ ^[Yy]$ ]]; then
    echo "Aborted." >&2
    exit 0
fi

echo "Starting VirusTotal scan..." >&2
echo "------------------------------------------------------------" >&2

for file in "${ALL_FILES[@]}"; do
    process_file "$file"
    echo >&2
done

echo "------------------------------------------------------------" >&2
echo "All files processed." >&2

# ----------------------------- Deferred uploads -----------------------------

if [[ "$UPLOAD_MISSING" == "false" ]] && [[ ${#MISSING_FILES[@]} -gt 0 ]]; then
    echo "Found ${#MISSING_FILES[@]} files with no VirusTotal report." >&2

    filtered_files=()
    for f in "${MISSING_FILES[@]}"; do
        sz=$(get_file_size "$f")
        if [[ -n "$sz" ]] && [[ "$sz" -le "$MAX_UPLOAD_BYTES" ]]; then
            filtered_files+=("$f")
        else
            echo "   ⚠️  Skipping oversized file: $(basename "$f") (>650MB)" >&2
        fi
    done
    MISSING_FILES=("${filtered_files[@]}")

    if [[ ${#MISSING_FILES[@]} -gt 0 ]]; then
        read -rp "Do you want to upload these ${#MISSING_FILES[@]} files now? (y/N): " upload_now
        if [[ "$upload_now" =~ ^[Yy]$ ]]; then
            read -rp "Are you sure? (y/N): " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                prompt_yn "Open uploaded files' report in the browser" "$OPEN_BROWSER_UPLOAD_BATCH" OPEN_BROWSER_UPLOAD_BATCH
                echo "Uploading ${#MISSING_FILES[@]} files..." >&2
                for f in "${MISSING_FILES[@]}"; do
                    f_dir=$(dirname "$f")
                    f_base=$(basename "$f")
                    echo "➜ Processing: $f_dir/" >&2
                    echo "   📂 Open Folder: file://$(path_to_file_uri "$f_dir")/" >&2
                    echo "   📄 File: $f_base" >&2
                    upload_file "$f" "" "$OPEN_BROWSER_UPLOAD_BATCH"
                    echo >&2
                done
            else
                echo "Upload cancelled." >&2
            fi
        else
            echo "Upload skipped." >&2
        fi
    else
        echo "No uploadable files (all oversized)." >&2
    fi
fi

# ----------------------------- View uploaded files' results -----------------
# Only files that were actually uploaded this run - not ones that already had
# an existing VirusTotal report (those are handled by the section below).

if [[ ${#UPLOADED_REPORT_URLS[@]} -gt 0 ]]; then
    echo "You uploaded ${#UPLOADED_REPORT_URLS[@]} file(s) this run." >&2
    read -rp "View results of the uploaded files now, oldest to newest? (Y/n): " view_uploaded
    view_uploaded="${view_uploaded:-y}"
    if [[ "$view_uploaded" =~ ^[Yy]$ ]]; then
        UPLOADED_VIEW_URLS=()
        for i in "${!UPLOADED_SHAS[@]}"; do
            print_uploaded_result "${UPLOADED_PATHS[$i]}" "${UPLOADED_SHAS[$i]}" "${UPLOADED_DIRS[$i]}" "${UPLOADED_BASES[$i]}"
        done
        if [[ ${#UPLOADED_VIEW_URLS[@]} -gt 0 ]]; then
            read -rp "Open ${#UPLOADED_VIEW_URLS[@]} of these report(s) in the browser too? (y/N): " open_uploaded_browser
            if [[ "$open_uploaded_browser" =~ ^[Yy]$ ]]; then
                for url in "${UPLOADED_VIEW_URLS[@]}"; do
                    open_url_background "$url"
                    sleep 0.5
                done
                echo "Opened in browser." >&2
            else
                echo "Skipped opening in browser." >&2
            fi
        fi
    else
        echo "Skipped viewing uploaded-file reports." >&2
    fi
fi

# ----------------------------- Leftover report links ------------------------

if [[ "$OPEN_BROWSER_SCAN" == "false" ]] && [[ ${#REPORT_URLS[@]} -gt 0 ]]; then
    echo "Found ${#REPORT_URLS[@]} report links that were not opened." >&2
    read -rp "Open all report links in the browser now? (y/N): " open_all
    if [[ "$open_all" =~ ^[Yy]$ ]]; then
        echo "Opening ${#REPORT_URLS[@]} report links in background..." >&2
        for url in "${REPORT_URLS[@]}"; do
            open_url_background "$url"
            sleep 0.5
        done
        echo "All links opened." >&2
    else
        echo "Skipped opening report links." >&2
    fi
fi

# ----------------------------- Malware summary -------------------------------

if [[ ${#MALWARE_PATHS[@]} -gt 0 ]]; then
    echo "------------------------------------------------------------" >&2
    echo "Malware detected." >&2
    for i in "${!MALWARE_PATHS[@]}"; do
        echo "File: ${MALWARE_PATHS[$i]}" >&2
        echo "   SHA256: ${MALWARE_SHAS[$i]}" >&2
        echo "   📊 Stats:" >&2
        echo "${MALWARE_STATS[$i]}" | sed -e 's/malicious:/☠️ malicious:/' \
                                          -e 's/suspicious:/⚠️ suspicious:/' \
                                          -e 's/undetected:/✅ undetected:/' \
                                          -e 's/harmless:/😇 harmless:/' \
                                          -e 's/timeout:/⏰ timeout:/' | sed 's/^/      /' >&2
        echo "   🔗 Report: ${MALWARE_URLS[$i]}" >&2
        echo "   📂 Open Folder: file://$(path_to_file_uri "${MALWARE_DIRS[$i]}")/" >&2
        echo "   📄 File: ${MALWARE_BASES[$i]}" >&2
        echo >&2
    done
    echo "${#MALWARE_PATHS[@]} of $total_files file(s) flagged as malicious/suspicious." >&2
fi

echo "Full log saved to: file://$(path_to_file_uri "$LOG_FILE")" >&2
read -p "Press Enter to close this window..." </dev/tty
