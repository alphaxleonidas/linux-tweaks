#!/bin/bash

# ----------------------------------------------------------------------
# Script: vt_scan_15s.sh
# Purpose: Scan all files in the current directory (and subdirs) using
#          VirusTotal by hash, and open the report in the browser.
# Usage:   ./vt_scan_15s.sh
# Requirement: VirusTotal API key
# How To Use? 
# 1. Copy the file into the directory you want to scan. 
# 2. Make the file an executable. 
# 3. Open terminal in the directory.
# 4. Run the file using: ./vt_scan_15s.sh
# 5. When prompted, enter the API key.

# ----------------------------------------------------------------------

# Ask for the VirusTotal API key
read -rp "Enter your VirusTotal API key: " API_KEY
if [[ -z "$API_KEY" ]]; then
    echo "Error: API key cannot be empty."
    exit 1
fi

# Temporary file for API responses
TMP_RESPONSE="/tmp/vt_response.json"
trap 'rm -f "$TMP_RESPONSE"' EXIT

# Function to open a URL in the default browser
open_url() {
    local url="$1"
    if command -v xdg-open &>/dev/null; then
        xdg-open "$url"
    elif command -v open &>/dev/null; then
        open "$url"
    else
        echo "Could not open browser. Please open manually: $url"
    fi
}

echo "Scanning files in $(pwd) and subdirectories..."
echo "Rate limit: 4 requests per minute – waiting 15 seconds between each file."
echo "------------------------------------------------------------"

# Find all regular files, process them one by one
find . -type f -print0 | while IFS= read -r -d '' file; do
    # Compute SHA‑256 hash (only the hash itself)
    sha=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
    if [[ -z "$sha" ]]; then
        echo "⚠️  Could not compute hash for '$file' – skipping."
        continue
    fi

    echo "➜ Processing: '$file'"
    echo "   SHA256: $sha"

    # Query VirusTotal for the hash
    http_code=$(curl -s -o "$TMP_RESPONSE" -w "%{http_code}" \
        -H "x-apikey: $API_KEY" \
        "https://www.virustotal.com/api/v3/files/$sha")

    # Handle response codes
    if [[ "$http_code" -eq 200 ]]; then
        report_url="https://www.virustotal.com/gui/file/$sha"
        echo "   ✅ Report found. Opening browser..."
        open_url "$report_url"
    elif [[ "$http_code" -eq 404 ]]; then
        echo "   ❌ No report found for this hash."
    elif [[ "$http_code" -eq 429 ]]; then
        echo "   ⏳ Rate limit exceeded. Waiting 60 seconds then retrying..."
        sleep 60
        # Retry once (simple approach – you can extend with a loop)
        http_code=$(curl -s -o "$TMP_RESPONSE" -w "%{http_code}" \
            -H "x-apikey: $API_KEY" \
            "https://www.virustotal.com/api/v3/files/$sha")
        if [[ "$http_code" -eq 200 ]]; then
            report_url="https://www.virustotal.com/gui/file/$sha"
            echo "   ✅ Report found (after retry). Opening browser..."
            open_url "$report_url"
        else
            echo "   ❌ Still no report (HTTP $http_code)."
        fi
    else
        echo "   ⚠️  Unexpected HTTP status $http_code – check your API key or network."
        # Optionally show the response body for debugging:
        # cat "$TMP_RESPONSE"
    fi

    # Wait 15 seconds to stay within the 4‑requests‑per‑minute limit
    echo "   Sleeping 15 seconds before next file..."
    sleep 15
done

echo "------------------------------------------------------------"
echo "All files processed."
