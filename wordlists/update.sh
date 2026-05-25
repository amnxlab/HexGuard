#!/usr/bin/env bash
# Update bundled wordlists from SecLists (danielmiessler/SecLists on GitHub).
set -euo pipefail

BASE="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

download() {
  local url="$1" dest="$DIR/$2"
  echo "  → $2"
  curl -fsSL "$url" -o "$dest"
  echo "    $(wc -l < "$dest") lines"
}

echo "Downloading SecLists wordlists into $DIR ..."

download "$BASE/common.txt"                      "common.txt"
download "$BASE/raft-medium-directories.txt"     "raft-medium-directories.txt"
download "$BASE/big.txt"                         "big.txt"
download "$BASE/api/api-endpoints.txt"           "api-endpoints.txt"

echo ""
echo "Done. Total files: $(ls "$DIR"/*.txt 2>/dev/null | wc -l)"
