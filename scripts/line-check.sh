#!/usr/bin/env bash
set -euo pipefail

limit=800
status=0

while IFS= read -r file; do
    lines=$(wc -l < "$file")
    if (( lines > limit )); then
        printf '%s has %s lines, limit is %s\n' "$file" "$lines" "$limit" >&2
        status=1
    fi
done < <(find crates -type f -name '*.rs' | sort)

exit "$status"
