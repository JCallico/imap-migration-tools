#!/usr/bin/env bash
#
# Fail when an Android artifact exceeds the size budget.
#
# Usage: tools/check_android_size.sh <artifact.apk|.aab> <budget-mb>
#
# The budget covers the whole artifact, including Chaquopy's interpreter,
# standard library, and native libraries for every packaged ABI. Google Play
# further reduces the per-device download size through ABI filtering, so the
# AAB budget looks generous next to what users actually download.
#
# To set or tighten the budget: build the artifact, read the "artifact size"
# line from a passing run, and keep roughly 30-40% headroom above it so a
# whole extra ABI (about 20-30 MB compressed) trips the check.

set -euo pipefail

artifact_path="${1:?usage: check_android_size.sh <artifact.apk|.aab> <budget-mb>}"
budget_mb="${2:?usage: check_android_size.sh <artifact.apk|.aab> <budget-mb>}"

if [[ ! -f "$artifact_path" ]]; then
    printf 'Android artifact not found: %s\nBuild it first with: gradle -p android assembleDebug bundleDebug\n' \
        "$artifact_path" >&2
    exit 2
fi

size_bytes="$(stat -c%s "$artifact_path" 2>/dev/null || stat -f%z "$artifact_path")"
size_mb="$(awk -v bytes="$size_bytes" 'BEGIN { printf "%.1f", bytes / 1048576 }')"
over_budget="$(awk -v bytes="$size_bytes" -v budget="$budget_mb" 'BEGIN { over = (bytes / 1048576) > budget; print over ? 1 : 0 }')"

largest_entries="$(
    unzip -l "$artifact_path" 2>/dev/null \
        | awk '/^--------+ / { seen++; next } seen == 1 && $1 ~ /^[0-9]+$/ { print $1" "$4 }' \
        | sort -k1 -rn \
        | awk 'NR <= 8 { printf "%s (%s bytes); ", $2, $1 }'
)"

if [[ "$over_budget" == "1" ]]; then
    printf 'FAIL %s is %s MB, over the %s MB budget.\n' "$artifact_path" "$size_mb" "$budget_mb" >&2
    printf 'Largest entries: %s\n' "$largest_entries" >&2
    printf 'If the growth is expected (for example a Chaquopy or Python upgrade),\n' >&2
    printf 'raise the budget deliberately in .github/workflows/android.yml.\n' >&2
    exit 1
fi

printf 'OK %s is %s MB (budget %s MB).\n' "$artifact_path" "$size_mb" "$budget_mb"
