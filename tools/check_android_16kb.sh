#!/usr/bin/env bash

set -euo pipefail

artifact_path="${1:-android/app/build/outputs/apk/debug/app-debug.apk}"
sdk_root="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"

if [[ ! -f "$artifact_path" ]]; then
    printf 'Android artifact not found: %s\nBuild it first with: gradle -p android assembleDebug bundleDebug\n' \
        "$artifact_path" >&2
    exit 2
fi

if [[ -z "$sdk_root" && -f android/local.properties ]]; then
    sdk_root="$(sed -n 's/^sdk.dir=//p' android/local.properties | tail -n 1)"
fi

if [[ -z "$sdk_root" || ! -d "$sdk_root" ]]; then
    printf 'Set ANDROID_HOME to an installed Android SDK, or configure android/local.properties.\n' >&2
    exit 2
fi

find_latest_tool() {
    local pattern="$1"
    find "$sdk_root" \( -type f -o -type l \) -path "$pattern" -print 2>/dev/null | sort | tail -n 1
}

zipalign_bin="${ZIPALIGN:-$(find_latest_tool "$sdk_root/build-tools/*/zipalign*")}"
readelf_bin="${LLVM_READELF:-$(find_latest_tool "$sdk_root/ndk/*/toolchains/llvm/prebuilt/*/bin/llvm-readelf*")}"

if [[ ! -x "$zipalign_bin" ]]; then
    printf 'zipalign was not found. Install Android SDK Build-Tools 35.0.0 or newer.\n' >&2
    exit 2
fi

if [[ ! -x "$readelf_bin" ]]; then
    printf 'llvm-readelf was not found. Install Android NDK 28 or newer.\n' >&2
    exit 2
fi

temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/imap-tools-16kb.XXXXXX")"
cleanup() {
    find "$temp_dir" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT

unzip -q "$artifact_path" '*.so' -d "$temp_dir"
failed=0
library_count=0
while IFS= read -r library; do
    library_count=$((library_count + 1))
    relative_path="${library#"$temp_dir/"}"
    load_alignments="$($readelf_bin -lW "$library" | awk '$1 == "LOAD" {print $NF}')"

    if [[ -z "$load_alignments" ]]; then
        printf 'FAIL %-64s no ELF LOAD segments\n' "$relative_path"
        failed=1
        continue
    fi

    library_failed=0
    while IFS= read -r alignment; do
        if (( alignment < 0x4000 )); then
            library_failed=1
            failed=1
        fi
    done <<< "$load_alignments"

    unique_alignments="$(printf '%s\n' "$load_alignments" | sort -u | paste -sd, -)"
    if (( library_failed )); then
        printf 'FAIL %-64s LOAD alignment %s\n' "$relative_path" "$unique_alignments"
    else
        printf 'PASS %-64s LOAD alignment %s\n' "$relative_path" "$unique_alignments"
    fi
done < <(find "$temp_dir" -type f -name '*.so' -print | sort)

if (( library_count == 0 )); then
    printf 'No native libraries were found in %s; expected Chaquopy libraries.\n' "$artifact_path" >&2
    exit 1
fi

case "$artifact_path" in
    *.apk)
        if ! "$zipalign_bin" -c -P 16 -v 4 "$artifact_path" >/dev/null; then
            printf 'FAIL APK native-library ZIP alignment\n'
            failed=1
        else
            printf 'PASS APK native-library ZIP alignment\n'
        fi
        ;;
    *.aab)
        gradle_home="${GRADLE_USER_HOME:-$HOME/.gradle}"
        bundletool_jar="$(find "$gradle_home/caches/modules-2/files-2.1/com.android.tools.build/bundletool" \
            -type f -name 'bundletool-*.jar' -print 2>/dev/null | sort | tail -n 1)"
        if [[ -z "$bundletool_jar" ]] || ! command -v java >/dev/null 2>&1; then
            printf 'Bundletool is unavailable. Run "gradle -p android bundleDebug" before validating the AAB.\n' >&2
            exit 2
        fi
        dependency_classpath="$(find "$gradle_home/caches/modules-2/files-2.1" -type f -name '*.jar' -print | paste -sd: -)"
        bundle_config="$(java -cp "$bundletool_jar:$dependency_classpath" \
            com.android.tools.build.bundletool.BundleToolMain dump config --bundle="$artifact_path")"
        if grep -Fq '"alignment": "PAGE_ALIGNMENT_16K"' <<< "$bundle_config"; then
            printf 'PASS AAB requests 16 KB page-aligned generated APKs\n'
        else
            printf 'FAIL AAB does not request PAGE_ALIGNMENT_16K for generated APKs\n'
            failed=1
        fi
        ;;
    *)
        printf 'Expected an .apk or .aab artifact: %s\n' "$artifact_path" >&2
        exit 2
        ;;
esac

if (( failed )); then
    printf '16 KB compatibility validation failed.\n' >&2
    exit 1
fi

printf 'Validated %d native libraries in %s for 16 KB page-size compatibility.\n' \
    "$library_count" "$artifact_path"
