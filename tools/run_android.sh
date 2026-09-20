#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

target=""
serial=""
avd_name=""
page_size_16k=0
headless=0
install_sdk=1
connected_tests=0

usage() {
    cat <<'EOF'
Usage: tools/run_android.sh [options]

Build, test, install, and launch IMAP Migration Tools on an emulator or physical device.

Options:
  --target emulator|device  Select the Android target without prompting.
  --serial SERIAL           Select a connected physical device or running emulator.
  --avd NAME                Use or create this emulator (default: medium_phone or imap_tools_16k).
  --16kb                    Use the Android 15 16 KB page-size emulator image.
  --headless                Start the emulator without its own window.
  --connected-tests         Run instrumentation tests before the final install.
  --skip-sdk-install        Do not install missing Android SDK packages.
  -h, --help                Show this help.
EOF
}

while (( $# )); do
    case "$1" in
        --target)
            target="${2:-}"
            shift 2
            ;;
        --serial)
            serial="${2:-}"
            shift 2
            ;;
        --avd)
            avd_name="${2:-}"
            shift 2
            ;;
        --16kb)
            page_size_16k=1
            shift
            ;;
        --headless)
            headless=1
            shift
            ;;
        --connected-tests)
            connected_tests=1
            shift
            ;;
        --skip-sdk-install)
            install_sdk=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -z "$target" ]]; then
    printf '%s\n' \
        'Choose a target:' \
        '  1) Standard Android emulator' \
        '  2) Android 15 emulator with 16 KB pages' \
        '  3) Connected physical Android device'
    read -r -p 'Selection [1]: ' selection
    case "${selection:-1}" in
        1) target="emulator" ;;
        2) target="emulator"; page_size_16k=1 ;;
        3) target="device" ;;
        *) printf 'Invalid selection.\n' >&2; exit 2 ;;
    esac
fi

if [[ "$target" != "emulator" && "$target" != "device" ]]; then
    printf '%s\n' '--target must be emulator or device.' >&2
    exit 2
fi

sdk_root="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [[ -z "$sdk_root" && -f android/local.properties ]]; then
    sdk_root="$(sed -n 's/^sdk.dir=//p' android/local.properties | tail -n 1)"
fi
if [[ -z "$sdk_root" ]]; then
    case "$(uname -s)" in
        Darwin) default_sdk="$HOME/Library/Android/sdk" ;;
        *) default_sdk="$HOME/Android/Sdk" ;;
    esac
    read -r -p "Android SDK path [$default_sdk]: " sdk_root
    sdk_root="${sdk_root:-$default_sdk}"
fi
if [[ ! -d "$sdk_root" ]]; then
    printf 'Android SDK directory not found: %s\nInstall Android Studio/SDK command-line tools, then rerun this script.\n' \
        "$sdk_root" >&2
    exit 2
fi

export ANDROID_HOME="$sdk_root"
export ANDROID_SDK_ROOT="$sdk_root"
export PATH="$sdk_root/platform-tools:$sdk_root/emulator:$PATH"

latest_command_line_tool() {
    local tool_name="$1"
    local preferred="$sdk_root/cmdline-tools/latest/bin/$tool_name"
    if [[ -x "$preferred" ]]; then
        printf '%s\n' "$preferred"
        return
    fi
    find "$sdk_root/cmdline-tools" -type f -path "*/bin/$tool_name" -print 2>/dev/null | sort | tail -n 1
}

sdkmanager_bin="$(latest_command_line_tool sdkmanager)"
avdmanager_bin="$(latest_command_line_tool avdmanager)"
adb_bin="$sdk_root/platform-tools/adb"
emulator_bin="$sdk_root/emulator/emulator"

if [[ ! -x "$sdkmanager_bin" || ! -x "$adb_bin" ]]; then
    printf 'Android SDK command-line tools and Platform-Tools are required under %s.\n' "$sdk_root" >&2
    exit 2
fi

if command -v mise >/dev/null 2>&1; then
    printf 'Ensuring repository-pinned JDK, Gradle, and Python are installed...\n'
    mise install gradle@8.13 java@temurin-17 python@3.13
fi

run_gradle() {
    if command -v mise >/dev/null 2>&1; then
        mise exec -- gradle "$@"
    elif command -v gradle >/dev/null 2>&1; then
        gradle "$@"
    else
        printf 'Gradle 8.13 was not found. Install mise and run "mise install", or install Gradle 8.13.\n' >&2
        return 127
    fi
}

sdk_packages=("platform-tools" "platforms;android-36" "build-tools;35.0.0")
if [[ "$target" == "emulator" ]]; then
    host_arch="$(uname -m)"
    case "$host_arch" in
        arm64|aarch64) image_arch="arm64-v8a" ;;
        *) image_arch="x86_64" ;;
    esac
    if (( page_size_16k )); then
        image_package="system-images;android-35;google_apis_ps16k;$image_arch"
        avd_name="${avd_name:-imap_tools_16k}"
        sdk_packages+=("ndk;28.2.13676358")
    else
        image_package="system-images;android-36;google_apis;$image_arch"
        avd_name="${avd_name:-medium_phone}"
    fi
    sdk_packages+=("emulator" "$image_package")
fi

if (( install_sdk )); then
    printf 'Ensuring required Android SDK packages are installed...\n'
    printf 'y\n%.0s' {1..100} | "$sdkmanager_bin" "${sdk_packages[@]}"
fi

"$adb_bin" start-server >/dev/null

if [[ "$target" == "emulator" ]]; then
    if [[ ! -x "$avdmanager_bin" || ! -x "$emulator_bin" ]]; then
        printf 'Android Emulator and avdmanager are required under %s.\n' "$sdk_root" >&2
        exit 2
    fi

    if ! "$emulator_bin" -list-avds | grep -Fxq "$avd_name"; then
        printf 'Creating emulator %s...\n' "$avd_name"
        printf 'no\n' | "$avdmanager_bin" create avd \
            --name "$avd_name" --package "$image_package" --device medium_phone
        if ! "$emulator_bin" -list-avds | grep -Fxq "$avd_name"; then
            printf 'avdmanager did not create %s. Create it in Android Studio Device Manager, then rerun this script.\n' \
                "$avd_name" >&2
            exit 1
        fi
    fi

    find_running_avd() {
        local candidate
        while read -r candidate _; do
            [[ "$candidate" == emulator-* ]] || continue
            if [[ "$("$adb_bin" -s "$candidate" shell getprop ro.boot.qemu.avd_name </dev/null 2>/dev/null | tr -d '\r')" == "$avd_name" ]]; then
                printf '%s\n' "$candidate"
                return 0
            fi
        done < <("$adb_bin" devices)
        return 1
    }

    reused_running_avd=0
    if [[ -z "$serial" ]]; then
        serial="$(find_running_avd || true)"
        [[ -n "$serial" ]] && reused_running_avd=1
    fi
    if [[ -n "$serial" && "$reused_running_avd" == 1 ]]; then
        printf 'Reusing already-running emulator %s (%s).\n' "$avd_name" "$serial"
    fi
    if [[ -z "$serial" ]]; then
        emulator_log="$HOME/.android/${avd_name}.log"
        emulator_args=(-avd "$avd_name" -no-snapshot-load)
        if (( headless )); then
            emulator_args+=(-no-window -no-audio -gpu software)
        fi
        printf 'Starting emulator %s (log: %s)...\n' "$avd_name" "$emulator_log"
        nohup "$emulator_bin" "${emulator_args[@]}" >"$emulator_log" 2>&1 &

        for _ in {1..120}; do
            serial="$(find_running_avd || true)"
            [[ -n "$serial" ]] && break
            sleep 2
        done
    fi
    if [[ -z "$serial" ]]; then
        printf 'The emulator did not register with ADB. Inspect ~/.android/%s.log.\n' "$avd_name" >&2
        exit 1
    fi
else
    if [[ -z "$serial" ]]; then
        connected_devices=()
        while IFS= read -r connected_device; do
            connected_devices[${#connected_devices[@]}]="$connected_device"
        done < <("$adb_bin" devices | awk '$2 == "device" {print $1}')
        if (( ${#connected_devices[@]} == 0 )); then
            printf '%s\n' \
                'No authorized device is connected.' \
                'Enable Developer options and USB debugging on the device, connect it, and accept its authorization prompt.'
            read -r -p 'Press Enter after the device is ready...'
            while IFS= read -r connected_device; do
                connected_devices[${#connected_devices[@]}]="$connected_device"
            done < <("$adb_bin" devices | awk '$2 == "device" {print $1}')
        fi
        if (( ${#connected_devices[@]} == 1 )); then
            serial="${connected_devices[0]}"
        elif (( ${#connected_devices[@]} > 1 )); then
            "$adb_bin" devices -l
            read -r -p 'Device serial: ' serial
        else
            printf 'No authorized Android device was found.\n' >&2
            exit 1
        fi
    fi
fi

printf 'Waiting for %s to finish booting...\n' "$serial"
"$adb_bin" -s "$serial" wait-for-device
for _ in {1..120}; do
    [[ "$("$adb_bin" -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]] && break
    sleep 2
done
if [[ "$("$adb_bin" -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" != "1" ]]; then
    printf 'Android did not finish booting on %s.\n' "$serial" >&2
    exit 1
fi

if (( page_size_16k )); then
    actual_page_size="$("$adb_bin" -s "$serial" shell getconf PAGE_SIZE | tr -d '\r')"
    if [[ "$actual_page_size" != "16384" ]]; then
        printf 'Expected a 16 KB emulator, but %s reports PAGE_SIZE=%s.\n' "$serial" "$actual_page_size" >&2
        exit 1
    fi
    printf 'Confirmed PAGE_SIZE=16384 on %s.\n' "$serial"
fi

printf 'Building and running local Android checks...\n'
run_gradle -p android lintDebug testDebugUnitTest assembleDebug

if (( page_size_16k )); then
    tools/check_android_16kb.sh android/app/build/outputs/apk/debug/app-debug.apk
fi

if (( connected_tests )); then
    printf 'Running instrumentation tests on %s...\n' "$serial"
    ANDROID_SERIAL="$serial" run_gradle -p android connectedDebugAndroidTest
fi

printf 'Installing and launching IMAP Migration Tools on %s...\n' "$serial"
"$adb_bin" -s "$serial" install -r android/app/build/outputs/apk/debug/app-debug.apk
"$adb_bin" -s "$serial" shell am start -W -n com.callicode.imaptools/.MainActivity

emulator_is_headless() {
    local target_serial="$1" target_avd
    [[ "$target_serial" == emulator-* ]] || return 1
    target_avd="$("$adb_bin" -s "$target_serial" shell getprop ro.boot.qemu.avd_name 2>/dev/null | tr -d '\r')"
    [[ -n "$target_avd" ]] || return 1
    ps -eo args= | grep -F -- "-avd $target_avd" | grep -q -- '-no-window'
}

printf '\nThe application is running on %s.\n' "$serial"
if [[ "$target" == "emulator" ]] && emulator_is_headless "$serial"; then
    printf 'The emulator is headless (no visible window). View it with: scrcpy --serial %s --no-audio\n' "$serial"
fi
