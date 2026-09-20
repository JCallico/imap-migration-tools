[CmdletBinding()]
param(
    [ValidateSet("emulator", "device")]
    [string]$Target,
    [string]$Serial,
    [string]$AvdName,
    [switch]$PageSize16Kb,
    [switch]$Headless,
    [switch]$ConnectedTests,
    [switch]$SkipSdkInstall
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $RepoRoot

if (-not $Target) {
    Write-Host "Choose a target:"
    Write-Host "  1) Standard Android emulator"
    Write-Host "  2) Android 15 emulator with 16 KB pages"
    Write-Host "  3) Connected physical Android device"
    $Selection = Read-Host "Selection [1]"
    if (-not $Selection) { $Selection = "1" }
    switch ($Selection) {
        "1" { $Target = "emulator" }
        "2" { $Target = "emulator"; $PageSize16Kb = $true }
        "3" { $Target = "device" }
        default { throw "Invalid selection." }
    }
}

function Get-LocalProperty([string]$Name) {
    $PropertiesPath = Join-Path $RepoRoot "android\local.properties"
    if (-not (Test-Path $PropertiesPath)) { return $null }
    $Match = Get-Content $PropertiesPath | Where-Object { $_ -like "$Name=*" } | Select-Object -Last 1
    if (-not $Match) { return $null }
    return $Match.Substring($Name.Length + 1).Replace('\:', ':').Replace('\\', '\')
}

$SdkRoot = $env:ANDROID_HOME
if (-not $SdkRoot) { $SdkRoot = $env:ANDROID_SDK_ROOT }
if (-not $SdkRoot) { $SdkRoot = Get-LocalProperty "sdk.dir" }
if (-not $SdkRoot) {
    $DefaultSdk = Join-Path $env:LOCALAPPDATA "Android\Sdk"
    $SdkRoot = Read-Host "Android SDK path [$DefaultSdk]"
    if (-not $SdkRoot) { $SdkRoot = $DefaultSdk }
}
if (-not (Test-Path -PathType Container $SdkRoot)) {
    throw "Android SDK directory not found: $SdkRoot. Install Android Studio/SDK command-line tools, then rerun this script."
}

$env:ANDROID_HOME = $SdkRoot
$env:ANDROID_SDK_ROOT = $SdkRoot
$env:PATH = "$(Join-Path $SdkRoot 'platform-tools');$(Join-Path $SdkRoot 'emulator');$env:PATH"

function Find-LatestSdkTool([string]$Name) {
    $Preferred = Join-Path $SdkRoot "cmdline-tools\latest\bin\$Name"
    if (Test-Path $Preferred) { return $Preferred }
    $Tool = Get-ChildItem (Join-Path $SdkRoot "cmdline-tools") -Recurse -File -Filter $Name -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -like "*\bin" } |
        Sort-Object FullName |
        Select-Object -Last 1
    if ($Tool) { return $Tool.FullName }
    return $null
}

$SdkManager = Find-LatestSdkTool "sdkmanager.bat"
$AvdManager = Find-LatestSdkTool "avdmanager.bat"
$Adb = Join-Path $SdkRoot "platform-tools\adb.exe"
$Emulator = Join-Path $SdkRoot "emulator\emulator.exe"

if (-not $SdkManager -or -not (Test-Path $Adb)) {
    throw "Android SDK command-line tools and Platform-Tools are required under $SdkRoot."
}

if (Get-Command mise -ErrorAction SilentlyContinue) {
    Write-Host "Ensuring repository-pinned JDK, Gradle, and Python are installed..."
    & mise install "gradle@8.13" "java@temurin-17" "python@3.13"
    if ($LASTEXITCODE -ne 0) { throw "mise could not install the repository-pinned build tools." }
}

function Invoke-Gradle([string[]]$GradleArgs) {
    if (Get-Command mise -ErrorAction SilentlyContinue) {
        & mise exec -- gradle @GradleArgs
    } elseif (Get-Command gradle -ErrorAction SilentlyContinue) {
        & gradle @GradleArgs
    } else {
        throw 'Gradle 8.13 was not found. Install mise and run "mise install", or install Gradle 8.13.'
    }
    if ($LASTEXITCODE -ne 0) { throw "Gradle failed with exit code $LASTEXITCODE." }
}

$SdkPackages = @("platform-tools", "platforms;android-36", "build-tools;35.0.0")
if ($Target -eq "emulator") {
    $ImageArchitecture = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64-v8a" } else { "x86_64" }
    if ($PageSize16Kb) {
        $ImagePackage = "system-images;android-35;google_apis_ps16k;$ImageArchitecture"
        if (-not $AvdName) { $AvdName = "imap_tools_16k" }
        $SdkPackages += "ndk;28.2.13676358"
    } else {
        $ImagePackage = "system-images;android-36;google_apis;$ImageArchitecture"
        if (-not $AvdName) { $AvdName = "medium_phone" }
    }
    $SdkPackages += @("emulator", $ImagePackage)
}

if (-not $SkipSdkInstall) {
    Write-Host "Ensuring required Android SDK packages are installed..."
    (1..100 | ForEach-Object { "y" }) | & $SdkManager @SdkPackages
    if ($LASTEXITCODE -ne 0) { throw "Android SDK package installation failed." }
}

& $Adb start-server | Out-Null
if ($LASTEXITCODE -ne 0) { throw "ADB failed to start." }

function Get-ConnectedDevices {
    $Result = @()
    foreach ($Line in (& $Adb devices)) {
        if ($Line -match '^([^\s]+)\s+device$') { $Result += $Matches[1] }
    }
    return $Result
}

function Find-RunningAvd([string]$Name) {
    foreach ($Device in (Get-ConnectedDevices)) {
        if ($Device -notlike "emulator-*") { continue }
        $RunningName = ((& $Adb -s $Device shell getprop ro.boot.qemu.avd_name 2>$null) -join "").Trim()
        if ($RunningName -eq $Name) { return $Device }
    }
    return $null
}

if ($Target -eq "emulator") {
    if (-not $AvdManager -or -not (Test-Path $Emulator)) {
        throw "Android Emulator and avdmanager are required under $SdkRoot."
    }

    $KnownAvds = @(& $Emulator -list-avds)
    if ($KnownAvds -notcontains $AvdName) {
        Write-Host "Creating emulator $AvdName..."
        "no" | & $AvdManager create avd --name $AvdName --package $ImagePackage --device medium_phone
        if ($LASTEXITCODE -ne 0) { throw "Could not create emulator $AvdName." }
        $KnownAvds = @(& $Emulator -list-avds)
        if ($KnownAvds -notcontains $AvdName) {
            throw "avdmanager did not create $AvdName. Create it in Android Studio Device Manager, then rerun this script."
        }
    }

    if (-not $Serial) { $Serial = Find-RunningAvd $AvdName }
    if (-not $Serial) {
        $StdoutLog = Join-Path $env:USERPROFILE ".android\$AvdName.stdout.log"
        $StderrLog = Join-Path $env:USERPROFILE ".android\$AvdName.stderr.log"
        $EmulatorArgs = @("-avd", $AvdName, "-no-snapshot-load")
        if ($Headless) { $EmulatorArgs += @("-no-window", "-no-audio", "-gpu", "software") }
        Write-Host "Starting emulator $AvdName (logs: $StdoutLog and $StderrLog)..."
        Start-Process -FilePath $Emulator -ArgumentList $EmulatorArgs `
            -RedirectStandardOutput $StdoutLog -RedirectStandardError $StderrLog | Out-Null

        for ($Attempt = 0; $Attempt -lt 120 -and -not $Serial; $Attempt++) {
            Start-Sleep -Seconds 2
            $Serial = Find-RunningAvd $AvdName
        }
    }
    if (-not $Serial) { throw "The emulator did not register with ADB." }
} elseif (-not $Serial) {
    $Devices = @(Get-ConnectedDevices)
    if ($Devices.Count -eq 0) {
        Write-Host "No authorized device is connected."
        Write-Host "Enable Developer options and USB debugging, connect the device, and accept its authorization prompt."
        Read-Host "Press Enter after the device is ready" | Out-Null
        $Devices = @(Get-ConnectedDevices)
    }
    if ($Devices.Count -eq 1) {
        $Serial = $Devices[0]
    } elseif ($Devices.Count -gt 1) {
        & $Adb devices -l
        $Serial = Read-Host "Device serial"
    } else {
        throw "No authorized Android device was found."
    }
}

Write-Host "Waiting for $Serial to finish booting..."
& $Adb -s $Serial wait-for-device
for ($Attempt = 0; $Attempt -lt 120; $Attempt++) {
    $BootComplete = ((& $Adb -s $Serial shell getprop sys.boot_completed 2>$null) -join "").Trim()
    if ($BootComplete -eq "1") { break }
    Start-Sleep -Seconds 2
}
if ($BootComplete -ne "1") { throw "Android did not finish booting on $Serial." }

if ($PageSize16Kb) {
    $ActualPageSize = ((& $Adb -s $Serial shell getconf PAGE_SIZE) -join "").Trim()
    if ($ActualPageSize -ne "16384") {
        throw "Expected a 16 KB emulator, but $Serial reports PAGE_SIZE=$ActualPageSize."
    }
    Write-Host "Confirmed PAGE_SIZE=16384 on $Serial."
}

Write-Host "Building and running local Android checks..."
Invoke-Gradle -GradleArgs @("-p", "android", "lintDebug", "testDebugUnitTest", "assembleDebug")

if ($PageSize16Kb) {
    $GitBashPath = Join-Path $env:ProgramFiles "Git\bin\bash.exe"
    $BashCommand = Get-Command bash -ErrorAction SilentlyContinue
    $BashPath = if (Test-Path $GitBashPath) { $GitBashPath } elseif ($BashCommand) { $BashCommand.Source } else { $null }
    if (-not $BashPath) { throw "16 KB ELF validation requires Git for Windows (bash.exe)." }
    $BashSdkRoot = ((& $BashPath -c 'cygpath -u "$1"' -- $SdkRoot) -join "").Trim()
    if (-not $BashSdkRoot) { throw "Git Bash could not translate the Android SDK path." }
    $PreviousAndroidHome = $env:ANDROID_HOME
    $PreviousAndroidSdkRoot = $env:ANDROID_SDK_ROOT
    try {
        $env:ANDROID_HOME = $BashSdkRoot
        $env:ANDROID_SDK_ROOT = $BashSdkRoot
        & $BashPath "tools/check_android_16kb.sh" "android/app/build/outputs/apk/debug/app-debug.apk"
        if ($LASTEXITCODE -ne 0) { throw "16 KB APK validation failed." }
    } finally {
        $env:ANDROID_HOME = $PreviousAndroidHome
        $env:ANDROID_SDK_ROOT = $PreviousAndroidSdkRoot
    }
}

if ($ConnectedTests) {
    Write-Host "Running instrumentation tests on $Serial..."
    $PreviousSerial = $env:ANDROID_SERIAL
    try {
        $env:ANDROID_SERIAL = $Serial
        Invoke-Gradle -GradleArgs @("-p", "android", "connectedDebugAndroidTest")
    } finally {
        $env:ANDROID_SERIAL = $PreviousSerial
    }
}

$Apk = Join-Path $RepoRoot "android\app\build\outputs\apk\debug\app-debug.apk"
Write-Host "Installing and launching IMAP Migration Tools on $Serial..."
& $Adb -s $Serial install -r $Apk
if ($LASTEXITCODE -ne 0) { throw "APK installation failed." }
& $Adb -s $Serial shell am start -W -n "com.callicode.imaptools/.MainActivity"
if ($LASTEXITCODE -ne 0) { throw "Application launch failed." }

Write-Host "`nThe application is running on $Serial."
if ($Headless) { Write-Host "The emulator is headless. Open it with: scrcpy --serial $Serial --no-audio" }
