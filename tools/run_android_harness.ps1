param(
  [string]$Serial = "ZY22K9DZG9",
  [int]$TimeoutSeconds = 900,
  [int]$PollSeconds = 2
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$apkPath = Join-Path $repoRoot "tests\android_harness\app\build\outputs\apk\debug\app-debug.apk"
$packageName = "org.tyrcrypto.harness"
$component = "$packageName/$packageName.MainActivity"

function Read-HarnessOutput() {
  $prevErrorActionPreference = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $lines = adb -s $Serial shell run-as $packageName cat files/last_test_output.txt 2>$null
  } finally {
    $ErrorActionPreference = $prevErrorActionPreference
  }
  if ($LASTEXITCODE -ne 0) {
    return ""
  }
  return [string]::Join("`n", $lines)
}

if (!(Test-Path $apkPath)) {
  throw "Missing APK at $apkPath. Run tools/build_android_harness.ps1 first."
}
if ($TimeoutSeconds -lt 1) {
  throw "TimeoutSeconds must be >= 1."
}
if ($PollSeconds -lt 1) {
  throw "PollSeconds must be >= 1."
}

adb -s $Serial install -r $apkPath
adb -s $Serial shell am force-stop $packageName | Out-Null
adb -s $Serial shell run-as $packageName rm -f files/last_test_output.txt | Out-Null
adb -s $Serial shell run-as $packageName rm -f files/last_trace_output.txt | Out-Null
adb -s $Serial shell am start -n $component | Out-Null

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while ((Get-Date) -lt $deadline) {
  $output = Read-HarnessOutput
  if ($output.StartsWith("exit=") -or $output.StartsWith("error=")) {
    Write-Output $output
    exit 0
  }
  Start-Sleep -Seconds $PollSeconds
}

throw "Timed out waiting for Android harness output after $TimeoutSeconds seconds."
