param(
  [ValidateSet("custom_crypto", "asymmetric_fast", "asymmetric_full")]
  [string]$HarnessTarget = "custom_crypto",
  [switch]$Release
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$harnessDir = Join-Path $repoRoot "tests\android_harness"
$zigDir = Join-Path $repoRoot "build\zig-windows-x86_64-0.13.0"
$androidSdk = if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT } else { "C:\Users\n1ght\AppData\Local\Android\Sdk" }
$javaHome = if ($env:JAVA_HOME) { $env:JAVA_HOME } else { "C:\Program Files\Android\Android Studio\jbr" }
$nimsimdPath = "C:\Users\n1ght\.nimble\pkgs2\nimsimd-1.3.2-5202ce48d46eaf593da54e884774cdb2a884e717"
$buildMode = if ($Release) { "release" } else { "debug" }
$targetMap = @{
  custom_crypto = @{
    EntryPoint = "tests\test_android_custom_crypto.nim"
    BinaryBase = "test_android_custom_crypto"
    NimcacheBase = "custom"
  }
  asymmetric_fast = @{
    EntryPoint = "tests\test_android_asymmetric_fast.nim"
    BinaryBase = "test_android_asymmetric_fast"
    NimcacheBase = "asymmetric_fast"
  }
  asymmetric_full = @{
    EntryPoint = "tests\test_android_asymmetric_crypto.nim"
    BinaryBase = "test_android_asymmetric_crypto"
    NimcacheBase = "asymmetric_full"
  }
}
$target = $targetMap[$HarnessTarget]

function Invoke-NimHarnessBuild(
  [string]$Cpu,
  [string]$CompilerPath,
  [string]$NimcachePath,
  [string]$OutputPath
) {
  $args = @(
    "c",
    "--os:linux",
    "--cpu:$Cpu",
    "--path:$nimsimdPath",
    "--cc:clang",
    "--clang.exe:$CompilerPath",
    "--clang.linkerexe:$CompilerPath",
    "--nimcache:$NimcachePath",
    "--out:$OutputPath"
  )
  if ($Cpu -eq "arm64") {
    $args += @(
      "-d:neon",
      "--passC:-fPIE",
      "--passL:-static"
    )
  }
  if ($Release) {
    $args += "-d:release"
  }
  $args += $target.EntryPoint
  & nim @args
  if ($LASTEXITCODE -ne 0) {
    throw "nim build failed for $Cpu"
  }
}

if (!(Test-Path (Join-Path $zigDir "zig.exe"))) {
  $zigZip = Join-Path $repoRoot "build\zig-windows-x86_64-0.13.0.zip"
  Invoke-WebRequest -Uri "https://ziglang.org/download/0.13.0/zig-windows-x86_64-0.13.0.zip" -OutFile $zigZip
  Expand-Archive -LiteralPath $zigZip -DestinationPath (Join-Path $repoRoot "build")
}

Push-Location $repoRoot
try {
  $arm64Out = "build\$($target.BinaryBase)_arm64"
  $x64Out = "build\$($target.BinaryBase)_x86_64"
  Invoke-NimHarnessBuild `
    -Cpu "arm64" `
    -CompilerPath "tools\zigcc_linux_aarch64.cmd" `
    -NimcachePath "build\nimcache_linux_arm64_$($target.NimcacheBase)_$buildMode" `
    -OutputPath $arm64Out
  Invoke-NimHarnessBuild `
    -Cpu "amd64" `
    -CompilerPath "tools\zigcc_linux_x86_64.cmd" `
    -NimcachePath "build\nimcache_linux_x64_$($target.NimcacheBase)_$buildMode" `
    -OutputPath $x64Out

  New-Item -ItemType Directory -Force (Join-Path $harnessDir "app\src\main\jniLibs\arm64-v8a") | Out-Null
  New-Item -ItemType Directory -Force (Join-Path $harnessDir "app\src\main\jniLibs\x86_64") | Out-Null
  Copy-Item -Force (Join-Path $repoRoot $arm64Out) (Join-Path $harnessDir "app\src\main\jniLibs\arm64-v8a\libtyrtests.so")
  Copy-Item -Force (Join-Path $repoRoot $x64Out) (Join-Path $harnessDir "app\src\main\jniLibs\x86_64\libtyrtests.so")

  $env:JAVA_HOME = $javaHome
  $env:ANDROID_HOME = $androidSdk
  $env:ANDROID_SDK_ROOT = $androidSdk
  $env:GRADLE_USER_HOME = Join-Path $repoRoot "build\gradle-home"
  New-Item -ItemType Directory -Force -Path $env:GRADLE_USER_HOME | Out-Null

  Push-Location $harnessDir
  try {
    .\gradlew.bat assembleDebug
  } finally {
    Pop-Location
  }
} finally {
  Pop-Location
}
