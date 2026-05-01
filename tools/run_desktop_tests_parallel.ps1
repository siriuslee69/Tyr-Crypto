param(
  [switch]$Full,
  [int]$MaxParallel = 0,
  [string]$Only = "",
  [string]$ChildNimFlags = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$buildRoot = Join-Path $repoRoot "build"
$logRoot = Join-Path $buildRoot "parallel_tests"
New-Item -ItemType Directory -Force -Path $logRoot | Out-Null

$env:NIMBLE_DIR = (Join-Path $repoRoot ".nimble_cache")
$env:LIBOQS_AUTO_BUILD = "yes"
$env:LIBSODIUM_AUTO_BUILD = "yes"

$defines = @()
if ($Full) {
  $defines += "-d:hasLiboqs"
  $defines += "-d:hasLibsodium"
  $defines += "-d:hasOpenSSL3"
}

$childFlags = @()
if ($ChildNimFlags.Trim().Length -gt 0) {
  $childFlags = $ChildNimFlags -split "\s+"
}

$groups = @(
  [pscustomobject]@{
    Name = "core"
    Tests = @(
      "test_common.nim",
      "test_registry.nim",
      "test_libsodium.nim",
      "test_nimcrypto.nim",
      "test_quick_api.nim",
      "test_primitives_api.nim",
      "test_hybrid_kex_triple.nim",
      "test_hybrid_kex_duo.nim",
      "test_signatures.nim",
      "test_liboqs.nim",
      "test_openssl.nim"
    )
  },
  [pscustomobject]@{
    Name = "custom_crypto"
    Tests = @("test_custom_crypto.nim")
  },
  [pscustomobject]@{
    Name = "sha3"
    Tests = @("test_sha3_custom.nim", "test_sha3_simd.nim")
  },
  [pscustomobject]@{
    Name = "poly1305"
    Tests = @("test_poly1305_custom.nim", "test_poly1305_simd.nim")
  },
  [pscustomobject]@{
    Name = "aes"
    Tests = @("test_aes_ctr.nim", "test_aes_gcm_compare.nim")
  },
  [pscustomobject]@{
    Name = "gimli"
    Tests = @("test_gimli_sse.nim", "test_gimli_vectors.nim")
  },
  [pscustomobject]@{
    Name = "blake3"
    Tests = @("test_blake3_simd.nim", "test_blake3_stream.nim")
  },
  [pscustomobject]@{
    Name = "xchacha20"
    Tests = @("test_xchacha20_simd.nim")
  },
  [pscustomobject]@{
    Name = "random"
    Tests = @("test_random_entropy.nim")
  },
  [pscustomobject]@{
    Name = "hmac"
    Tests = @("test_custom_hmac.nim")
  },
  [pscustomobject]@{
    Name = "otp"
    Tests = @("test_otp.nim")
  },
  [pscustomobject]@{
    Name = "x25519"
    Tests = @("test_x25519_custom.nim", "test_x25519_simd.nim")
  },
  [pscustomobject]@{
    Name = "kyber"
    Tests = @("test_kyber_tyr.nim", "test_kyber_kat.nim")
  },
  [pscustomobject]@{
    Name = "frodo"
    Tests = @("test_frodo_tyr.nim", "test_frodo_kat.nim")
  },
  [pscustomobject]@{
    Name = "bike"
    Tests = @("test_bike_tyr.nim", "test_bike_kat.nim")
  },
  [pscustomobject]@{
    Name = "ntru"
    Tests = @("test_ntru_tyr.nim")
  },
  [pscustomobject]@{
    Name = "saber"
    Tests = @("test_saber_tyr.nim")
  },
  [pscustomobject]@{
    Name = "dilithium"
    Tests = @("test_dilithium_tyr.nim", "test_dilithium_kat.nim")
  },
  [pscustomobject]@{
    Name = "falcon512"
    Aliases = @("falcon")
    Env = @{
      TYR_FALCON_TEST_VARIANT = "512"
    }
    Tests = @("test_falcon_tyr.nim")
  },
  [pscustomobject]@{
    Name = "falcon1024"
    Aliases = @("falcon")
    Env = @{
      TYR_FALCON_TEST_VARIANT = "1024"
    }
    Tests = @("test_falcon_tyr.nim")
  },
  [pscustomobject]@{
    Name = "sphincs"
    Tests = @("test_sphincs_tyr.nim", "test_sphincs_kat.nim")
  },
  [pscustomobject]@{
    Name = "mceliece"
    Tests = @("test_mceliece_tyr.nim")
  }
)

function Test-GroupSelected {
  param(
    [object]$Group,
    [hashtable]$Wanted
  )

  $groupName = $Group.Name.ToLowerInvariant()
  if ($Wanted.ContainsKey($groupName)) {
    return $true
  }

  if ($Group.PSObject.Properties.Name -contains "Aliases") {
    foreach ($alias in $Group.Aliases) {
      $aliasName = ([string]$alias).ToLowerInvariant()
      if ($Wanted.ContainsKey($aliasName)) {
        return $true
      }
    }
  }

  return $false
}

if ($Only.Trim().Length -gt 0) {
  $wanted = @{}
  foreach ($name in ($Only -split ",")) {
    $trimmed = $name.Trim().ToLowerInvariant()
    if ($trimmed.Length -gt 0) {
      $wanted[$trimmed] = $true
    }
  }
  $groups = @($groups | Where-Object { Test-GroupSelected -Group $_ -Wanted $wanted })
  if ($groups.Count -eq 0) {
    throw "No test groups matched -Only '$Only'"
  }
}

if ($MaxParallel -le 0 -or $MaxParallel -gt $groups.Count) {
  $MaxParallel = $groups.Count
}

function Start-TestGroupJob {
  param(
    [object]$Group,
    [string]$RepoRoot,
    [string]$LogRoot,
    [string[]]$Defines,
    [string[]]$ChildFlags,
    [hashtable]$GroupEnv,
    [switch]$Full
  )

  $scriptBlock = {
    param($GroupName, $Tests, $RepoRoot, $LogRoot, $Defines, $ChildFlags, $GroupEnv, $Full)

    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"
    Set-Location $RepoRoot

    $env:NIMBLE_DIR = (Join-Path $RepoRoot ".nimble_cache")
    $env:LIBOQS_AUTO_BUILD = "yes"
    $env:LIBSODIUM_AUTO_BUILD = "yes"
    foreach ($entry in $GroupEnv.GetEnumerator()) {
      Set-Item -Path ("Env:{0}" -f $entry.Key) -Value ([string]$entry.Value)
    }

    $start = Get-Date
    $logPath = Join-Path $LogRoot ("$GroupName.log")
    if (Test-Path $logPath) {
      Remove-Item -LiteralPath $logPath -Force
    }

    "[$GroupName] start $($start.ToString('s')) full=$Full" | Out-File -FilePath $logPath -Encoding utf8

    foreach ($test in $Tests) {
      $testBase = [System.IO.Path]::GetFileNameWithoutExtension($test)
      $cache = Join-Path $RepoRoot (Join-Path "build" "nimcache_test_parallel_${GroupName}_${testBase}")
      $testPath = Join-Path "tests" $test
      $args = @("c", "--nimcache:$cache") + $ChildFlags + $Defines + @("-r", $testPath)

      "`n[$GroupName] nim $($args -join ' ')" | Out-File -FilePath $logPath -Append -Encoding utf8
      $oldErrorActionPreference = $ErrorActionPreference
      $ErrorActionPreference = "Continue"
      if (Test-Path Variable:\PSNativeCommandUseErrorActionPreference) {
        $oldNativeErrorAction = $PSNativeCommandUseErrorActionPreference
        $PSNativeCommandUseErrorActionPreference = $false
      }
      & nim @args *>> $logPath
      $code = $LASTEXITCODE
      if (Test-Path Variable:\oldNativeErrorAction) {
        $PSNativeCommandUseErrorActionPreference = $oldNativeErrorAction
        Remove-Variable oldNativeErrorAction -ErrorAction SilentlyContinue
      }
      $ErrorActionPreference = $oldErrorActionPreference
      if ($code -ne 0) {
        "[${GroupName}] failed $test exit=$code" | Out-File -FilePath $logPath -Append -Encoding utf8
        [pscustomobject]@{
          Name = $GroupName
          Status = "failed"
          ExitCode = $code
          Log = $logPath
          Seconds = [int]((Get-Date) - $start).TotalSeconds
        }
        return
      }
    }

    $elapsed = [int]((Get-Date) - $start).TotalSeconds
    "[${GroupName}] pass elapsed=${elapsed}s" | Out-File -FilePath $logPath -Append -Encoding utf8
    [pscustomobject]@{
      Name = $GroupName
      Status = "passed"
      ExitCode = 0
      Log = $logPath
      Seconds = $elapsed
    }
  }

  Start-Job -Name $Group.Name -ScriptBlock $scriptBlock -ArgumentList @(
    $Group.Name,
    $Group.Tests,
    $RepoRoot,
    $LogRoot,
    $Defines,
    $ChildFlags,
    $GroupEnv,
    [bool]$Full
  )
}

Write-Host "Running $($groups.Count) desktop test groups with MaxParallel=$MaxParallel"
Write-Host "Logs: $logRoot"

$pending = [System.Collections.Queue]::new()
foreach ($group in $groups) {
  $pending.Enqueue($group)
}

$running = @()
$results = @()

while ($pending.Count -gt 0 -or $running.Count -gt 0) {
  while ($pending.Count -gt 0 -and $running.Count -lt $MaxParallel) {
    $group = $pending.Dequeue()
    $groupEnv = @{}
    if ($group.PSObject.Properties.Name -contains "Env" -and $null -ne $group.Env) {
      $groupEnv = $group.Env
    }
    Write-Host "[$($group.Name)] queued"
    $running += Start-TestGroupJob -Group $group -RepoRoot $repoRoot -LogRoot $logRoot -Defines $defines -ChildFlags $childFlags -GroupEnv $groupEnv -Full:$Full
  }

  $completed = Wait-Job -Job $running -Any
  $received = Receive-Job -Job $completed
  $results += $received
  Remove-Job -Job $completed
  $running = @($running | Where-Object { $_.Id -ne $completed.Id })

  foreach ($item in $received) {
    if ($item.Status -eq "passed") {
      Write-Host "[$($item.Name)] pass in $($item.Seconds)s"
    } else {
      Write-Host "[$($item.Name)] FAILED in $($item.Seconds)s; log=$($item.Log)"
    }
  }
}

$failed = @($results | Where-Object { $_.Status -ne "passed" })
if ($failed.Count -gt 0) {
  Write-Host ""
  Write-Host "Failed test groups:"
  foreach ($item in $failed) {
    Write-Host "- $($item.Name): $($item.Log)"
    Write-Host "  tail:"
    Get-Content -LiteralPath $item.Log -Tail 120
  }
  exit 1
}

$totalSeconds = ($results | Measure-Object -Property Seconds -Maximum).Maximum
Write-Host ""
Write-Host "All desktop test groups passed. Longest group: ${totalSeconds}s"
