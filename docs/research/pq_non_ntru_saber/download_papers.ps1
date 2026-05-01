param(
  [string]$LockPath = (Join-Path $PSScriptRoot "papers.lock.json"),
  [switch]$IncludeTracked,
  [switch]$Force
)

$ErrorActionPreference = "Stop"

function Get-RepoRoot {
  $root = Join-Path $PSScriptRoot "..\..\.."
  $resolved = Resolve-Path -LiteralPath $root
  return $resolved.Path
}

function Get-TargetPath {
  param(
    [string]$RepoRoot,
    [string]$LocalPath
  )

  $relative = $LocalPath -replace '/', [IO.Path]::DirectorySeparatorChar
  return Join-Path $RepoRoot $relative
}

function Test-DocumentHash {
  param(
    [string]$Path,
    [string]$Sha256
  )

  if (-not (Test-Path -LiteralPath $Path)) {
    return $false
  }

  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
  return $actual -eq $Sha256
}

$repoRoot = Get-RepoRoot
$manifest = Get-Content -Raw -LiteralPath $LockPath | ConvertFrom-Json

foreach ($document in $manifest.documents) {
  if (($document.gitPolicy -eq "tracked") -and (-not $IncludeTracked)) {
    continue
  }

  $target = Get-TargetPath -RepoRoot $repoRoot -LocalPath $document.localPath
  $targetDir = Split-Path -Parent $target
  New-Item -ItemType Directory -Force -Path $targetDir | Out-Null

  if ((-not $Force) -and (Test-DocumentHash -Path $target -Sha256 $document.sha256)) {
    Write-Host "ok   $($document.localPath)"
    continue
  }

  $tmp = "$target.download"
  if (Test-Path -LiteralPath $tmp) {
    Remove-Item -LiteralPath $tmp -Force
  }

  Write-Host "get  $($document.localPath)"
  Invoke-WebRequest -Uri $document.pdfUrl -OutFile $tmp

  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $tmp).Hash.ToLowerInvariant()
  if ($actual -ne $document.sha256) {
    Remove-Item -LiteralPath $tmp -Force
    throw "sha256 mismatch for $($document.localPath): expected $($document.sha256), got $actual"
  }

  Move-Item -LiteralPath $tmp -Destination $target -Force
}
