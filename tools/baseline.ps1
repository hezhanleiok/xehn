# baseline.ps1 -- create a rollback point before a round of changes.
#
# What it does (and does NOT do):
#   1. git add -A + commit (no-op when the tree is already clean)
#   2. tag the commit: baseline-<yyyyMMdd>-<Name>
#   3. zip the sources to <drive>:\<backup dir>\xehn-android-<tag>.zip
#   4. NEVER pushes: this repo has no remote and pushing is not allowed.
#
# Usage:
#   .\tools\baseline.ps1 -Name r3 -Message "bump version, notes"
#
# NOTE: keep this file ASCII-only. Windows PowerShell 5.1 reads UTF-8 without BOM
# as ANSI, which used to turn a Chinese backup path into a garbled directory name.
param(
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$Message = ""
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

# "备份" written as code points so the script stays pure ASCII.
$backupDir = Join-Path (Split-Path -Parent $repo) ([string]::Concat([char]0x5907, [char]0x4EFD))
$stamp = Get-Date -Format 'yyyyMMdd'
$tag = "baseline-$stamp-$Name"

if (-not (Test-Path (Join-Path $repo '.git'))) {
    throw "not a git repository: $repo"
}

$remotes = (& git remote) 2>$null
if ($remotes) {
    Write-Host "WARNING: repo has remotes ($($remotes -join ', ')). This script will not push." -ForegroundColor Yellow
}

# 1) commit
& git add -A
$dirty = (& git status --porcelain)
if ($dirty) {
    $msg = if ($Message) { $Message } else { "baseline: $Name" }
    & git commit -q -m $msg
    if ($LASTEXITCODE -ne 0) { throw "git commit failed" }
    Write-Host "committed: $msg"
} else {
    Write-Host "working tree already clean, nothing to commit"
}

$head = (& git rev-parse --short HEAD)

# 2) tag (re-point silently if the name already exists)
if ((& git tag -l $tag)) {
    & git tag -f $tag | Out-Null
    Write-Host "tag updated: $tag -> $head"
} else {
    & git tag $tag
    Write-Host "tagged: $tag -> $head"
}

# 3) source snapshot (no build output, no .git, no apk/aar, no logs)
if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir | Out-Null }
$zipPath = Join-Path $backupDir ("xehn-android-" + $tag + ".zip")
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

$skip = @('\build\', '\.gradle\', '\.kotlin\', '\.git\')
$files = Get-ChildItem $repo -Recurse -File -Force | Where-Object {
    $p = $_.FullName
    if ($_.Extension -in @('.log', '.apk', '.aar', '.zip')) { return $false }
    if ($_.Name -like '.tmp_*') { return $false }
    foreach ($s in $skip) { if ($p.Contains($s)) { return $false } }
    return $true
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$fs = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::Create)
$zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
$info = "xehn-android source snapshot`r`ntag     : $tag`r`ncommit  : $head`r`ncreated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`nexcluded: build/, .gradle/, .kotlin/, .git/, *.apk, *.aar, *.log, .tmp_*`r`n"
$entry = $zip.CreateEntry('SNAPSHOT-INFO.txt')
$writer = New-Object System.IO.StreamWriter($entry.Open())
$writer.Write($info)
$writer.Flush(); $writer.Dispose()
foreach ($f in $files) {
    $rel = $f.FullName.Substring($repo.Length + 1).Replace('\', '/')
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
        $zip, $f.FullName, $rel, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
}
$zip.Dispose(); $fs.Dispose()

$size = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
Write-Host "snapshot: $zipPath ($size MB, $($files.Count) files)"
Write-Host ""
Write-Host "next round: bump versionCode/versionName in app/build.gradle.kts, then edit." -ForegroundColor Cyan
Write-Host "rollback  : git checkout $tag -- engine app" -ForegroundColor Cyan
