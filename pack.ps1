# pack.ps1 — assemble the portable XEHN ZIP (v2rayN-style layout).
#
#   .\pack.ps1 [-MihomoPath <path>] [-PsiphonExePath <path>] [-PsiphonConfigPath <path>]
#              [-Version <tag>] [-SkipBuild]
#
# Layout produced in dist\:
#   XEHN\
#   ├── xehn.exe          ← the only program file: double-click opens the GUI;
#   │                       arguments run the CLI in the calling terminal
#   ├── core\
#   │   ├── mihomo.exe    ← the Clash core, updatable independently
#   │   ├── psiphon.exe   ← optional: the Psiphon exit sidecar (GPL-3.0)
#   │   ├── client.config ← optional: official Psiphon credentials (needed with psiphon.exe)
#   │   └── server_list.dat ← optional: initial Psiphon server list
#   ├── licenses\
#   │   └── GPL-3.0.txt   ← license text for the bundled mihomo + Psiphon
#   ├── THIRD_PARTY_NOTICES.md
#   └── README.txt
#
# Everything else (account, scan cache, state, config.yaml, logs) is created at
# runtime next to the exe thanks to portable-mode auto-anchoring. The staging
# tree is verified below and packaging aborts if any account or runtime state
# file sneaks in, so a fresh extraction starts with no credentials and its
# first connect/scan registers a new WARP device for that machine.
param(
    [string]$MihomoPath = "",
    [string]$PsiphonExePath = "",
    [string]$PsiphonConfigPath = "",
    [string]$Version = "",
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$dist = Join-Path $here 'dist'
$buildDir = Join-Path $dist 'build'
$bin = Join-Path $buildDir 'xehn.exe'
$root = Join-Path $dist 'XEHN'
$stamp = Get-Date -Format 'yyyyMMddHHmmss'
if (-not $Version) { $Version = "0.3.0-$stamp" }

New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

if (-not $SkipBuild) {
    # Environment: keep Go caches inside the workspace when unset outside.
    if (-not $env:GOMODCACHE) { $env:GOMODCACHE = 'E:\xiaohe\xhwarp\.gomod' }
    if (-not $env:GOCACHE)    { $env:GOCACHE    = 'E:\xiaohe\xhwarp\.gocache' }
    if (-not $env:GOPATH)     { $env:GOPATH     = 'E:\xiaohe\xhwarp\.gopath' }
    if (-not $env:GOPROXY)    { $env:GOPROXY    = 'https://goproxy.cn,direct' }
    $env:GOOS = 'windows'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'

    Push-Location $here

    # Regenerate the logo artifacts from the source art: the embedded PNG the
    # in-app brand + window/taskbar icon render from, and the multi-size .ico
    # rsrc bakes into the exe as the program icon. The source lives one level up
    # (the workspace root); a missing source leaves the committed artifacts.
    $logoSrc = Join-Path $here '..\logo.png'
    if (Test-Path $logoSrc) {
        go run ./tools/mklogo -src $logoSrc -png assets/logo.png -ico logo.ico
        if ($LASTEXITCODE -ne 0) { Pop-Location; throw "mklogo failed to build the logo artifacts" }
    }

    # Embed the Win32 manifest (comctl32 v6 + PerMonitorV2 DPI) and the app icon
    # (.ico -> the exe's program/taskbar-group icon). walk's native widgets
    # require themed common controls or NewMainWindow fails with
    # "TTM_ADDTOOL failed" at startup. rsrc is installed via
    #   go install github.com/akavel/rsrc@latest
    $rsrc = Join-Path $env:GOPATH 'bin\rsrc.exe'
    $syso = Join-Path $here 'rsrc_windows_amd64.syso'
    $icoArgs = @()
    if (Test-Path (Join-Path $here 'logo.ico')) { $icoArgs = @('-ico', (Join-Path $here 'logo.ico')) }
    if (Test-Path $rsrc) {
        & $rsrc -manifest (Join-Path $here 'app.manifest') @icoArgs -o $syso -arch amd64
        if ($LASTEXITCODE -ne 0) { Pop-Location; throw "rsrc failed to embed manifest/icon" }
    } elseif (-not (Test-Path $syso)) {
        Pop-Location; throw "rsrc_windows_amd64.syso missing AND rsrc.exe not installed — install via: go install github.com/akavel/rsrc@latest"
    }

    # ONE program file. The windowsgui subsystem keeps a double-click free of a
    # console window; CLI subcommands dispatch through the same exe and attach
    # to the caller's terminal at startup, so the old console twin is gone.
    go build -trimpath -ldflags "-s -w -H windowsgui -X main.version=$Version -X main.windowsGUIBuild=1 -X main.buildStamp=$stamp" -o $bin .
    if ($LASTEXITCODE -ne 0) { Pop-Location; throw "single windowsgui build failed" }

    Pop-Location
    Write-Host "built xehn.exe ($Version)"
} elseif (-not (Test-Path $bin)) {
    throw "-SkipBuild given but $bin is missing; run pack.ps1 without -SkipBuild first"
}

# A release must not carry this machine's WARP identity. Excluding the account
# file is not enough: a stray go:embed or a pasted constant would put the
# private key inside the binary, where no file-level check would ever see it.
# Only secret fields are checked. peer_public_key is deliberately not: it is
# Cloudflare's public peer key (the same constant warp.go compiles in), so
# finding it proves nothing.
$acctFile = Join-Path $here 'warpscout-account.json'
if (Test-Path $acctFile) {
    $acct = Get-Content $acctFile -Raw | ConvertFrom-Json
    $localKeys = @($acct.private_key, $acct.token)
    if ($acct.outer) { $localKeys += @($acct.outer.private_key, $acct.outer.token) }
    if ($acct.masque) { $localKeys += @($acct.masque.private_key, $acct.masque.token) }
    $localKeys = @($localKeys | Where-Object { $_ -and $_.Length -ge 16 })
    if ($localKeys.Count -gt 0) {
        $exeText = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($bin))
        foreach ($k in $localKeys) {
            if ($exeText.Contains($k)) {
                throw "refusing to package: xehn.exe embeds this machine's WARP credentials (a private key or token from warpscout-account.json was found in the binary)"
            }
        }
        Write-Host "verified: no local WARP credentials embedded in the exe"
    }
}

# Older packs wrote a second GUI-named exe into the source tree. Remove that
# stale artifact so the layout cannot be mistaken for a two-program release.
$legacyGUI = Join-Path $here 'warp-client-gui.exe'
if (Test-Path $legacyGUI) {
    Remove-Item $legacyGUI -Force -ErrorAction SilentlyContinue
    if (Test-Path $legacyGUI) {
        Write-Host 'note: warp-client-gui.exe is in use; close it and delete it manually'
    }
}

# Fresh staging tree. Only files copied explicitly below can reach the ZIP.
if (Test-Path $root) { Remove-Item $root -Recurse -Force }
New-Item -ItemType Directory -Force -Path "$root\core" | Out-Null

Copy-Item $bin (Join-Path $root 'xehn.exe')

# Core: bundled when provided, otherwise the GUI downloads it on first run.
if ($MihomoPath -and (Test-Path $MihomoPath)) {
    Copy-Item $MihomoPath (Join-Path $root 'core\mihomo.exe') -Force
    Write-Host "bundled core: $([math]::Round((Get-Item $MihomoPath).Length/1MB,1)) MB"
} else {
    Write-Host "no -MihomoPath given: core/ stays empty; the GUI offers one-click download"
}

# Geo databases: the "bypass mainland" preset renders GEOSITE,cn / GEOIP,CN,
# and mihomo refuses a config that references geodata it cannot find. Bundling
# them keeps that preset working on a machine that cannot reach GitHub; a
# package without them downloads them on first use instead.
foreach ($g in @('geosite.dat', 'geoip.metadb')) {
    $gp = Join-Path $here "core\$g"
    if (Test-Path $gp) {
        Copy-Item $gp (Join-Path $root "core\$g") -Force
        Write-Host ("bundled geo data: {0} ({1} MB)" -f $g, [math]::Round((Get-Item $gp).Length/1MB,1))
    } else {
        Write-Host "no core\${g}: the bypass preset will download it on first use"
    }
}

# Psiphon exit sidecar (V1): bundled when present. Both the executable and the
# official client config are required for `connect --psiphon` — the config carries
# the SponsorId / PropagationChannelId / server-list URLs without which Psiphon
# discovers zero servers. Defaults look in the source core\ dir so a dev tree
# that already has them packs them automatically.
if (-not $PsiphonExePath)    { $PsiphonExePath    = Join-Path $here 'core\psiphon.exe' }
if (-not $PsiphonConfigPath) { $PsiphonConfigPath = Join-Path $here 'core\client.config' }
if (Test-Path $PsiphonExePath) {
    Copy-Item $PsiphonExePath (Join-Path $root 'core\psiphon.exe') -Force
    Write-Host "bundled psiphon sidecar: $([math]::Round((Get-Item $PsiphonExePath).Length/1MB,1)) MB"
} else {
    Write-Host "no psiphon.exe: core\psiphon.exe absent; connect --psiphon will fail until it is placed"
}
if (Test-Path $PsiphonConfigPath) {
    Copy-Item $PsiphonConfigPath (Join-Path $root 'core\client.config') -Force
    Write-Host "bundled psiphon config: $PsiphonConfigPath"
    # The initial server list travels with the config: Psiphon uses it before it
    # has a downloaded list of its own.
    $serverList = Join-Path (Split-Path -Parent $PsiphonConfigPath) 'server_list.dat'
    if (Test-Path $serverList) {
        Copy-Item $serverList (Join-Path $root 'core\server_list.dat') -Force
        Write-Host "bundled psiphon server list: $([math]::Round((Get-Item $serverList).Length/1KB,0)) KB"
    }
} else {
    Write-Host "no client.config: core\client.config absent; connect --psiphon will fail until it is placed"
}

Copy-Item (Join-Path $here 'README-portable.txt') (Join-Path $root 'README.txt')

# Third-party license inventory + the GPL-3.0 text. The ZIP bundles GPL-3.0
# binaries (mihomo, Psiphon), so redistributing it must carry both.
if (Test-Path (Join-Path $here 'THIRD_PARTY_NOTICES.md')) {
    Copy-Item (Join-Path $here 'THIRD_PARTY_NOTICES.md') (Join-Path $root 'THIRD_PARTY_NOTICES.md')
}
$gpl = Join-Path $here 'third_party\GPL-3.0.txt'
if (Test-Path $gpl) {
    New-Item -ItemType Directory -Force -Path (Join-Path $root 'licenses') | Out-Null
    Copy-Item $gpl (Join-Path $root 'licenses\GPL-3.0.txt')
    Write-Host 'bundled licenses\GPL-3.0.txt'
} else {
    Write-Host 'WARNING: third_party\GPL-3.0.txt missing — the ZIP bundles GPL-3.0 binaries and must ship the license'
}

# A release ZIP is handed to other people: it must not carry this machine's
# WARP identity or runtime state. With no warpscout-account.json, ensureAccount()
# registers a new device on the recipient's first connect/scan.
$forbiddenNames = @(
    'warpscout-account.json', 'state.json', 'settings.json', 'cache.json',
    'config.yaml', 'cache.db', 'xehn.log',
    'vpngate-underlay.json', 'vpngate-failed.json', 'vpngate-last.json',
    'vpngate-nodes.json', 'vpngate-nodes-v2.json'
)
$leaks = @(Get-ChildItem $root -Recurse -File | Where-Object {
    ($forbiddenNames -contains $_.Name) -or
    ($_.Name -like 'vpngate-*.json') -or
    ($_.Name -like 'warp-report-*.txt')
})
if ($leaks.Count -gt 0) {
    $names = ($leaks | ForEach-Object { $_.FullName.Substring($root.Length + 1) }) -join ', '
    throw "refusing to package credentials/runtime state: $names"
}

$topExes = @(Get-ChildItem $root -File -Filter *.exe)
if ($topExes.Count -ne 1 -or $topExes[0].Name -ne 'xehn.exe') {
    throw "release must expose exactly one top-level program: xehn.exe"
}

# Zip it. Compress-Archive opens every file without sharing, and a freshly
# written 20 MB exe is often still being scanned by Defender at that moment:
# retry a few times, then fall back to the .NET API, which opens read-only.
$zip = Join-Path $dist "XEHN.$Version.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
$zipped = $false
for ($i = 1; $i -le 3 -and -not $zipped; $i++) {
    try {
        Compress-Archive -Path $root -DestinationPath $zip -CompressionLevel Optimal -ErrorAction Stop
        $zipped = $true
    } catch {
        Write-Host ("compress attempt {0} failed: {1}" -f $i, $_.Exception.Message)
        Start-Sleep -Seconds 3
        if (Test-Path $zip) { Remove-Item $zip -Force -ErrorAction SilentlyContinue }
    }
}
if (-not $zipped) {
    Write-Host 'falling back to System.IO.Compression'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($root, $zip, [System.IO.Compression.CompressionLevel]::Optimal, $true)
}

# Verify the archive itself, not only the staging tree: this is the artifact
# that leaves the machine.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($zip)
try {
    $entries = @($archive.Entries | ForEach-Object { $_.FullName.Replace('\', '/') })
} finally {
    $archive.Dispose()
}
$leakedEntries = @($entries | Where-Object {
    $_ -match '(^|/)(warpscout-account\.json|state\.json|settings\.json|cache\.json|config\.yaml|cache\.db|xehn\.log)$' -or
    $_ -match '(^|/)vpngate-.*\.json$' -or
    $_ -match '(^|/)warp-report-.*\.txt$'
})
if ($leakedEntries.Count -gt 0) {
    throw "archive contains credentials/runtime state: $($leakedEntries -join ', ')"
}
$zipExes = @($entries | Where-Object { $_ -match '^XEHN/[^/]+\.exe$' })
if ($zipExes.Count -ne 1) {
    throw "archive must contain exactly one top-level program, found: $($zipExes -join ', ')"
}

Write-Host ""
Write-Host "ZIP ready: $zip ($([math]::Round((Get-Item $zip).Length/1MB,1)) MB)"
Write-Host "One program: xehn.exe (no account data in the archive)"
Write-Host "Layout:"
Get-ChildItem $root -Recurse -File | ForEach-Object {
    Write-Host ("  " + $_.FullName.Substring($root.Length + 1) + "  ($([math]::Round($_.Length/1MB,2)) MB)")
}
