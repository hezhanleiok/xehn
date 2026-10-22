# 开发期辅助：解析检查本目录所有 .ps1 的语法（不执行）
$ok = $true
Get-ChildItem $PSScriptRoot -Filter *.ps1 | ForEach-Object {
    $errs = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$errs)
    if ($errs -and $errs.Count -gt 0) {
        $ok = $false
        Write-Host ("[语法错误] " + $_.Name) -ForegroundColor Red
        $errs | ForEach-Object { Write-Host ("   line " + $_.Extent.StartLineNumber + ": " + $_.Message) }
    } else {
        Write-Host ("[OK] " + $_.Name) -ForegroundColor Green
    }
}
if ($ok) { exit 0 } else { exit 1 }
