param([string]$Apk = "E:\xehn-android\app\build\outputs\apk\debug\app-debug.apk")

Add-Type -AssemblyName System.IO.Compression.FileSystem
$item = Get-Item $Apk
"APK: {0}  {1:N1} MB  {2}" -f $item.FullName, ($item.Length / 1MB), $item.LastWriteTime

$zip = [IO.Compression.ZipFile]::OpenRead($Apk)
$text = New-Object System.Text.StringBuilder
foreach ($e in $zip.Entries) {
    if ($e.FullName -like "classes*.dex") {
        $s = $e.Open()
        $ms = New-Object IO.MemoryStream
        $s.CopyTo($ms)
        [void]$text.Append([Text.Encoding]::UTF8.GetString($ms.ToArray()))
        $ms.Dispose()
        $s.Dispose()
    }
}
$zip.Dispose()
$all = $text.ToString()

foreach ($k in @(
    "connect 被引擎拒绝",
    "引擎还在上一轮连接里",
    "连接流程异常",
    "已连续",
    "保留当前连接、不再因速度换节点",
    "测延迟",
    "NodeProbeStore"
)) {
    "{0,-24} {1}" -f $k, $all.Contains($k)
}
