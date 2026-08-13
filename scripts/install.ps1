$ErrorActionPreference = 'Stop'
$repo = 'Teknesyum/AiScanner'
$installDir = Join-Path $env:LOCALAPPDATA 'Programs\AiScanner'
$release = Invoke-RestMethod -Headers @{ 'User-Agent' = 'AiScanner-Installer' } -Uri "https://api.github.com/repos/$repo/releases/latest"
$asset = $release.assets | Where-Object { $_.name -match '^AiScanner-v.+-win-x64\.zip$' } | Select-Object -First 1
if (-not $asset) { throw 'The latest release does not contain a Windows x64 package.' }

$temporaryDir = Join-Path ([IO.Path]::GetTempPath()) ("AiScanner-" + [guid]::NewGuid().ToString('N'))
$archivePath = Join-Path $temporaryDir 'AiScanner.zip'
New-Item -ItemType Directory -Force -Path $temporaryDir | Out-Null

try {
    Invoke-WebRequest -UseBasicParsing -Uri $asset.browser_download_url -OutFile $archivePath
    if (Test-Path $installDir) {
        $runningProcesses = @(Get-Process -Name 'AiScanner' -ErrorAction SilentlyContinue)
        if ($runningProcesses.Count -gt 0) {
            $runningProcesses | Stop-Process -Force
            $runningProcesses | ForEach-Object { $_.WaitForExit(5000) }
        }
        Remove-Item -LiteralPath $installDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    Expand-Archive -LiteralPath $archivePath -DestinationPath $installDir -Force

    $executable = Join-Path $installDir 'AiScanner.exe'
    if (-not (Test-Path $executable)) { throw 'AiScanner.exe was not found in the downloaded package.' }

    $desktop = [Environment]::GetFolderPath('Desktop')
    $shortcutPath = Join-Path $desktop 'AI Scanner.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $executable
    $shortcut.WorkingDirectory = $installDir
    $shortcut.Description = 'Local process telemetry and behavioral threat analysis'
    $shortcut.IconLocation = "$executable,0"
    $shortcut.Save()

    Start-Process -FilePath $executable
    Write-Host "AI Scanner $($release.tag_name) was installed successfully." -ForegroundColor Cyan
} finally {
    if (Test-Path $temporaryDir) { Remove-Item -LiteralPath $temporaryDir -Recurse -Force }
}
