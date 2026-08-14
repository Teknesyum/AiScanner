$ErrorActionPreference = 'Stop'
$repo = 'Teknesyum/ProcWitness'
$installDir = Join-Path $env:LOCALAPPDATA 'Programs\ProcWitness'
$release = Invoke-RestMethod -Headers @{ 'User-Agent' = 'ProcWitness-Installer' } -Uri "https://api.github.com/repos/$repo/releases/latest"
$asset = $release.assets | Where-Object { $_.name -match '^ProcWitness-.+-win-x64\.zip$' } | Select-Object -First 1
if (-not $asset) { throw 'The latest release does not contain a Windows x64 package.' }

$temporaryDir = Join-Path ([IO.Path]::GetTempPath()) ("ProcWitness-" + [guid]::NewGuid().ToString('N'))
$archivePath = Join-Path $temporaryDir 'ProcWitness.zip'
New-Item -ItemType Directory -Force -Path $temporaryDir | Out-Null

try {
    Invoke-WebRequest -UseBasicParsing -Uri $asset.browser_download_url -OutFile $archivePath
    if (Test-Path $installDir) {
        $runningProcesses = @(Get-Process -Name 'ProcWitness' -ErrorAction SilentlyContinue)
        if ($runningProcesses.Count -gt 0) {
            $runningProcesses | Stop-Process -Force
            $runningProcesses | ForEach-Object { $_.WaitForExit(5000) }
        }
        Remove-Item -LiteralPath $installDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    Expand-Archive -LiteralPath $archivePath -DestinationPath $installDir -Force

    $executable = Join-Path $installDir 'ProcWitness.exe'
    if (-not (Test-Path $executable)) { throw 'ProcWitness.exe was not found in the downloaded package.' }

    $desktop = [Environment]::GetFolderPath('Desktop')
    $shortcutPath = Join-Path $desktop 'ProcWitness.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $executable
    $shortcut.WorkingDirectory = $installDir
    $shortcut.Description = 'Local process telemetry and behavioral threat analysis'
    $shortcut.IconLocation = "$executable,0"
    $shortcut.Save()

    $cliDirectory = Join-Path $installDir 'cli'
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $pathParts = @($userPath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($pathParts -notcontains $cliDirectory) {
        [Environment]::SetEnvironmentVariable('Path', (($pathParts + $cliDirectory) -join ';'), 'User')
        $env:Path = "$env:Path;$cliDirectory"
    }

    Start-Process -FilePath $executable
    Write-Host "ProcWitness $($release.tag_name) was installed successfully." -ForegroundColor Cyan
} finally {
    if (Test-Path $temporaryDir) { Remove-Item -LiteralPath $temporaryDir -Recurse -Force }
}
