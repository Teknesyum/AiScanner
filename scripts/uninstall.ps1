$ErrorActionPreference = 'Stop'
$installDir = Join-Path $env:LOCALAPPDATA 'Programs\ProcWitness'
$shortcutPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'ProcWitness.lnk'
Get-Process -Name 'ProcWitness' -ErrorAction SilentlyContinue | Stop-Process -Force
if (Test-Path $shortcutPath) { Remove-Item -LiteralPath $shortcutPath -Force }
$cliDirectory = Join-Path $installDir 'cli'
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$updatedPath = @($userPath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -ne $cliDirectory }) -join ';'
[Environment]::SetEnvironmentVariable('Path', $updatedPath, 'User')

$cleanup = Join-Path ([IO.Path]::GetTempPath()) ("ProcWitness-Uninstall-" + [guid]::NewGuid().ToString('N') + '.ps1')
@"
Start-Sleep -Seconds 2
if (Test-Path '$($installDir.Replace("'", "''"))') { Remove-Item -LiteralPath '$($installDir.Replace("'", "''"))' -Recurse -Force }
Remove-Item -LiteralPath `$PSCommandPath -Force
"@ | Set-Content -LiteralPath $cleanup -Encoding UTF8
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $cleanup
Write-Host 'ProcWitness was removed. Local telemetry was retained.' -ForegroundColor Cyan
