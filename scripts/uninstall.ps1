$ErrorActionPreference = 'Stop'
$installDir = Join-Path $env:LOCALAPPDATA 'Programs\AiScanner'
$shortcutPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'AI Scanner.lnk'
Get-Process -Name 'AiScanner' -ErrorAction SilentlyContinue | Stop-Process -Force
if (Test-Path $shortcutPath) { Remove-Item -LiteralPath $shortcutPath -Force }

$cleanup = Join-Path ([IO.Path]::GetTempPath()) ("AiScanner-Uninstall-" + [guid]::NewGuid().ToString('N') + '.ps1')
@"
Start-Sleep -Seconds 2
if (Test-Path '$($installDir.Replace("'", "''"))') { Remove-Item -LiteralPath '$($installDir.Replace("'", "''"))' -Recurse -Force }
Remove-Item -LiteralPath `$PSCommandPath -Force
"@ | Set-Content -LiteralPath $cleanup -Encoding UTF8
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $cleanup
Write-Host 'AI Scanner was removed. Local telemetry was retained.' -ForegroundColor Cyan
