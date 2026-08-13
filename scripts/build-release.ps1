param([string]$Version = '0.2.0')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$publishDir = Join-Path $projectRoot 'artifacts\publish\win-x64'
$releaseDir = Join-Path $projectRoot 'artifacts\release'
$archive = Join-Path $releaseDir "AiScanner-v$Version-win-x64.zip"

dotnet test (Join-Path $projectRoot 'AiScanner.sln') -c Release
if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
dotnet publish (Join-Path $projectRoot 'src\AiScanner.App\AiScanner.App.csproj') -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:Version=$Version -o $publishDir
if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }

Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'uninstall.ps1') -Destination $publishDir -Force
New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null
if (Test-Path $archive) { Remove-Item -LiteralPath $archive -Force }
Compress-Archive -Path (Join-Path $publishDir '*') -DestinationPath $archive -CompressionLevel Optimal
Write-Host $archive
