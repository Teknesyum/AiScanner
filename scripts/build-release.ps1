param([string]$Version = '0.3.0')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$project = Join-Path $root 'src\AiScanner.App\AiScanner.App.csproj'
$release = Join-Path $root 'artifacts\release'
dotnet test (Join-Path $root 'AiScanner.sln') -c Release
if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
New-Item -ItemType Directory -Force -Path $release | Out-Null
foreach ($rid in @('win-x64','linux-x64','osx-x64','osx-arm64')) {
    $publish = Join-Path $root "artifacts\publish\$rid"
    if (Test-Path $publish) { Remove-Item -LiteralPath $publish -Recurse -Force }
    dotnet publish $project -c Release -r $rid --self-contained true -p:PublishSingleFile=true -p:Version=$Version -o $publish
    if ($LASTEXITCODE -ne 0) { throw "Publish failed for $rid." }
    if ($rid -eq 'win-x64') {
        $archive = Join-Path $release "AiScanner-v$Version-$rid.zip"
        if (Test-Path $archive) { Remove-Item -LiteralPath $archive -Force }
        Compress-Archive -Path (Join-Path $publish '*') -DestinationPath $archive -CompressionLevel Optimal
    } else {
        $archive = Join-Path $release "AiScanner-v$Version-$rid.tar.gz"
        if (Test-Path $archive) { Remove-Item -LiteralPath $archive -Force }
        tar -czf $archive -C $publish .
        if ($LASTEXITCODE -ne 0) { throw "Archive failed for $rid." }
    }
    Write-Host $archive
}
