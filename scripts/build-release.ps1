param([string]$Version = '0.9.0')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$project = Join-Path $root 'src\ProcWitness.App\ProcWitness.App.csproj'
$cliProject = Join-Path $root 'src\ProcWitness.Cli\ProcWitness.Cli.csproj'
$release = Join-Path $root 'artifacts\release'
dotnet test (Join-Path $root 'ProcWitness.sln') -c Release
if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
New-Item -ItemType Directory -Force -Path $release | Out-Null
foreach ($rid in @('win-x64','linux-x64','osx-x64','osx-arm64')) {
    $publish = Join-Path $root "artifacts\publish\$rid"
    if (Test-Path $publish) { Remove-Item -LiteralPath $publish -Recurse -Force }
    dotnet publish $project -c Release -r $rid --self-contained true -p:PublishSingleFile=true -p:Version=$Version -o $publish
    if ($LASTEXITCODE -ne 0) { throw "Publish failed for $rid." }
    $cliPublish = Join-Path $root "artifacts\publish-cli\$rid"
    if (Test-Path $cliPublish) { Remove-Item -LiteralPath $cliPublish -Recurse -Force }
    dotnet publish $cliProject -c Release -r $rid --self-contained true -p:PublishSingleFile=true -p:Version=$Version -o $cliPublish
    if ($LASTEXITCODE -ne 0) { throw "CLI publish failed for $rid." }
    New-Item -ItemType Directory -Force -Path (Join-Path $publish 'cli') | Out-Null
    Copy-Item -Path (Join-Path $cliPublish '*') -Destination (Join-Path $publish 'cli') -Recurse -Force
    if ($rid -eq 'win-x64') {
        $archive = Join-Path $release "ProcWitness-$Version-$rid.zip"
        if (Test-Path $archive) { Remove-Item -LiteralPath $archive -Force }
        Compress-Archive -Path (Join-Path $publish '*') -DestinationPath $archive -CompressionLevel Optimal
    } else {
        $archive = Join-Path $release "ProcWitness-$Version-$rid.tar.gz"
        if (Test-Path $archive) { Remove-Item -LiteralPath $archive -Force }
        tar -czf $archive -C $publish .
        if ($LASTEXITCODE -ne 0) { throw "Archive failed for $rid." }
    }
    Write-Host $archive
}
