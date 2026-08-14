param(
    [Parameter(Mandatory = $true)][string]$CertificateThumbprint,
    [string]$Executable = "$PSScriptRoot\..\src\ProcWitness.App\bin\Release\net9.0-windows\win-x64\publish\ProcWitness.exe"
)

$certificate = Get-Item "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction Stop
if (-not $certificate.HasPrivateKey) { throw "Kod imzalama sertifikasının özel anahtarı bulunamadı." }

$signTool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe |
    Where-Object FullName -Like "*\x64\signtool.exe" |
    Sort-Object FullName -Descending |
    Select-Object -First 1
if (-not $signTool) { throw "Windows SDK signtool.exe bulunamadı." }

& $signTool.FullName sign /sha1 $CertificateThumbprint /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $Executable
if ($LASTEXITCODE -ne 0) { throw "İmzalama başarısız oldu: $LASTEXITCODE" }
& $signTool.FullName verify /pa /v $Executable
