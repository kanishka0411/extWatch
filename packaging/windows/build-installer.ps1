# Builds extwatch.exe, deploys Qt next to it and produces a signed (optional) Inno Setup installer.
#   $env:SIGNTOOL_CERT_THUMBPRINT = "..."   # optional: code signing certificate in the user store
#   $env:QT_ROOT = "C:\Qt\6.8.3\msvc2022_64" # optional if qtpaths is on PATH
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..\..")
$version = (Select-String -Path CMakeLists.txt -Pattern 'VERSION ([0-9.]+)$' | Select-Object -First 1).Matches.Groups[1].Value
if ($env:QT_ROOT) { $env:PATH = "$env:QT_ROOT\bin;$env:PATH" }

cmake --preset ci-windows -DEXTWATCH_BUILD_TESTS=OFF
cmake --build --preset ci-windows
# The Visual Studio generator puts the exe under the build root, not under src\: look for it.
$exe = Get-ChildItem -Path build\ci-windows -Recurse -Filter extwatch.exe |
  Where-Object { $_.FullName -notmatch '\\deploy\\' } | Select-Object -First 1 -ExpandProperty FullName
if (-not $exe) { throw "extwatch.exe not found under build\ci-windows" }
$deploy = "build\ci-windows\deploy"
if (Test-Path $deploy) { Remove-Item -Recurse -Force $deploy }
New-Item -ItemType Directory -Path $deploy | Out-Null
Copy-Item $exe $deploy
windeployqt --release --no-translations --no-opengl-sw --sql --concurrent --network "$deploy\extwatch.exe"

if ($env:SIGNTOOL_CERT_THUMBPRINT) {
  signtool sign /sha1 $env:SIGNTOOL_CERT_THUMBPRINT /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 "$deploy\extwatch.exe"
}
New-Item -ItemType Directory -Force -Path dist | Out-Null
iscc "/DAppVersion=$version" "/DSourceDir=$(Resolve-Path $deploy)" packaging\windows\installer.iss
$setup = "dist\ExtWatch-$version-windows-setup.exe"
if ($env:SIGNTOOL_CERT_THUMBPRINT) {
  signtool sign /sha1 $env:SIGNTOOL_CERT_THUMBPRINT /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $setup
}
Compress-Archive -Force -Path "$deploy\*" -DestinationPath "dist\ExtWatch-$version-windows-portable.zip"
Write-Host "built $setup and dist\ExtWatch-$version-windows-portable.zip"
