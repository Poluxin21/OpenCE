<#
.SYNOPSIS
  Gera o instalador grafico do Quarry (quarry-setup.exe) com tudo embutido,
  sem ferramentas externas (so o Rust/cargo).

.DESCRIPTION
  1) Compila o quarry.exe em release (icone + manifesto de Admin).
  2) Baixa e prepara o WinDivert em dist\WinDivert (driver da aba Redirect).
  3) Compila o instalador (installer\setup), que EMBUTE o quarry.exe + WinDivert
     + icone via include_bytes! e vira um wizard grafico auto-extraivel.
  4) Copia o resultado para dist\quarry-setup-<versao>.exe

  Rode num PowerShell comum:
    powershell -ExecutionPolicy Bypass -File installer\build-installer.ps1
#>

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Version = '0.1.0'
$WinDivertVersion = '2.2.2'
$WinDivertUrl = "https://github.com/basil00/WinDivert/releases/download/v$WinDivertVersion/WinDivert-$WinDivertVersion-A.zip"

Write-Host "==> 1/4  Compilando quarry.exe (release)..." -ForegroundColor Cyan
cargo build --release
if ($LASTEXITCODE -ne 0) { throw "cargo build --release falhou." }

Write-Host "==> 2/4  Preparando WinDivert $WinDivertVersion..." -ForegroundColor Cyan
$DistWd = Join-Path $Root 'dist\WinDivert'
if (-not (Test-Path (Join-Path $DistWd 'WinDivert64.sys'))) {
    New-Item -ItemType Directory -Force -Path $DistWd | Out-Null
    $Zip = Join-Path $env:TEMP "windivert-$WinDivertVersion.zip"
    $Extract = Join-Path $env:TEMP "windivert-$WinDivertVersion"
    Write-Host "    baixando $WinDivertUrl"
    Invoke-WebRequest -Uri $WinDivertUrl -OutFile $Zip
    if (Test-Path $Extract) { Remove-Item -Recurse -Force $Extract }
    Expand-Archive -Path $Zip -DestinationPath $Extract
    $x64 = Get-ChildItem -Path $Extract -Recurse -Directory | Where-Object { $_.Name -eq 'x64' } | Select-Object -First 1
    if (-not $x64) { throw "pasta x64 nao encontrada no zip do WinDivert." }
    Copy-Item (Join-Path $x64.FullName 'WinDivert.dll')   $DistWd -Force
    Copy-Item (Join-Path $x64.FullName 'WinDivert64.sys') $DistWd -Force
    $lic = Get-ChildItem -Path $Extract -Recurse -Filter 'LICENSE' | Select-Object -First 1
    if ($lic) { Copy-Item $lic.FullName $DistWd -Force }
    Write-Host "    WinDivert pronto em $DistWd"
} else {
    Write-Host "    WinDivert ja presente em $DistWd (pulando download)."
}

Write-Host "==> 3/4  Compilando o instalador (embute tudo)..." -ForegroundColor Cyan
cargo build --release --manifest-path installer\setup\Cargo.toml
if ($LASTEXITCODE -ne 0) { throw "build do instalador falhou." }

Write-Host "==> 4/4  Empacotando..." -ForegroundColor Cyan
$Out = Join-Path $Root 'dist'
$SetupExe = Join-Path $Root 'installer\setup\target\release\quarry-setup.exe'
$Final = Join-Path $Out "quarry-setup-$Version.exe"
Copy-Item $SetupExe $Final -Force

$sizeMb = [math]::Round((Get-Item $Final).Length / 1MB, 1)
Write-Host ""
Write-Host "Pronto! Instalador gerado:" -ForegroundColor Green
Write-Host "  $Final  ($sizeMb MB)"
Write-Host "Distribua esse unico .exe: ele instala o Quarry, o WinDivert e os atalhos."
