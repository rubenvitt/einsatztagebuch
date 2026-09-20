#requires -Version 7.4
#requires -PSEdition Core
<#
.SYNOPSIS
Builds the Windows native operator release inputs from nothing, repeatably.

.DESCRIPTION
Clones (or updates) the repository and produces the two executables the signed
Windows bundle is made of:

  * einsatzarchiv.exe        - the parent CLI, from apps/cli
  * ea-native-operator.exe   - the native helper, from
                               crates/ea-admin/native/windows

It INSTALLS what is missing and then rechecks it before continuing. git, rustup
and the MSVC build tools come from winget and land on the machine, which is
provisioning and may raise a UAC prompt. The .NET SDK does NOT: `global.json`
pins the 10.0.1xx feature band, and winget only ever carries the newest band
(measured: 10.0.401), so the pinned SDK is fetched with `dotnet-install` into
the working copy instead. ACCEPTANCE.md measured it exactly that way - an
isolated SDK, no global install.

Run `-NoInstall` to get the previous behaviour, where anything missing only
prints its exact remediation command and stops. That switch is right for CI.

After each install the process PATH is reloaded from the registry, because
winget writes the new entries there and not into the running shell. If a tool
is still absent after that, the script says so and asks for a new terminal
rather than continuing into a confusing build error.

It STOPS BEFORE packaging and signing. Package.ps1 needs a Microsoft VC++
redistributable plus its SHA-256, and Sign-Release.ps1 needs a certificate
thumbprint. Neither input can be derived from a checkout, and neither step
belongs in an unattended run. The final output of this script is the two
commands to run next, with those inputs left as placeholders.

Out of scope: the WASM reader, the desktop and web frontends, and the Postgres
and S3 integration services. This builds the Windows native release path only.

PREREQUISITE THIS SCRIPT CANNOT CHECK FOR ITSELF: PowerShell 7. The `#requires`
lines above mean Windows PowerShell 5.1 - the `powershell.exe` that ships with
Windows - refuses to run this file, and the `pwsh` that would run it does not
exist until PowerShell 7 is installed:

    winget install --id Microsoft.PowerShell -e

Then open a NEW terminal so `pwsh` is on PATH. PowerShell 7 is required for the
rest of the Windows release path anyway: Package.ps1, Sign-Release.ps1 and
Install-Release.ps1 all declare `#requires -Version 7.4`.

.PARAMETER Path
Working directory for the checkout. Created if absent.

.PARAMETER Ref
Git ref to build. Defaults to `main`.

.PARAMETER Runtime
`win-x64` or `win-arm64`. Defaults to the architecture of this host.

.PARAMETER SkipTests
Skip the portable .NET protocol suite. The build itself still runs.

.PARAMETER NoInstall
Do not install anything. Report a missing prerequisite with its winget command
and stop. Use this in CI or on a managed machine.

.EXAMPLE
pwsh -File bootstrap-windows-build.ps1
.EXAMPLE
pwsh -File bootstrap-windows-build.ps1 -Path D:\build\ea -Ref main -Runtime win-arm64
#>
[CmdletBinding()]
param(
    [string]$Path = (Join-Path $HOME 'einsatztagebuch'),
    [string]$Ref = 'main',
    [ValidateSet('win-x64', 'win-arm64', IgnoreCase = $false)][string]$Runtime,
    [switch]$SkipTests,
    [switch]$NoInstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$RepositoryUrl = 'https://github.com/rubenvitt/einsatztagebuch.git'
# The .NET SDK writes a development HTTPS certificate on its first run. This
# build needs no such certificate and the prompt would stall an unattended run.
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'

function Write-Step([string]$Text) { Write-Host "`n==> $Text" -ForegroundColor Cyan }
function Write-Note([string]$Text) { Write-Host "    $Text" -ForegroundColor DarkGray }

function Stop-WithRemedy([string]$Problem, [string]$Remedy) {
    Write-Host "`nFEHLT: $Problem" -ForegroundColor Red
    Write-Host "Abhilfe: $Remedy" -ForegroundColor Yellow
    exit 1
}

function Test-Tool([string]$Name) { $null -ne (Get-Command $Name -ErrorAction SilentlyContinue) }

# Ein winget-Lauf aendert die PATH-Eintraege in der Registrierung, nicht die
# Kopie im laufenden Prozess. Ohne dieses Nachladen faende die unmittelbar
# folgende Pruefung das gerade installierte Programm NICHT, und die
# Selbstheilung liefe ins Leere.
function Update-PathFromRegistry {
    $parts = @(
        [Environment]::GetEnvironmentVariable('Path', 'Machine')
        [Environment]::GetEnvironmentVariable('Path', 'User')
    ) | Where-Object { $_ }
    if ($parts) { $env:Path = $parts -join ';' }
}

function Install-Prerequisite {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$WingetId,
        [string[]]$ExtraArguments = @()
    )
    if ($NoInstall) {
        Stop-WithRemedy $Label "winget install --id $WingetId -e $($ExtraArguments -join ' ')"
    }
    if (-not (Test-Tool 'winget')) {
        Stop-WithRemedy 'winget (App Installer)' `
            'Aus dem Microsoft Store "App Installer" installieren, dann erneut ausfuehren.'
    }
    Write-Note "$Label fehlt - wird installiert (winget kann eine UAC-Abfrage zeigen)"
    $arguments = @('install', '--id', $WingetId, '-e', '--accept-package-agreements',
        '--accept-source-agreements', '--disable-interactivity') + $ExtraArguments
    Write-Note "winget $($arguments -join ' ')"
    & winget @arguments
    # winget meldet "bereits installiert" mit einem eigenen Code; das ist kein
    # Fehlschlag. Ueber Erfolg entscheidet die Pruefung danach, nicht der Code.
    if ($LASTEXITCODE -ne 0) { Write-Note "winget endete mit Code $LASTEXITCODE - Pruefung entscheidet" }
    Update-PathFromRegistry
}

function Assert-Tool {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$WingetId,
        [string[]]$ExtraArguments = @()
    )
    if (Test-Tool $Name) { return }
    Install-Prerequisite -Label $Label -WingetId $WingetId -ExtraArguments $ExtraArguments
    if (Test-Tool $Name) {
        Write-Note "$Label installiert"
        return
    }
    Stop-WithRemedy "$Label ist nach der Installation immer noch nicht im PATH." `
        'Ein NEUES Terminal oeffnen und das Skript erneut ausfuehren.'
}

function Invoke-Checked([string]$What, [string]$Exe, [string[]]$Arguments, [string]$WorkingDirectory) {
    Write-Note "$Exe $($Arguments -join ' ')"
    $previous = Get-Location
    if ($WorkingDirectory) { Set-Location -LiteralPath $WorkingDirectory }
    try { & $Exe @Arguments } finally { Set-Location -LiteralPath $previous }
    if ($LASTEXITCODE -ne 0) { throw "$What failed with exit code $LASTEXITCODE" }
}

# ---------------------------------------------------------------- host checks

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Stop-WithRemedy 'Dieses Skript baut den Windows-Pfad und braucht einen Windows-Wirt.' `
        'Auf Windows 11 (Build 22000 oder neuer) ausfuehren.'
}

if (-not $Runtime) {
    $Runtime = switch ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
        ([Runtime.InteropServices.Architecture]::Arm64) { 'win-arm64' }
        ([Runtime.InteropServices.Architecture]::X64) { 'win-x64' }
        default { Stop-WithRemedy 'Unbekannte Wirtsarchitektur.' 'Runtime ausdruecklich angeben: -Runtime win-x64' }
    }
}
$RustTriple = if ($Runtime -eq 'win-arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }

Write-Step "Ziel: $Runtime ($RustTriple), Ref $Ref, Arbeitsverzeichnis $Path"

# ------------------------------------------------------------- prerequisites

Write-Step 'Voraussetzungen pruefen'

if ($NoInstall) { Write-Note 'NoInstall: fehlende Voraussetzungen werden nur gemeldet' }

Assert-Tool -Name 'git' -Label 'git' -WingetId 'Git.Git'
Write-Note "git: $((git --version) -join '')"

Assert-Tool -Name 'rustup' -Label 'rustup' -WingetId 'Rustlang.Rustup'
Write-Note "rustup: $((rustup --version 2>$null) -join ' ')"

# Der MSVC-Linker ist die Voraussetzung, die auf einem frischen Rechner am
# haeufigsten fehlt, und cargo meldet sie als kryptischen Linkerfehler statt
# als fehlendes Werkzeug. vswhere liegt bei jedem Visual-Studio-Installer.
# Die verlangte Komponente haengt am ZIEL, nicht am Wirt: ein Bau nach
# aarch64-pc-windows-msvc braucht das ARM64-Toolset, und das kommt bei der
# VCTools-Workload NICHT mit `--includeRecommended` mit.
$MsvcComponent = if ($Runtime -eq 'win-arm64') {
    'Microsoft.VisualStudio.Component.VC.Tools.ARM64'
}
else {
    'Microsoft.VisualStudio.Component.VC.Tools.x86.x64'
}

function Get-MsvcPath([string]$Component) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) { return $null }
    $found = & $vswhere -latest -products '*' -requires $Component -property installationPath
    if ($LASTEXITCODE -ne 0) { return $null }
    return ($found | Select-Object -First 1)
}

$msvc = Get-MsvcPath $MsvcComponent
if (-not $msvc) {
    Install-Prerequisite -Label "MSVC-Buildwerkzeuge fuer $Runtime ($MsvcComponent)" `
        -WingetId 'Microsoft.VisualStudio.2022.BuildTools' `
        -ExtraArguments @('--override',
            "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --add $MsvcComponent --includeRecommended")
    $msvc = Get-MsvcPath $MsvcComponent
    if (-not $msvc) {
        Stop-WithRemedy "MSVC-Komponente $MsvcComponent ist nach der Installation nicht auffindbar." `
            'Visual Studio Installer oeffnen, Workload "Desktopentwicklung mit C++" samt passendem Toolset ergaenzen, dann erneut ausfuehren.'
    }
}
Write-Note "MSVC ($MsvcComponent): $msvc"

# ------------------------------------------------------------------ checkout

Write-Step 'Arbeitskopie herstellen'

if (Test-Path -LiteralPath (Join-Path $Path '.git')) {
    Write-Note "vorhandene Arbeitskopie wird auf $Ref gesetzt"
    Invoke-Checked 'git fetch' 'git' @('fetch', '--prune', 'origin') $Path
    Invoke-Checked 'git checkout' 'git' @('checkout', '--force', $Ref) $Path
    # Nur wenn der Ref ein Branch ist, gibt es ein Gegenstueck zum Zuruecksetzen.
    & git -C $Path rev-parse --verify --quiet "origin/$Ref" *> $null
    if ($LASTEXITCODE -eq 0) { Invoke-Checked 'git reset' 'git' @('reset', '--hard', "origin/$Ref") $Path }
    Invoke-Checked 'git clean' 'git' @('clean', '-fdx', '--', 'crates/ea-admin/native/windows') $Path
}
else {
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    Invoke-Checked 'git clone' 'git' @('clone', '--branch', $Ref, $RepositoryUrl, $Path) $null
}

$Path = (Resolve-Path -LiteralPath $Path).Path
$WindowsRoot = Join-Path $Path 'crates\ea-admin\native\windows'
if (-not (Test-Path -LiteralPath $WindowsRoot)) { throw "Windows-Teilbaum fehlt in der Arbeitskopie: $WindowsRoot" }
Write-Note "HEAD: $((git -C $Path rev-parse --short HEAD) -join '')"

# ------------------------------------------------------------ toolchain pins

Write-Step 'Werkzeugfestlegungen pruefen'

$toolchainFile = Join-Path $Path 'rust-toolchain.toml'
$pinMatch = Select-String -LiteralPath $toolchainFile -Pattern '^\s*channel\s*=\s*"([^"]+)"' |
    Select-Object -First 1
if (-not $pinMatch) { throw "Kein channel-Pin in $toolchainFile" }
$pin = $pinMatch.Matches[0].Groups[1].Value
Write-Note "rust-toolchain.toml: $pin"

# Diese Falle hat auf dem Entwicklungsrechner eine Stunde gekostet: ein von
# aussen gesetztes RUSTUP_TOOLCHAIN ueberstimmt rust-toolchain.toml samt dessen
# targets-Zeile, und der Bau laeuft still auf einer anderen Fassung.
if ($env:RUSTUP_TOOLCHAIN -and $env:RUSTUP_TOOLCHAIN -ne $pin) {
    Stop-WithRemedy "RUSTUP_TOOLCHAIN ist auf '$env:RUSTUP_TOOLCHAIN' gesetzt und ueberstimmt den Pin $pin." `
        'Variable entfernen: Remove-Item Env:RUSTUP_TOOLCHAIN'
}

Invoke-Checked 'rustup toolchain install' 'rustup' @('toolchain', 'install', $pin, '--profile', 'minimal') $Path
Invoke-Checked 'rustup target add' 'rustup' @('target', 'add', '--toolchain', $pin, $RustTriple) $Path

# Die Fassung wird ueber die Umgebung gewaehlt und NICHT ueber `cargo +<pin>`.
# Gemessen auf Windows/PowerShell 7: das `+`-Argument kam beim rustup-Shim als
# EIN Argument an, und rustup meldete
#   toolchain '1.95.0 build --locked --release -p ...' is not installed
# waehrend dieselbe Uebergabeform fuer `rustup target add` sauber durchlief.
# Warum genau das `+`-Token anders behandelt wird, ist offen; die Variable
# umgeht die Frage und ist ohnehin die deutlichere Aussage. Ein FREMDER Wert
# ist weiter oben bereits abgewiesen worden, hier wird also nur der Pin gesetzt,
# den `rust-toolchain.toml` selbst nennt.
$env:RUSTUP_TOOLCHAIN = $pin
Write-Note "RUSTUP_TOOLCHAIN: $env:RUSTUP_TOOLCHAIN"

$sdkPin = (Get-Content -LiteralPath (Join-Path $WindowsRoot 'global.json') -Raw | ConvertFrom-Json).sdk.version
# Das SDK kommt ISOLIERT in die Arbeitskopie und nicht auf die Maschine.
#
# Zwei Gruende, und beide sind belegt statt gewaehlt: `global.json` steht auf
# `rollForward: disable` und verlangt damit GENAU $sdkPin, waehrend die
# Downloadseite pro Band nur noch den neuesten Patch fuehrt (Stand 2026-09-20
# im 1xx-Band die 10.0.112) und winget ohnehin das neueste Feature-Band bringt
# (gemessen: 10.0.401). Und `ACCEPTANCE.md` hat genau so gemessen — ein
# offizielles SDK, mit Microsofts Installer in ein isoliertes Verzeichnis, ohne
# globale Installation. Eine maschinenweite Fassung wuerde also weder den Pin
# erfuellen noch der dokumentierten Abnahme entsprechen.
#
# `dotnet-install` holt eine exakte Fassung auch dann, wenn die Downloadseite
# nur den neuesten Patch des Bandes anzeigt.
$DotnetRoot = Join-Path $Path '.dotnet'
$Dotnet = Join-Path $DotnetRoot 'dotnet.exe'

function Test-SdkPin([string]$Version) {
    if (-not (Test-Path -LiteralPath $Dotnet)) { return $false }
    return ((& $Dotnet --list-sdks) -join "`n") -match ('(?m)^' + [regex]::Escape($Version) + '\s')
}

if (-not (Test-SdkPin $sdkPin)) {
    if ($NoInstall) {
        Stop-WithRemedy "Isoliertes .NET SDK $sdkPin fehlt unter $DotnetRoot." `
            "& ([scriptblock]::Create((iwr https://dot.net/v1/dotnet-install.ps1).Content)) -Version $sdkPin -InstallDir '$DotnetRoot' -NoPath"
    }
    Write-Note "SDK $sdkPin wird isoliert nach $DotnetRoot geholt"
    $installer = Join-Path ([IO.Path]::GetTempPath()) 'dotnet-install.ps1'
    Invoke-WebRequest -Uri 'https://dot.net/v1/dotnet-install.ps1' -OutFile $installer -UseBasicParsing
    & $installer -Version $sdkPin -InstallDir $DotnetRoot -NoPath
    if (-not (Test-SdkPin $sdkPin)) {
        Stop-WithRemedy "SDK $sdkPin liess sich nicht isoliert installieren." `
            'Ausgabe von dotnet-install oben pruefen; Netzzugang zu dot.net und den Azure-CDN-Hosts noetig.'
    }
}
Write-Note ".NET SDK (isoliert): $sdkPin unter $DotnetRoot"

# Die Werkzeugkette laeuft vollstaendig gegen diese Fassung: DOTNET_ROOT und ein
# vorangestellter PATH, damit auch ein von MSBuild gestarteter Unterprozess
# nicht auf die maschinenweite 10.0.401 zurueckfaellt. DOTNET_CLI_HOME liegt
# ebenfalls in der Arbeitskopie, wie in ACCEPTANCE.md gemessen.
$env:DOTNET_ROOT = $DotnetRoot
$env:DOTNET_MULTILEVEL_LOOKUP = '0'
$env:DOTNET_CLI_HOME = Join-Path $Path '.dotnet-home'
$env:Path = $DotnetRoot + ';' + $env:Path

# Ein geteiltes Cargo-Zielverzeichnis laesst Cargo ein Binary aus einer ANDEREN
# Arbeitskopie fuer frisch halten. Das Zielverzeichnis gehoert deshalb in diese
# Arbeitskopie, und der aufgeloeste Pfad wird ausgegeben, damit ein Fehlgriff
# sichtbar ist statt still.
$env:CARGO_TARGET_DIR = Join-Path $Path 'target'
Write-Note "CARGO_TARGET_DIR: $env:CARGO_TARGET_DIR"

# ------------------------------------------------------------------- builds

Write-Step 'Parent-CLI bauen (einsatzarchiv.exe)'
Invoke-Checked 'cargo build' 'cargo' @(
    'build', '--locked', '--release',
    '-p', 'einsatzarchiv-cli', '--target', $RustTriple) $Path

$parentExe = Join-Path $env:CARGO_TARGET_DIR "$RustTriple\release\einsatzarchiv.exe"
if (-not (Test-Path -LiteralPath $parentExe)) { throw "cargo meldete Erfolg, aber $parentExe fehlt" }

Write-Step 'Nativen Helfer bauen (ea-native-operator.exe)'
Invoke-Checked 'dotnet restore' $Dotnet @(
    'restore', 'ea-native-operator.csproj', '--locked-mode') $WindowsRoot
Invoke-Checked 'dotnet build' $Dotnet @(
    'build', 'ea-native-operator.csproj', '-c', 'Release', '-r', $Runtime,
    '--no-restore', '-p:UseSharedCompilation=false') $WindowsRoot

$helperDir = Join-Path $WindowsRoot "bin\Release\net10.0-windows10.0.22000.0\$Runtime"
$helperExe = Join-Path $helperDir 'ea-native-operator.exe'
if (-not (Test-Path -LiteralPath $helperExe)) { throw "dotnet meldete Erfolg, aber $helperExe fehlt" }

# ------------------------------------------------------------------- tests

if (-not $SkipTests) {
    Write-Step 'Portable Protokollsuite'
    Invoke-Checked 'dotnet restore tests' $Dotnet @(
        'restore', 'tests/ProtocolTests.csproj', '--locked-mode') $WindowsRoot
    Invoke-Checked 'dotnet run tests' $Dotnet @(
        'run', '--project', 'tests/ProtocolTests.csproj',
        '--no-restore', '-p:UseSharedCompilation=false') $WindowsRoot
}
else {
    Write-Note 'Tests uebersprungen (-SkipTests)'
}

# ------------------------------------------------------------------ summary

Write-Step 'Gebaut'
Write-Host "  Parent : $parentExe"
Write-Host "  Helfer : $helperExe"
Write-Host "  Helferverzeichnis enthaelt zusaetzlich die verwalteten DLLs, die das Bundle braucht."

Write-Step 'Naechste Schritte - ausdrueckliche Eingaben, bewusst nicht automatisiert'
Write-Host @"
1) Paketieren. Braucht den passenden Microsoft-VC++-Redistributable und dessen SHA-256;
   Package.ps1 prueft Signatur, Hash und Dateinamen und installiert nichts.

   pwsh -File "$WindowsRoot\scripts\Package.ps1" ``
       -Runtime $Runtime ``
       -VCRedistPath <pfad\zu\vc_redist.$(if ($Runtime -eq 'win-arm64') { 'arm64' } else { 'x64' }).exe> ``
       -VCRedistSha256 <64 Hexzeichen>

2) Signieren. Braucht ein vorhandenes Code-Signing-Zertifikat mit privatem
   Schluessel in Cert:\CurrentUser\My, EKU 1.3.6.1.5.5.7.3.3, angegeben ueber
   seinen Thumbprint. Parent und Helfer MUESSEN dasselbe Zertifikat tragen -
   der Rust-Kern prueft die DER-Gleichheit beider Signaturen.

   pwsh -File "$WindowsRoot\scripts\Sign-Release.ps1" ``
       -ParentBinary "$parentExe" ``
       -HelperPackage <paketierte-ausgabe-aus-schritt-1> ``
       -Destination <ziel\bundle> ``
       -ManagementDestination <ziel\management> ``
       -Architecture $Runtime ``
       -Version 0.1.0 ``
       -CertificateThumbprint <40 Hexzeichen>

3) Installieren mit Install-Release.ps1 und die Laufzeitabnahme nach
   ACCEPTANCE.md durchfuehren (NativeReadOnly unter einem nicht erhoehten Konto).
"@
