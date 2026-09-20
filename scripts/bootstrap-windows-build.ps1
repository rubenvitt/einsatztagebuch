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

It PACKAGES too. Package.ps1 wants a Microsoft VC++ redistributable and its
expected SHA-256, and both can be obtained honestly without a human in the
loop: `aka.ms/vs/17/release/vc_redist.<arch>.exe` redirects to a Microsoft CDN
URL that carries the file's SHA-256 in its path, so the expected hash comes
from what Microsoft publishes rather than from the bytes we happened to
receive. Package.ps1 then re-checks that hash, the Authenticode signature, the
Microsoft subject and the file name itself. `-SkipPackage` stops after the
build.

What this does NOT reach is the `reviewed` in the subtree README's phrase
`reviewed architecture-matching, Microsoft-signed VC++ Redistributable`: the
redistributable is official, signed and hash-matched, but no person looked at
this particular version. Pin the printed hash in the repository once it has
been reviewed, and this step becomes a pinned check instead of a published one.

It STOPS BEFORE SIGNING. Sign-Release.ps1 needs a code-signing certificate
thumbprint, and that is not a scripting gap - the certificate does not exist
yet. Nothing here can substitute for it.

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

.PARAMETER SkipPackage
Stop after the build instead of staging the release bundle with Package.ps1.

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
    [switch]$SkipPackage,
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

# Perl, und zwar fuer den RUST-Teil — deshalb steht es nicht in der README des
# Windows-Teilbaums, die nur den .NET-Helfer beschreibt.
#
# `Cargo.toml` pinnt `rusqlite`/`libsqlite3-sys` auf das Merkmal
# `bundled-sqlcipher-vendored-openssl` (ADR 0002, verschluesselter lokaler
# Speicher). SQLCipher braucht OpenSSLs Krypto, das Repo vendored es statt sich
# auf ein System-OpenSSL zu verlassen, und `openssl-src` fuehrt zum Bauen
# `perl ./Configure` aus. Ohne perl bricht `openssl-sys` mit
#   Error configuring OpenSSL build: Command 'perl' not found
# ab — gemessen auf ARM64 am 2026-09-20. NASM braucht es nicht, der Aufruf
# uebergibt `no-asm`; cmake ebenfalls nicht, `aws-lc-sys` ist nicht im Lockfile.
Assert-Tool -Name 'perl' -Label 'Perl (baut das vendored OpenSSL von SQLCipher)' `
    -WingetId 'StrawberryPerl.StrawberryPerl'

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

# ----------------------------------------------------------------- package

$packaged = $null
if (-not $SkipPackage) {
    Write-Step 'Release-Bundle paketieren'

    $arch = if ($Runtime -eq 'win-arm64') { 'arm64' } else { 'x64' }
    $redistDir = Join-Path $Path '.redist'
    if (-not (Test-Path -LiteralPath $redistDir)) { New-Item -ItemType Directory -Path $redistDir -Force | Out-Null }
    $redist = Join-Path $redistDir "vc_redist.$arch.exe"

    # Die ERWARTETE Pruefsumme kommt aus dem, was Microsoft veroeffentlicht, und
    # nicht aus den Bytes, die wir zufaellig bekommen haben — sonst pruefte
    # Package.ps1 die Datei gegen sich selbst und die Zusage waere leer.
    #
    # `aka.ms/vs/17/release/vc_redist.<arch>.exe` leitet auf eine CDN-Adresse
    # um, die die SHA-256 der Datei im Pfad traegt. Dass dieser Hexblock
    # tatsaechlich die SHA-256 ist, wurde am 2026-09-20 gegen die
    # heruntergeladene Datei geprueft (arm64:
    # 5139E1440C3A20B92153A4DB561C069A0175AAF76C276C3E5B6F56099EDCF4B0).
    $short = "https://aka.ms/vs/17/release/vc_redist.$arch.exe"
    Write-Note "Aufloesen: $short"
    $resolved = (Invoke-WebRequest -Uri $short -Method Head -MaximumRedirection 10).BaseResponse.RequestMessage.RequestUri.AbsoluteUri
    Write-Note "Microsoft-CDN: $resolved"

    $published = [regex]::Match($resolved, '/([0-9A-Fa-f]{64})/')
    if (-not $published.Success) {
        Stop-WithRemedy "Die Microsoft-Adresse traegt keine SHA-256 mehr: $resolved" `
            "Redistributable von Hand holen und Package.ps1 mit -VCRedistPath/-VCRedistSha256 aufrufen."
    }
    $expected = $published.Groups[1].Value.ToUpperInvariant()
    Write-Note "veroeffentlichte SHA-256: $expected"

    Invoke-WebRequest -Uri $resolved -OutFile $redist -UseBasicParsing
    $actual = (Get-FileHash -LiteralPath $redist -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($actual -ne $expected) {
        Stop-WithRemedy "Der Redistributable stimmt nicht mit der veroeffentlichten Pruefsumme ueberein.`n  erwartet: $expected`n  gemessen: $actual" `
            "Datei loeschen und erneut versuchen; bei Wiederholung nicht verwenden."
    }
    Write-Note "Pruefsumme stimmt"

    # Package.ps1 prueft Hash, Authenticode, Microsoft-Subjekt und Dateinamen
    # selbst noch einmal — diese Zeile ersetzt keine seiner Pruefungen.
    Invoke-Checked 'Package.ps1' 'pwsh' @(
        '-NoProfile', '-File', (Join-Path $WindowsRoot 'scripts\Package.ps1'),
        '-Runtime', $Runtime,
        '-VCRedistPath', $redist,
        '-VCRedistSha256', $expected) $WindowsRoot

    $packaged = Join-Path $WindowsRoot "artifacts\$Runtime"
    Write-Note "Paket: $packaged"
}

# -------------------------------------------------------------- smoke start

# Das gebaute Programm einmal wirklich starten. Ohne Argumente schreibt es
# seine Kommandouebersicht und endet mit 0 (gemessen), es ist also ein
# ungefaehrlicher Lebendnachweis und zugleich die Antwort auf „und was kann
# das Ding jetzt".
Write-Step 'Einsatzarchiv starten'
Invoke-Checked 'einsatzarchiv' $parentExe @() $Path

# ------------------------------------------------------------------ summary

Write-Step 'Fertig'
Write-Host "  Parent : $parentExe"
Write-Host "  Helfer : $helperExe"
if ($packaged) { Write-Host "  Paket  : $packaged" }

Write-Step 'Was jetzt noch fehlt - und warum kein Skript es loesen kann'
Write-Host @"
Signieren (Sign-Release.ps1) braucht ein Code-Signing-Zertifikat mit privatem
Schluessel in Cert:\CurrentUser\My, EKU 1.3.6.1.5.5.7.3.3. So eines gibt es
fuer dieses Projekt noch nicht. Das ist keine Luecke in diesem Skript: der
Rust-Kern prueft Authenticode und die DER-Gleichheit der Signaturen von Parent
und Helfer, und ohne Zertifikat existiert nichts, was er pruefen koennte.

Sobald es da ist:

   pwsh -File "$WindowsRoot\scripts\Sign-Release.ps1" ``
       -ParentBinary "$parentExe" ``
       -HelperPackage "$packaged" ``
       -Destination <ziel\bundle> ``
       -ManagementDestination <ziel\management> ``
       -Architecture $Runtime ``
       -Version 0.1.0 ``
       -CertificateThumbprint <40 Hexzeichen>

Danach Install-Release.ps1 und die Laufzeitabnahme nach ACCEPTANCE.md
(NativeReadOnly unter einem nicht erhoehten Konto).

Und auch ein signiertes, installiertes Bundle ist noch kein bedienbarer
Writer: davor liegt die Organisationszeremonie - Root, Trust Anchor, Registry,
Operator-Bereitstellung. Siehe docs/operator-ceremony.md.
"@
