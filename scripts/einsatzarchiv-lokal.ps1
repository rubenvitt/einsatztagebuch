#requires -Version 7.4
#requires -PSEdition Core
<#
.SYNOPSIS
Ein Aufruf: Einsatzarchiv unter Windows bauen, säen und öffnen.

.DESCRIPTION
Dies ist der EINE Einstiegspunkt. Er ruft die Teilskripte in der richtigen
Reihenfolge und beweist am Ende an echten Daten, dass die Kette trägt:

  1. bootstrap-windows-build.ps1   Werkzeuge, CLI, nativer Helfer, Paket,
                                   selbstsignierte Signatur, Installation;
                                   mit -Desktop zusätzlich FIXTURE-Wirt und
                                   Fixture-Helfer
  2. xtask seed-demo               eine vollständige Fixture-Demo-Welt
  3. einsatzarchiv verify/list     die gesäte Welt gegen die gebaute CLI
  4. (nur -Desktop)                ZWEI FIXTURE-Fenster: Writer und Verwaltung
  5. bootstrap-windows-reader.ps1  Web-Reader bauen und im Browser öffnen

WAS FUNKTIONIERT UND WAS NICHT

Die CLI arbeitet auf der gesäten Welt mit ECHTEN Daten. Das ist gemessen, nicht
behauptet: auf macOS meldet `verify` über derselben Welt 57 Archivobjekte,
1 Eintragspaket und null Fehler in allen sechs Fehlerklassen.

Der Web-Reader öffnet im Datei-Modus das gesäte Archiv und zeigt den
Verifikations- und Server-Bestätigungsstand der Objekte: den Eintrag als
gültig, nicht serverbestätigt. Entschlüsselte Eintragsinhalte zeigt er mit
dieser Saat NICHT. Der Reader hat keine Eingabe für einen Rohschlüssel;
Schlüssel kommen ausschließlich über das Enrollment, gebunden an einen
WebAuthn-Authenticator mit PRF-Erweiterung. Das ist Absicht, und der
Fixture-Schlüssel der Saat lässt sich deshalb nicht einbringen.

Die Desktop-Fenster (-Desktop) sind eine FIXTURE-ANWENDUNG OHNE NATIVE
SICHERHEITSKETTE. Der ausgelieferte Wirt `ea-desktop.exe` geht immer über
`NativeOperatorProvider::open_installed` und öffnet ohne signierten,
installierten Helfer keine Sitzung. `-Desktop` baut deshalb stattdessen das
eigene Programm `ea-desktop-fixture.exe` (Merkmal `test-support`, Ruling A,
DRK-437): es nimmt dieselben Startflags, legt den Fixture-Helfer als
`ea-native-operator.exe` in jedes Stationsverzeichnis und antwortet mit den
öffentlich bekannten Schlüsseln der Demowelt. Kein Schlüsselbund, keine
Identitätsprüfung, keine Anwesenheits- und keine Sperrprüfung. Nur für die
Handprobe gegen die gesäte Welt, nie gegen echte Daten.

Writer und Verwaltung sind zwei Prozesse: `--writer-config` und
`--administration-config` schließen sich am Wirt gegenseitig aus.

VORAUSSETZUNG: ein als Administrator gestartetes Terminal. Die Installation
verlangt einen geschützten Verzeichnisbaum, dessen Besitzer SYSTEM,
Administratoren oder TrustedInstaller ist.

.PARAMETER Path
Arbeitsverzeichnis für die Arbeitskopie. Vorgabe: <Benutzer>\einsatztagebuch.

.PARAMETER Ref
Git-Ref, der gebaut wird. Vorgabe: windows-build-bootstrap.

.PARAMETER DemoRoot
Verzeichnis für die Demo-Welt. Vorgabe: <Path>\demowelt.

.PARAMETER Desktop
FIXTURE-Wirt und Fixture-Helfer bauen und nach der Saat zwei Fenster starten,
Writer und Verwaltung. Zieht Node und pnpm nach. Siehe den Kasten oben: das ist
eine Fixture-Anwendung ohne native Sicherheitskette.

.PARAMETER SkipReader
Den Web-Reader auslassen.

.PARAMETER NoInstall
Nichts installieren; fehlende Voraussetzungen nur melden. Dann entfällt auch
die Signatur- und Installationsstufe.

.EXAMPLE
pwsh -File scripts\einsatzarchiv-lokal.ps1

.EXAMPLE
pwsh -File scripts\einsatzarchiv-lokal.ps1 -Desktop -DemoRoot D:\demo
#>
[CmdletBinding()]
param(
    [string]$Path = (Join-Path $HOME 'einsatztagebuch'),
    [string]$Ref = 'windows-build-bootstrap',
    [string]$DemoRoot,
    [switch]$Desktop,
    [switch]$SkipReader,
    [switch]$NoInstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch { }

function Write-Stage([string]$Text) {
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor DarkCyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ('=' * 72) -ForegroundColor DarkCyan
}
function Write-Line([string]$Text) { Write-Host "    $Text" -ForegroundColor DarkGray }

function Stop-Here([string]$Problem, [string]$Remedy) {
    Write-Host ''
    Write-Host "ABBRUCH: $Problem" -ForegroundColor Red
    Write-Host "Abhilfe: $Remedy" -ForegroundColor Yellow
    exit 1
}

function Invoke-Stage([string]$What, [string[]]$Arguments) {
    Write-Line ('pwsh ' + ($Arguments -join ' '))
    & pwsh @Arguments
    if ($LASTEXITCODE -ne 0) {
        Stop-Here "$What endete mit Code $LASTEXITCODE." 'Die Ausgabe oben nennt den Grund.'
    }
}

function Write-FixtureWarning {
    Write-Host ''
    Write-Host ('!' * 72) -ForegroundColor Red
    Write-Host '  FIXTURE-ANWENDUNG OHNE NATIVE SICHERHEITSKETTE' -ForegroundColor Red
    Write-Host '  ea-desktop-fixture.exe ist NICHT der ausgelieferte Wirt. Kein signierter' -ForegroundColor Yellow
    Write-Host '  Helfer, keine Identitätsprüfung, kein Schlüsselbund, keine Anwesenheits-' -ForegroundColor Yellow
    Write-Host '  und keine Sperrprüfung. Alle Schlüssel sind öffentlich bekannte' -ForegroundColor Yellow
    Write-Host '  Konstanten der Demowelt. Nur für die Handprobe, nie gegen echte Daten.' -ForegroundColor Yellow
    Write-Host ('!' * 72) -ForegroundColor Red
}

# Start-Process fügt -ArgumentList nur mit Leerzeichen zusammen und setzt
# keine Anführungszeichen. Ein Pfad mit Leerzeichen zerfiele sonst in zwei
# Argumente.
function ConvertTo-ArgumentString([string[]]$Arguments) {
    ($Arguments | ForEach-Object { '"' + ($_ -replace '"', '\"') + '"' }) -join ' '
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Stop-Here 'Dieses Skript ist der Windows-Einstieg.' 'Auf Windows 11 (Build 22000 oder neuer) ausführen.'
}

$here = Split-Path -Parent $PSCommandPath
$buildScript = Join-Path $here 'bootstrap-windows-build.ps1'
$readerScript = Join-Path $here 'bootstrap-windows-reader.ps1'
foreach ($s in @($buildScript, $readerScript)) {
    if (-not (Test-Path -LiteralPath $s)) {
        Stop-Here "Teilskript fehlt: $s" 'Das ganze scripts-Verzeichnis holen, nicht nur diese Datei.'
    }
}

$runtime = switch ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
    ([Runtime.InteropServices.Architecture]::Arm64) { 'win-arm64' }
    ([Runtime.InteropServices.Architecture]::X64) { 'win-x64' }
    default { Stop-Here 'Unbekannte Wirtsarchitektur.' 'Die Teilskripte einzeln mit -Runtime aufrufen.' }
}
$triple = if ($runtime -eq 'win-arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
if (-not $DemoRoot) { $DemoRoot = Join-Path $Path 'demowelt' }
$stages = if ($Desktop) { 5 } else { 4 }

Write-Stage "Einsatzarchiv lokal - $runtime, Ref $Ref"
Write-Line "Arbeitskopie : $Path"
Write-Line "Demo-Welt    : $DemoRoot"
if ($Desktop) { Write-FixtureWarning }

# ------------------------------------------------------- 1. bauen und signieren

Write-Stage "1/$stages  Bauen, signieren, installieren"

$buildArgs = @('-NoProfile', '-File', $buildScript, '-Path', $Path, '-Ref', $Ref)
# Nur den Fixture-Bau, NICHT `-Desktop`: das startete die leere Schale des
# ausgelieferten Wirts, die ohne installierten Helfer keine Sitzung öffnet.
# Clang (ARM64) und der vite-Bau laufen im Teilskript für beide Schalter.
if ($Desktop) { $buildArgs += '-DesktopFixture' }
if ($NoInstall) {
    $buildArgs += '-NoInstall'
    Write-Line 'NoInstall: Signatur und Installation entfallen'
}
else {
    $buildArgs += '-SelfSignedCert'
}
Invoke-Stage 'Der Bau' $buildArgs

$release = Join-Path $Path "target\$triple\release"
$cli = Join-Path $release 'einsatzarchiv.exe'
if (-not (Test-Path -LiteralPath $cli)) {
    Stop-Here "Die gebaute CLI fehlt: $cli" 'Die Ausgabe der Baustufe oben prüfen.'
}
$fixtureHost = Join-Path $release 'ea-desktop-fixture.exe'
$fixtureHelper = Join-Path $release 'ea-native-operator-fixture.exe'
if ($Desktop) {
    foreach ($p in @($fixtureHost, $fixtureHelper)) {
        if (-not (Test-Path -LiteralPath $p)) {
            Stop-Here "Der Fixture-Bau fehlt: $p" 'Die Ausgabe der Baustufe oben prüfen.'
        }
    }
}

# --------------------------------------------------------------- 2. Welt säen

Write-Stage "2/$stages  Demo-Welt säen"

# Die Welt ist an die PLATTFORMFAMILIE gebunden, nicht an den Rechner: die
# Kontoableitung unterscheidet macOS, Linux und Windows. Eine anderswo gesäte
# Welt trägt hier nicht, deshalb wird sie hier erzeugt und nicht mitgeliefert.
if (Test-Path -LiteralPath $DemoRoot) {
    Write-Line "vorhandene Welt wird entfernt: $DemoRoot"
    # Ein noch offenes Fixture-Fenster hält seinen Helfer im Stationsverzeichnis
    # fest; dann scheitert das Entfernen mit einer Zugriffsmeldung.
    Remove-Item -LiteralPath $DemoRoot -Recurse -Force
}

$previous = Get-Location
Set-Location -LiteralPath $Path
try {
    $env:CARGO_TARGET_DIR = Join-Path $Path 'target'
    & cargo run --locked -q -p xtask --features seed-demo -- seed-demo $DemoRoot
    if ($LASTEXITCODE -ne 0) {
        Stop-Here "Das Säen endete mit Code $LASTEXITCODE." 'Die Ausgabe oben nennt den Grund.'
    }
}
finally { Set-Location -LiteralPath $previous }

$anchor = Join-Path $DemoRoot 'fixture-demo-trust-anchor.etb'
$archive = Join-Path $DemoRoot 'archiv'
$writerStation = Join-Path $DemoRoot 'writer-station'
$adminStation = Join-Path $DemoRoot 'admin-station'
$seeded = @($anchor, $archive,
    (Join-Path $writerStation 'operator.json'), (Join-Path $writerStation 'writer.json'),
    (Join-Path $adminStation 'operator.json'), (Join-Path $adminStation 'administration.json'))
foreach ($p in $seeded) {
    if (-not (Test-Path -LiteralPath $p)) { Stop-Here "Die Saat hat $p nicht erzeugt." 'Ausgabe oben prüfen.' }
}

# ------------------------------------------------------------- 3. Nachweis CLI

Write-Stage "3/$stages  Nachweis: die gebaute CLI liest die gesäte Welt"

# Diese zwei Kommandos brauchen KEINE native Identität - sie prüfen ein
# Archiv gegen einen Anker und öffnen keine Bedienersitzung. Deshalb tragen
# sie den Nachweis auch ohne Installation.
Write-Line "$cli --trust-anchor <anker> verify <archiv>"
& $cli --trust-anchor $anchor verify $archive
$verifyCode = $LASTEXITCODE
if ($verifyCode -ne 0) {
    Stop-Here "verify endete mit Code $verifyCode." 'Die Zeilen darüber nennen die Fehlerklasse.'
}

Write-Host ''
Write-Line "$cli --trust-anchor <anker> list <archiv>"
& $cli --trust-anchor $anchor list $archive
$listCode = $LASTEXITCODE
if ($listCode -ne 0) { Stop-Here "list endete mit Code $listCode." 'Ausgabe oben prüfen.' }

Write-Host ''
Write-Host '    Die Kette trägt: Anker, Registry, Kette und Eintrag sind stimmig.' -ForegroundColor Green

# ------------------------------------------------------ 4. Fixture-Fenster

$writerArgs = @(
    '--operator-config', (Join-Path $writerStation 'operator.json'),
    '--trust-anchor', $anchor,
    '--writer-config', (Join-Path $writerStation 'writer.json'))
$adminArgs = @(
    '--operator-config', (Join-Path $adminStation 'operator.json'),
    '--trust-anchor', $anchor,
    '--administration-config', (Join-Path $adminStation 'administration.json'))

if ($Desktop) {
    Write-Stage "4/$stages  FIXTURE-Fenster starten: Writer und Verwaltung"
    Write-FixtureWarning
    Write-Host ''
    # Zwei Prozesse, weil sich --writer-config und --administration-config am
    # Wirt ausschließen. Jeder bekommt sein eigenes Konsolenfenster mit dem
    # Fixture-Hinweis und einer etwaigen Fehlermeldung beim Start.
    foreach ($window in @(
            @{ Label = 'Writer'; Arguments = $writerArgs },
            @{ Label = 'Verwaltung'; Arguments = $adminArgs })) {
        Write-Line "$($window.Label): $fixtureHost $($window.Arguments -join ' ')"
        $started = Start-Process -FilePath $fixtureHost -PassThru `
            -ArgumentList (ConvertTo-ArgumentString $window.Arguments)
        Start-Sleep -Seconds 3
        if ($started.HasExited) {
            Stop-Here "Das $($window.Label)-Fenster endete sofort mit Code $($started.ExitCode)." `
                'Den Befehl darüber in einem Terminal von Hand starten; die Konsole nennt den Grund.'
        }
        Write-Line "$($window.Label): läuft als Prozess $($started.Id)"
    }
}

# ------------------------------------------------------------------ Abschluss

# Der Abschluss steht VOR dem Reader: dessen Teilskript hält den
# Vorschauserver bis Strg+C offen, und was danach käme, sähe niemand.
Write-Stage 'So benutzt du es'

Write-Host @"
  Reader (Datei-Modus):
    Im Browser auf die Seite gehen, oben "Datei-Modus" wählen. In Edge und
    Chrome gibt es dort den Ordnerweg über showDirectoryPicker; dann diesen
    Ordner wählen:

      $archive

    Der Reader zeigt dann den Verifikations- und Server-Bestätigungsstand der
    Objekte: den Eintrag als gültig, nicht serverbestätigt. Entschlüsselte
    Eintragsinhalte zeigt er mit dieser Saat NICHT. Der Reader hat keine
    Eingabe für einen Rohschlüssel; Schlüssel kommen ausschließlich über das
    Enrollment, gebunden an einen WebAuthn-Authenticator mit PRF-Erweiterung.
    Der Fixture-Schlüssel der Saat lässt sich deshalb nicht einbringen - das
    ist Absicht, kein Fehler.

  CLI (funktioniert ohne Installation):
    & "$cli" --trust-anchor "$anchor" verify "$archive"
    & "$cli" --trust-anchor "$anchor" list   "$archive"
"@

if ($Desktop) {
    Write-Host @"

  Desktop - FIXTURE-ANWENDUNG OHNE NATIVE SICHERHEITSKETTE:
    Zwei Fenster laufen, Titel "FIXTURE ohne native Sicherheitskette - ...".
    In jedem zuerst anmelden; die Sitzung beginnt erst mit der Anmeldung.
    Von Hand erneut starten:

    & "$fixtureHost" $(ConvertTo-ArgumentString $writerArgs)
    & "$fixtureHost" $(ConvertTo-ArgumentString $adminArgs)

    Der Fixture-Wirt legt den Helfer beim Start selbst als
    ea-native-operator.exe in das Stationsverzeichnis.
"@
}
else {
    Write-Host @"

  Desktop:
    Nicht gebaut. Mit -Desktop entstehen der FIXTURE-Wirt und zwei Fenster
    (Writer und Verwaltung) gegen diese Welt - eine Fixture-Anwendung ohne
    native Sicherheitskette. Der ausgelieferte Wirt ea-desktop.exe öffnet
    ohne signierten, installierten Helfer keine Sitzung.
"@
}

# ------------------------------------------------------------------ Reader

if (-not $SkipReader) {
    Write-Stage "$stages/$stages  Web-Reader bauen und öffnen"
    $readerArgs = @('-NoProfile', '-File', $readerScript, '-Path', $Path)
    if ($NoInstall) { $readerArgs += '-NoInstall' }
    Invoke-Stage 'Der Reader' $readerArgs
}
else {
    Write-Stage "$stages/$stages  Web-Reader übersprungen (-SkipReader)"
}
