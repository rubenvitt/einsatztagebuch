#requires -Version 7.4
#requires -PSEdition Core
<#
.SYNOPSIS
Ein Aufruf: Einsatzarchiv unter Windows bauen, saeen und oeffnen.

.DESCRIPTION
Dies ist der EINE Einstiegspunkt. Er ruft die drei Teilskripte in der richtigen
Reihenfolge und beweist am Ende an echten Daten, dass die Kette traegt:

  1. bootstrap-windows-build.ps1   Werkzeuge, CLI, nativer Helfer, Paket,
                                   selbstsignierte Signatur, Installation
  2. xtask seed-demo               eine vollstaendige Fixture-Demo-Welt
  3. einsatzarchiv verify/list     die gesaete Welt gegen die gebaute CLI
  4. bootstrap-windows-reader.ps1  Web-Reader bauen und im Browser oeffnen

WAS FUNKTIONIERT UND WAS NICHT

Der Reader und die CLI arbeiten auf der gesaeten Welt mit ECHTEN Daten. Das ist
gemessen, nicht behauptet: auf macOS meldet `verify` ueber derselben Welt
61 Archivobjekte, 1 Eintragspaket und null Fehler in allen sechs Fehlerklassen.

Die beiden Desktop-Fenster (Writer und Verwaltung) oeffnen KEINE Sitzung, und
das liegt nicht an der Signatur. `InteractiveOperatorRuntime::open` geht immer
ueber `NativeOperatorProvider::open_installed`, und dessen
`NativeExecutableIdentity::for_installed` verlangt unter Windows, dass die
AUFRUFENDE Datei genau `einsatzarchiv.exe` heisst und `ea-native-operator.exe`
als Geschwisterdatei neben sich hat. Die Tauri-Anwendung heisst
`ea-desktop.exe` beziehungsweise `Einsatzarchiv.exe` und faellt damit durch die
Namenspruefung, egal wie sie signiert ist. Im Windows-Release-Bundle
(`WINDOWS_RELEASE_ASSETS`) kommt ueberhaupt kein Desktop-Programm vor.

`-Desktop` baut und startet das Fenster trotzdem, damit die Oberflaeche sichtbar
ist. Es zeigt dann die leere Schale ohne Erfassungsflaeche. Das ist der ehrliche
Stand und kein Fehler des Baus.

VORAUSSETZUNG: ein als Administrator gestartetes Terminal. Die Installation
verlangt einen geschuetzten Verzeichnisbaum, dessen Besitzer SYSTEM,
Administratoren oder TrustedInstaller ist.

.PARAMETER Path
Arbeitsverzeichnis fuer die Arbeitskopie. Vorgabe: <Benutzer>\einsatztagebuch.

.PARAMETER Ref
Git-Ref, der gebaut wird. Vorgabe: windows-build-bootstrap.

.PARAMETER DemoRoot
Verzeichnis fuer die Demo-Welt. Vorgabe: <Path>\demowelt.

.PARAMETER Desktop
Tauri-Fenster zusaetzlich bauen und starten. Siehe Einschraenkung oben.

.PARAMETER SkipReader
Den Web-Reader auslassen.

.PARAMETER NoInstall
Nichts installieren; fehlende Voraussetzungen nur melden. Dann entfaellt auch
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

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Stop-Here 'Dieses Skript ist der Windows-Einstieg.' 'Auf Windows 11 (Build 22000 oder neuer) ausfuehren.'
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

Write-Stage "Einsatzarchiv lokal - $runtime, Ref $Ref"
Write-Line "Arbeitskopie : $Path"
Write-Line "Demo-Welt    : $DemoRoot"

# ------------------------------------------------------- 1. bauen und signieren

Write-Stage '1/4  Bauen, signieren, installieren'

$buildArgs = @('-NoProfile', '-File', $buildScript, '-Path', $Path, '-Ref', $Ref)
if ($Desktop) { $buildArgs += '-Desktop' }
if ($NoInstall) {
    $buildArgs += '-NoInstall'
    Write-Line 'NoInstall: Signatur und Installation entfallen'
}
else {
    $buildArgs += '-SelfSignedCert'
}
Invoke-Stage 'Der Bau' $buildArgs

$cli = Join-Path $Path "target\$triple\release\einsatzarchiv.exe"
if (-not (Test-Path -LiteralPath $cli)) {
    Stop-Here "Die gebaute CLI fehlt: $cli" 'Die Ausgabe der Baustufe oben pruefen.'
}

# --------------------------------------------------------------- 2. Welt saeen

Write-Stage '2/4  Demo-Welt saeen'

# Die Welt ist an die PLATTFORMFAMILIE gebunden, nicht an den Rechner: die
# Kontoableitung unterscheidet macOS, Linux und Windows. Eine anderswo gesaete
# Welt traegt hier nicht, deshalb wird sie hier erzeugt und nicht mitgeliefert.
if (Test-Path -LiteralPath $DemoRoot) {
    Write-Line "vorhandene Welt wird entfernt: $DemoRoot"
    Remove-Item -LiteralPath $DemoRoot -Recurse -Force
}

$previous = Get-Location
Set-Location -LiteralPath $Path
try {
    $env:CARGO_TARGET_DIR = Join-Path $Path 'target'
    & cargo run --locked -q -p xtask --features seed-demo -- seed-demo $DemoRoot
    if ($LASTEXITCODE -ne 0) {
        Stop-Here "Das Saeen endete mit Code $LASTEXITCODE." 'Die Ausgabe oben nennt den Grund.'
    }
}
finally { Set-Location -LiteralPath $previous }

$anchor = Join-Path $DemoRoot 'fixture-demo-trust-anchor.etb'
$archive = Join-Path $DemoRoot 'archiv'
foreach ($p in @($anchor, $archive)) {
    if (-not (Test-Path -LiteralPath $p)) { Stop-Here "Die Saat hat $p nicht erzeugt." 'Ausgabe oben pruefen.' }
}

# ------------------------------------------------------------- 3. Nachweis CLI

Write-Stage '3/4  Nachweis: die gebaute CLI liest die gesaete Welt'

# Diese zwei Kommandos brauchen KEINE native Identitaet - sie pruefen ein
# Archiv gegen einen Anker und oeffnen keine Bedienersitzung. Deshalb tragen
# sie den Nachweis auch ohne Installation.
Write-Line "$cli --trust-anchor <anker> verify <archiv>"
& $cli --trust-anchor $anchor verify $archive
$verifyCode = $LASTEXITCODE
if ($verifyCode -ne 0) {
    Stop-Here "verify endete mit Code $verifyCode." 'Die Zeilen darueber nennen die Fehlerklasse.'
}

Write-Host ''
Write-Line "$cli --trust-anchor <anker> list <archiv>"
& $cli --trust-anchor $anchor list $archive
if ($LASTEXITCODE -ne 0) { Stop-Here "list endete mit Code $LASTEXITCODE." 'Ausgabe oben pruefen.' }

Write-Host ''
Write-Host '    Die Kette traegt: Anker, Registry, Kette und Eintrag sind stimmig.' -ForegroundColor Green

# ------------------------------------------------------------------ 4. Reader

if (-not $SkipReader) {
    Write-Stage '4/4  Web-Reader bauen und oeffnen'
    $readerArgs = @('-NoProfile', '-File', $readerScript, '-Path', $Path)
    if ($NoInstall) { $readerArgs += '-NoInstall' }
    Invoke-Stage 'Der Reader' $readerArgs
}
else {
    Write-Stage '4/4  Web-Reader uebersprungen (-SkipReader)'
}

# ------------------------------------------------------------------ Abschluss

Write-Stage 'Fertig'

Write-Host @"
SO BENUTZT DU ES

  Reader (funktioniert mit echten Daten):
    Im Browser auf die Seite gehen, oben "Datei-Modus" waehlen, dort
    "Archiv oeffnen" und dieses Verzeichnis nehmen:

      $archive

    Der private Reader-Schluessel steht in der Ausgabe der Saat weiter oben
    (X25519, roh, hex). Ohne ihn und den mitgelieferten Grant zeigt der Reader
    nichts - das ist die Zusage des Formats, kein Fehler.

  CLI (funktioniert ohne Installation):
    & "$cli" --trust-anchor "$anchor" verify "$archive"
    & "$cli" --trust-anchor "$anchor" list   "$archive"

WAS HEUTE NOCH NICHT GEHT

  Die Desktop-Fenster fuer Erfassung und Verwaltung oeffnen keine Sitzung.
  Die Saat hat die richtigen Startbefehle ausgegeben und die Welt ist gueltig -
  es fehlt die Identitaetspruefung: `for_installed` verlangt unter Windows, dass
  die aufrufende Datei genau `einsatzarchiv.exe` heisst. Die Tauri-Anwendung
  heisst anders und faellt durch, unabhaengig von der Signatur. Im
  Windows-Release-Bundle kommt kein Desktop-Programm vor.

  Das ist eine Luecke im Produkt, keine in diesem Skript.
"@
