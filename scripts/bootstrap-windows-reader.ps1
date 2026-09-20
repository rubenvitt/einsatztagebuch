#requires -Version 7.4
#requires -PSEdition Core
<#
.SYNOPSIS
Baut den Web-Reader (`apps/web`) auf Windows und startet ihn als lokale Vorschau.

.DESCRIPTION
Eigenständig und wiederholbar. Das Skript prüft seine Voraussetzungen, beschafft
fehlende über winget beziehungsweise cargo, baut die wasm-Brücke, baut das
Bündel und startet `vite preview`. Danach öffnet es den Browser über den NAMEN
`localhost` und nicht über eine IP-Adresse.

Vier Schritte in dieser Reihenfolge, und die Reihenfolge ist keine Vorliebe:

  1. `pnpm install --frozen-lockfile` in der Wurzel — der Arbeitsbereich aus
     `pnpm-workspace.yaml` deckt `apps/web` mit ab.
  2. `cargo run --locked -p xtask -- build-wasm` — erzeugt
     `apps/web/src/bridge/pkg`. Ohne diesen Schritt findet der Bau die Brücke
     nicht: das Verzeichnis ist erzeugt und über `.gitignore` ausgeschlossen.
  3. `vite build` in `apps/web` — `vite preview` BAUT nicht, es liefert `dist/`
     aus. Dieselbe Reihenfolge steht in `apps/web/playwright.config.ts` und aus
     demselben Grund.
  4. `vite preview --host 127.0.0.1 --port 4174 --strictPort`.

Schritt 2 ist fail-closed und wird hier NICHT gelockert. `run_build_wasm` in
`tools/xtask/src/main.rs` prüft vor dem Bau drei Dinge — installiertes Ziel
`wasm32-unknown-unknown`, eine zur Lockfile ZEICHENGLEICHE `wasm-bindgen`-CLI
und die vorhandene Brücken-Crate. Das Skript stellt diese drei Dinge her,
statt an den Prüfungen zu drehen. Die verlangte CLI-Fassung liest es aus
`Cargo.lock` und nicht aus `mise.toml`: mise gibt es auf Windows nicht, und
`Cargo.lock` ist die Quelle, gegen die xtask selbst vergleicht (gemessen am
2026-09-20: beide nennen 0.2.126).

WAS DIESES SKRIPT NICHT BRAUCHT, obwohl das Nachbarskript
`bootstrap-windows-build.ps1` es verlangt: Perl. Dessen SQLCipher-Pfad zieht
ein vendored OpenSSL nach, dieser hier nicht — `cargo tree` über `xtask` (Wirt)
und über `ea-reader-wasm` (Ziel `wasm32-unknown-unknown`) nennt weder
`openssl-sys` noch `libsqlite3-sys` (gemessen am 2026-09-20). Die
MSVC-Buildwerkzeuge braucht es dagegen sehr wohl: `xtask` und
`wasm-bindgen-cli` sind WIRTS-Binaries und wollen einen Linker.

.PARAMETER Path
Die Arbeitskopie. Vorgabe ist der Baum, in dem dieses Skript liegt.

.PARAMETER Port
Der Port der Vorschau. Vorgabe 4174 — derselbe, den
`apps/web/playwright.config.ts` pinnt, damit die E2E-Suite des Desktops (4173)
daneben laufen kann.

.PARAMETER NoInstall
Nichts installieren. Eine fehlende Voraussetzung wird mit ihrem genauen
Abhilfe-Kommando gemeldet, dann bricht das Skript ab. Die Form für CI und für
verwaltete Rechner.

.PARAMETER NoBrowser
Den Browser nicht öffnen. Die Vorschau läuft trotzdem und die Adresse steht in
der Ausgabe.

.EXAMPLE
pwsh -File scripts\bootstrap-windows-reader.ps1

.EXAMPLE
pwsh -File scripts\bootstrap-windows-reader.ps1 -NoInstall -NoBrowser

.NOTES
UNGETESTET AUF WINDOWS. Geschrieben und geprüft wurde es auf macOS; dort gibt
es kein PowerShell-Fenster, in dem dieser Ablauf einmal durchgelaufen wäre.
Gemessen ist die KOMMANDOKETTE, nicht ihre PowerShell-Hülle:
`build-wasm` (Code 0, `ea_reader_wasm_bg.wasm` 4.280.779 Bytes),
`pnpm install --frozen-lockfile` (191 Pakete, 3,7 s),
`vite build` (1525 Module, 440 ms) und `vite preview` samt Abruf über
`http://127.0.0.1:<Port>/` UND `http://localhost:<Port>/` — beide 200, aber
mit curl auf macOS. Über das Rückfallverhalten eines Windows-Clients sagt das
NICHTS; genau deshalb misst das Skript den Namen selbst, bevor es einen
Browser öffnet.
Ebenfalls gemessen: ein belegter Port 4174 lässt `vite preview --strictPort`
mit `Port 4174 is already in use` und Code 1 abbrechen — es weicht nicht aus.

Die Helferfunktionen sind bewusst eine zweite Kopie neben
`bootstrap-windows-build.ps1`. Beide Dateien sollen einzeln lauffähig bleiben;
ein späterer Schritt führt sie zusammen.
#>
[CmdletBinding()]
param(
    [string]$Path = (Join-Path $PSScriptRoot '..'),
    [int]$Port = 4174,
    [switch]$NoInstall,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

# Die Ausgabe dieses Skripts ist deutsch und trägt echte Umlaute. Ohne diese
# Zeile zeigt eine Konsole mit einer Codepage ungleich 65001 dort Buchstabensalat.
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch { }

# Corepack fragt beim ersten Holen einer pnpm-Fassung interaktiv nach. Ein
# Bootstrap-Lauf, der auf eine Eingabe wartet, die niemand erwartet, sieht aus
# wie ein Hänger.
$env:COREPACK_ENABLE_DOWNLOAD_PROMPT = '0'

function Write-Step([string]$Text) { Write-Host "`n==> $Text" -ForegroundColor Cyan }
function Write-Note([string]$Text) { Write-Host "    $Text" -ForegroundColor DarkGray }

function Stop-WithRemedy([string]$Problem, [string]$Remedy) {
    Write-Host "`nFEHLT: $Problem" -ForegroundColor Red
    Write-Host "Abhilfe: $Remedy" -ForegroundColor Yellow
    exit 1
}

function Test-Tool([string]$Name) { $null -ne (Get-Command $Name -ErrorAction SilentlyContinue) }

# Ein winget-Lauf ändert die PATH-Einträge in der Registrierung, nicht die
# Kopie im laufenden Prozess. Ohne dieses Nachladen fände die unmittelbar
# folgende Prüfung das gerade installierte Programm NICHT.
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
            'Aus dem Microsoft Store "App Installer" installieren, dann erneut ausführen.'
    }
    Write-Note "$Label fehlt – wird installiert (winget kann eine UAC-Abfrage zeigen)"
    $arguments = @('install', '--id', $WingetId, '-e', '--accept-package-agreements',
        '--accept-source-agreements', '--disable-interactivity') + $ExtraArguments
    Write-Note "winget $($arguments -join ' ')"
    & winget @arguments
    # winget meldet "bereits installiert" mit einem eigenen Code; das ist kein
    # Fehlschlag. Über Erfolg entscheidet die Prüfung danach, nicht der Code.
    if ($LASTEXITCODE -ne 0) { Write-Note "winget endete mit Code $LASTEXITCODE – die Prüfung entscheidet" }
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
        'Ein NEUES Terminal öffnen und das Skript erneut ausführen.'
}

function Invoke-Checked([string]$What, [string]$Exe, [string[]]$Arguments, [string]$WorkingDirectory) {
    Write-Note "$Exe $($Arguments -join ' ')"
    $previous = Get-Location
    if ($WorkingDirectory) { Set-Location -LiteralPath $WorkingDirectory }
    try { & $Exe @Arguments } finally { Set-Location -LiteralPath $previous }
    if ($LASTEXITCODE -ne 0) { throw "$What scheiterte mit Code $LASTEXITCODE" }
}

# Wer hält den Port? Die Antwort gehört in die Abbruchmeldung, sonst bleibt dem
# Nutzer nur die Aussage, dass „irgendetwas" belegt ist.
#
# Die Funktion ENTSCHEIDET nichts; sie beschriftet nur. Gefragt wird nach jeder
# Adresse dieses Ports, und ein Treffer kann auch ein Lauscher sein, der einer
# Bindung an 127.0.0.1 gar nicht im Weg steht — über die Belegung entscheidet
# deshalb `Test-PortFree`.
function Get-PortOwner([int]$Port) {
    if (-not (Test-Tool 'Get-NetTCPConnection')) { return $null }
    $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $listener) { return $null }
    $process = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
    if ($process) { return "PID $($listener.OwningProcess) ($($process.ProcessName))" }
    return "PID $($listener.OwningProcess)"
}

# Der Rückfallweg ohne `Get-NetTCPConnection`: selbst binden. Gelingt die
# Bindung, ist der Port frei.
function Test-PortFree([int]$Port) {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    try {
        $listener.Start()
        return $true
    }
    catch {
        return $false
    }
    finally {
        try { $listener.Stop() } catch { }
    }
}

function Test-HttpReachable([string]$Url) {
    try {
        Invoke-WebRequest -Uri $Url -TimeoutSec 3 -NoProxy | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

# ---------------------------------------------------------------- Wirtsprüfung

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Stop-WithRemedy 'Dieses Skript ist der Windows-Weg und braucht einen Windows-Wirt.' `
        'Auf macOS oder Linux genügen `pnpm install`, `pnpm build:wasm`, `pnpm --dir apps/web exec vite build` und `vite preview`.'
}

$Path = (Resolve-Path -LiteralPath $Path).Path
foreach ($marker in @('Cargo.lock', 'package.json', 'apps\web\playwright.config.ts')) {
    if (-not (Test-Path -LiteralPath (Join-Path $Path $marker))) {
        Stop-WithRemedy "$Path sieht nicht wie die Arbeitskopie aus – $marker fehlt." `
            'Das Skript aus scripts\ der Arbeitskopie starten oder -Path angeben.'
    }
}
Write-Step "Arbeitskopie: $Path"

if ($Port -ne 4174) {
    Write-Note "Port $Port statt 4174 – apps\web\playwright.config.ts pinnt 4174, die E2E-Suite läuft weiter dort"
}

# DIE PORTPRÜFUNG STEHT VOR DEM BAU, nicht danach: ein belegter Port soll die
# zehn Minuten Bauzeit gar nicht erst kosten. `--strictPort` unten bleibt
# trotzdem der Rückhalt für den Fall, dass zwischen Prüfung und Start jemand
# schneller war — es weicht nicht still auf 4175 aus, auf dem dann niemand
# antwortet.
#
# ENTSCHIEDEN wird über den Bindeversuch und nicht über die Verbindungsliste:
# `Get-NetTCPConnection` führt auch Einträge, die einer Bindung an 127.0.0.1
# gar nicht im Weg stehen, und ein Abbruch auf so einen Eintrag wäre ein
# falscher Abbruch mit einer PID, die niemandem hilft. Die Liste liefert
# deshalb nur den Text zur Meldung.
Write-Step "Port $Port prüfen"
if (-not (Test-PortFree $Port)) {
    $owner = Get-PortOwner $Port
    $detail = if ($owner) { ": $owner" } else { ' (Halter nicht ermittelbar).' }
    Stop-WithRemedy "Port $Port ist belegt$detail" `
        "Den Prozess beenden (Stop-Process -Id <PID>) oder einen anderen Port wählen: -Port 4184"
}
Write-Note "Port $Port ist frei"

# ------------------------------------------------------------ Voraussetzungen

Write-Step 'Voraussetzungen prüfen'
if ($NoInstall) { Write-Note 'NoInstall: fehlende Voraussetzungen werden nur gemeldet' }

# --- Node und pnpm ---------------------------------------------------------

Assert-Tool -Name 'node' -Label 'Node.js' -WingetId 'OpenJS.NodeJS'
$wantedNode = (Get-Content -LiteralPath (Join-Path $Path '.node-version') -Raw).Trim()
$haveNode = ((& node --version) -join '').TrimStart('v')
if ($haveNode.Split('.')[0] -ne $wantedNode.Split('.')[0]) {
    # Eine andere HAUPTfassung ist etwas anderes als ein anderer Patchstand:
    # `apps/web` baut mit Vite 8 und testet mit Vitest 4, und `vite.config.ts`
    # trägt eine Ausnahme, die ausdrücklich an Node 26 hängt
    # (`--no-experimental-webstorage`).
    Stop-WithRemedy "Node $haveNode hat eine andere HAUPTfassung als der Pin $wantedNode." `
        "winget install --id OpenJS.NodeJS -e --version $wantedNode, danach ein neues Terminal."
}
if ($haveNode -ne $wantedNode) {
    # KEIN Abbruch, und das ist gemessen statt gemutmaßt: `.npmrc` trägt
    # `engine-strict=true` und `package.json` verlangt `"node": "26.7.0"`,
    # trotzdem installiert pnpm 11.20.0 unter Node 26.8.2 durch und schreibt
    # nur `[WARN] Unsupported engine` (macOS, 2026-09-20). Ein harter Abbruch
    # an dieser Stelle wäre strenger als das Werkzeug selbst.
    Write-Note "Node $haveNode statt $wantedNode aus .node-version – weiter, aber gemerkt"
}
else {
    Write-Note "Node $haveNode (entspricht .node-version)"
}

# pnpm kommt aus `packageManager` und NICHT aus winget: die Fassung steht im
# Repo, corepack liefert genau sie.
Assert-Tool -Name 'npm' -Label 'npm (kommt mit Node.js)' -WingetId 'OpenJS.NodeJS'
if (-not (Test-Tool 'corepack')) {
    if ($NoInstall) {
        Stop-WithRemedy 'corepack fehlt.' 'npm install --global corepack'
    }
    Write-Note 'corepack fehlt – wird über npm nachgezogen'
    Invoke-Checked 'npm install corepack' 'npm' @('install', '--global', 'corepack') $Path
    Update-PathFromRegistry
    if (-not (Test-Tool 'corepack')) {
        Stop-WithRemedy 'corepack ist nach der Installation nicht im PATH.' `
            'Ein NEUES Terminal öffnen und das Skript erneut ausführen.'
    }
}

$packageManager = (Get-Content -LiteralPath (Join-Path $Path 'package.json') -Raw |
    ConvertFrom-Json).packageManager
Write-Note "packageManager: $packageManager"

# `corepack enable` legt Shims IM Node-Verzeichnis an und braucht unter
# `C:\Program Files\nodejs` erhöhte Rechte. Es ist deshalb ein VERSUCH und
# keine Bedingung: schlägt es fehl, läuft alles über `corepack pnpm ...`, was
# ohne Shims und ohne Rechteerhöhung auskommt.
$pnpmPrefix = @('pnpm')
$pnpmExe = 'corepack'
try {
    Invoke-Checked 'corepack enable' 'corepack' @('enable') $Path
    Update-PathFromRegistry
    if (Test-Tool 'pnpm') {
        $pnpmExe = 'pnpm'
        $pnpmPrefix = @()
    }
}
catch {
    Write-Note "corepack enable ging nicht durch ($($_.Exception.Message)) – weiter über 'corepack pnpm'"
}
Invoke-Checked 'corepack prepare' 'corepack' @('prepare', $packageManager, '--activate') $Path

function Invoke-Pnpm([string]$What, [string[]]$Arguments, [string]$WorkingDirectory) {
    Invoke-Checked $What $pnpmExe ($pnpmPrefix + $Arguments) $WorkingDirectory
}

Invoke-Pnpm 'pnpm --version' @('--version') $Path

# --- Rust, Linker, Ziel, Generator ----------------------------------------

Assert-Tool -Name 'rustup' -Label 'rustup' -WingetId 'Rustlang.Rustup'
Write-Note "rustup: $((rustup --version 2>$null) -join ' ')"

# Der MSVC-Linker fehlt auf einem frischen Rechner am häufigsten, und cargo
# meldet ihn als kryptischen Linkerfehler statt als fehlendes Werkzeug. Er
# gehört zum WIRT und nicht zum wasm-Ziel: `xtask` und `wasm-bindgen-cli` sind
# Wirts-Binaries. vswhere liegt bei jedem Visual-Studio-Installer.
$MsvcComponent = if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq
    [Runtime.InteropServices.Architecture]::Arm64) {
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
    Install-Prerequisite -Label "MSVC-Buildwerkzeuge ($MsvcComponent)" `
        -WingetId 'Microsoft.VisualStudio.2022.BuildTools' `
        -ExtraArguments @('--override',
            "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --add $MsvcComponent --includeRecommended")
    $msvc = Get-MsvcPath $MsvcComponent
    if (-not $msvc) {
        Stop-WithRemedy "MSVC-Komponente $MsvcComponent ist nach der Installation nicht auffindbar." `
            'Visual Studio Installer öffnen, Workload "Desktopentwicklung mit C++" samt passendem Toolset ergänzen, dann erneut ausführen.'
    }
}
Write-Note "MSVC ($MsvcComponent): $msvc"

$toolchainFile = Join-Path $Path 'rust-toolchain.toml'
$pinMatch = Select-String -LiteralPath $toolchainFile -Pattern '^\s*channel\s*=\s*"([^"]+)"' |
    Select-Object -First 1
if (-not $pinMatch) { throw "Kein channel-Pin in $toolchainFile" }
$pin = $pinMatch.Matches[0].Groups[1].Value
Write-Note "rust-toolchain.toml: $pin"

# Diese Falle kostet Zeit, bevor man sie sieht: ein von außen gesetztes
# RUSTUP_TOOLCHAIN überstimmt `rust-toolchain.toml` SAMT dessen targets-Zeile,
# und der Bau läuft still auf einer anderen Fassung. Die Fehlermeldung von
# `ensure_wasm32_target_available` in tools/xtask/src/main.rs schreibt genau
# das aus.
if ($env:RUSTUP_TOOLCHAIN -and $env:RUSTUP_TOOLCHAIN -ne $pin) {
    Stop-WithRemedy "RUSTUP_TOOLCHAIN ist auf '$env:RUSTUP_TOOLCHAIN' gesetzt und überstimmt den Pin $pin." `
        'Variable entfernen: Remove-Item Env:RUSTUP_TOOLCHAIN'
}

Invoke-Checked 'rustup toolchain install' 'rustup' @('toolchain', 'install', $pin, '--profile', 'minimal') $Path

# Die Fassung wird über die UMGEBUNG gewählt und nicht über `cargo +<pin>`;
# das `+`-Argument kam beim rustup-Shim unter Windows als EIN Argument an
# (gemessen im Nachbarskript bootstrap-windows-build.ps1).
$env:RUSTUP_TOOLCHAIN = $pin
Write-Note "RUSTUP_TOOLCHAIN: $env:RUSTUP_TOOLCHAIN"

# Weil RUSTUP_TOOLCHAIN jetzt gesetzt ist, zählt die targets-Zeile aus
# `rust-toolchain.toml` NICHT mehr mit. Das Ziel kommt deshalb ausdrücklich
# dazu — es ist der erste der vier fail-closed Schritte von `build-wasm`.
Invoke-Checked 'rustup target add' 'rustup' @('target', 'add', '--toolchain', $pin, 'wasm32-unknown-unknown') $Path

# Ein GETEILTES Cargo-Zielverzeichnis lässt Cargo ein Binary aus einer anderen
# Arbeitskopie für frisch halten — eine im Projekt belegte Falle. Das
# Zielverzeichnis gehört deshalb in DIESE Arbeitskopie, und der aufgelöste Pfad
# wird ausgegeben, damit ein Fehlgriff sichtbar ist statt still. Der Name
# bleibt kurz: der Pfad zur Arbeitskopie ist schon tief, und MAX_PATH beißt bei
# den langen Abhängigkeitspfaden des wasm-Baums zuerst.
$env:CARGO_TARGET_DIR = Join-Path $Path 'target\win-reader'
Write-Note "CARGO_TARGET_DIR: $env:CARGO_TARGET_DIR"

# Die verlangte Generatorfassung kommt aus `Cargo.lock`, also aus derselben
# Quelle, gegen die `ensure_wasm_bindgen_cli_matches_lockfile` vergleicht. Auf
# Windows gibt es kein mise, das `cargo:wasm-bindgen-cli` auflösen könnte;
# `cargo install` liefert dieselbe Fassung aus derselben Registry.
$lock = Get-Content -LiteralPath (Join-Path $Path 'Cargo.lock') -Raw
$lockMatch = [regex]::Match($lock, '(?m)^name = "wasm-bindgen"\r?\nversion = "([^"]+)"')
if (-not $lockMatch.Success) { throw 'Cargo.lock nennt keine wasm-bindgen-Fassung' }
$wantedBindgen = $lockMatch.Groups[1].Value
Write-Note "Cargo.lock: wasm-bindgen $wantedBindgen"

# `cargo install` legt nach `%USERPROFILE%\.cargo\bin`. rustup trägt das in den
# PATH des BENUTZERS ein, nicht in den dieses Prozesses, wenn es gerade erst
# installiert wurde.
$cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
if ((Test-Path -LiteralPath $cargoBin) -and ($env:Path -notlike "*$cargoBin*")) {
    $env:Path = $cargoBin + ';' + $env:Path
}

# Dieselbe Lesart wie in xtask: erste Zeile, letztes Feld.
function Get-WasmBindgenVersion {
    if (-not (Test-Tool 'wasm-bindgen')) { return $null }
    $line = (& wasm-bindgen --version 2>$null | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0 -or -not $line) { return $null }
    return ($line.Trim() -split '\s+')[-1]
}

$haveBindgen = Get-WasmBindgenVersion
if ($haveBindgen -ne $wantedBindgen) {
    if ($NoInstall) {
        Stop-WithRemedy "wasm-bindgen-cli $wantedBindgen fehlt (gefunden: $(if ($haveBindgen) { $haveBindgen } else { 'nichts' }))." `
            "cargo install wasm-bindgen-cli --version $wantedBindgen --locked"
    }
    Write-Note "wasm-bindgen-cli: $(if ($haveBindgen) { $haveBindgen } else { 'fehlt' }) – $wantedBindgen wird gebaut (das dauert)"
    # KEIN --force: stimmt die Fassung schon, kommt dieser Zweig gar nicht erst
    # dran, und ein zweiter Lauf kostet nichts.
    Invoke-Checked 'cargo install wasm-bindgen-cli' 'cargo' @(
        'install', 'wasm-bindgen-cli', '--version', $wantedBindgen, '--locked') $Path
    $haveBindgen = Get-WasmBindgenVersion
    if ($haveBindgen -ne $wantedBindgen) {
        Stop-WithRemedy "wasm-bindgen-cli meldet $haveBindgen statt $wantedBindgen." `
            "PATH prüfen: $cargoBin muss VOR einer anderen wasm-bindgen.exe stehen."
    }
}
Write-Note "wasm-bindgen: $haveBindgen"

# -------------------------------------------------------------------- Bauen

Write-Step 'Abhängigkeiten installieren'
Invoke-Pnpm 'pnpm install' @('install', '--frozen-lockfile') $Path

Write-Step 'wasm-Brücke bauen (xtask build-wasm)'
# `--locked` und der Umweg über xtask sind Absicht: die vier fail-closed
# Schritte stecken IN xtask, ein direkter `cargo build --target
# wasm32-unknown-unknown` ginge an ihnen vorbei.
Invoke-Checked 'xtask build-wasm' 'cargo' @('run', '--locked', '-p', 'xtask', '--', 'build-wasm') $Path

$bridge = Join-Path $Path 'apps\web\src\bridge\pkg\ea_reader_wasm.js'
if (-not (Test-Path -LiteralPath $bridge)) { throw "build-wasm meldete Erfolg, aber $bridge fehlt" }
Write-Note "Brücke: $bridge"

Write-Step 'Bündel bauen (vite build)'
Invoke-Pnpm 'vite build' @('--dir', 'apps/web', 'exec', 'vite', 'build') $Path

$bundle = Join-Path $Path 'apps\web\dist\index.html'
if (-not (Test-Path -LiteralPath $bundle)) { throw "vite build meldete Erfolg, aber $bundle fehlt" }
Write-Note "Bündel: $bundle"

# ---------------------------------------------------------------- Vorschau

$LoopbackUrl = "http://127.0.0.1:$Port/"
# ÜBER DEN NAMEN und nicht über die IP, und der Grund ist gemessen und steht im
# Kopf von apps\web\playwright.config.ts: WebAuthn leitet die
# Relying-Party-Kennung aus dem Host der Herkunft ab, und eine IP-Adresse ist
# dort KEIN gültiger Wert — derselbe `navigator.credentials.create`, der unter
# `http://localhost:<Port>` durchläuft, fällt unter `http://127.0.0.1:<Port>`
# mit `SecurityError: This is an invalid domain.`
$ReaderUrl = "http://localhost:$Port/"

Write-Step "Vorschau starten (Port $Port)"

$preview = $null
try {
    # GEBUNDEN AN 127.0.0.1, wie in apps\web\playwright.config.ts: eine Bindung
    # an alle Schnittstellen (`--host` ohne Wert) machte die Vorschau im ganzen
    # Netz sichtbar, und das ist für einen Reader, der später Archive öffnet,
    # keine Nebensache. Der Name `localhost` erreicht dieselbe Bindung, weil
    # der Browser auf 127.0.0.1 zurückfällt, wenn [::1] nicht antwortet.
    #
    # Gestartet über cmd.exe, damit `taskkill /T` unten den GANZEN Baum
    # erwischt: pnpm startet node als Enkel, und ein beendeter Elternprozess
    # ließe den Enkel auf dem Port sitzen — der nächste Lauf bräche dann an
    # einer Portkollision ab, die niemand verursacht hat.
    $previewCommand = @('/c', $pnpmExe) + $pnpmPrefix + @(
        '--dir', 'apps/web', 'exec', 'vite', 'preview',
        '--host', '127.0.0.1', '--port', "$Port", '--strictPort')
    Write-Note "$($previewCommand -join ' ')"
    $preview = Start-Process -FilePath $env:ComSpec -ArgumentList $previewCommand `
        -WorkingDirectory $Path -NoNewWindow -PassThru

    $deadline = (Get-Date).AddSeconds(120)
    $ready = $false
    while ((Get-Date) -lt $deadline) {
        if ($preview.HasExited) {
            throw "vite preview endete sofort mit Code $($preview.ExitCode). Bei einem belegten Port meldet --strictPort das laut; die Zeilen darüber sagen, was war."
        }
        if (Test-HttpReachable $LoopbackUrl) { $ready = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw "Die Vorschau antwortete binnen 120 s nicht auf $LoopbackUrl" }
    Write-Note "erreichbar: $LoopbackUrl"

    # Die eine Sache, die auf einem Nicht-Windows-Rechner nicht zu prüfen war:
    # ob der NAME auf diesem Wirt bei derselben Bindung landet. Deshalb wird
    # sie hier gemessen statt behauptet. Schlägt sie fehl, öffnet das Skript
    # KEINEN Browser auf eine tote Seite, sondern sagt, was zu tun ist — die
    # Vorschau läuft weiter, damit der Nutzer es selbst ansehen kann.
    $nameReaches = Test-HttpReachable $ReaderUrl
    if ($nameReaches) {
        Write-Note "erreichbar: $ReaderUrl"
    }
    else {
        $addresses = 'nicht auflösbar'
        try {
            $addresses = ([Net.Dns]::GetHostAddresses('localhost') |
                ForEach-Object { $_.IPAddressToString }) -join ', '
        }
        catch { }
        Write-Host "`nACHTUNG: $LoopbackUrl antwortet, $ReaderUrl nicht." -ForegroundColor Yellow
        Write-Host "  'localhost' löst hier auf: $addresses" -ForegroundColor Yellow
        Write-Host '  Die Vorschau ist an 127.0.0.1 gebunden; wenn der Name zuerst [::1] meint und' -ForegroundColor Yellow
        Write-Host '  der Client nicht zurückfällt, findet er nichts.' -ForegroundColor Yellow
        Write-Host '  Ein Browser fällt üblicherweise zurück, dieser HTTP-Client nicht – erst' -ForegroundColor Yellow
        Write-Host "  $ReaderUrl selbst aufrufen." -ForegroundColor Yellow
        Write-Host '  Bleibt die Seite leer, die Vorschau an den Namen binden:' -ForegroundColor Yellow
        Write-Host "    pnpm --dir apps/web exec vite preview --host localhost --port $Port --strictPort" -ForegroundColor Yellow
        Write-Host '  Über die IP zu gehen ist KEINE Abhilfe: WebAuthn nimmt keine IP als Relying Party.' -ForegroundColor Yellow
    }

    if ($NoBrowser) {
        Write-Note "NoBrowser: bitte selbst öffnen – $ReaderUrl"
    }
    elseif ($nameReaches) {
        Write-Step "Browser öffnen: $ReaderUrl"
        Start-Process $ReaderUrl
    }
    else {
        Write-Note "Browser wird NICHT automatisch geöffnet, solange der Name nicht antwortet."
    }

    Write-Step 'Was dort zu sehen ist'
    Write-Host '  Kopfzeile "Einsatzarchiv — Reader", darunter die Navigation'
    Write-Host '  Reader | Enrollment | Datei-Modus | Einzelexport | Reader-Cache.'
    Write-Host ''
    Write-Host '  Die Startroute "/" ist der Reader. Die Fläche "Archiv öffnen" liegt unter'
    Write-Host '  "Datei-Modus" (Route /datei): ein gewöhnliches Dateifeld nimmt dort die eine'
    Write-Host '  exportierte Archivdatei entgegen, und der Komfortweg über einen Ordner'
    Write-Host '  erscheint nur, wenn die Engine showDirectoryPicker anbietet.'
    Write-Host "  Direkt dorthin: http://localhost:$Port/datei — der Vorschauserver liefert für"
    Write-Host '  diesen Pfad dieselbe index.html aus (gemessen: 200, relative Beiwerkspfade).'
    Write-Host ''
    Write-Host '  OHNE eine .eip-Datei UND einen dazu passenden Grant zeigt der Reader KEINE' -ForegroundColor Yellow
    Write-Host '  Inhalte. Das ist der erwartete Zustand und kein Fehlschlag dieses Baus.' -ForegroundColor Yellow
    Write-Host '  Beides liefert ein eigenes Saat-Kommando, das NICHT Teil dieses Skripts ist.' -ForegroundColor Yellow

    Write-Step "Vorschau läuft – mit Strg+C beenden"
    # SilentlyContinue, weil eine Vorschau, die zwischen Bereitschaftstest und
    # dieser Zeile stirbt, sonst als roter PowerShell-Fehler endet statt als
    # ruhiger Abgang.
    Wait-Process -Id $preview.Id -ErrorAction SilentlyContinue
}
finally {
    if ($preview -and -not $preview.HasExited) {
        # /T, weil der eigentliche Server ein Enkel ist: cmd.exe -> pnpm/corepack -> node.
        & taskkill /PID $preview.Id /T /F *> $null
    }
}
