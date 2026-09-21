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

It CAN SIGN AND INSTALL, mit `-SelfSignedCert`. Sign-Release.ps1 braucht einen
Zertifikats-Thumbprint, und ohne gekauftes Zertifikat gibt es dafür genau einen
ehrlichen Weg: ein selbstsigniertes Code-Signing-Zertifikat, das auf DIESEM
Rechner verankert wird. Das reicht, weil der Rust-Prüfer (native_identity.rs)
nur eine vom Betriebssystem als `Valid` bewertete Authenticode-Signatur und die
DER-Gleichheit der Zertifikate von Parent, Helfer und Manifest verlangt — es
gibt, anders als bei macOS mit `anchor apple generic`, KEINE Forderung nach
einem öffentlichen Anker. Keine Prüfung wird dafür geändert oder umgangen.

    ############################################################
    #  NUR FÜR EIGENE, KONTROLLIERTE RECHNER.                  #
    #  Eine selbstsignierte Kette trägt KEINE Verteilung an     #
    #  Dritte. Wer das Zertifikat in `LocalMachine\Root` legt,  #
    #  erklärt es maschinenweit zur Wurzel: alles, was mit      #
    #  seinem privaten Schlüssel signiert ist, gilt diesem      #
    #  Rechner als vertrauenswürdig. Auf einem fremden oder     #
    #  geteilten Rechner ist das eine Vertrauensausweitung und  #
    #  kein Behelf. Für echte Auslieferung: ein Zertifikat      #
    #  einer öffentlichen CA, danach dieselben Skripte ohne     #
    #  `-SelfSignedCert`.                                      #
    ############################################################

Der Schalter erzeugt (oder verwendet wieder) das Zertifikat in
`Cert:\CurrentUser\My`, verankert seinen ÖFFENTLICHEN Teil in
`LocalMachine\Root` und `LocalMachine\TrustedPublisher`, beweist mit einer
Wegwerfdatei, dass `Set-AuthenticodeSignature` damit `Valid` liefert, legt einen
geschützten Ablage- und Installationsbaum an und ruft dann Sign-Release.ps1 und
Install-Release.ps1 unverändert auf. Ablage und Installation bekommen je eine
eigene Laufkennung, ein bestehendes Verzeichnis wird also nie überschrieben oder
gelöscht. Ein zweiter Lauf nimmt dasselbe Zertifikat wieder, solange es noch
mehr als 30 Tage gültig ist; danach legt er ein neues an und sagt dazu, dass das
alte im Wurzelspeicher verankert bleibt, bis jemand es von Hand entfernt.

`-SelfSignedCert` verlangt einen ERHÖHTEN Lauf (Install-Release.ps1 besteht
selbst darauf) und ändert damit den Rechner: Wurzelspeicher und ein geschützter
Installationsbaum. Zwei Folgen davon sind unangenehm und deshalb hier benannt:
ein erhöhter Lauf hinterlässt Arbeitskopie, `.dotnet` und `target` mit erhöhtem
Besitzer, was einen späteren nicht erhöhten Lauf auf demselben `-Path` stören
kann — deshalb für `-SelfSignedCert` einen EIGENEN `-Path` nehmen und nicht die
Arbeitskopie, in der normal entwickelt wird, etwa
`-Path C:\ea-release -SelfSignedCert`; und die native Anmeldung selbst kann
dieser Lauf nicht vorführen, weil sie
ein NICHT erhöhtes interaktives Konto braucht. Das Skript gibt den dafür nötigen
Befehl am Ende aus, statt einen Erfolg zu behaupten.

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

.PARAMETER Desktop
Also build the Tauri writer application and start it. This pulls in Node and
pnpm, which the release path does not need, so it is opt-in.

.PARAMETER NoInstall
Do not install anything. Report a missing prerequisite with its winget command
and stop. Use this in CI or on a managed machine.

.PARAMETER SelfSignedCert
Selbstsignierte Signaturkette: Zertifikat anlegen/wiederverwenden, maschinenweit
verankern, signieren, installieren. Nur für eigene, kontrollierte Rechner (siehe
Kasten oben). Verlangt einen erhöhten Lauf und verträgt sich weder mit
-NoInstall noch mit -SkipPackage.

.PARAMETER ReleaseRoot
Wurzel des geschützten Ablage- und Installationsbaums für -SelfSignedCert.
Muss ein lokaler Pfad mit Laufwerksbuchstaben auf einem festen Datenträger sein.
Voreinstellung C:\Einsatzarchiv.

.PARAMETER Version
Fassung für Manifest und Installation. Voreinstellung ist die Fassung aus
crates/ea-admin/Cargo.toml - genau die Kiste, deren CARGO_PKG_VERSION der
Prüfer gegen das Manifest hält.

.PARAMETER CertificateProvider
Schlüsselspeicheranbieter für ein NEU angelegtes Zertifikat. Leer heisst: die
Voreinstellung von New-SelfSignedCertificate (CNG). Falls die Signierprobe
scheitert, ist der eine dokumentierte Ausweichwert
'Microsoft Enhanced RSA and AES Cryptographic Provider'.

.EXAMPLE
pwsh -File bootstrap-windows-build.ps1
.EXAMPLE
pwsh -File bootstrap-windows-build.ps1 -Path D:\build\ea -Ref main -Runtime win-arm64
.EXAMPLE
pwsh -File bootstrap-windows-build.ps1 -SelfSignedCert
#>
[CmdletBinding()]
param(
    [string]$Path = (Join-Path $HOME 'einsatztagebuch'),
    [string]$Ref = 'main',
    [ValidateSet('win-x64', 'win-arm64', IgnoreCase = $false)][string]$Runtime,
    [switch]$SkipTests,
    [switch]$SkipPackage,
    [switch]$Desktop,
    [switch]$NoInstall,
    [switch]$SelfSignedCert,
    [string]$ReleaseRoot = 'C:\Einsatzarchiv',
    [string]$Version,
    [string]$CertificateProvider
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

# ------------------------------------------------ selbstsignierte Kette: Teile

# Ein fester Betreff, damit ein zweiter Lauf dasselbe Zertifikat wiederfindet,
# statt den Speicher mit Schlüsseln zuzumüllen.
$SelfSignedSubject = 'CN=Einsatzarchiv Self-Signed Release Signer, O=Einsatzarchiv, OU=Self-signed local trust'
$CodeSigningOid = '1.3.6.1.5.5.7.3.3'

# Diese beiden Zeichenketten sind WÖRTLICH die aus ReleaseSecurity.psm1 (der
# SDDL, den der Installer seinem eigenen Ziel gibt). Nicht "so ähnlich":
# Besitzer Administratoren, SYSTEM und Administratoren voll, Builtin-Benutzer
# nur lesen/ausführen (0x1200a9, kein einziges Bit aus der Schreibmaske
# 0x500D0156), geschützte DACL ohne Vererbung von oben.
$ProtectedDirectorySddl = 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'
$ProtectedFileSddl = 'O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)'

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        return [Security.Principal.WindowsPrincipal]::new($identity).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    finally { $identity.Dispose() }
}

function Test-CodeSigningEku($Certificate) {
    foreach ($extension in $Certificate.Extensions) {
        if ($extension -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($usage in $extension.EnhancedKeyUsages) {
                if ($usage.Value -eq $CodeSigningOid) { return $true }
            }
        }
    }
    return $false
}

# Dieselben Bedingungen, die Sign-Release.ps1 danach selbst stellt: privater
# Schlüssel, gültiger Zeitraum, EKU Codesignatur. Der Sicherheitsabstand von 30
# Tagen verhindert, dass ein Lauf ein Zertifikat wiederverwendet, das noch
# während der Restlaufzeit des Bundles abläuft - ohne Zeitstempel endet die
# Gültigkeit der Signatur mit dem Zertifikat.
function Find-SelfSignedSigner {
    $found = @(Get-ChildItem -LiteralPath 'Cert:\CurrentUser\My' | Where-Object {
            $_.Subject -like '*CN=Einsatzarchiv Self-Signed Release Signer*' -and
            $_.Issuer -eq $_.Subject -and $_.HasPrivateKey -and
            $_.NotBefore -le [DateTime]::Now -and $_.NotAfter -gt [DateTime]::Now.AddDays(30) -and
            (Test-CodeSigningEku $_)
        })
    return ($found | Sort-Object NotAfter -Descending | Select-Object -First 1)
}

function New-SelfSignedSigner {
    $parameters = @{
        Type              = 'CodeSigningCert'
        Subject           = $SelfSignedSubject
        FriendlyName      = 'Einsatzarchiv self-signed release signer'
        CertStoreLocation = 'Cert:\CurrentUser\My'
        KeyAlgorithm      = 'RSA'
        KeyLength         = 3072
        HashAlgorithm     = 'SHA256'
        # Fünf Minuten Vorlauf gegen Uhrenversatz, drei Jahre Laufzeit. Ohne
        # Zeitstempeldienst ist die Signatur danach nicht mehr `Valid`.
        NotBefore         = (Get-Date).AddMinutes(-5)
        NotAfter          = (Get-Date).AddYears(3)
    }
    if ($CertificateProvider) { $parameters.Provider = $CertificateProvider }
    # New-SelfSignedCertificate kommt aus dem PKI-Modul und läuft in PowerShell 7
    # über die Windows-PowerShell-Kompatibilitätsschicht. Das Ergebnis ist ein
    # DESERIALISIERTES Objekt ohne Methoden - nur der Thumbprint wird übernommen,
    # das echte Zertifikat kommt danach aus dem Speicher.
    $created = New-SelfSignedCertificate @parameters
    return $created.Thumbprint
}

# Verankert ausschliesslich den ÖFFENTLICHEN Teil. Der private Schlüssel bleibt,
# wo er hingehört: im Benutzerspeicher des Signierenden.
function Add-MachineTrust([byte[]]$Der, [string]$StoreName) {
    $public = [Security.Cryptography.X509Certificates.X509Certificate2]::new($Der)
    $store = [Security.Cryptography.X509Certificates.X509Store]::new(
        $StoreName, [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $present = @($store.Certificates | Where-Object { $_.Thumbprint -eq $public.Thumbprint })
        if ($present.Count -gt 0) {
            Write-Note "LocalMachine\$StoreName : bereits verankert"
            return
        }
        $store.Add($public)
        Write-Note "LocalMachine\$StoreName : verankert"
    }
    finally {
        $store.Close()
        $store.Dispose()
        $public.Dispose()
    }
}

# Die Signierprobe. Sign-Release.ps1 prüft nach JEDEM Signieren auf Status
# `Valid`, und das hängt an der Vertrauenskette und daran, ob
# Set-AuthenticodeSignature mit dem Schlüsselanbieter dieses Zertifikats
# überhaupt umgehen kann. Beides hier zu klären kostet eine Sekunde; es erst
# beim Signieren zu erfahren kostet den ganzen Bau.
function Test-CodeSigning($Certificate) {
    $probe = Join-Path ([IO.Path]::GetTempPath()) "ea-sign-probe-$([Guid]::NewGuid().ToString('N')).ps1"
    try {
        Set-Content -LiteralPath $probe -Value '# Einsatzarchiv Signierprobe' -Encoding utf8
        $signed = Microsoft.PowerShell.Security\Set-AuthenticodeSignature `
            -LiteralPath $probe -Certificate $Certificate -HashAlgorithm SHA256 -ErrorAction Stop
        return [string]$signed.Status
    }
    catch {
        # Ein unpassender Schluesselanbieter meldet sich als FEHLER und nicht als
        # Status. Beides muss hier ankommen, sonst zerlegt es den Lauf mit einem
        # Rohfehler statt mit dem Wiederholungsbefehl.
        return "Fehler: $($_.Exception.Message)"
    }
    finally { Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue }
}

function Set-ProtectedSecurity([string]$LiteralPath) {
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $directory = (Get-Item -LiteralPath $LiteralPath -Force).PSIsContainer

    # Besitzer und DACL verlangen UNTERSCHIEDLICHE Rechte - WRITE_OWNER gegen
    # WRITE_DAC -, und ein Aufruf, der beides traegt, scheitert an dem Teil, der
    # fehlt. Deshalb erst der Besitzer allein: Set-Acl schreibt nur die
    # Abschnitte, die am uebergebenen Deskriptor auch wirklich gesetzt wurden.
    # Der Besitzer ist hier keine Formsache - Assert-EaAclPolicy laesst nur
    # SYSTEM, Administratoren und TrustedInstaller durch, und der Erzeuger eines
    # frischen Verzeichnisses ist je nach Richtlinie keins davon.
    $owner = if ($directory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $owner.SetOwner($administrators)
    Set-Acl -LiteralPath $LiteralPath -AclObject $owner

    $sddl = if ($directory) { $ProtectedDirectorySddl } else { $ProtectedFileSddl }
    $security = if ($directory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $security.SetSecurityDescriptorSddlForm($sddl)
    Set-Acl -LiteralPath $LiteralPath -AclObject $security

    # Zurueckgelesen statt geglaubt. Ohne diese Zeile faellt ein nicht
    # uebernommener Besitzerwechsel erst spaeter auf, als nacktes
    # 'Protected owner and DACL required' aus dem Modul - richtig geurteilt,
    # aber ohne den Hinweis, woran es lag.
    $applied = Get-Acl -LiteralPath $LiteralPath
    $appliedOwner = $applied.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($appliedOwner -ne $administrators.Value) {
        Stop-WithRemedy "Besitzer von '$LiteralPath' ist $appliedOwner statt der Administratorengruppe; Install-Release.ps1 lehnt den Baum damit ab." `
            "Besitz uebernehmen und erneut ausfuehren:`n  takeown /F `"$LiteralPath`" /A"
    }
}

function New-ProtectedDirectory([string]$LiteralPath) {
    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        New-Item -ItemType Directory -Path $LiteralPath | Out-Null
    }
    # Ein frisch unter C:\ angelegtes Verzeichnis erbt von der Wurzel ACEs, die
    # authentifizierten Benutzern Schreibrechte geben. Deshalb wird der
    # geschützte Deskriptor gesetzt, und zwar bei JEDEM Lauf: so heilt ein
    # zweiter Lauf einen von Hand verbogenen Baum, statt daran zu scheitern.
    Set-ProtectedSecurity $LiteralPath
}

# Geprüft wird NICHT mit nachgebauter Logik, sondern mit dem Tor selbst:
# Assert-EaProtectedPins aus ReleaseSecurity.psm1 braucht nur ein Objekt mit
# .Paths. Dieselbe Prüfung, die Install-Release.ps1 später wirklich anwendet -
# also keine Abweichung zwischen Vorprüfung und Urteil.
function Assert-ProtectedTree([string]$LiteralPath) {
    $chain = @()
    $current = [IO.Path]::GetFullPath($LiteralPath)
    while ($current) {
        $chain += $current
        $parent = [IO.Directory]::GetParent($current)
        $current = if ($null -eq $parent) { $null } else { $parent.FullName }
    }
    Assert-EaProtectedPins ([pscustomobject]@{ Paths = $chain })
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

# ------------------------------------------- selbstsignierte Kette: Teil 1/2
#
# Alles, was ohne Arbeitskopie entschieden werden kann, wird hier entschieden -
# VOR dem Bau. Ein fehlender Rechteschritt oder ein Zertifikat, mit dem sich
# nicht signieren lässt, soll nach einer Sekunde auffallen und nicht nach einer
# halben Stunde Bauzeit.

$SigningCertificate = $null
$SigningCertificateDer = $null
$SigningPin = $null
$InstalledBundle = $null

if ($SelfSignedCert) {
    Write-Step 'Selbstsignierte Signaturkette vorbereiten'
    Write-Note 'NUR fuer eigene, kontrollierte Rechner - keine Verteilung an Dritte'

    if ($NoInstall) {
        Stop-WithRemedy '-SelfSignedCert und -NoInstall widersprechen sich: die Kette legt ein Zertifikat in den Maschinenspeicher und installiert das Bundle.' `
            'Einen der beiden Schalter weglassen.'
    }
    if ($SkipPackage) {
        Stop-WithRemedy '-SelfSignedCert braucht das Paket aus Package.ps1 als Eingabe fuer Sign-Release.ps1.' `
            '-SkipPackage weglassen.'
    }
    if (-not (Test-Elevated)) {
        # Kein stilles Scheitern und kein heimliches Nachfordern: Install-Release.ps1
        # verlangt in seiner Zeile 90 ausdruecklich einen erhoehten Administrator,
        # und das Verankern im Maschinenspeicher braucht es ebenfalls.
        Stop-WithRemedy 'Dieser Lauf ist nicht erhoeht. Die selbstsignierte Kette schreibt in LocalMachine\Root und Install-Release.ps1 besteht auf einem erhoehten Administrator.' `
            "Terminal als Administrator oeffnen (UAC bestaetigen) und erneut ausfuehren:`n  pwsh -NoProfile -File `"$PSCommandPath`" -SelfSignedCert"
    }
    if ($ReleaseRoot.Length -lt 4 -or -not [char]::IsAsciiLetter($ReleaseRoot[0]) -or
        $ReleaseRoot[1] -ne ':' -or $ReleaseRoot[2] -ne '\' -or $ReleaseRoot.Substring(2).Contains(':')) {
        Stop-WithRemedy "ReleaseRoot '$ReleaseRoot' ist kein lokaler Pfad mit Laufwerksbuchstaben unterhalb der Wurzel." `
            'Etwa -ReleaseRoot C:\Einsatzarchiv angeben; das native Installationsmodul lehnt alles andere ab.'
    }
    # Die Wurzel selbst scheidet aus: sie gehoert nicht uns, und ihre Rechte
    # koennen wir nicht auf den geschuetzten Deskriptor ziehen, ohne dem ganzen
    # Datentraeger die Vererbung umzuhaengen.
    $ReleaseRoot = [IO.Path]::GetFullPath($ReleaseRoot).TrimEnd('\')

    $signer = Find-SelfSignedSigner
    if ($signer) {
        Write-Note "Zertifikat wiederverwendet: $($signer.Thumbprint) (gueltig bis $($signer.NotAfter.ToString('yyyy-MM-dd')))"
        $thumbprint = $signer.Thumbprint
    }
    else {
        # Ehrlich bleiben: ein abgelaufenes oder in den 30-Tage-Abstand
        # gelaufenes Zertifikat desselben Betreffs wird NICHT ersetzt. Es bleibt
        # im Benutzerspeicher und vor allem bleibt es im Wurzelspeicher der
        # Maschine verankert. Wer nicht aufraeumt, hat danach zwei Wurzeln fuer
        # dasselbe Projekt - deshalb steht es hier und wird nicht verschwiegen.
        $stale = @(Get-ChildItem -LiteralPath 'Cert:\CurrentUser\My' |
            Where-Object { $_.Subject -like '*CN=Einsatzarchiv Self-Signed Release Signer*' })
        foreach ($old in $stale) {
            Write-Note "ALT: $($old.Thumbprint) laeuft $($old.NotAfter.ToString('yyyy-MM-dd')) ab und bleibt verankert - von Hand entfernen"
        }
        Write-Note 'Kein brauchbares Zertifikat gefunden - es wird eines angelegt'
        $thumbprint = New-SelfSignedSigner
        Write-Note "Zertifikat angelegt: $thumbprint"
    }

    $SigningCertificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$thumbprint"
    $SigningCertificateDer = $SigningCertificate.RawData
    # Kleinschreibung ist Pflicht: Install-Release.ps1 prueft -ExpectedCertificateSha256
    # gegen \A[0-9a-f]{64}\z und vergleicht danach gross-/kleinempfindlich.
    $SigningPin = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($SigningCertificateDer)).ToLowerInvariant()
    Write-Note "oeffentlicher DER-SHA-256-Pin: $SigningPin"

    # Erst verankern, dann pruefen: Set-AuthenticodeSignature meldet `Valid` nur,
    # wenn die Kette schon beim Signieren steht.
    Add-MachineTrust $SigningCertificateDer 'Root'
    Add-MachineTrust $SigningCertificateDer 'TrustedPublisher'

    $probeStatus = Test-CodeSigning $SigningCertificate
    if ($probeStatus -ne 'Valid') {
        Stop-WithRemedy "Signierprobe ergab Status '$probeStatus' statt 'Valid'. Sign-Release.ps1 wuerde an genau dieser Bedingung scheitern." `
            ("Haeufigste Ursache ist der Schluesselanbieter des Zertifikats. Altes Zertifikat entfernen und mit dem Ausweichanbieter neu anlegen:`n" +
             "  Remove-Item -LiteralPath 'Cert:\CurrentUser\My\$thumbprint'`n" +
             "  pwsh -NoProfile -File `"$PSCommandPath`" -SelfSignedCert -CertificateProvider 'Microsoft Enhanced RSA and AES Cryptographic Provider'")
    }
    Write-Note 'Signierprobe: Valid'
}

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

# ------------------------------------------- selbstsignierte Kette: Teil 2/2

if ($SelfSignedCert) {
    Write-Step 'Signieren und installieren'

    # Gelesen, nicht geaendert: dieselben Module, die Sign-Release.ps1 und
    # Install-Release.ps1 benutzen. Assert-EaProtectedPins kommt aus
    # ReleaseSecurity.psm1 und ruft Assert-EaAclPolicy aus ReleaseManifest.psm1.
    Import-Module (Join-Path $WindowsRoot 'scripts\ReleaseManifest.psm1') -Force
    Import-Module (Join-Path $WindowsRoot 'scripts\ReleaseSecurity.psm1') -Force

    if (-not $Version) {
        # Der Pruefer haelt das Manifest gegen CARGO_PKG_VERSION der Kiste
        # ea-admin; die Fassung kommt deshalb aus deren Cargo.toml.
        $versionMatch = Select-String -LiteralPath (Join-Path $Path 'crates\ea-admin\Cargo.toml') `
            -Pattern '^\s*version\s*=\s*"([^"]+)"' | Select-Object -First 1
        if (-not $versionMatch) { throw 'Keine Fassung in crates/ea-admin/Cargo.toml gefunden' }
        $Version = $versionMatch.Matches[0].Groups[1].Value
    }
    if ($Version -cnotmatch '\A[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\z') {
        Stop-WithRemedy "Fassung '$Version' passt nicht auf das Muster, das Sign-Release.ps1 verlangt." `
            'Fassung ausdruecklich angeben: -Version 0.1.0'
    }
    Write-Note "Fassung: $Version"

    # Eine Laufkennung je Lauf. Damit ist die Wiederholbarkeit ohne Loeschen
    # erfuellt: Sign-Release.ps1 und Install-Release.ps1 bestehen beide auf
    # frischen Zielen, und ein zweiter Lauf nimmt eigene, statt einem
    # bestehenden Verzeichnis nahe zu kommen.
    $runId = Get-Date -Format 'yyyyMMdd-HHmmss'
    $stageRoot = Join-Path $ReleaseRoot 'stage'
    $installRoot = Join-Path $ReleaseRoot 'install'
    $runStage = Join-Path $stageRoot "$Version-$Runtime-$runId"
    $bundle = Join-Path $runStage 'bundle'
    $kit = Join-Path $runStage 'management'
    $InstalledBundle = Join-Path $installRoot "$Version-$Runtime-$runId"

    # Install-Release.ps1 prueft Besitzer und wirksame DACL der Quelle UND jedes
    # Vorfahren, und ebenso des Zielelternteils. Ein Ablageordner im Profil oder
    # unter Downloads faellt dabei durch - deshalb dieser eigene Baum.
    Write-Note "geschuetzter Baum: $ReleaseRoot"
    foreach ($directory in @($ReleaseRoot, $stageRoot, $installRoot, $runStage)) {
        New-ProtectedDirectory $directory
    }
    Assert-ProtectedTree $runStage
    Assert-ProtectedTree $installRoot

    Invoke-Checked 'Sign-Release.ps1' 'pwsh' @(
        '-NoLogo', '-NoProfile', '-NonInteractive',
        '-File', (Join-Path $WindowsRoot 'scripts\Sign-Release.ps1'),
        '-ParentBinary', $parentExe,
        '-HelperPackage', $packaged,
        '-Destination', $bundle,
        '-ManagementDestination', $kit,
        '-Architecture', $Runtime,
        '-Version', $Version,
        '-CertificateThumbprint', $SigningCertificate.Thumbprint) $Path

    # Sign-Release.ps1 legt seine Ziele mit den geerbten Rechten an, und der
    # Besitzer eines neu angelegten Objekts ist je nach Richtlinie der Erzeuger
    # und nicht die Administratorengruppe. Erst danach traegt das Bundle die
    # Rechte, die der Installer sehen will. Das schwaecht nichts ab: es ist
    # genau der Deskriptor, den Install-Release.ps1 seinem eigenen Ziel gibt.
    Set-ProtectedSecurity $bundle
    foreach ($file in Get-ChildItem -LiteralPath $bundle -Force) {
        Set-ProtectedSecurity $file.FullName
        Assert-ProtectedTree $file.FullName
    }
    Assert-ProtectedTree $bundle
    Write-Note "signiertes Bundle: $bundle"
    Write-Note "Management-Kit: $kit"

    # Der Aufruf geht ueber den Pfad INNERHALB des Kits: Install-Release.ps1
    # prueft sein eigenes Verzeichnis auf genau acht Eintraege und seine eigenen
    # Bytes gegen den Pin. Deshalb landet hier auch nichts weiter im Kit - kein
    # Protokoll, keine Kopie, nichts.
    Invoke-Checked 'Install-Release.ps1' 'pwsh' @(
        '-NoLogo', '-NoProfile', '-NonInteractive',
        '-File', (Join-Path $kit 'Install-Release.ps1'),
        '-Bundle', $bundle,
        '-Destination', $InstalledBundle,
        '-Architecture', $Runtime,
        '-Version', $Version,
        '-ExpectedCertificateSha256', $SigningPin) $Path

    Write-Note "Installation: $InstalledBundle"
}

# ----------------------------------------------------------------- desktop

$desktopExe = $null
if ($Desktop) {
    Write-Step 'Tauri-Anwendung bauen'

    Assert-Tool -Name 'node' -Label 'Node.js' -WingetId 'OpenJS.NodeJS'
    $wantedNode = (Get-Content -LiteralPath (Join-Path $Path '.node-version') -Raw).Trim()
    $haveNode = ((& node --version) -join '').TrimStart('v')
    if ($haveNode -ne $wantedNode) {
        # Kein Abbruch: `.node-version` ist der Pin der Entwicklungsumgebung,
        # und der vite-Bau ist nicht die Stelle, an der eine Patchabweichung
        # ein Urteil kippt. Sichtbar bleibt sie trotzdem.
        Write-Note "Node $haveNode statt $wantedNode aus .node-version - weiter, aber gemerkt"
    }

    # pnpm kommt aus `packageManager` und nicht aus winget: die Fassung steht im
    # Repo, corepack liefert genau sie.
    $packageManager = (Get-Content -LiteralPath (Join-Path $Path 'package.json') -Raw |
        ConvertFrom-Json).packageManager
    Write-Note "packageManager: $packageManager"
    Invoke-Checked 'corepack enable' 'corepack' @('enable') $Path
    Invoke-Checked 'corepack prepare' 'corepack' @('prepare', $packageManager, '--activate') $Path

    Invoke-Checked 'pnpm install' 'pnpm' @('install', '--frozen-lockfile') $Path
    # Der Rust-Wirt bettet `apps/desktop/dist` ein, das muss also VOR dem
    # cargo-Bau stehen (tauri.conf.json: frontendDist = ../dist).
    Invoke-Checked 'vite build' 'pnpm' @('--dir', 'apps/desktop', 'exec', 'vite', 'build') $Path

    Invoke-Checked 'cargo build (desktop)' 'cargo' @(
        'build', '--locked', '--release', '-p', 'ea-desktop', '--target', $RustTriple) $Path

    $desktopExe = Join-Path $env:CARGO_TARGET_DIR "$RustTriple\release\ea-desktop.exe"
    if (-not (Test-Path -LiteralPath $desktopExe)) { throw "cargo meldete Erfolg, aber $desktopExe fehlt" }

    Write-Step 'Einsatzarchiv-Fenster starten'
    # OHNE --operator-config und --trust-anchor: die Schale oeffnet sich, zeigt
    # aber nur die Flaechen, die eine GEPRUEFTE Sitzung freischaltet. Ohne
    # bereitgestellte Operator-Identitaet ist das die leere Schale. Das ist der
    # ehrliche Stand und kein Fehler des Baus.
    Write-Note 'ohne Operator-Konfiguration: die Schale oeffnet leer'
    Start-Process -FilePath $desktopExe
}

# -------------------------------------------------------------- smoke start

# Das gebaute Programm einmal wirklich starten. Ohne Argumente schreibt es
# seine Kommandouebersicht und endet mit Code 2 - das ist ein NUTZUNGSFEHLER und
# fuer diesen Aufruf der richtige Ausgang, kein Defekt.
#
# Eine fruehere Fassung dieses Kommentars nannte Code 0 „gemessen". Die Messung
# war falsch: sie lief durch eine Pipe, und gemessen wurde der Exitcode des
# nachgeschalteten `head`, nicht der des Programms. Ohne Pipe liefert es auf
# macOS wie auf Windows 2.
#
# Deshalb wird hier nicht auf Code 0 geprueft, sondern auf genau 2 UND auf die
# Kommandouebersicht in der Ausgabe. Ein Absturz oder ein fehlendes Laufzeit-DLL
# endet mit einem anderen Code oder ohne diese Zeile und faellt damit weiter auf.
Write-Step 'Einsatzarchiv starten'
Write-Note "$parentExe"
$usage = & $parentExe 2>&1 | Out-String
$usageCode = $LASTEXITCODE
Write-Host $usage.TrimEnd()
if ($usageCode -ne 2 -or $usage -notmatch '(?m)^einsatzarchiv --trust-anchor ') {
    throw "einsatzarchiv lieferte Code $usageCode statt der Kommandouebersicht mit Code 2"
}
Write-Note 'Kommandouebersicht mit Code 2 - das Programm laeuft'

# ------------------------------------------------------------------ summary

Write-Step 'Fertig'
Write-Host "  Parent : $parentExe"
Write-Host "  Helfer : $helperExe"
if ($packaged) { Write-Host "  Paket  : $packaged" }
if ($desktopExe) { Write-Host "  Fenster: $desktopExe" }
if ($InstalledBundle) { Write-Host "  Install: $InstalledBundle" }

if ($SelfSignedCert) {
    Write-Step 'Was diese Kette traegt - und was nicht'
    Write-Host @"
Signiert und installiert mit einem SELBSTSIGNIERTEN Zertifikat:

   Thumbprint : $($SigningCertificate.Thumbprint)
   DER-Pin    : $SigningPin
   verankert  : LocalMachine\Root und LocalMachine\TrustedPublisher
   Installation: $InstalledBundle

Das gilt NUR auf diesem Rechner und nur, solange dieses Zertifikat im
Wurzelspeicher liegt. Es traegt keine Verteilung an Dritte: wer das Bundle
woanders hinkopiert, hat dort eine Signatur ohne Anker. Ohne Zeitstempel
endet die Gueltigkeit ausserdem mit dem Zertifikat.

Die native Anmeldung kann dieser Lauf NICHT vorfuehren - sie verlangt ein
nicht erhoehtes, interaktives Konto. Dafuer in einem NORMALEN Terminal
(ohne Administratorrechte):

   & "$InstalledBundle\einsatzarchiv.exe"

Die Organisationszeremonie bleibt davon unberuehrt - Root, Trust Anchor,
Registry, Operator-Bereitstellung. Siehe docs/operator-ceremony.md.

Aufraeumen (keine Automatik, damit nichts unbemerkt verschwindet):
Ablage- und Installationsverzeichnisse unter $ReleaseRoot tragen je eine
Laufkennung und bleiben stehen. Zertifikat zurueckziehen hiesse: aus
Cert:\CurrentUser\My, Cert:\LocalMachine\Root und
Cert:\LocalMachine\TrustedPublisher entfernen.
"@
}
else {
    Write-Step 'Was jetzt noch fehlt'
    Write-Host @"
Signieren (Sign-Release.ps1) braucht ein Code-Signing-Zertifikat mit privatem
Schluessel in Cert:\CurrentUser\My, EKU 1.3.6.1.5.5.7.3.3. Fuer eigene,
kontrollierte Rechner erzeugt und verankert -SelfSignedCert genau so eines
und laeuft die Kette bis zur Installation durch (erhoehtes Terminal noetig):

   pwsh -NoProfile -File "$PSCommandPath" -SelfSignedCert

Fuer eine Auslieferung an Dritte fuehrt daran kein Weg vorbei: ein Zertifikat
einer oeffentlichen CA, danach dieselben Skripte mit dessen Thumbprint:

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
}
