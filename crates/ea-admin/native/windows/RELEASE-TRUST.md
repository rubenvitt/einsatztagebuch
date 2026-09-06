# Windows release installation and known restore

The Windows subtree now supplies explicit signing, fresh protected installation
and affected-account restore entrypoints. The parent owns Rust release identity,
launch environment, pipe creation and process/session deadlines. **No release was
signed or installed on the development host; native Windows acceptance remains
open on both architectures.** See [ACCEPTANCE.md](ACCEPTANCE.md) for measured
fixture/compile evidence.

## Closed release contract

The current [parent verifier](../../src/native_identity.rs) requires the fixed
sibling manifest `ea-native-operator.release.psd1`. Its exact seven fields are Schema
(integer 1), Product `org.einsatzarchiv`, ParentRole `org.einsatzarchiv.cli`,
HelperRole `org.einsatzarchiv.operator.native`, Version equal to the parent
Cargo package version (currently `0.1.0`), Architecture `win-x64` or `win-arm64`,
and Assets. Assets contains exactly nine lowercase SHA-256 digests:

- `einsatzarchiv.exe`
- `ea-native-operator.exe`
- `ea-native-operator.dll`
- `ea-native-operator.deps.json`
- `ea-native-operator.runtimeconfig.json`
- `NSec.Cryptography.dll`
- `libsodium.dll`
- `WinRT.Runtime.dll`
- `Microsoft.Windows.SDK.NET.dll`

The installed directory is exactly these nine assets plus the signed manifest:
**ten regular files, no subdirectories or extras**. Parent, apphost and manifest
must have OS-verified valid Authenticode signatures with the **same exact DER
signing certificate**. PE machine types must match the selected architecture.
The signed manifest binds third-party DLLs and runtime configuration without
replacing third-party signatures. An unsigned hash inventory or matching
publisher display name does not establish this contract.

## Explicit release production

Run the following only on the trusted Windows release workstation with reviewed
inputs and PowerShell Core **7.4 or newer**. Supply an existing, currently valid
code-signing certificate explicitly; no certificate/key is created, imported,
selected by default or silently trusted. The version must match the actual Rust
parent build. These are deployment instructions, not commands executed here.

```powershell
rtk proxy pwsh -NoLogo -NoProfile -NonInteractive -File scripts/Package.ps1 -Runtime win-x64 -VCRedistPath $ReviewedX64Redist -VCRedistSha256 $ReviewedRedistHash
rtk proxy pwsh -NoLogo -NoProfile -NonInteractive -File scripts/Sign-Release.ps1 -ParentBinary $ReviewedParent -HelperPackage artifacts/win-x64 -Destination $FreshBundle -ManagementDestination $FreshManagementKit -Architecture win-x64 -Version 0.1.0 -CertificateThumbprint $ExplicitReleaseThumbprint
```

Repeat with the matching parent/helper/redistributable and `win-arm64`.
`Package.ps1` is **unsigned staging**. Its docs, licenses, VC++ redistributable,
lock file, management source and SHA256SUMS remain outside the installed bundle.
`Sign-Release.ps1` copies inputs to fresh destinations, signs parent/apphost,
then creates/signs the manifest over final asset bytes and verifies the result.
Optional `-TimestampServer` is an explicitly supplied HTTP(S) service and requires
a verified timestamp result. Without a timestamp, there is no claim that the
signature remains usable after certificate expiry.

The separate eight-file management kit contains three modules, the installer,
known-restore and backup-policy scripts, a signed
`ea-native-management.release.psd1`, and a public DER `release-signer.cer`.
Its closed manifest binds six script/module digests, version, architecture and
role `org.einsatzarchiv.operator.management`. Each script/module is also
release-signed. The signer prints the **public DER SHA-256 pin** for distribution
through a trusted independent channel. Reading a pin from the same untrusted
download would not establish expected identity.

The deployment system must authenticate the entrypoint **before executing it**,
using its independently trusted release pin and trusted PowerShell installation.
Use a fresh no-profile process with a clean environment and the organization's
existing signature/execution policy. No entrypoint can authenticate malicious
code already substituted before it starts; these scripts do not modify policy
or certificate trust. Their internal checks require valid OS signatures plus
the supplied certificate pin, verify the closed management manifest and all
hashes, then import the **same verified module bytes**. PSD1 is parsed as a
literal hashtable using `Ast.SafeGetValue`, never executed.
[Authenticode verification, including byte content and the pre-7.4 encoding limit](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature?view=powershell-7.5),
[signing and timestamps](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature?view=powershell-7.5),
[constant-only AST evaluation](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.language.ast.safegetvalue?view=powershellsdk-7.4.0).

## Fresh protected installation

The release deployment system must first stage the signed bundle in a **protected
local source tree**, and supply an existing protected destination parent. The
installer verifies actual ownership/DACLs of source assets and every ancestor,
so an ordinary Downloads/profile staging directory does not qualify. Path
spelling alone is insufficient. Existing source protection and a trusted
management entrypoint are explicit prerequisites, not flags asserted by this tool.

From the authenticated management kit, as the elevated deployment administrator:

```powershell
rtk proxy pwsh -NoLogo -NoProfile -NonInteractive -File Install-Release.ps1 -Bundle $ProtectedStagedBundle -Destination $FreshProtectedDestination -Architecture win-x64 -Version 0.1.0 -ExpectedCertificateSha256 $TrustedReleaseDerHash
```

The native installation module accepts only local fixed volumes with persistent
ACLs. It opens all path components without following reparse points, rejects
subdirectories/extra files and multiple hard links, and holds read handles
denying writes/deletes through verification/copy/reverification. Non-root
ancestor handles also deny write/delete opens. Sharing flags alone do not
prevent attribute/security changes; the installer separately requires protected
owners and effective DACLs before the Authenticode path checks.

Trusted owners/writers are SYSTEM, Administrators and TrustedInstaller. Null
DACLs, unprivileged effective write/delete/WRITE_DAC/WRITE_OWNER permissions and
reparse points fail closed. The same `0x500D0156` write mask and volume-root
create-unrelated-children exception as the parent are applied. It verifies all
three signers, exact DER, closed metadata, architecture and all asset hashes
**before copying** from the held streams.

`CreateDirectoryW` and `CreateFileW(CREATE_NEW)` receive the final protected
security descriptors atomically: owner Administrators, SYSTEM/Administrators
full control, Builtin Users read/execute, protected DACL. It then reopens and
reverifies the entire target including effective ACLs. No existing installation
is overwritten, permissions repaired in place, or existing data deleted.
Incomplete fresh output is retained and rejected by the closed parent gate;
there is no automatic recursive cleanup or update/rollback mechanism.
[Directory security attributes and persistent-ACL requirement](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw),
[file creation, reparse handling and sharing limits](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).

Target deployment must separately provide the serviced matching .NET 10 and
Microsoft VC++ runtimes and explicitly run the authenticated
`Configure-BackupPolicy.ps1` for the actual account's fixed marker directory.
The installer does not execute a redistributable, install PowerShell, alter the
trust store or create account credentials. Runtime servicing and the parent's
sanitized launch environment remain part of release acceptance.
[.NET runtime environment inputs](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-environment-variables).

## Supported known-restore path

A known restore requires external revocation/reprovisioning policy. Close the
affected account's app/providers and quarantine use of its old binding. Under
the **actual unelevated, interactive affected account**, run the authenticated
management kit with its expected account SID and known **public** installation
pin. Neither parameter selects a profile path or another account to impersonate.

```powershell
rtk proxy pwsh -NoLogo -NoProfile -NonInteractive -File Reset-KnownRestore.ps1 -InstalledBundle $VerifiedInstalledBundle -ExpectedAccountSid $AffectedSid -ExpectedInstallationId $AffectedPublicInstallationId -Architecture win-x64 -Version 0.1.0 -ExpectedCertificateSha256 $TrustedReleaseDerHash
```

The script verifies the protected installed bundle before launch. It keeps all
files pinned, starts only its fixed verified helper apphost with private
redirected pipes and a cleared environment, and checks the actual child image
before sending IPC. The actual Windows identity must match the expected SID and
must not be elevated. A pinned native `account` response must have the exact
binary SID, actual authority/subauthorities and unlocked state.

It then calls only `reset` with the same pin and `presence:true`.
The existing helper requires **fresh owner-window/current-account Windows Hello**,
rechecks native session/account/marker state, invalidates that installation
marker and acknowledges the old ID. Both ordinary requests use EOF framing;
each has a single 60-second transport deadline covering launch/write/read/exit
(the helper's Hello budget is 45 seconds). Response schemas, byte limits,
installation pin, stderr and exit status are strict. Timeout or uncertain
completion fails without retry or automatic repair.

This invalidates **only the currently accessible marker of that account**. It
does not enumerate/delete Credential Manager slots, create credentials, initialize
a replacement marker, erase archive data, select a different user's profile or
fall back to file deletion if presence is denied. Other-account/elevated/SYSTEM
use, wrong pins, missing/unreadable markers, unavailable presence or missing
backup policy fail closed. An unreadable marker is already unusable; this bounded
entrypoint does not provide a stopped-context repair procedure for it. New
provisioning still requires external identity verification, a new native instance
key, administrative authorization, a new binding and revocation of the old one.

## Security and acceptance limits

The **public random32 installation ID** and **independent secret random32 wrapping
key** persist together only in the account-DPAPI-protected excluded installation
marker. The wrapping key is never in IPC, IDs, logs, manifests or this management
kit. Credentials need both that secret and native account protection. Marker
absence/fresh initialization never enumerates the previous namespace.

Windows backup exclusions are real configured facilities, **not universal
anti-rollback enforcement**. System Restore/System State exceptions, best-effort
VSS exclusion and whole-volume restores without an updated LastRestoreId remain.
A full same-device rollback restoring marker, DPAPI/credential material and
restore indicators together can revive the old key. The explicit known-restore
reset prevents continued use of the current old namespace after that reset; it
does not revoke an already copied snapshot or detect an unknown full rollback.
**The absolute §6.8 no-restore claim is still unproven.**
[Microsoft backup/restore exclusions and LastRestoreId](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore),
[VSS exclusion limits](https://learn.microsoft.com/en-us/windows/win32/vss/excluding-files-from-shadow-copies).

Pure fixtures and cross-publish do not prove Windows signatures, ACL/share-mode
behavior, actual parent pipes, Hello/WTS, runtime loading or restore handling.
Required disposable-host QA includes positive signed installs and launches on
both RIDs; unsigned/wrong-DER/wrong-role/version/architecture bundles; each DLL
and runtime-JSON swap; writable/reparse/hard-link trees and copy/launch races;
known restore with fresh presence, denied presence and wrong account; and the
documented full-rollback limitation. No native acceptance or independent-review
closure is claimed by this document.
