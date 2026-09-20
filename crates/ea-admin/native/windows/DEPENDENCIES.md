# Windows helper dependency review

Scope: helper subtree only; no Rust/Cargo or parent manifest changes. This is a
bounded dependency/use review, not an independent audit of NSec or libsodium.

| Dependency | Resolution/use | License |
|---|---|---|
| NSec.Cryptography | exact `[26.4.0]`, Ed25519 seed import/public derivation/sign only | MIT, bundled notice |
| libsodium | transitive 1.0.22, pinned by both packages.lock.json files with SHA-512 package content hashes | ISC, bundled notice |
| Microsoft.Windows.SDK.NET.Ref | exact SDK projection 10.0.22000.57, Hello desktop interop/WinRT runtime | Microsoft package terms |
| .NET 10 SDK/runtime | cross-build SDK pinned to band 10.0.1xx (`global.json`: 10.0.112, `rollForward: latestPatch`), installed isolated; release uses currently serviced target .NET 10 runtime | .NET/Microsoft distribution terms |
| Visual C++ Redistributable | matching x64 or ARM64 native runtime required by libsodium; externally reviewed hash/signature required by packaging | Microsoft redistribution terms |

Microsoft's [Windows native Composite ML-DSA notice](https://learn.microsoft.com/en-us/dotnet/core/compatibility/cryptography/11/compositemldsa-windows-native)
states that Windows does not support EdDSA. Therefore OS protection wraps a
software Ed25519 key in this helper; there is no claim of CNG/TPM-backed Ed25519.
NSec's [installation documentation](https://nsec.rocks/docs/install) specifies
26.4.0, Windows x64/x86/ARM64 assets and the VC++ prerequisite, including clean
machines on which a .NET runtime alone is insufficient. The product deliberately
ships x64/ARM64 only, matching the reviewed 64-bit WTS structure layout.

Private seeds are generated as fresh 32-byte CSPRNG values, imported as
`RawPrivateKey` with default private export disabled, used for Ed25519, disposed
and cleared. Only public keys and signatures leave the helper for signing slots.
RFC8032 test vector 1 checks both public derivation and deterministic signature.
AES-GCM wrapping is .NET cryptography; DPAPI adds OS account protection. No
custom Ed25519, fallback curve, credential-password input or external signing
service is used. NSec's [API reference](https://nsec.rocks/docs/api/nsec.cryptography)
and [project source](https://github.com/ektrah/nsec) are primary implementation
references; [libsodium source](https://github.com/jedisct1/libsodium) is the native
transitive dependency. Installed package nuspec/license files were read to verify
the recorded resolution and MIT/ISC licenses.

`packages.lock.json` pins exact package content and must be used with locked
restore in release builds. The SDK projection is separately pinned because it
is an implicit framework reference. Restore enables transitive NuGet auditing;
release CI must retain current audit evidence and independently review updates.
The shipped helper, NSec, libsodium, WinRT assemblies, runtimeconfig and deps file
form one integrity boundary: install in a protected signed bundle; an attacker
who can replace those files can replace the signing implementation.

The helper's Win32 P/Invokes resolve from System32. The external VC++ binary is
not vendored or executed in this worktree; Package.ps1 accepts only a supplied
hash-matching Microsoft-signed artifact and creates a package hash inventory.
Clean-machine runtime and installer/Authenticode acceptance are separate from
successful cross compilation. See [Microsoft VC runtime distribution](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist).

Native security semantics are grounded in Microsoft's
[CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata),
[CREDENTIAL persistence](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw),
[WTSINFOEX lock fields](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wtsinfoex_level1_w),
and [GetProfileType](https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-getprofiletype)
documentation. User DPAPI can roam with a roaming profile, which is why it is
combined with local-profile rejection, a fixed nonroaming excluded marker and
local-only Credential Manager persistence. This still does not defeat privileged
copying/full-device rollback; README records the exact backup limitations.
