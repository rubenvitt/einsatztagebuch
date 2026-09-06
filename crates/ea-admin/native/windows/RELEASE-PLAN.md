# Windows release completion implementation plan

**Goal:** Runnable explicit signing, protected fresh installation, and affected-account known-restore reset without changing parent/native runtime ownership.

**Architecture:** Pure closed-manifest validation is shared with temporary fixtures. Windows-only entrypoints verify OS Authenticode and exact DER publisher identity before importing management code, copying executable assets, or invoking native reset. No test/fake signer is selectable by production entrypoints.

**Spec:** Current `../../src/native_identity.rs` Windows release contract and design §6.8. User limits this plan and implementation to `native/windows/**`; no commits, system mutation, actual signing, or CI edits.

## Contract

- `ea-native-operator.release.psd1`; exactly Schema 1, Product `org.einsatzarchiv`, ParentRole `org.einsatzarchiv.cli`, HelperRole `org.einsatzarchiv.operator.native`, explicit matching Version (`0.1.0` currently), Architecture `win-x64` or `win-arm64`, Assets.
- Exact nine assets returned by `Get-EaReleaseAssets`; installed directory exactly ten regular files and no subdirectories. Docs, notices, management scripts and VC++ redist stay outside.
- Parent/apphost/manifest use the same verified DER certificate. Bundle handles deny writes/deletes during verification/copy; protected target ACLs admit writes only to SYSTEM/Administrators/TrustedInstaller.
- Known restore uses existing native `reset` with `presence:true`, a required expected public installation pin, and actual current TokenUser SID equality. Never enumerate/delete slots, guess a profile path, or fall back to a file deletion after denied/unavailable presence.

## Steps

- [x] Extend `tests/release_manifest.ps1` with failing schema/hash/inventory/PE/ACL-policy probes and parse every management script. Run with temporary PowerShell and fixtures only.
- [x] Extend `scripts/ReleaseManifest.psm1` with `Assert-EaReleaseManifest`, strict inventory/hash snapshots and bounded PE checks. Add `scripts/ReleaseSecurity.psm1` for native Authenticode/DER, file locking, protected-tree validation and atomic protected-directory creation.
- [x] Finish `scripts/Sign-Release.ps1`: fresh exact bundle, explicit existing certificate, verify executables and signed manifest, separate fresh signed management kit; original inputs never signed in place.
- [x] Add `scripts/Install-Release.ps1`: release-signed entrypoint/module validation before import, verify bundle before copy, fresh destination under an already protected parent, copy from held source handles, reverify target/ACLs. No replacement/deletion/update of existing data.
- [x] Add `scripts/Reset-KnownRestore.ps1` plus bounded management transport: verify signed installed bundle and actual unelevated account SID, obtain pinned native account response, invoke native fresh-presence reset, require exact response/exit. No initialization or automatic retries.
- [x] Run fixtures, parser/compatibility probes and targeted negative entrypoint tests; update Package/docs/acceptance with commands, trust bootstrap, restore boundaries and exact measured versus unexecuted Windows behavior.

Implementation and fixture steps complete; actual Windows signing/install/restore and native runtime acceptance remain open in ACCEPTANCE.md.
