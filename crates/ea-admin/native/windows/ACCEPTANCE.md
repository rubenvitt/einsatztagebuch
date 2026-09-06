# DRK-271 Windows helper verification — 2026-09-06

Updated for review WIN-01, `private-console-line`, challenged persistent `watch-session`,
and explicit release-signing/protected-installation/known-restore tooling
with newline request / retained stdin framing. Earlier review fingerprints/counts
describe the pre-follow-up source; the hashes below identify this follow-up.

Scope: NEW `crates/ea-admin/native/windows/**` only. No changes to other agents'
source, Rust manifests, root manifests, CI or parent bridge; no commits.

## Measured on this host

Host: macOS ARM64. SDK: official .NET **10.0.100**, downloaded using Microsoft's
installer into `/private/tmp/drk271-dotnet`, with CLI home and NuGet cache also
isolated under `/private/tmp`. No global SDK/package installation. SDK/NuGet
network access was approved by the execution approval review.

| Check | Observed result |
|---|---|
| Initial `dotnet build ... -r win-x64` | exit 0, 0 warnings, 0 errors |
| `dotnet build ... -r win-arm64` | exit 0, 0 warnings, 0 errors |
| Final `dotnet publish ... -r win-x64 --self-contained false --no-restore -p:UseSharedCompilation=false` | exit 0 |
| Final corresponding ARM64 publish | exit 0 |
| Original helper locked restore, transitive audit enabled (dependency pins unchanged in follow-up) | exit 0, no dependency/audit warning emitted |
| `dotnet run --project tests/ProtocolTests.csproj --no-restore -p:UseSharedCompilation=false` | exit 0; **164 checks passed** |
| `python3 tests/process_protocol.py <isolated-dotnet> <ARM64-publish-dll>` | exit 0; **36 real-process checks passed** |
| `dotnet build tests/NativeReadOnly/NativeReadOnly.csproj -c Release -r win-x64 --no-restore -p:UseSharedCompilation=false` | exit 0, 0 warnings, 0 errors; actual native account regression **compiled only** |
| Corresponding native-read-only ARM64 build | exit 0, 0 warnings, 0 errors; **compiled only** |
| Native-read-only restore/audit using isolated paths | initial restricted-network NU1900 failure; approved network retry exit 0, no warning |
| Published package inventory | all 8 required executable/config/library assets present for both RIDs |
| `file` on apphosts | PE32+ console x86-64 and PE32+ console Aarch64, both Windows executables |
| Source whitespace inspection | passed |
| `pwsh -NoLogo -NoProfile -NonInteractive -File tests/release_manifest.ps1` | exit 0; **128 release-manifest checks** on this macOS host |
| `pwsh -NoLogo -NoProfile -NonInteractive -File tests/management_fixtures.ps1` | exit 0; **42 management fixture checks** on this macOS host |
| Embedded release security and restore transport C# (`Add-Type`) | compiled successfully under PowerShell 7.6.5; no native methods invoked |

PowerShell **7.6.5 macOS ARM64** was unpacked only under
`/private/tmp/drk271-powershell-7.6.5`, with state/cache variables also redirected
to temporary directories. The official release archive SHA-256
`8196d4b4e7c21b7f6df9d45687bb4e42dc8335f330b580d9eb15f3ef5042a8c3`
matched Microsoft's published checksum. No package/trust installation occurred.
[Official archive installation instructions](https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-macos?view=powershell-7.5),
[official v7.6.5 assets and checksums](https://github.com/PowerShell/PowerShell/releases/tag/v7.6.5).

The release fixtures exercise the closed seven-field/nine-asset manifest,
actual file hashes, missing/extra/directory inputs, exact-case architecture,
wrong scalar/array types, unsafe PSD1 expressions, invalid UTF-8, byte limits,
bounded PE machine reads, trusted owner/null-DACL/effective write-mask policy,
and parsing every management script. Management fixtures compile both embedded
C# modules and exercise the actual strict restore-response parser against binary
SID components, pin mismatches, malformed/duplicate/extra fields and wrong types.
They also check the shared authenticated-byte bootstrap ordering. Two negative
entrypoint guards run only on non-Windows hosts; Windows therefore runs **40**
management checks, with no native/signing/state methods invoked. This is an
expected conditional count, not Windows runtime evidence.

The parent-owned CI step now invokes `./tests/release_manifest.ps1` and then
`./tests/management_fixtures.ps1` separately with `$ErrorActionPreference = 'Stop'`.
The earlier nested invocation was removed to avoid running management fixtures
twice. PowerShell Core 7.4+ is required; the current workflow uses `shell: pwsh`.
No CI edit was made here.

The 164 checks exercise the **actual production** protocol, Unicode input-state,
watch framing/lifetime and crypto source,
including closed/duplicate-key grammar, field/slot/kind/presence policy,
installation pin requirements, secret length/hex, bounded stream sizes, RFC8032
public/signature vector, envelope integrity, wrong marker key, **public ID cannot
decrypt**, swapped installation/slot/public metadata, closed secret response,
and request-secret disposal. Added checks cover the documented Known Folder
access mask, fixed `prompt` labels/literal `extern-geprueft`, strict integer/byte/
time bounds, Unicode surrogate/backspace/repeat/control behavior, closed escaped
line output and buffer clearing. Chunked still-open streams exercise the exact
watch parser: newline dispatch while stdin remains open, ordinary requests still
waiting for EOF, no second input, and both closed newline output schemas. Fixed
300000 ms expiry and terminal latching are checked without sleeping five minutes;
documented WTS transition and native console/pipe ABI layouts are also checked.
The challenge extension adds bounded/fragmented 1024-byte frames, exact ACKs,
unknown/duplicate/escaped/invalid fields, queued/reused nonces, bounded replay
history, and a terminal observed coverage gap over 1000 ms. The 300s lifetime is
never renewed by challenges. These tests exercise production framing/lifetime
code; no simulated production provider or independently responding ACK thread exists.
They use real NSec/libsodium and .NET AES-GCM, not a
fake cryptographic provider. They do not invoke a native OS store/session API.

The 36 process tests start the compiled production helper DLL under the matching
ARM64 .NET runtime, use anonymous subprocess pipes, and verify bounded stdout,
empty stderr, exact stable error object and exit 1. Malformed/incomplete requests
terminate before the native account/store code. One valid watch
request runs **only on non-Windows hosts** to prove it dispatches with stdin held
open: it receives the helper's `platform-unavailable` guard response within the
3-second probe bound. An ordinary valid JSON line with stdin retained still hits
the existing 10-second `io-failed` framing deadline. They are evidence
for process/protocol behavior on macOS, **not Windows native execution**.

### Negative evidence retained

- WIN-01's explicit token mask regression first failed with QUERY-only (`0x8`),
  exit 134 and the assertion requiring QUERY/IMPERSONATE/DUPLICATE. After using
  `0x000e` in the actual token-open path, the portable suite passed. The native
  read-only regression links that **real** constructor and compares its binary
  SID to `WindowsIdentity.GetCurrent()` and Known Folder path to the OS local
  application-data folder, then rechecks the account. It neither mocks the API
  nor touches a marker/credential, but has **not run on Windows**. No HRESULT or
  universal old-mask failure is claimed.
  [Microsoft token contract](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath).
- Each new console/watch operation had a positive parser regression fail before
  implementation (exit 134); both now pass with closed operation-specific fields.
- The stopped-watch coverage regression first failed (exit 134): the old
  lifetime code accepted a 1001 ms observation gap. It now refuses that gap and
  every later observation. The native STA loop drains/rechecks before ACKs and
  cannot acknowledge from a separate reader thread. Real Windows subscriber
  suspension/blocked-native-call behavior still requires runtime acceptance.
- The missing-EOF test first failed: the child remained blocked after 13 seconds.
  A cancellation token alone did not cancel the in-flight console read. After
  bounding the wait itself with `WaitAsync`, the same test passed with the
  10-second input deadline and exact `io-failed` error. This is a measured
  RED → GREEN regression witness, not an assumed timeout.
- Attempting to load the x64 Windows DLL under ARM64 .NET initially failed before
  Main with an architecture mismatch. Using the architecture-matching ARM64
  assembly fixed the test setup; it did not establish native Windows acceptance.
- The first SDK invocation printed a development-certificate initialization
  message and a CSSM error despite `DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1`. Successful
  Keychain modification was **not established** and is not claimed absent merely
  from this output. Subsequent commands explicitly set
  `DOTNET_GENERATE_ASPNET_CERTIFICATE=false`. No helper initialization, OS account
  store tests, Windows registry writes or VC++ installer were executed here.

### Published artifact hashes

Artifacts are build outputs ignored by Git under
`bin/Release/net10.0-windows10.0.22000.0/<RID>/publish/`.

| RID / file | SHA-256 |
|---|---|
| x64 / ea-native-operator.exe | `40865eaa1fa4684764794b5264bbf9b361db01ecfb96655b925c1e6ee9f1e445` |
| x64 / ea-native-operator.dll | `ef649b94358ba6183b0984298d038135833adca4b52d8e896e7394decdc3897b` |
| ARM64 / ea-native-operator.exe | `8a4699bd39f91bfbdb51a69c2ad9955e40777a587ef9f7670e36369bffc8feab` |
| ARM64 / ea-native-operator.dll | `d30ae590e9bfdc7febccd514cdbb6f607845adb12848eedd5c713df97c091f36` |
| both / NSec.Cryptography.dll | `e13a3f375f153c48a8220c29dd83827462a80099537c9e43b10d9aaad2176d6b` |
| x64 / libsodium.dll | `64a1f143868309069f0a0a3c8141c0853c4f17243ddf734e92b11c5411739771` |
| ARM64 / libsodium.dll | `1616d5625f8721c9914ee7276f3ce63bc873eab530dfcf04e8c4184e2e77052c` |

## Native/release acceptance still required

No Windows execution environment was available. Actual TokenUser/account
cross-checks, pipe peer APIs with the Rust parent, owner-window Hello,
DPAPI/Credential Manager roundtrip, directory ACL behavior, WTS lock/notification
races and real backup/restores are **compiled, not runtime-accepted**. The
new console handle/mode/event behavior, finally restoration, native Known Folder
positive path, WTS watcher readiness/quick-transition latching, read-only marker
sharing, filesystem notifications, `NtQueryInformationFile` stdout state/quota,
EOF/reader-loss/parent-death cleanup, challenge ACKs after actual event draining,
real subscriber stalls over 1s, and actual 300s watch expiry also need Windows
runtime evidence on both architectures. Portable logic tests do not establish
those native API behaviors. PowerShell **fixtures were executed**; production
signing, protected installation, backup policy and known-restore entrypoints were
not executed on Windows. No Microsoft VC++ redistributable was supplied, copied into a release
package or installed; Package.ps1 requires its reviewed signature/hash. The
published apphost bundle still needs a serviced .NET 10 runtime and matching
VC++ runtime on the target, a real release signature, and native installer/restore
validation. The implementation now includes explicit signer/installer/restore
entrypoints; their Windows behavior remains an acceptance gate.

The independent review was read and WIN-01's concrete access-mask issue fixed.
No new independent re-review or Rust integration gate is claimed for this
follow-up. The parent owns full-project checks, WIN-02 inherited environment,
WIN-03 total IPC timeout, and the pre-secret release trust verifier. The new
[release/restore runbook](RELEASE-TRUST.md) distinguishes system-protected code
installation, validated publisher/role/digests, the signed apphost and **all** its
managed/native/config dependencies. No signing credential, VC++ installer,
Windows account/store mutation or trust-store change was performed by this
follow-up. Publishing here does not create a signed release package. In particular,
no valid/wrong-publisher certificate, actual file ACL, reparse/share-mode race,
positive signed-bundle launch, Hello reset or real restore experiment was exercised.

## Security semantics to coordinate with the parent

1. `installation_id` is a **public, independent random32**. A separate random32
   wrapping key remains solely in the user-DPAPI-protected excluded marker.
   Native credential names use a derived HMAC namespace tag, not either raw
   marker value. Every slot operation checks the expected public ID before
   credential/presence access, and every success echoes it. Initial bootstrap
   `account`/`initialize` cannot require a value the parent has not yet learned.
2. Ciphertexts require both the secret marker key and current-user native
   protection. Knowing the public ID or restoring Credential Manager without
   the marker cannot restore signing. Missing/invalid markers never enumerate
   old slots. Explicit initialize is the only creation path; explicit
   authenticated reset invalidates the current namespace.
   `Reset-KnownRestore.ps1` verifies the installed release, actual unelevated
   affected account and known public pin, checks a pinned account response and
   invokes only fresh-presence native reset. Missing/unreadable markers or denied
   presence fail without filesystem fallback. It does not enumerate/delete slots,
   provision replacement credentials or implement stopped-context repair.
3. Actual registry exclusion configuration is checked on every operation.
   **It is not universal backup enforcement.** Microsoft documents exceptions
   for System Restore/System State Backup, best-effort VSS exclusions, and
   restores that do not update `LastRestoreId`. Full same-device rollback of
   marker, DPAPI/store and restore indicators remains possible; §6.8's absolute
   no-restore requirement is **not met by a proof**. Sources and exact limits:
   [Windows backup registry](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore),
   [VSS exclusions](https://learn.microsoft.com/en-us/windows/win32/vss/excluding-files-from-shadow-copies).
4. `watch-session` is a real separate WTS listener with public pin, not repeated
   one-shot queries. Send its request newline and retain stdin as a lifetime
   guard. WTS registration and marker observation precede `ready`; subsequently
   one exact fresh challenge frame (at most 1024 bytes) is permitted at a time.
   Only the native event loop returns the exact pinned challenge ACK after fresh
   native checks. EOF, malformed/queued/reused challenges, observed coverage gap
   over 1000 ms, lock/session/account/marker change, observation error or fixed 300s
   expiry ends it permanently. The secret marker key and exclusive installation
   gate are released before ready. The parent must await ready before account/
   presence, require an exact fresh ACK within 1s before **and after** sensitive
   calls, latch all invalidations/exits, never restart within that provider,
   terminate/reap on disposal, and maintain the inactivity/session policy.
5. `private-console-line` uses JSON field **`prompt`** for the four fixed labels,
   plus `max_bytes`, `timeout_ms` and public pin, with ordinary EOF framing.
   Only `line` is returned on checked IPC; no entered line or marker wrapping key
   goes to console output/errors/logs. The parent adapter owns `Zeroizing<String>`
   and exact `extern-geprueft` comparison. Finally restores and verifies console
   mode on normal managed completion/failure; forced process kill cannot promise
   finally, so parent cleanup needs target validation. The parent total process
   limit is the requested native input timeout **plus 30000 ms** for startup,
   finally and pipe disposal, before last-resort kill. This does not extend the
   native 1–300000 ms input budget or provider/runtime 300s validity; stale
   successes remain denied, and forced-kill cleanup is not guaranteed.
6. The parent owns external identity proof, revocation/reprovisioning after loss
   or restore, audit, signed fixed-bundle validation, private anonymous-pipe
   creation/handle inheritance, total IPC timeout and uncertain mutation
   reconciliation. The helper does not grant archive roles from slot names.

See [README](README.md) for protocol, native design and restore limitations and
[dependency review](DEPENDENCIES.md) for primary sources, pins, licensing and
VC++ packaging prerequisites.
