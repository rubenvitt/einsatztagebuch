# Windows native operator helper — DRK-271

This is the actual Windows `.NET` helper, built as `ea-native-operator.exe`.
It uses native TokenUser, Windows Hello desktop interop, user DPAPI, Windows
Credential Manager and WTS APIs. Ed25519 uses exact **NSec.Cryptography 26.4.0**;
there is no simulated production provider, CNG Ed25519 substitution or blanket
unsupported implementation. Windows 11/build 22000 or later, x64/ARM64, a loaded
local profile and the current unelevated Explorer account/session are required.

## Bridge contract

The operation/slot policy follows [the macOS contract](../macos/INTERFACE.md)
and [the parent bridge](../../src/native_provider.rs). Ordinary operations use one
UTF-8 JSON object on stdin, EOF required, at most 65,536 bytes, and one bounded
newline-terminated JSON object on stdout. `watch-session` alone uses one request
line with stdin retained open, followed by ready/challenge/terminal lines below.
No arguments, trailing JSON, duplicate/escaped-duplicate fields,
unknown fields, nested values, coercions, uppercase hex or arbitrary slot paths
are accepted. Input has a 10-second deadline; Hello has a 45-second deadline.
The parent must enforce an overall process/write deadline and terminate a stuck
child. Every native call requires local byte pipes with peer PIDs belonging to
the parent/helper and an actual same-account parent token. Windows anonymous
pipes use the named-pipe implementation internally; the parent remains responsible
for creating private anonymous pipes with restricted handle inheritance. Pipe
metadata alone cannot prove that no other process has a duplicated handle.

Success always includes `ok:true,installation_id:<64 lowercase hex>`. Error
responses contain **exactly** `ok:false,code:<stable string>`; no exception text,
HRESULT, OS account name, private seed, marker key or payload is included.
Success exits 0; errors exit 1, matching the macOS contract.
`account` returns `platform:"windows"`, binary `sid` in lowercase hex,
`identifier_authority` as the actual six SID bytes in hex, numeric unsigned
`subauthorities`, and conservative boolean `locked`. SID components come from
the same validated `GetTokenInformation(TokenUser)` buffer, never text parsing.

Initial `account` and explicit `initialize` may omit `installation_id` because
they establish the parent pin. Every slot operation and `reset` requires it;
every subsequent parent operation, including `account`, should send it. A
mismatch is rejected **before any slot read or mutation**, and success echoes
the validated value. A missing marker cannot be implicitly initialized by a
pinned request. The public identifier does not grant access to an old namespace.

| Operation | Policy/result |
|---|---|
| `account` | Read current installation/account; absent marker is `installation-missing`; presence rejected |
| `initialize` | Explicit creation only; fresh independent randomness; no old-slot lookup |
| `generate` | `kind:ed25519` or `secret32`, exclusive; returns public key or null |
| `public-key` | Public metadata or null; presence rejected; never decrypts private slot data |
| `contains` | Authenticated metadata boolean; presence rejected; no enumeration |
| `sign` | Ed25519 signature; `operator-instance`, admin, root and other nonwriter slots require fresh presence; writer can use false |
| `wrap-secret` | Exactly 32 bytes, exclusively in `database-key`/`draft-key`; no secret response |
| `unwrap-secret` | Only database/draft, returns 32 bytes on the checked private parent pipe |
| `delete` | One explicitly named slot, idempotent; no enumeration |
| `reset` | Fresh presence mandatory; invalidates marker; echoes invalidated installation ID; parent discards its provider |
| `private-console-line` | Fixed `prompt` label, bounded `max_bytes`/`timeout_ms`; reads the real console privately; returns `line` on IPC |
| `watch-session` | Required public installation pin; subscribe before `ready`; terminal `invalidated` event within fixed five-minute lifetime |

Slots use `[a-z0-9-]{1,64}` as on macOS. Only `operator-instance` permits
`replace:true`, with `kind:ed25519` and `presence:true`. Only database/draft are
`secret32`. Optional `kind` on existing-slot operations must match. A supplied
`presence:true` prompts freshly on permitted operations. All slot access requires
an unlocked current interactive account before and after the operation.

### Private console input

An ordinary EOF-framed request has **exactly** `op`, `installation_id`, `prompt`,
`max_bytes` (integer 1–4096, UTF-8 byte limit), and `timeout_ms` (integer
1–300000). `prompt` is a label, never free-form prompt text. Allowed values are
`external-identity-confirmation`, `authority-subject-id`, `display-name`, and
`function-label`. The confirmation prompt literally asks for `extern-geprueft`.
The parent compares that literal token and owns the external identity decision;
the helper does not infer authority from a line or normalize/trim its contents.

The native reader opens fixed `CONIN$` and `CONOUT$` handles, validates character
device type and both console modes, disables echo/cooked/processed/VT input and
Quick Edit, and reads bounded Unicode KEY_EVENT records with
`ReadConsoleInputExW(CONSOLE_READ_NOWAIT)`. It discards pre-prompt typeahead;
surrogate pairs and scalar backspace preserve the exact UTF-8 budget. Invalid
surrogates, control characters, overflow, Escape/Ctrl-C/Ctrl-Break/Ctrl-Z, mode
changes, account/marker changes and locks fail without a partial line. Polling
uses one monotonic deadline; key repeats do not extend it. The original input
mode is restored **and read back in finally** before response serialization.
No console allocation, redirected-stdin fallback, password collection, entered
text echo, or profile/credential persistence occurs. Success is exactly:

```json
{"ok":true,"installation_id":"<64 lowercase hex>","line":"<entered Unicode>"}
```

Owned input/event/output buffers are cleared. OS console buffers and .NET/OS
memory handling are not a secure-desktop boundary against another process under
this same account. Abrupt process termination does not execute managed `finally`;
the parent enforces **requested input timeout + 30000 ms** as its separate total
process limit (up to 330000 ms). The added allowance covers startup, console
finally and pipe disposal before last-resort termination; it neither renews the
native input deadline (1–300000 ms) nor extends the provider/runtime watch's
original 300s lifetime. Every stale success remains rejected. Console mode
recovery after abnormal stalls/forced termination still requires Windows QA;
there is no absolute finally/cleanup guarantee under a process kill. These APIs are
cross-compiled, not yet exercised on a Windows terminal/ConPTY host.
[Console handles](https://learn.microsoft.com/en-us/windows/console/console-handles),
[console modes](https://learn.microsoft.com/en-us/windows/console/setconsolemode),
[Unicode key events](https://learn.microsoft.com/en-us/windows/console/key-event-record-str),
[nonblocking console event read](https://learn.microsoft.com/en-us/windows/console/readconsoleinputex).

### Persistent session watch

Write the following single JSON line, flush, and **keep stdin open**:

```json
{"op":"watch-session","installation_id":"<64 lowercase hex>"}
```

The request newline is mandatory (LF or CRLF); no timeout/presence/slot fields or
pre-ready additional input are accepted. Unlike ordinary operations, EOF is a disconnect.
The initial line must arrive within the normal 10-second input deadline. Native
platform/pipe/account/installation checks run first. The helper registers its
live WTS window **before** readiness, subscribes to marker/directory filesystem
changes, checks the expected public ID, and releases the installation gate and
zeroes the decrypted secret marker key. Only public context, protected-blob
hashes, read-only observations and native listener/process handles remain.

It then flushes exactly:

```json
{"ok":true,"installation_id":"<64 lowercase hex>","ready":true}
```

The same STA thread pumps WTS events every at most 50 ms of scheduled polling,
queries WTSINFOEX/Explorer/token state, and rechecks marker hash/ACL/path/backup
policy/restore context. Filesystem events (including error/overflow) and current
session transitions are latched, so observing a later unlocked session or the
original marker bytes cannot revive that watch. Read-only marker handles are
short-lived; normal helper calls remain serialized by `operation.lock` and are
not blocked by a five-minute exclusive marker/gate handle.

After ready the parent sends one outstanding fresh challenge line at a time:

```json
{"challenge":"<fresh 64 lowercase hex characters>"}
```

Only the **same native event loop** may answer, after draining WTS events and
fresh account/marker/pipe checks both before and after consuming the challenge:

```json
{"ok":true,"installation_id":"<same public pin>","challenge":"<same fresh challenge>"}
```

There is no ACK thread. A monotonic observed gap **over 1000 ms** between completed
native observations, a regressing clock, malformed/unknown/duplicate fields,
noncanonical nonce, a reused nonce, queued second frame, EOF, or a frame over
**1024 bytes including LF** irreversibly invalidates the watch. Partial frames
are bounded; reading input alone never renews coverage. Replay history is bounded
to 16384 distinct challenges; exhaustion also invalidates. Checks run again
immediately before ACK emission; a delayed native call/write still requires the
parent's independent deadline. Initial readiness does not authorize future calls
without a fresh challenge round trip.

A lock, logoff, connect/disconnect, account/session change, marker change, failed
observation/challenge/coverage check, or fixed **300000 ms** lifetime ends it with:

```json
{"ok":true,"installation_id":"<64 lowercase hex>","invalidated":true}
```

Neither challenge success nor activity resets the deadline. A held process handle detects original-parent death
without PID reuse; the open input pipe is checked for EOF and bounded challenge bytes.
The write-only stdout handle is queried with `NtQueryInformationFile` /
`FilePipeLocalInformation` for connected state and sufficient write quota, so
loss of the parent's reader ends the process without waiting for expiry. If a
terminal record cannot be written, the child exits 1. Before `ready`, ordinary
stable errors apply; after readiness only ACKs and one terminal invalidation are
permitted, never an ordinary error record.

The parent must retain one watcher child **and its stdin guard per provider**,
await `ready` before account/presence calls, and require a fresh nonce ACK within
**1 second before AND after every sensitive call**. Validate all closed schemas,
the pin and exact pending nonce; reject queued/replayed/unrequested ACKs and
permanently latch every invalidation, unexpected output, pipe error or
child exit. Never restart a watcher inside an existing provider. It still owns
its overall process deadline, provider disposal/reaping and application inactivity
timer; native blocking/scheduling can exceed a polling interval. This is not a
proof against unreported privileged full-system rollback while the watcher is
absent. WTS and Windows pipe/filesystem behavior require target runtime acceptance.
[WTS session messages](https://learn.microsoft.com/en-us/windows/win32/termserv/wm-wtssession-change),
[PeekNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-peeknamedpipe),
[local pipe state](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_pipe_local_information).

## Marker and key security semantics

`SHGetKnownFolderPath(FOLDERID_LocalAppData, currentToken)` determines the fixed
`Einsatzarchiv\NativeOperator-v1\marker.bin` path; it is not taken from an
environment variable, profile field or caller path. Temporary, roaming and
mandatory profiles, nonfixed volumes and reparse paths are rejected. The marker
directory has a protected owner/SYSTEM-only DACL, checked on access. An exclusive
file handle serializes operations; the opened marker is held and rechecked.
The explicit Known Folder token is opened with `TOKEN_QUERY |
TOKEN_IMPERSONATE | TOKEN_DUPLICATE` (`0x000e`); the native output allocation is
freed on success and failure. Unrelated token reads retain query-only access.
This corrects review WIN-01's insufficient explicit-token mask.
[Microsoft's explicit-token contract](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath).

The marker's **user-DPAPI-protected** payload is exactly:

```
version:u8(1) || installation_id:public_random32 || wrapping_key:secret_random32
```

The two 32-byte values are independent CSPRNG draws. The wrapping key is never
used as an identifier or exposed through IPC, metadata or logs. These two values
are persisted together only inside this protected, excluded marker. The
credential namespace is a domain-separated HMAC tag, so Credential Manager names
do not persist another copy of either marker value. DPAPI's
additional entropy binds the marker to the binary SID, machine GUID and observed
`LastRestoreId` state, under a domain label. These are context values, not secret
keys. Both DPAPI calls use `CRYPTPROTECT_UI_FORBIDDEN` and **never**
`CRYPTPROTECT_LOCAL_MACHINE`.

Private slot seed/secret32 → AES-256-GCM with the **secret marker key**, binding
public installation ID, slot, kind and public key as associated data → user DPAPI
→ `CredWriteW(CRED_TYPE_GENERIC, CRED_PERSIST_LOCAL_MACHINE)`. This last persistence
constant means subsequent logons of the **same user on this computer**, not
machine-wide DPAPI access. Enterprise/roaming persistence is never selected.
Authenticated public metadata can be checked without unprotecting a slot.
The native credential store holds only encrypted envelopes, never a plain key
file. Seed import into NSec disables private export. Temporary managed/native
buffers are zeroed where owned; .NET/OS paging, dump capture and a hostile process
already executing as this account are not eliminated by buffer clearing.

The helper never calls `CredEnumerate`. Missing markers cause no old-slot access.
Reinitialization creates an unrelated identifier and wrapping key. Old ciphertext
does not open with the new marker, even if an attacker knows both public IDs.
Malformed, wrong-account, changed-machine, changed-RestoreId or unexcluded markers
fail closed without trying older credentials. No automatic repair or fallback.

## Actual backup facilities and precise restore limits

An elevated **target installer**, not the helper, adds the literal marker-directory
entry to both HKLM `SYSTEM\CurrentControlSet\Control\BackupRestore` facilities
`FilesNotToBackup` and `FilesNotToSnapshot`, as REG_MULTI_SZ. The helper verifies
both exact entries using the 64-bit registry view before creation and every
operation, and again before returning results. Missing policy is
`backup-policy-required`. Archive/hidden flags and a custom `backup_enforced`
boolean are not used. [Configure-BackupPolicy.ps1](scripts/Configure-BackupPolicy.ps1)
performs the real registry writes and readback; it is **not run by builds/tests**.

This is verification of configured backup policy, **not proof that all backups
honor it**. Microsoft documents that Windows Server Backup/Wbadmin block restores
delete `FilesNotToBackup` entries on restore, while System Restore and System
State Backup do not honor that exclusion. `FilesNotToSnapshot` deletion is best
effort, has requester-specific limitations, and cannot exclude with VSS
auto-recovery disabled. See [Windows backup registry semantics](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
and [VSS exclusion semantics](https://learn.microsoft.com/en-us/windows/win32/vss/excluding-files-from-shadow-copies).

`LastRestoreId` changes invalidate the marker for reported system-state restores;
Microsoft explicitly says whole boot/system-volume restores do not set it.
A same-device snapshot/clone restoring the excluded marker, DPAPI material,
Credential Manager state, machine GUID and old restore indicator together can
revive the old key. An application-only restore retaining the marker is also not
detectable. Backup software/cloud tools that ignore exclusions, administrator
copies, VHD/profile-container clones and raw disk imaging remain outside this
policy guarantee. Local-profile checks do not attest absence of third-party sync.

**The absolute no-restore assertion in §6.8 is not proven.** This implementation
must not be represented as unconditional §6.8 acceptance. Deployment needs an
actual restore drill for its chosen backup facility and external revocation /
fresh provisioning after installation loss or a known restore. The explicit
[known-restore entrypoint](RELEASE-TRUST.md#supported-known-restore-path) verifies
the release bundle and affected account, then invokes pinned `reset` with fresh
native presence. It has no marker/file-deletion fallback on denied or unavailable
presence and does not repair unreadable markers. `reset` invalidates
the installation but is not physical SSD erasure and cannot revoke a previously
copied full snapshot. No hardware-backed Ed25519 or cryptographic anti-rollback
claim is made.

## Presence, lock and parent responsibilities

Hello uses the Windows SDK projection of
`IUserConsentVerifierInterop::RequestVerificationForWindowAsync` with a live
helper-owned top-level HWND. Current process token, session and Explorer owner
are cross-checked before/after; impersonated/elevated helper execution is rejected.
Only `UserConsentVerificationResult.Verified` succeeds. Cancellation, unavailable
hardware/policy and any nonverified result fail closed. OS credentials stay in
the OS-owned UI. [Microsoft desktop Hello API](https://learn.microsoft.com/en-us/windows/win32/api/userconsentverifierinterop/nf-userconsentverifierinterop-iuserconsentverifierinterop-requestverificationforwindowasync).

WTSINFOEX level/session/state is queried conservatively and a real window is
registered for WTS notifications. Lock, disconnect and logoff are latched during
the invocation, so a quick lock/unlock cannot resurrect its pending signature.
The separate persistent `watch-session` process covers **between invocations**
when the parent retains and observes it as specified above. The parent owns
provider and five-minute inactivity invalidation for long-lived sessions. Parent orchestration
also owns trust/revocation, audit, external identity proof, executable/bundle
signature validation, and overall IPC deadlines. Those files are outside this
helper's ownership. Side effects can have completed before a final lock/marker
recheck rejects the response; inspect state, do not blindly retry mutations.
Inherited .NET launch environment and total helper deadline fixes from review
WIN-02/WIN-03 belong to the parent. A helper's self-check cannot establish its
identity to the caller before secret IPC. See [release trust handoff](RELEASE-TRUST.md)
for the required signed installed-bundle validation boundary.

## Build, package and acceptance

All source/build artifacts are confined to this Windows subtree. Use an installed
or isolated .NET 10 SDK. Disable SDK first-run certificate generation explicitly:

```sh
rtk proxy env DOTNET_GENERATE_ASPNET_CERTIFICATE=false dotnet restore ea-native-operator.csproj --locked-mode
rtk proxy env DOTNET_GENERATE_ASPNET_CERTIFICATE=false dotnet build ea-native-operator.csproj -c Release -r win-x64 --no-restore -p:UseSharedCompilation=false
rtk proxy env DOTNET_GENERATE_ASPNET_CERTIFICATE=false dotnet build ea-native-operator.csproj -c Release -r win-arm64 --no-restore -p:UseSharedCompilation=false
rtk proxy env DOTNET_GENERATE_ASPNET_CERTIFICATE=false dotnet run --project tests/ProtocolTests.csproj --no-restore -p:UseSharedCompilation=false
rtk proxy python3 tests/process_protocol.py /path/to/dotnet bin/Release/net10.0-windows10.0.22000.0/win-arm64/ea-native-operator.dll
```

Restore `tests/ProtocolTests.csproj --locked-mode` once as well. Neither portable
test suite accesses native account, backup policy, marker, OS stores or Hello.
For process parser tests use the build architecture matching the test host's
runtime (ARM64 on the recorded Mac); the Windows API paths are never entered.
Cross compilation produces a Windows apphost `.exe` plus managed/native DLLs;
it does not execute Windows APIs and is not NativeAOT or a hardware key provider.
`tests/NativeReadOnly/NativeReadOnly.csproj` links the actual `NativeAccount` path:
on Windows it checks TokenUser against `WindowsIdentity.GetCurrent()`, calls the
real explicit-token Known Folder API and rechecks the account. It has no marker,
credential, backup-registry write or Hello calls. Build it with either RID and
run it under an unelevated local Windows account to complete WIN-01 runtime
acceptance. A non-Windows run reports NOT RUN and exits 2.

[Package.ps1](scripts/Package.ps1) requires a reviewed architecture-matching,
Microsoft-signed VC++ Redistributable plus its expected SHA-256. It checks the
signature/hash, locked restore, required DLLs and includes the redist, notices,
management source and unsigned hash inventory. It does not install prerequisites.
[Sign-Release.ps1](scripts/Sign-Release.ps1) produces a fresh ten-file signed
parent/helper bundle and a separate eight-file signed management kit, using only
an explicitly selected existing certificate. [Install-Release.ps1](scripts/Install-Release.ps1)
verifies the protected source bundle before copying to a fresh protected target,
then reverifies its signatures, exact DER publisher, closed manifest and ACLs.
Docs, licenses and redistributables stay outside that ten-file directory.
Target deployment separately supplies the VC++ runtime, a serviced .NET 10
runtime, PowerShell Core 7.4+ for the management tools, and the exact account backup
exclusion policy. See [release/restore commands and trust bootstrap](RELEASE-TRUST.md).
A framework-dependent publish
uses the target runtime's latest installed servicing patch. No automatic download,
global package installation or registry modification occurs on helper startup.
`SHA256SUMS` is a build inventory, **not a signed release trust anchor**. The
apphosts produced here are not release-signed. No release signature, certificate
or publisher pin has been invented or installed by this task.

Run the two fixture scripts separately, matching the parent-owned CI step.
Management fixtures compile the embedded C# without invoking native methods:

```sh
rtk proxy pwsh -NoLogo -NoProfile -NonInteractive -File tests/release_manifest.ps1
rtk proxy pwsh -NoLogo -NoProfile -NonInteractive -File tests/management_fixtures.ps1
```

They create only disposable fixture files. Neither invokes the release signer,
installer, backup policy, actual restore transport, certificate store or Hello.

Release acceptance still requires a disposable Windows account and real checks:

1. Signed bundle, VC runtime absent/present, both architecture apphosts and private
   parent pipes; exact binary SID agreement and cross-account/elevation rejection.
2. Explicit initialize; all slots, exclusive create, writer sign verified against
   returned public key, database/draft roundtrip, delete, restart, wrong-ID rejection.
3. Actual Hello verified/cancel/timeout, owner HWND, account switch, WTS lock and
   disconnect during consent and signing; quick lock/unlock between calls while
   a watcher remains active; no provider reuse after any watch exit or expiry.
4. Exclusion removal/type mismatch, marker tampering/removal, changed restore
   indicator and same-device backup restore. New marker never discovers old slots.
5. Record separately the unavoidable full-clone/rollback limitation above.
6. Watch `ready` only after subscription; ordinary operations proceed while it
   runs; marker remove/replace/change events latch; EOF and separately stdout
   reader loss while the parent remains alive terminate the watcher. Fixed 300s
   expiry must emit invalidated and exit, without automatic restart. Suspend or
   stall the real subscriber for over 1s: no ACK may be accepted after resume,
   even if a lock/unlock pair or challenge queued meanwhile. Exercise malformed,
   duplicate/replayed/fragmented/oversize challenges and parent pre/post-call ACKs.
7. Real console/Windows Terminal: redirected stdin cannot supply a line; all four
   fixed prompts, Unicode/surrogate/backspace/byte limits, empty line, cancel,
   overflow, timeout and lock; original mode restored after each failure and
   success; no entered text on CONOUT$/stderr/logs, only the private response.

Current measured build/test evidence is in [ACCEPTANCE.md](ACCEPTANCE.md).
