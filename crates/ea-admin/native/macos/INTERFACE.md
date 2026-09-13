# macOS native operator helper contract

Executable: `ea-native-operator`, installed as a fixed, signed sibling of the
parent executable. Ordinary calls use one stdin JSON object (at most 65,536 bytes, EOF required),
one stdout JSON object, no diagnostics containing OS names, identifiers or data.
The parent owns spawning, timeouts, private anonymous pipes, signing identity
verification, sessions, authorization, and installation/account cross-checks.

`watch-session` instead requires a single newline-terminated request with only
`op` and the expected `installation_id`, with stdin retained. It emits exactly
one `ok:true,ready:true,installation_id` frame, then at most one
`ok:true,invalidated:true,installation_id` terminal frame. In between, the parent
sends exact `{"challenge":"<fresh 64 lowercase hex digits>"}` lines, one
outstanding, at most 1,024 bytes including LF. Only the native event loop may
reply with exact `ok:true,installation_id,challenge` fields after draining
events and verifying current coverage. The parent requires the exact nonce
within one second before and after every sensitive call. Replay, malformed or
unsolicited input/output, coverage loss, a one-second event-loop stall, timeout
or EOF invalidates irreversibly. Its 300-second lifetime is never renewed by a
challenge. Ordinary EOF-terminated operations remain unchanged.
The signed privileged ES monitor must already be deployed
and have observed login/unlock plus an ES heartbeat. Its exact protocol,
coverage and operator startup instructions are in [WATCH-SESSION.md](WATCH-SESSION.md).

Every success includes `ok:true` and `installation_id` (32 bytes, 64 lowercase
hex digits). Every failure has exactly `ok:false,code:<stable string>`.
`account` fails with `installation-missing` without the excluded marker;
`initialize` explicitly creates it. Neither discovers an old namespace.

Requests: `op`, optional `slot`, `kind` (`ed25519` or `secret32`), `data`
(lowercase hex), `presence` (boolean, default false), `replace` (boolean,
default false), `installation_id` (expected public ID, 32 bytes hex). When
present, the expected ID must match the current marker before any Keychain or
presence call; mismatches return `installation-changed`. Bootstrap account and
initialize may omit it. Unknown fields and invalid combinations are rejected.
`slot` matches `[a-z0-9-]{1,64}`. Intended slots are `operator-instance`,
`writer-signing`, `admin-signing`, `root-signing`, `database-key`, `draft-key`.

- `account` / `initialize`: `platform:"macos"`, `guid_values:[String]`,
  `unique_id_values:[String]`, numeric `uid`, mandatory conservative `locked`.
- `generate`: `public_key` (32 bytes hex for Ed25519; null for secret32).
  Always fresh; exclusive creation. Only `operator-instance` permits
  `replace:true`, with `kind:"ed25519"` and `presence:true`.
- `public-key`: `public_key` or null; never prompts or retrieves private data.
- `sign`: `signature` (64 bytes hex). Operator/admin/root require
  `presence:true`; writer may use false, but the account must remain unlocked.
- `wrap-secret`: stores exactly 32 supplied bytes in the native Keychain,
  exclusively, in `database-key` / `draft-key`; returns no secret.
- `unwrap-secret`: returns `secret` (32 bytes hex), only for those two slots
  and only through an anonymous pipe to the parent.
- `delete`: deletes one explicitly named slot. No enumeration.
- `contains`: `contains` boolean. Metadata only; never prompts.
- `reset`: requires `presence:true`; removes the excluded marker and its
  wrapping key. Returns `reset:true` and the **invalidated** `installation_id`.
  It never enumerates old Keychain entries or creates a replacement identity.

`presence:true` performs fresh `deviceOwnerAuthentication` except on
`account`, `public-key` and `contains`, where it is rejected. OS credentials
are entered only in the OS-owned dialog, never read or stored by the helper.

## Stable failure codes

Failures return exit status 1 and one JSON object with no account names, native
error descriptions, key bytes or echoed request fields. The closed production
code set is:

- Protocol/transport: `invalid-request`, `request-too-large`,
  `protected-pipe-required`, `io-failed`, `native-failed`.
- Account/session: `account-invalid`, `account-unavailable`, `account-changed`,
  `locked`, `watch-unavailable`, `code-identity-invalid`.
- Installation: `installation-missing`, `installation-invalid`,
  `installation-changed`, `installation-exists`, `backup-exclusion-failed`,
  `busy`, `entropy-unavailable`.
- Native authentication: `presence-required`, `presence-unavailable`,
  `presence-failed`, `presence-cancelled`, `presence-timeout`.
- Keychain/cryptography: `key-exists`, `key-missing`, `key-invalid`,
  `key-kind-mismatch`, `keychain-entitlement`, `keychain-unavailable`,
  `crypto-failed`.

A success exits 0. `public-key` on a missing or secret32 slot returns null;
`contains` returns false on an absent slot; `delete` is idempotent. Authentication
has a 45-second internal deadline. Other IPC and native-call timeouts belong to
the parent. The helper does not interpret a caller-selected slot as proof of
archive role authorization.

## Backup limitation requiring parent awareness

The marker contains three independent random 32-byte values: the **public**
installation ID, a private account-instance namespace, and a **secret** wrapping
key. Neither private value is returned over IPC. It also contains an internal
domain-separated account digest, never a raw GUID/UID. The marker is a file of
mode 0600 in a directory of mode 0700, under the current OS account's fixed
`~/Library/Application Support/Einsatzarchiv/NativeOperator/installation-v1`.
The home path comes from `getpwuid_r(getuid())`, never `HOME` or a profile.
Both marker and containing directory are excluded using
`NSURLIsExcludedFromBackupKey`, and both exclusions are checked on every call.
This API reports effective exclusion, which may be inherited from a containing
directory or system policy; it does not prove a particular backup's behavior.
Symlinks, hardlinks, unexpected owners/modes/sizes, malformed bytes, account
changes and a false/failed effective exclusion check fail closed. The namespace is derived
from fresh installation/account-instance random identifiers, never a stable
account name or a profile-supplied namespace.

CryptoKit ChaChaPoly encrypts each Ed25519 seed and secret32 with the separate
marker wrapping key and a fresh nonce before it enters Keychain. Authenticated
additional data binds the installation, account digest, slot, kind and public
key metadata. The namespace record contains identifiers and a SHA-256 hash of
the wrapping key; it **does not contain the wrapping key**. The public
`installation_id` is never used as an encryption key. The stored key ciphertext
is 60 bytes (12-byte nonce, 32-byte ciphertext, 16-byte authentication tag).
These ciphertexts and the matching namespace record live in the data-protection
Keychain (`kSecUseDataProtectionKeychain`, non-sync,
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`). Missing, malformed, copied to
another account, or unexcluded markers fail closed. A new installation gets
new random identifiers and never enumerates the surviving old Keychain items.

Therefore a Keychain backup without the excluded marker lacks the key required
to decrypt the restored key ciphertexts. Both the OS account's Keychain access
and the excluded marker are required; UID file permissions alone are
insufficient. No raw signing seed or DB/draft secret is written to a file.
Swift/CryptoKit may copy sensitive data in process memory; no complete memory
zeroization or protection against a compromised same-user process is claimed.

This prevents ordinary restores that honor the exclusion from reviving an old
binding. It cannot detect a same-device full snapshot/clone that restores both
the excluded marker and Keychain, or restores application files while retaining
an existing marker. `ThisDeviceOnly` permits same-device restore; exclusion is
a backup policy, not cryptographic anti-rollback. The normative absolute
no-restore claim in §6.8 is **not proved** by these APIs. Installation reset
must remove the marker; external binding revocation/re-provisioning remains a
parent/operational responsibility. No hardware-backed Ed25519 claim is made.

## Reset / reinstall / restore procedure

1. The parent stops sessions and signing, records the affected binding, and
   arranges its external revocation. It must not infer identity from old profile
   or Keychain entries.
2. While running as the affected account in its unlocked GUI session, send
   `{"op":"reset","presence":true}` through the protected bridge. Fresh native
   authentication is required. The marker is unlinked and the directory synced;
   the response names the installation just invalidated. The old Keychain
   ciphertexts are left unreachable, with no wildcard queries or deletions.
3. Drop all cached account/installation values. A following `account` must fail
   with `installation-missing`. Send `initialize` (with `presence:true` when
   provisioning calls for reauthentication); the new ID must differ. Generate
   fresh keys, complete external reidentification, admin authorization and the
   new Root-signed binding before allowing actions.
4. The install/restore workflow must invalidate the marker after the final
   application/profile restore and before reopening the runtime, **even on the same device**. If the old
   installation is already gone, never restore/copy its excluded marker. When
   a malformed marker cannot be opened, an explicit maintenance action under
   the affected OS account removes only the fixed `installation-v1` file before
   initialization; it must not search for/import another marker or key namespace.
   The helper deliberately has no profile-supplied repair path.

The concrete [install.sh](install.sh) and [restore.sh](restore.sh) workflows
perform namespace invalidation under each affected account's native marker
lock, using the OS account database and fixed path. They require explicit
operator-approved privileged execution, real signed release inputs and all
affected UIDs. [WATCH-SESSION.md](WATCH-SESSION.md) defines the sequence and its
limits; in-place marker retention is never treated as an accepted exception.

An in-place restore that retains the marker and a full snapshot that restores
both marker and Keychain cannot be recognized automatically. Treat them as a
mandatory reset and reidentification event. Unlinking is not secure erasure of
historical APFS snapshots; exclusion and operational revocation are essential.

## Closed signing-backup transport

`backup-signing-seed` is a separate internal parent/helper operation. Its request
is exactly `op`, `slot`, `installation_id`, `expected_public_key`, `presence`:
only `admin-signing`/`root-signing`, both public values lowerhex32, presence true,
at most 512 request bytes and EOF. No kind/data/replace/path/prompt fields.
Both parser and provider enforce the closed operation; generic `unwrap-secret`
continues to reject signing keys. No slot generation, import, replacement or
mutation occurs. Existing native presence, installation/account/lock checks and
actual seed-derived public-key binding precede the response.

Success is a fixed 106-byte binary response, **without newline**:
`EABKSEED` (8), version1 (1), role Admin1/Root2 (1), installation32,
actual Ed25519 publickey32, seed32. Only the private Rust backup adapter may
consume it, requiring exact frame, EOF and Exit0 before its deadline, then
existing v1 encrypted-container sealing and final host admission. Failures have
nonzero exit and only static error diagnostics. No seed enters JSON, hex strings,
argv, environment or logs. Controlled buffers are cleared on normal completion
and error paths; this does not prove erasure of OS/library/compiler copies or
cleanup after process termination. Partial pipewrites cannot be retracted.
This transport alone supplies no retained backup medium, Step3/7 or Ready proof.
