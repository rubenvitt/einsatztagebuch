# Ubuntu native operator helper

`ea-native-operator` is a C implementation of the macOS
[IPC contract](../macos/INTERFACE.md) consumed by
[`native_provider.rs`](../../src/native_provider.rs). The binary links libsecret,
GIO, libpolkit-gobject, JSON-GLib and OpenSSL 3. It does not spawn `secret-tool`,
`pkexec`, a password-reading shell command, or an identity stub.

## Interface and parent integration

Normal operations receive one flat JSON request, at most 65,536 bytes, through
an anonymous stdin pipe followed by EOF. One bounded JSON response is written
to an anonymous stdout pipe. `watch-session` has the separate persistent,
newline-framed contract below. Linux `pipefs` identifies anonymous pipes; a named FIFO,
terminal, socket or regular file is rejected. No command-line options select
keys, identities, services or paths. The helper suppresses native diagnostic
messages, disables core dumps and process dumpability, and has a 90-second
whole-process deadline for normal operations. The watcher is limited to 300
seconds. Timeout terminates the process without claiming success.
The parent still owns its timeout, installed executable integrity, role
authorization, challenge domains, sessions and post-call identity verification.

Accepted request fields are `op`, `slot`, `kind`, `data`, `presence`, `replace`
and `installation_id`. Unknown fields, duplicate keys (including escaped
spellings), nesting, null, numeric booleans, non-ASCII strings and invalid
combinations are rejected. JSON string escapes for ASCII are decoded before
validation. Hex must be lowercase. Slots follow `[a-z0-9-]{1,64}` as in the
Mac contract; the six intended slots are `operator-instance`, `writer-signing`,
`admin-signing`, `root-signing`, `database-key`, `draft-key`.

Every success exits 0 and includes `ok:true` and the **public**
`installation_id` as 64 lowercase hex digits. Every failure exits 1 and returns
exactly `ok:false,code:<stable-code>`. An expected request `installation_id`
is compared with the marker before any service or presence call. A mismatch
does not initialize or mutate storage. Bootstrap `account` and `initialize`
may omit it. Loss of a marker is never repaired implicitly.

| Operation | Result / constraint |
| --- | --- |
| `account`, `initialize` | `platform:"linux"`, actual numeric `getuid()`, `machine_id_bytes` containing the **unchanged `/etc/machine-id` bytes hex-encoded**, and conservative `locked` |
| `generate` | Fresh exclusive `ed25519` or `secret32`; `public_key` is 32 bytes hex or null |
| `public-key` | Public metadata only; absent/secret32 returns null; never loads native secret values |
| `sign` | 64-byte signature hex; all signing slots except `writer-signing` require `presence:true` |
| `wrap-secret` | Exclusive storage of exactly 32 supplied bytes in `database-key` or `draft-key`; returns no secret |
| `unwrap-secret` | Exactly 32 bytes hex in `secret`, only for those two secret slots |
| `contains` | Metadata-only boolean; never loads native secret values |
| `delete` | One explicit slot; idempotent when absent; no enumeration |
| `reset` | Requires fresh presence; unlinks and directory-syncs marker; returns `reset:true` and the **invalidated** public ID |
| `watch-session` | Only `op` and mandatory `installation_id`; newline request, retained stdin writer; readiness, fresh challenge acknowledgements, at most one invalidation frame |

`kind` is mandatory for `generate`, optional on other slot operations and must
match the slot's type. Only operator-instance/ed25519 generation accepts
`replace:true`, with presence required. `presence:true` is rejected for
`account`, `public-key`, and `contains`; otherwise it requests a fresh native
authentication. The default is false. All key operations require an unlocked
session and login collection, even writer signing without a prompt.

`/etc/machine-id` is opened without following a symlink; it must be a protected
root-owned regular file containing 32 lowercase nonzero hex digits, optionally
followed by LF. That LF is preserved in IPC. Rust owns canonical decoding and
the normative CBOR account-binding hash. The marker's separate local fingerprint
is SHA-256 over the original machine-ID bytes followed by the big-endian u32 UID.
The helper rejects setuid/setgid execution. It never uses `HOME`, `USER`,
`XDG_SESSION_ID` or an IPC profile to decide identity.

## Continuous session watcher

The parent sends this **public** request followed by LF and keeps its stdin
write handle open for the watcher's entire lifetime:

```json
{"op":"watch-session","installation_id":"<64 lowercase hex digits>"}
```

No `presence` field (even false), slot, kind, data or replacement flag is
accepted. A watch request without LF is rejected at EOF. Complete normal
requests, including those followed by LF, continue to wait for EOF. Input before
readiness or coalesced after the initial request is terminal; pipelined requests
are not discarded. The only accepted continuation after readiness is a challenge.

Only after subscriptions are installed and the actual account, expected marker,
process-bound active GUI session, awake logind manager, unlocked login collection
and native account-instance secret have been verified does the helper emit LF
after this exact object:

```json
{"ok":true,"installation_id":"<same public ID>","ready":true}
```

Before **and after every sensitive call**, the parent sends a fresh random
32-byte nonce encoded as 64 lowercase hex digits, followed by LF. It allows only
one outstanding challenge and accepts only that nonce's exact acknowledgement
within **one second**, on the same private verified pipes:

```json
{"challenge":"<fresh 64 lowercase hex digits>"}
{"ok":true,"installation_id":"<same public ID>","challenge":"<same nonce>"}
```

The request has exactly one JSON string member; ASCII JSON whitespace/escapes
are decoded with the strict parser, duplicate or extra members are rejected.
Each LF-terminated continuation is at most **1024 bytes including LF**. Partial
frames expire one second after the first received byte. Unknown/malformed
input, a second outstanding frame (even a partial one), or any repeated nonce
invalidates. All consumed nonces remain in bounded memory until exit; at 65,536
distinct nonces the next request fails closed instead of forgetting history.
Receiving input never itself produces an acknowledgement.

Native events and coverage failures irrevocably latch invalidation. After
readiness the helper emits at most one terminal line, then exits:

```json
{"ok":true,"installation_id":"<same public ID>","invalidated":true}
```

EOF on stdin means the parent is gone: stop without another frame. Before
readiness, failed checks return the ordinary `ok:false,code` object. Any stdout
EOF, malformed frame, timeout, failed readiness or process termination must
invalidate the parent's session. The parent must never restart a failed watch
and reuse the old session. A newly authenticated provider/session is required.
The public ID is the only installation material in these messages; the wrapping
key and native account-instance secret never enter this stream.

Both fixed GDBus connections are retained. Native signal handlers are installed
with explicit, synchronously acknowledged `AddMatch` rules before the initial
readiness checks; merely obtaining a subscription ID is insufficient. The
logind owner must run as root, the Secret Service owner as the actual UID.
Unique owners are pinned. `NameOwnerChanged` (including disappear/reappear) and
either connection's `closed` signal invalidate without reconnecting.

Every signal from the pinned logind owner invalidates, including session `Lock`,
`PropertiesChanged`, seat/active-session and user/session lifecycle changes,
`PrepareForSleep` and shutdown. An immediate `Unlock` or resume never clears the
latch. This deliberately also invalidates on unrelated logind activity; it
trades availability for conservative coverage. The native keyring subscription
pins the `_account-instance` object: its changes/deletion, collection lock or
replacement, invalidated/unknown properties and unknown signals invalidate.
Known, correctly typed changes to ordinary key items and collection item lists
that retain the account-instance object are allowed, so normal key creation and
deletion do not cancel their own parent provider.

Linux inotify subscribes before initial marker acceptance to machine/account
files, backup-policy and marker directories/files, their relevant parents and
both bus socket directories. Mutation followed immediately by restoration still
leaves an event. Watch loss, unmount, overflow, malformed/unknown records and
missing coverage invalidate; watches are never rebuilt to clear a latch. The
marker directory's exclusive `flock` is released before the persistent wait,
so other helper operations remain possible.

Queued native events are drained after the initial verification and owner
barriers, before readiness. For every challenge, the subscribing GDBus loop
checks account/marker/socket identities and subscription coverage, then starts
**six new asynchronous probes** for both pinned owners, the same process/session
path, typed session/manager state and unlocked login collection. Earlier periodic
replies cannot satisfy a later nonce. Each probe times out after 750 ms. After all
replies succeed, the same loop rechecks local state and drains queued native
signals, inotify and input again before one atomic nonblocking acknowledgement.
No other thread acknowledges. A stalled native query remains interruptible by
lock, EOF and timeout events. An earlier unfinished periodic query can reduce the
available response time; inability to complete within one second fails closed.

A 100 ms event-loop timer and checks before/after every dispatch observe elapsed
`CLOCK_BOOTTIME`. A gap **greater than one second**, backwards/unknown time, or
an expired challenge latches before the previous dispatch timestamp is advanced;
a queued timer cannot hide SIGSTOP, a blocked callback or suspend. Supplemental
state checks still run every five seconds. The original BOOTTIME deadline plus a
hard process alarm caps the entire watch at **300 seconds**; neither challenges
nor callbacks renew it. Native subscriptions cover intervals between requests.
The parent must reject missing, stale, unsolicited or replayed acknowledgements,
including when the child is stopped and cannot emit invalidation. Delivery still
has OS/IPC scheduling latency; this is not an atomic transaction with a concurrent
desktop lock.

## Native session, PAM and authentication

The helper uses the fixed system bus socket `/run/dbus/system_bus_socket`.
It verifies the connection's unique name resolves to **its own PID and UID**,
then asks logind `GetSessionByPID` for that PID. It never searches all sessions
for an unlocked session belonging to the same UID. Every check requires typed
`Active=true`, `LockedHint=false`, `Remote=false`, `State="active"`,
`Class="user"`, a nonempty seat, X11/Wayland, and the same session UID.
The session object path must remain unchanged. Missing logind, absent fields,
an SSH/TTY session, a process outside a session, user switching and lock states
fail closed. An existing installation can return `locked:true` from `account`
when this evidence or Secret Service is unavailable; this is not presence.

The same live unique system-bus name is the `PolkitSystemBusName` subject.
The shipped action has `allow_active=auth_self`, `allow_inactive=no`,
`allow_any=no`, and **no retention**. The helper checks the installed action
defaults, requires an unauthenticated nonretained challenge before requesting
user interaction, then rejects cancellation, retained authorization and
temporary authorization IDs. A pre-authorized `yes` result is not accepted as
fresh presence. Credentials are entered only into the OS-owned Polkit agent;
the helper never receives, stores or logs an OS password. Root-controlled
Polkit rules must not override this action with a different identity or policy:
Polkit's result does not expose which authentication identity a custom rule chose.

The session bus is fixed to `/run/user/<getuid()>/bus` after ownership and
permissions checks; an inherited bus-address override is replaced. Secret
Service must already be running as this UID. Its unique bus owner is pinned and
rechecked. The helper resolves only the existing **`login` alias** and requires
the actual GNOME path `/org/freedesktop/secrets/collection/login`, never the
default alias or a new dedicated collection. Its libsecret subclass
rejects Secret Service prompts, including a lock race. PAM/GDM must have
unlocked this login collection. libsecret's encrypted DH transport session is
required before sending or fetching secrets; plaintext transport is refused.

PAM's automatic unlock targets the login keyring; an independently created
collection does not inherit that property. The installer checks the supported
GNOME/GDM PAM auth/session configuration, without modifying PAM. Those static
checks cannot attest how a particular runtime collection was unlocked.
Passwordless/autologin, non-GNOME providers, and GNOME launches that run outside
a logind session are not automatically supported by this implementation.

## Exact storage and security semantics

There are **three independent random values**, each generated with OpenSSL CSPRNG:

| Value | Storage | IPC / purpose |
| --- | --- | --- |
| Public installation ID, 32 bytes | Excluded marker; its hash selects a Secret Service namespace | Echoed on every success; never a cryptographic key |
| Secret marker wrapping key, 32 bytes | **Only** the excluded `0600` marker | Never sent to Secret Service, IPC or logs |
| Secret account-instance value, 32 bytes | **Only** the fresh `_account-instance` item in the PAM login collection | Never returned by IPC; marker stores only its SHA-256 hash |

The marker is `/var/lib/ea-native-operator/<uid>/marker`, outside roaming/home
storage. Binary layout: 8-byte `EANAT01\0` magic, public ID[32], wrapping key[32],
instance-secret hash[32], local account fingerprint[32], exactly 136 bytes.
No raw signing seed, database secret or draft secret is ever persisted to a file.

The actual encryption key is HKDF-SHA256 with marker wrapping key as input key
material, the Secret Service instance secret as salt, and domain-separated info
plus the public installation ID. **Both secret storage locations are required.**
Knowing the public ID, marker file permissions, or either one of the secrets
alone is insufficient to decrypt the signing seed. The public ID is never used
as an encryption key. Loss of either secret blocks old key possession.

All Ed25519 seeds and secret32 values are AES-256-GCM encrypted before entering
Secret Service. The 61-byte envelope is version[1], random nonce[12],
ciphertext[32], tag[16]. Authenticated data binds versioned domain, installation
ID, account fingerprint, slot, kind and public key. Metadata has a separate
domain-separated HMAC-SHA256 under the marker wrapping key, so public-key/contains
can validate it without loading Secret Service secrets. Private signing uses
OpenSSL Ed25519 `EVP_DigestSignInit(..., NULL, ...)` and one-shot
`EVP_DigestSign`, without prehashing; derived public keys must match metadata.
Sensitive application buffers are cleansed, but complete erasure of all
GLib/OpenSSL/kernel copies or swap/hibernation memory is not claimed.
GNOME Keyring returns binary stored values with `text/plain` MIME metadata;
the helper accepts it or `application/octet-stream`, and always authenticates
the exact-length bytes using the instance hash or AES-GCM rather than the MIME tag.

Initialization creates a new random account-instance item in the login
collection, then publishes the marker exclusively. Failures can leave an
unreachable fresh namespace; they never discover or adopt surviving old items.
Directory-inode `flock`, no-follow opens, ownership/mode/size/link checks,
exclusive atomic publication and fsync protect the marker. Duplicate native
slot items fail closed. Operator replacement removes the old item first; a
crash may lose availability, never silently substitute the former instance.
Account, marker, session, collection owner and namespace are rechecked before
returning private results. The parent retains the independent watcher across
requests. Neither mechanism is an atomic guarantee against a desktop locking
immediately after the final observation.

## Installed backup policy and remaining §6.8 boundary

Secret Service collection flags **do not provide backup exclusion or
non-roaming guarantees**. The supported installation profile instead installs:

- Root-owned `/etc/ea-native-operator/backup-policy` and `backup-excludes`.
  Their exact protected contents are checked on every helper invocation.
- Root-owned `/var/lib/ea-native-operator`, mode 0755, with an account-owned
  mode-0700 UID subdirectory. Both require the kernel `FS_NODUMP_FL` flag.
  The helper sets and reads back `nodump` on the marker before publication.
  Unsupported filesystems or removed flags fail closed; there is no fallback.
- `/usr/libexec/ea-native-backup`, a restricted GNU-tar entry point that always
  applies the installed exclusions, clears `TAR_OPTIONS`, accepts no tar options,
  resolves the source path and rejects the marker tree as a direct source.
  Existing backup jobs are **not** silently edited or claimed to honor the file.

For this explicitly selected backup profile, route **all system/application
file backups** through the installed entry point. Merely installing the helper
does not retrofit other backup jobs. Do not back up this marker with snapshot,
image, alternative-path bind-mount, home-roaming, or third-party tools; configure
and separately prove their equivalent exclusions before permitting their use.
`nodump` is additional policy metadata, not a guarantee that every tool obeys it.

The verification suite creates a real tar archive and verifies that both the
marker and an in-progress `.pending` publication are absent. It also proves
direct and symlink-source attempts cannot bypass the wrapper. A backed-up login
keyring without the excluded marker cannot recover the old private keys.

**Absolute §6.8 no-restore/account-recreation acceptance remains unproved.**
A full clone that bypasses exclusion and restores both stores, an in-place
application restore retaining the marker, or reuse of both the old marker and
unlocked keyring after UID recreation cannot be detected cryptographically here.
Unlink is not secure erasure of historical filesystem snapshots. Root, a
compromised same-user desktop, and arbitrary snapshot rollback are outside the
protection provided by these APIs. No hardware-backed or nonexportable Ed25519
claim is made; the protection profile is `osWrapped`.

Before reinstall/restore or account deletion/recreation, stop use of the old
binding, arrange external revocation, and perform the native `reset` while the
old account is still available. Native reset still requires the actual old
user's unlocked session, login collection and fresh Polkit presence. It cannot
be authenticated by a root script or by impersonating the UID. The managed
administrator entry point below performs **administrative invalidation**, which
is a separate authority and never an attestation that native reset occurred.
Never import a marker from backup. The installer refuses to adopt an existing
UID directory as a new enrollment and does not hook arbitrary account deletion
commands. A fresh `initialize`, fresh operator key, external identity check,
admin authorization and Root-signed binding are mandatory before resuming.

Reset/restore enforcement review:

| Entry point | Actual enforcement |
| --- | --- |
| Native `reset` request | Requires `presence:true`, an unlocked process-bound session and login collection, fresh nonretained Polkit `auth_self`, and valid account/marker/native instance before unlinking the marker |
| `install.sh` | Refuses an existing UID directory, including an empty directory left by reset; it does **not** perform or attest that authenticated reset |
| Managed `ea-native-restore restore --account-uid UID` | Root-controlled fixed job runs under maintenance leases; only after its final successful restore are the final UID namespace's marker and pending publication invalidated, before fresh initialization becomes possible |
| Managed `ea-native-restore reenroll --account-uid UID` | Explicit administrative invalidation of the fixed namespace under the same leases, without running a restore job or creating keys |
| Unmanaged restore retaining the marker / full snapshot | No enforced hook; backup flags and the tar exclusion wrapper do **not** detect or prevent retained-marker rollback |
| Arbitrary administrator directory removal / account tools | Outside the native authentication boundary; file absence is not proof of authenticated reset |

## Managed restore and reenrollment

`install.sh` installs [restore.py](restore.py) as
`/usr/libexec/ea-native-restore` (root-owned executable, isolated system Python 3)
and creates the root-controlled `/etc/ea-native-operator/restore.d` directory.
Deployment must install the **matching updated native helper** before using this
entry point; an older helper has no maintenance gate. This is implementation,
not evidence that the installer or a real restore has been executed.

The administrator explicitly selects a canonical decimal **non-root UID**
(`1` through `4294967294`, no leading zero, username, sign or traversal). The CLI
requires real/effective root and accepts no alternate filesystem root, command,
marker path, job path or environment override. Runtime identity remains actual
`getuid()`; the maintenance UID argument is never a native account assertion.

Configure exactly `/etc/ea-native-operator/restore.d/1000` as a root-owned,
single-link regular file with mode **0700**, for example by installing the site's
reviewed foreground restore script there. Its content is deployment-specific;
no default job is installed. All ancestors must be protected root-owned
directories. The script runs through `/bin/sh` from its already-checked open
descriptor, with no arguments, a fixed system PATH and public `EA_RESTORE_UID`.
stdin/stdout/stderr are `/dev/null`; it must not prompt or handle credentials.
The job must quiesce application writers, finish **all** final restore writes
before returning success, and must not spawn background/detached jobs, downgrade
the helper, close the inherited maintenance lease descriptors, replace the protected control tree, change the maintenance record,
or preserve copies of secret markers. The administrator controls backup/source
selection in this fixed script, not through untrusted IPC arguments.

Exact installed usage (shown only; not executed for this implementation):

```sh
sudo /usr/libexec/ea-native-restore restore --account-uid 1000 --dry-run
sudo /usr/libexec/ea-native-restore restore --account-uid 1000
```

The dry run validates ownership/types/paths, the job and lock availability. It
does not run the job, create a guard, change ownership, remove state or prove the
restore script's behavior. A passed dry run is not a reservation for a later run.

For explicit reenrollment, or invalidation **after an already completed and
quiesced final restore**, use:

```sh
sudo /usr/libexec/ea-native-restore reenroll --account-uid 1000 --dry-run
sudo /usr/libexec/ea-native-restore reenroll --account-uid 1000
```

`reenroll` performs no restore itself. It cannot infer whether an arbitrary
external restore has really finished; that ordering remains the administrator's
responsibility. The managed `restore` mode enforces ordering around its fixed
foreground job. These commands preserve the empty enrolled UID directory; do
**not** rerun the initial installer for that existing directory. After success,
the actual user must log into the supported GNOME session and use the normal
parent's fresh enrollment flow. No maintenance command invokes `initialize`,
native `reset`, Polkit or Secret Service, and none creates an authentication proof.

The implementation takes nonblocking exclusive `flock` leases on the root
control directory (serializing administrative maintenance) and affected UID
directory (the same inode locked by ordinary helper operations). An active
operation refuses maintenance before the job runs. It then durably creates
root-owned `/var/lib/ea-native-operator/.restore-1000` **before** the job. Any
presence or unreadability of that record blocks the updated helper with
`installation-maintenance`; native watchers also latch its create/remove events.
The guard contains only a public format tag, no ID or wrapping secret.

The restore child inherits the leases, so killing its manager cannot reopen the
namespace while that job still runs. Job failure, timeout (30 minutes), observed
background descendants, unexpected entries or lost control-path coverage refuses
completion; the durable guard stays closed. Only its still-owned direct child
may be terminated on timeout; the runner never signals a potentially reused
process-group ID. Surviving descendants require explicit administrator cleanup
and retain their inherited leases. Symlinks/path traversal, unprotected
ancestors, non-regular objects and external hardlinks are rejected. The native
publisher's exact interrupted two-name `marker`/`.pending` hardlink pair is
recognized. No recursive deletion or secret-marker content read occurs.

After the final job, the implementation checks the control path and guard again,
locks the **final** UID directory even if the job replaced its inode, temporarily
makes it root-owned 0700, validates and removes only `marker` and `.pending`,
fsyncs and verifies emptiness, then returns ownership to the affected UID. Only
then is the guard removed and durably synced. A directory's existing `nodump`
flag is preserved. If an external job replaced it without the mandatory flag,
fresh native initialization fails `backup-policy-required`; repairing that
filesystem policy is explicit administrator work, not an implicit fallback.

On failure, inspect and repair the fixed job/protected namespace, ensure its
writers are finished, then use explicit `reenroll` or rerun the managed restore.
Never remove a pending guard merely to make native calls work. A guard may
protect a temporarily root-owned UID directory after an interrupted invalidation;
the entry point accepts that recovery state and invalidates it before reopening.

These are enforced filesystem semantics for this supported entry point, not
universal rollback detection. An unmanaged restore can bypass the entry point;
a full snapshot can restore both secrets, the control tree and application state.
Neither exclusion metadata nor managed-restore fixture tests solve that §6.8
limit. External revocation, reidentification, deployment enforcement and actual
desktop/parent acceptance remain required. No parent native API extension is
needed for this administrative path; unknown `installation-maintenance` failures
already fail closed, while user-facing lifecycle orchestration belongs to the
parent/deployment owner.

## Build, install and verify

Ubuntu 24.04 native development packages:
`build-essential pkg-config libsecret-1-dev libglib2.0-dev
libpolkit-gobject-1-dev libjson-glib-dev libssl-dev python3 e2fsprogs dbus-daemon`.
Runtime additionally needs the distribution's GNOME Keyring, GDM/PAM integration,
systemd-logind, D-Bus, a native Polkit agent, GNU tar and the linked shared
libraries. No package installation is performed by `install.sh`.

With dependencies already available:

```sh
make
make check
```

Install explicitly as administrator for one numeric account, into the same
protected directory as the parent executable:

```sh
sudo sh install.sh 1000 /usr/lib/einsatzarchiv gnu-tar
```

That UID is **an installer enrollment argument only**. Runtime always obtains
the UID from `getuid()`. A helper upgrade preserves the excluded marker and
requires normal release/package orchestration; do not treat reenrollment as an
upgrade. The installer intentionally refuses an existing account directory.

`Dockerfile` and `verify-container.sh` build and test in an owned disposable
Ubuntu container, with source mounted read-only and no host package changes.
The container gate also runs `make check-install`, which refuses ordinary hosts
and verifies installation/filesystem/backup behavior. Its PAM file and native
marker contents are **test fixtures**, never evidence of real desktop presence.
`make check-secret-service` additionally runs storage operations against a real
private D-Bus and `gnome-keyring-daemon`, with a random test-keyring passphrase
unrelated to any OS account password. It verifies fresh native storage,
Ed25519 sign/verify, wrap/unwrap, two-secret necessity, deletion and collection
lock rejection. It calls the internal storage layer after the authorization
boundary; it does **not** verify PAM, Polkit presence or logind session acceptance.

`make check` also runs deterministic watcher wire/state tests, real GDBus signal
delivery on a private test bus, inotify mutation/restore, coverage loss and an
event delivered while an asynchronous native query remains unanswered. Challenge
tests cover exact acknowledgements, malformed/duplicate/queued/oversized frames,
partial/EOF input, replay history, the fixed deadline and queued events winning
over acknowledgements. A separate **test executable** exercises actual SIGSTOP /
SIGCONT and a blocked GLib callback; its loop fixture omits native acceptance and
is unavailable in the shipped helper. These tests do not authenticate. The
private bus supplies events only; it does not impersonate a successful desktop
authentication path. Headless tests keep the parent writer open and prove the
actual executable refuses readiness both without installation and with a valid
fixture marker. The real private GNOME-Keyring test additionally verifies that
ordinary key writes do not invalidate the watch, while collection lock does.

`make check-maintenance` (also in `make check`) runs the native maintenance gate
and Python descriptor-relative restore tests under newly created temporary
directories. They exercise dry run, final restored-marker deletion, interrupted
and replaced namespaces, job failures, inherited leases after manager death,
concurrent-operation refusal, and symlink/hardlink/mode/path rejection. They do
not invoke the root CLI against `/`, install anything or simulate native presence.

Real desktop acceptance is still required for: positive/negative fresh Polkit
prompts, no retained authentication, GNOME lock and user switching during calls,
login-keyring/PAM unlock and loss, duplicate/locked native items, account
deletion and UID reuse, restore/reinstall lifecycle and parent challenge flows.
Do not use container or simulated-service tests to mark those accepted.

## Stable Linux error codes

Protocol/process: `invalid-request`, `request-too-large`, `io-failed`,
`protected-pipe-required`, `process-protection-failed`, `watch-unavailable`.
Account/presence: `account-invalid`, `account-unavailable`, `account-changed`,
`locked`, `presence-required`, `presence-denied`.
Installation: `backup-policy-required`, `installation-not-enrolled`,
`installation-missing`, `installation-invalid`, `installation-changed`,
`installation-instance-missing`, `installation-write-failed`, `installation-maintenance`, `busy`.
Native keys: `secret-service-unavailable`, `key-store-unavailable`,
`key-ambiguous`, `key-invalid`, `key-missing`, `key-exists`, `key-delete-failed`,
`key-write-failed`, `crypto-failed`.
Native error descriptions and request fields are never echoed in failures.

## Official references

- [GNOME Keyring PAM integration](https://wiki.gnome.org/Projects/GnomeKeyring/Pam)
  documents automatic login-keyring unlock and the limits of other collections.
- [Polkit actions and authentication policy](https://polkit.pages.freedesktop.org/polkit/polkit.8.html),
  [system-bus subjects](https://polkit.pages.freedesktop.org/polkit/PolkitSystemBusName.html),
  and [authorization retention results](https://polkit.pages.freedesktop.org/polkit/PolkitAuthorizationResult.html).
- [OpenSSL Ed25519 signatures](https://docs.openssl.org/3.0/man7/EVP_SIGNATURE-ED25519/)
  specifies a NULL digest and single-shot signing.
- [libsecret collection searches](https://gnome.pages.gitlab.gnome.org/libsecret/method.Collection.search_sync.html)
  distinguishes metadata queries from explicit unlock/secret-load flags.
- [GIO signal subscription and thread-default context](https://docs.gtk.org/gio/method.DBusConnection.signal_subscribe.html),
  [connection closure](https://docs.gtk.org/gio/signal.DBusConnection.closed.html),
  and [D-Bus AddMatch](https://dbus.freedesktop.org/doc/dbus-specification.html#bus-messages-add-match).
- [GNOME Keyring's native collection/item implementation](https://github.com/GNOME/gnome-keyring/blob/master/daemon/dbus/gkd-secret-objects.c)
  informs the typed distinction between ordinary key-item events and account/lock events;
  the shipped private-keyring test checks that distinction against Ubuntu's actual daemon.

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
