# Native session watcher and deployment

This is the macOS implementation for a provider-lifetime watch. EndpointSecurity
is an implementation choice to satisfy the requested §6.8 lifecycle. It does
not imply user approval to install a privileged service. Actual entitled OS
acceptance is pending; see the parent's ADR 0006.

## Parent protocol

Spawn the verified signed sibling `ea-native-operator` with anonymous stdin and
stdout pipes. Send one compact JSON line, then retain stdin until the provider
guard is dropped:

```json
{"op":"watch-session","installation_id":"<64 lowercase hex digits>"}
```

The LF is mandatory. No presence, slot, timeout, additional field or second
initial request is allowed. Before readiness the usual closed error
object and exit status 1 apply. The parent currently allows 10 seconds for this
handshake. The helper's daemon connection has a shorter bounded handshake.

```json
{"ok":true,"ready":true,"installation_id":"<same ID>"}
```

After readiness, send a fresh unpredictable 64-digit lowercase hex challenge
on retained stdin, with exactly this field and LF. Only one may be outstanding:

```json
{"challenge":"<fresh 64 lowercase hex digits>"}
```

The helper replies with exactly these fields and LF, on its actual native event
loop after draining callbacks and monitor input and checking coverage/freshness:

```json
{"ok":true,"installation_id":"<same ID>","challenge":"<same challenge>"}
```

The parent must require the exact fresh nonce within **one second before and
after every sensitive call**. An unread pipe or a live process alone cannot
prove coverage. Unsolicited, duplicate, malformed, extra or stale output,
timeout, EOF, failed code validation or helper death irreversibly terminates
the retained parent session. The parent owns this Rust integration and its
separate stopped-watch regression test; the native fixture suite does not
certify the parent implementation.

Challenge frames are at most 1,024 bytes including LF; incomplete frames expire
after one second. Unknown/duplicate fields, non-lowercase or malformed nonces,
extra/pipelined input and nonce reuse are terminal. The helper retains at most
16,384 nonces per watch and invalidates when this bound is exhausted. There is
no background acknowledgement thread. An observed main event-loop stall of
one second invalidates before queued events can restore readiness. Bounded
drains that cannot establish an empty queue also invalidate.

There is one ready frame, zero or more requested acknowledgements, and at most
one terminal frame:

```json
{"ok":true,"invalidated":true,"installation_id":"<same ID>"}
```

No recovery frame exists. Watch lifetime is at most 300 seconds from startup,
including sleep, and is never renewed by challenges; the helper also has an
independent process alarm. Output frames are atomic, nonblocking writes below
PIPE_BUF. Parent disconnect exits the helper. A full pipe never extends its
lifetime. These frames contain no raw account identity or secret key.

The parent must start this guard before native reauthentication, retain it
through proof use/publication, and invalidate retained proofs when it ends.
Creating a new helper at each key request cannot substitute for this guard,
even within one short-lived CLI invocation. Unlock cannot revive an old guard.

## Event source and coverage

`ea-native-monitor` is a separate root launchd daemon. The actual-UID helper
continues to own OpenDirectory, LocalAuthentication, marker and data-protection
Keychain access. The daemon never opens the Keychain, authenticates a user,
enumerates accounts, or reads ES event identity payloads for transmission.

The daemon subscribes to `NOTIFY_LW_SESSION_LOCK`, `LOGOUT`, `LOGIN`, `UNLOCK`
and `NOTIFY_EXIT` before opening its fixed socket. It uses no AUTH event or
authorization response. Any login-window event invalidates all existing
connections conservatively, irrespective of account. Only an observed
login/unlock permits a **new** connection. Initial state is unknown.

`NOTIFY_EXIT` supplies an actual ES delivery heartbeat: at most one disposable
`/usr/bin/true` child runs at a time, at 250 ms intervals. Only an exit whose
ES process parent PID is this daemon counts as a heartbeat. Other exit events
advance the global sequence check without retaining their payloads. The
daemon requires fresh ES heartbeat evidence before readiness and throughout
the connection. A timer-only heartbeat would not detect a stalled ES delivery
queue. Self-signals are unsuitable: Apple's ESMessage.h explicitly excludes
self-signals from the signal event.

Global sequence numbers must advance exactly by one after the first observed
message; no undocumented initial sequence value is assumed. There are no
accepted sessions before the first heartbeat and login/unlock. A sequence
gap, unsupported message version, heartbeat lapse of one second, changed
subscription set, or daemon scheduler stall permanently closes its current
coverage. Restart and a new observed login/unlock are required. Default path
mutes are cleared for this client's five NOTIFY subscriptions. No application
event queue or ES message retention is used.

Every event preserves its SDK `es_message_t.mach_time` generation age, converted
to the continuous clock at receipt. Future or one-second-old events fail
closed. The previous heartbeat deadline is checked **before** a callback can
replace it and before connection admission; a late heartbeat cannot erase a
gap or admit a new session. A failure on admission invalidates existing clients
too. Heartbeat broadcasts are paced at most once per 100 ms independently of
listener activity and repeat the source event time, never the send time.

The actual-UID helper subscribes to NSWorkspace session/sleep notifications,
documented DirectoryService user-cache invalidation, and the supplementary
distributed screen-lock/unlock names before its initial account/namespace
check. It pumps the run loop, checks the authenticated daemon heartbeat, and
rechecks account/console/namespace. A marker lock held by a concurrent presence
operation skips only a subsequent namespace poll; the account comparison and
ES monitor remain active. An initial busy state fails. Locked, changed or
missing namespace results always invalidate.

NSWorkspace resign-active covers switching sessions; it does not document
screen-lock coverage. `com.apple.screenIsLocked` / `screenIsUnlocked` are
undocumented distributed notification names and never establish readiness.
The authoritative lock/logout source is ES. Apple's SDK also explains that
login-window events originate in platform userspace, not the kernel: their
guarantee concerns Apple's emitting login-window implementation. No claim is
made about arbitrary replacement OS components or zero notification latency.
Physical lifecycle acceptance must validate supported macOS releases.

## Protected monitor IPC and signing

The fixed endpoint is
`/private/var/run/org.einsatzarchiv.operator.monitor.sock`. Root owns its
non-writable parent chain. A root-owned, no-follow, exclusively locked companion
file serializes daemon instances; only a stale root socket is removed. The
socket allows connections from user accounts, but authenticates each peer
before allocating an accepted watch. Each ready/heartbeat frame is exactly
18 bytes: `R` or `H`, 16 lowercase hex digits encoding the source ES heartbeat's
continuous-clock nanoseconds, then LF. Invalidation remains `I\n`. No account
identity crosses this socket. The helper requires source age below one second
before and after each check; timestamps must never move backward. Old
untimestamped peers fail closed, so helper and monitor must ship together.

Each check drains through EAGAIN and checks for terminal poll flags, with a
1,024-byte/32-read ceiling. Exhaustion, an incomplete frame, a queued terminal
behind heartbeats, EOF, malformed/duplicate readiness or stale evidence closes
the connection irreversibly. Identity revalidation is followed by another
drain. There are at most 32 accepted sockets, backlog 8, no queued
application messages, bounded nonblocking writes, and a 300-second ceiling
per connection. launchd limits file descriptors to 128 and forbids core dumps.

Stable signing identifiers:

| Component | Identifier |
| --- | --- |
| Actual-UID helper | `org.einsatzarchiv.operator.native` |
| Invoking Rust CLI | `org.einsatzarchiv.cli` |
| Root ES monitor | `org.einsatzarchiv.operator.monitor` |

`CodeIdentity.swift` validates its own Apple-anchored code before deriving its
Team ID. The helper requires the server's kernel-reported socket UID to be
root. Both ends use `LOCAL_PEERPID`, `SecCodeCopyGuestWithAttributes`, and
`SecCodeCheckValidity` with the exact counterpart identifier, Apple anchor and
same Team. Linked static-code checks verify hardened-runtime flags and reject
debugging/library-validation/dyld/JIT bypass entitlements. Dynamic validity is
checked again afterward. The helper repeats server identity checks during use.
PID lookup is tied to a live connected socket; no claimed PID comes from IPC.

These checks complement the parent's separate validation of the helper before
sending secrets. The parent must authenticate its expected sibling at launch
and use; an untrusted helper cannot attest to its own identity for the parent.
Only separately compiled test executables provide fake event sources. There is
no production CLI, environment, account field or plist bypass.

## Build, install, restore

`build.sh` creates both unsigned Mach-O executables. The signed build requires
the actual compiled Rust CLI, explicit Apple Team ID, signing-certificate
SHA-1 identity, and two Apple-issued provisioning profiles. One profile must
authorize the helper's dedicated Keychain access group (see the wildcard
qualification below); the other must authorize
`com.apple.developer.endpoint-security.client`. Mismatched, expired,
unsafe or development profiles fail. A wildcard fails everywhere EXCEPT the
helper's Keychain group, where Apple issues `<team>.*` and no exact group at
all (measured on profile L4L537AM9Z, 2026-09-20); `validate_profile` therefore
accepts a team-pinned wildcard as the authorization envelope, while the signed
entitlement still names the exact group and `verify_code` pins it. The ES
entitlement must be obtained through Apple's deployment process; no script
grants it.

```sh
rtk proxy sh crates/ea-admin/native/macos/build-signed.sh \
  --team REALTEAMID --identity CERTIFICATE_SHA1 \
  --cli /absolute/path/to/ea-cli \
  --helper-profile /absolute/path/to/helper.provisionprofile \
  --monitor-profile /absolute/path/to/monitor.provisionprofile \
  --output /absolute/new/release-directory
```

The placeholders above must be replaced with real deployment inputs. Relative
and absolute input/output paths are accepted by the release wrapper;
relative paths are normalized against the caller's working directory before
`build.sh` changes directory. Final symlinks are still rejected where required.
Both wrappers embed their profile and use their native executable as
CFBundleExecutable. `ea-cli` is signed separately as the helper's sibling,
then the wrapper is sealed; blanket `codesign --deep` is not used. Release
verification checks all three identities, exact entitlements and profiles.

An operator must explicitly approve and execute installation as root. Supply
every affected non-root OS account UID, repeating `--account-uid` as needed:

```sh
rtk proxy sudo /bin/sh crates/ea-admin/native/macos/install.sh \
  --release /absolute/release-directory --team REALTEAMID --account-uid 501
```

The fixed install root is `/Library/Application Support/Einsatzarchiv`.
The installer stages and revalidates signed bytes under a root-only directory,
stops the old monitor, takes each existing namespace's native marker lock,
unlinks only its fixed `installation-v1`, syncs the directory, and holds those
locks through bundle publication. The account home comes from the OS account
database. Marker symlinks/hardlinks and unexpected ownership/modes fail.
Install/restore never enumerate or delete Keychain entries. Old ciphertexts
remain unreachable without the deleted wrapping key.

`restore.sh` performs the same protected bundle replacement and explicit
namespace invalidation **after** application/profile/backup restoration has
finished and **before** reopening the runtime. Thus a marker retained by an
in-place restore is invalidated too. The backup restore itself uses the
deployment's backup tooling. Run `restore.sh` with the same explicit release,
Team and affected-UID arguments. Complete external reidentification, revoke
the old binding and provision a new binding; neither script invents identity.
Do not restore a marker again afterward. Arbitrary full-system/APFS rollback
is not solved, and unlinking does not erase historical snapshots.

Installation leaves the service stopped. After explicit deployment approval,
the real ES entitlement/profile and required Full Disk Access approval must
be in place. The operator then starts the installed launchd job:

```sh
rtk proxy sudo /bin/launchctl bootstrap system \
  /Library/LaunchDaemons/org.einsatzarchiv.operator.monitor.plist
```

Complete an OS login or lock/unlock **after monitor startup**, then invoke the
CLI from the installed helper bundle's `Contents/MacOS/ea-cli` in the actual
user GUI session, without sudo. This supplies the observed initial event and
ES heartbeat before the CLI's 10-second watch handshake. Missing deployment
approval, entitlement, native coverage or initial event returns a closed
failure; the helper never opens an OS permission panel automatically.

## Evidence and remaining acceptance

After the independent review fixes on 2026-09-06, the final
`rtk proxy sh crates/ea-admin/native/macos/verify.sh` exited **0** with
**234 self-tests (91 provider + 143 watcher/monitor), 33 production protocol
cases, 23 watch-pipe scenarios and 12 release fixture tests**. The three original
Mac requirement probes now exit 0; the stopped-watch parent integration remains
the Rust owner's responsibility. Both production binaries also build for the
arm64 macOS 13 target with Swift 6 warnings as errors. Exact RED/GREEN commands,
fixture boundaries and acceptance limits are in [VERIFICATION.md](VERIFICATION.md).

Before this review fix, on 2026-09-06,
`rtk proxy sh crates/ea-admin/native/macos/verify-watch.sh`
exited 0: **91 watcher/monitor state assertions, 8 watch-pipe scenarios,
33 production protocol cases, and 10 release fixture tests**. Both optimized
production executables built with warnings as errors and a macOS 13 deployment
target on this arm64 host. The standalone `build.sh` also exited 0; shell syntax
checks passed. This is build/fixture evidence, not a macOS 13 runtime test.

The pre-fixture combined `verify.sh` reproducibly exited 1 with
`account-unavailable` at its real OpenDirectory read under the sandbox.
After separating live OS probes, the combined command exited **0** in the same
sandbox: **182 self-tests (91 provider + 91 watcher), 33 production protocol
cases, 8 watch-pipe cases and 10 release fixture tests**. The original 89
provider/parser/crypto assertions are retained with synthetic account values;
two positive backup-policy invocation checks make the provider count 91.
The existing negative policy, account-change, locked-store, crypto binding,
marker removal/recreation, symlink, permissions and reset cases all execute.

`verify-watch.sh` builds both production binaries with Swift 6 warnings as
errors, runs isolated watcher/ES-state fixtures, retained anonymous-pipe
scenarios, production parser rejection cases, and release validation fixtures.
It never creates an ES client, runs the root daemon, launches a permission
dialog, or mutates a production Keychain/marker. Default `verify.sh` uses only
`SELF_TEST` typed account and backup-policy injection for the provider tests;
it has no live account-directory or production Keychain dependency. Marker
filesystem operations and CryptoKit remain real and use disposable data.

The explicit `verify-host-read-only.sh` suite preserves the three live account
checks and two effective Foundation exclusion probes on disposable public
files. It is compile-checked by the default suite, but was not executed during
this fixture change. A failed manual OS probe is never turned into a passing
test or a skipped provider regression. No escalation, dialog or host permission
change was used to make the combined suite pass.

Real signed wrapper launch, dynamic peer validation between entitled deployed
binaries, Keychain/presence behavior, ES delivery including its exit heartbeat,
physical lock/unlock/switch/sleep, service crash/restart, and install/restore
on a controlled account remain unaccepted. Fixture success is not §6.8 OS
acceptance. The parent owns integration and independent re-review.

Primary API references: [EndpointSecurity client requirements](https://developer.apple.com/documentation/endpointsecurity/client),
[login-window lock event](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_lw_session_lock),
[message sequence fields](https://developer.apple.com/documentation/endpointsecurity/es_message_t),
[event generation time](https://developer.apple.com/documentation/endpointsecurity/es_message_t/mach_time),
[NSWorkspace session resignation](https://developer.apple.com/documentation/appkit/nsworkspace/sessiondidresignactivenotification),
[dynamic code validation](https://developer.apple.com/documentation/security/seccodecheckvalidity(_:_:_:)),
[macOS Keychain entitlement requirements](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains).
The local macOS SDK's EndpointSecurity/ESClient.h, ESMessage.h, ESTypes.h,
Security/CSCommon.h and notify_keys.h were also inspected directly.
