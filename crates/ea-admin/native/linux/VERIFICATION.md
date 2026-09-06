# DRK-271 Linux helper verification — 2026-09-06

Scope: new files under `crates/ea-admin/native/linux/**` only. No commits,
Rust edits, macOS edits, host package installation, or changes to preexisting
services were performed for this implementation.

## Current challenge and managed-restore follow-up

Built in an explicitly owned Ubuntu 24.04 arm64 container,
`ea-drk271-linux-restore-235437d0`, from image
`ea-drk271-linux-restore:235437d0`, with the Linux source mounted read-only.
The current follow-up executed only temporary builds, private pipe/D-Bus/process
fixtures and temporary filesystem transactions. **No real installer, native
reset, Polkit prompt, PAM change, system service or native key change was run.**
`check-install` and `check-secret-service` were not rerun in this follow-up.

```sh
rtk proxy docker exec ea-drk271-linux-restore-235437d0 make BUILD=/tmp/ea-build check
```

| Current gate | Observed result |
| --- | --- |
| Normal GCC build with C11, warnings as errors and hardening | Exit 0 |
| Protocol/real OpenSSL crypto | 4 C groups passed |
| Native watch state, messages and event coverage | 20 C groups passed |
| Watch process stalls and private-pipe continuations | 6 Python tests passed, including actual SIGSTOP/SIGCONT and a blocked GLib callback |
| Real helper IPC / headless fail-closed behavior | 12 Python tests passed; no successful native readiness was simulated |
| Native maintenance guard | 1 C group passed against an owned temporary directory |
| Managed restore / reenrollment filesystem and process fixtures | 17 Python tests passed in Ubuntu; also passed on the macOS host using only owned temporary paths |
| GCC `-fanalyzer`, all production C | Exit 0, no diagnostic |
| AddressSanitizer + UndefinedBehaviorSanitizer, full `make check` | Same 25 C groups and 35 Python tests passed, exit 0, no sanitizer diagnostic |

Static analysis used a separate `/tmp/ea-analyzer` build with `-O0 -fanalyzer`.
The sanitizer build used `/tmp/ea-asan`, `-O1 -fsanitize=address,undefined
-fno-omit-frame-pointer` and matching sanitizer link flags. No source-tree build
output or host package changes were required.
After verification the exact owned container and its own image tag were removed
successfully. No shared containers, image tags or Docker resources were pruned.

The new valid challenge test was first observed **RED**: the old retained-input
handler rejected a legitimate post-ready challenge. The final tests exercise
exact public-ID/nonce acknowledgements, no response from the input callback,
new-probe gating, replay of a non-most-recent nonce, duplicate/escaped duplicate
members, wrong types, queued frames/partial frames, 1024-byte boundaries, bounded
history, EOF, one-second frame expiry, irreversible loop-gap expiry and the
unchanged 300-second cap. Queued native lock/unlock and other coverage events
win over a pending acknowledgement. A native query stalled on the private bus
continues to admit Lock events. The process fixture uses actual production
dispatch/drain/framing/clock functions but omits desktop/account acceptance;
only the test executable exposes that fixture mode.

The restore tests first failed with the entry point absent. Linux then exposed
a directory enumeration cache/cursor issue after a restore job: a second scan
could miss an unexpected final entry. The corrected fresh descriptor-relative
scan passes and preserves both marker and durable guard on that failure.
Fixtures also prove post-job invalidation of restored bytes and a replaced final
UID directory, dry-run immutability, active-operation/concurrent-maintenance
refusal, guarded job failure, manager-death lease inheritance, background-writer
refusal, symlink/path/mode/hardlink checks and explicit reenrollment recovery.
A further RED/GREEN regression prevents signaling a numeric process group after
the job leader was reaped: a reused group ID must never target an unrelated
process. The runner now stops only its still-owned direct child, retaining the
deny gate for administrator cleanup of any remaining descendants.
Native load/publish/recheck/reset all reject a matching maintenance record; its
creation and removal between watch requests permanently latch inotify invalidation.

## Earlier executed installation and native-storage gates

The following results predate the current challenge/restore additions. They are
retained as historical storage/installation evidence, not a claim that those
mutating gates were run again against this follow-up.

The initial implementation's complete shipped runner was executed from the
requested worktree:

```sh
rtk proxy sh crates/ea-admin/native/linux/verify-container.sh
```

Result: **exit 0**. That runner built its own Ubuntu 24.04 image, mounted the
source read-only, ran all three Makefile gates, and cleaned up its own container
and image. The watcher follow-up was built and tested in another explicitly
owned disposable container, `ea-drk271-linux-watch-235437d0`, with the same
Ubuntu Dockerfile and a read-only source mount:

```sh
rtk proxy docker exec -e EA_DISPOSABLE_TEST=1 ea-drk271-linux-watch-235437d0 make BUILD=/tmp/ea-build check check-install check-secret-service
```

Earlier watcher follow-up result: **exit 0**. The compilation used GCC with `-std=c11 -Wall -Wextra
-Wpedantic -Werror`, stack protection, PIE, RELRO and immediate relocation.
The follow-up container and its own `ea-drk271-linux-watch:235437d0` image were
removed successfully after verification. No preexisting services were changed.

| Gate | Observed result |
| --- | --- |
| `make check` | 4 protocol/crypto C groups, 11 watcher C groups and 12 Python subprocess tests passed |
| `make check-install` | 6 integration tests passed, including the C native-filesystem marker lifecycle test |
| `make check-secret-service` | Actual isolated GNOME Keyring storage and native event roundtrip passed |
| GCC `-fanalyzer` of all production C sources | Build exit 0, no diagnostic |
| AddressSanitizer + UndefinedBehaviorSanitizer | All 4 protocol/crypto and 11 watcher groups passed, exit 0, no sanitizer diagnostic |

Tested architecture: Linux aarch64 (arm64), Ubuntu 24.04. Library versions
reported by `pkg-config`: GIO/GLib 2.80.0, libsecret 0.21.4,
polkit-gobject 124, JSON-GLib 1.8.0, OpenSSL 3.0.13.
No x86_64, other Ubuntu version or real desktop acceptance result is claimed.

## Earlier evidence covered

- Closed/duplicate/escaped/oversized JSON rejection, EOF framing, lowercase hex,
  strict operation/slot-kind/presence combinations, stable failures and no stderr
  data, rejection of regular files and named FIFOs as secret transport.
- RFC 8032 Ed25519 reference signature plus actual OpenSSL verification,
  damaged-signature rejection, randomized AES-GCM envelopes, authentication of
  slot/kind/installation, every envelope-byte mutation, and refusal when the
  public ID substitutes for the secret wrapping key or either secret changes.
- Actual filesystem ownership/modes, `nodump` ioctls, directory locks,
  exclusive publication, account mismatch, missing marker, mode tampering,
  hardlinks, symlinks and marker reset.
- Real `getuid()` and exact machine-ID file bytes in IPC, mandatory conservative
  `locked:true` in a headless container, expected-installation rejection before
  authentication, and absence of the secret wrapping key in output.
- Newline watcher handshake with stdin retained, EOF-only watch rejection,
  unchanged EOF framing for normal operations (including trailing LF), no
  discarded pipelined input, and silent shutdown when the parent is already
  gone. The actual headless executable refuses readiness both without native
  installation and with a valid installed fixture marker.
- Exactly one readiness and at most one invalidation frame, public ID only;
  terminal EOF handling (post-ready challenge input is extended above), irreversible deadline expiry, typed
  session/suspend state and missing/wrong-type property rejection.
- Actual GDBus signal delivery from pinned unique service owners on a private
  test bus: Lock/Unlock bursts, PropertiesChanged, seat/session/user changes,
  suspend/shutdown, keyring events, owner disappear/reappear, wrong owner UID,
  disconnect and unknown signals. Spoofed sender events do not impersonate the
  pinned service. Lock arrives while an asynchronous native probe remains
  unanswered, before that query's timeout.
- Actual inotify change-and-restore and rename-and-restore events and watch
  removal; deterministic overflow, unknown descriptor and malformed-record
  coverage tests use kernel event record formats without flooding host limits.
- Installed GNU-tar wrapper produces an archive without the marker tree or
  `.pending` data; direct and symlink sources inside the excluded tree are
  refused, caller `TAR_OPTIONS` cannot override exclusions, removal of the
  installed policy blocks the helper, and existing account directories are
  not silently reenrolled.
- The real native `reset` entry point with matching installation and
  `presence:true` refuses the headless account with `locked`; marker bytes remain
  unchanged. This proves denied-reset enforcement, not a positive Polkit prompt.
- Real libsecret/GIO calls against a private `gnome-keyring-daemon`: native
  account-instance item creation, exclusive generation, Ed25519 sign/verify,
  wrap/unwrap, missing secret components, idempotent delete, absent `contains`
  and actual collection-lock rejection. The resolved collection path was the
  GNOME PAM login collection. This caught and corrected GNOME's return of
  `text/plain` MIME metadata for binary stored secrets.
  With the native watcher attached, regular generate/wrap/delete operations
  leave it active, while the real collection-lock event invalidates it.

The pipe and backup-source tests were observed failing before their corrections,
and the native keyring test was observed failing on the MIME assumption before
the corrected final successful run. The watch request was first observed
failing the new protocol test, and the actual keyring test reproduced overbroad
invalidation on ordinary key creation before the corrected filter passed.
Tests operate on the implementation, not
source-text snapshots or mock signing algorithms.

## Required qualification

The actual keyring test uses an independently generated **test-keyring**
passphrase and calls the internal storage layer. No OS account password is
used. Installation tests use a synthetic PAM configuration and marker fixtures.
Neither is a positive PAM/Polkit/logind authentication observation. No stub
presence result exists in the production helper.
The watcher tests' private D-Bus only supplies deterministic native messages;
they do not cause the production helper to report a simulated desktop ready.
Real GNOME lock/user-switch/suspend observation with the complete parent/helper
chain remains required. Logind events conservatively include unrelated system
activity, so real-desktop availability also remains to be assessed.

The public installation ID and secret marker wrapping key are independent.
A third secret lives only in the native login collection. HKDF requires both
secrets for AES-GCM key recovery; private signing seeds never leave the helper
over IPC or persist in the marker. The exact storage layout and parent IPC
constraints are documented in [README.md](README.md).

Full §6.8 acceptance is **not established**: native GNOME lock/user-switch,
suspend and fresh Polkit `auth_self` dialogs still need real desktop observation,
including the parent's challenge deadline before and after sensitive calls.
The managed restore path now implements final namespace invalidation under
leases; its root-controlled job must actually be deployed and obey the documented
foreground/final-write/control-tree restrictions. This administrative action is
not native authenticated reset and produces no user-presence evidence. No parent
native operation extension is required; `ok:false` maintenance refusals already
fail closed. User-facing revocation, reidentification and fresh binding issuance
remain the parent's/deployment's responsibility.

An unmanaged in-place restore can retain the old marker; a full snapshot can
restore both secrets and the control tree. Neither is detected by backup flags
or by this opt-in managed path. Existing backup jobs and account-deletion tools
are not automatically converted. The initial installer still refuses an existing
UID directory; explicit managed reenrollment now invalidates its marker while
retaining the empty enrollment directory, without impersonating its owner or
creating a replacement marker. Exact usage and limits are in
[README.md](README.md#managed-restore-and-reenrollment).
