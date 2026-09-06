# macOS native operator provider

`ea-native-operator` is a Swift executable with ordinary single-request calls
and a provider-lifetime `watch-session` operation. It uses OpenDirectory,
LocalAuthentication, the Security data-protection Keychain and CryptoKit. Its
JSON interface and exact backup/reset semantics are in [INTERFACE.md](INTERFACE.md).
Rust owns trust verification, external reidentification, authorization, fresh
domain-separated challenges, audit, session expiry and IPC launch.

The watcher now uses a separate signed privileged EndpointSecurity monitor.
Concrete signed build/install/restore scripts, startup requirements, exact
event coverage and the unaccepted native runtime boundary are documented in
[WATCH-SESSION.md](WATCH-SESSION.md). No privileged service was installed or run.

## Build and safe verification

From the repository root, on macOS with the Xcode Swift compiler:

```sh
rtk proxy sh crates/ea-admin/native/macos/build.sh
rtk proxy sh crates/ea-admin/native/macos/verify.sh
```

`build.sh` creates `macos/build/ea-native-operator` and `ea-native-monitor` (or the directory supplied as
its first argument, resolved relative to this source directory). It compiles an
optimized standalone Mach-O executable; it does not sign, install or execute it.
All modules are system frameworks; no package manager or Rust manifest changes
are needed. This is a host-target build, not a cross-platform acceptance result.

`verify.sh` typechecks with Swift 6 and warnings as errors, builds a separate
self-test executable, then runs provider, watcher, production parser/transport
and release fixtures. Real CryptoKit signing/verification/encryption and native
marker file locking, permissions, exclusive publication and reset are exercised
under an isolated `/private/tmp/ea-native-isolated-*` directory removed on exit.
Markers contain disposable random wrapping keys, not production secrets.

The provider tests use the existing `SELF_TEST`-only typed account-reader
injection with a synthetic GUID, an in-memory Keychain, simulated presence and
lock transitions, and explicit backup-policy fixtures. `getuid()` supplies
temporary-file ownership; no OpenDirectory query or real account GUID/home
lookup runs. Positive fixture checks verify that both directory and marker
backup-policy checks are invoked; the existing negative exclusion test still
proves rejection before Keychain access. Native `evaluatePolicy` and production
Keychain operations never run. There is no production switch for these fixtures.

The original live OpenDirectory and effective Foundation exclusion probes are
in the explicit manual `verify-host-read-only.sh` suite. It reads the current
account and checks exclusion on disposable public files in `/private/tmp`,
printing only counts. The default suite compile-checks this probe without
executing it. A host probe denial remains a failed OS probe, but cannot strand
the provider algorithm tests. Run it only as part of separately authorized
native host validation; it does not test Keychain, presence dialogs or ES.

## Signing and installation contract

A bare or ad-hoc-signed Swift binary is sufficient for the tests above, but is
not sufficient evidence of production data-protection Keychain access. Apple's
[TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
requires access-group entitlements authorized by a provisioning profile and an
app-like wrapper for a command-line tool that uses them. The helper must run in
the actual user's GUI login context; a root daemon or `sudo` cannot impersonate
the intended operator. No legacy-login-Keychain fallback exists.

The release owner must package the helper according to Apple's
[restricted-entitlement wrapper instructions](https://developer.apple.com/documentation/xcode/signing-a-daemon-with-a-restricted-entitlement).
Use the registered helper bundle ID, real team ID and a provisioning profile
authorizing `com.apple.application-identifier`,
`com.apple.developer.team-identifier`, and its dedicated `keychain-access-groups`.
The helper should be the bundle's `CFBundleExecutable` and retain its exact
name `ea-native-operator`. One structure compatible with the bridge's sibling
lookup is an app-like wrapper containing both the helper main executable and
the separately signed Rust CLI as a sibling:

```text
EinsatzarchivNative.app/
  Contents/
    Info.plist                 CFBundleExecutable = ea-native-operator
    embedded.provisionprofile  authorizes the helper's restricted entitlements
    MacOS/
      ea-native-operator       signed helper, dedicated keychain access group
      ea-cli                   separately signed invoking Rust executable
    _CodeSignature/
```

This packaging layout is implemented by `build-signed.sh`, but is not an executed
production signing test. The parent must be invoked from its final location so its sibling
lookup finds this exact helper. Distribution signing, profile validation and
the native acceptance run must confirm the arrangement on the supported Macs.
Do not copy only the helper binary out of its signed wrapper. Do not launch it
via PATH, a shell, environment overrides, or a profile-selected path. Use
Hardened Runtime without get-task-allow or disabled library validation; sign
nested code separately and then seal the wrapper (no blanket `codesign --deep`).

For ordinary IPC the parent supplies dedicated anonymous stdin/stdout pipes, closes
stdin after at most 65,536 bytes, bounds output and lifetime, suppresses payload
logging, checks the signed helper identity and rechecks account/installation
before and after each operation. The helper rejects regular files, terminals
and named FIFOs for these endpoints. Anonymous pipes prove transport type,
not the peer's signing identity; peer/process integrity remains the installer's
and parent's responsibility. OS-account results must not enter persistent logs.
The retained watch instead accepts one fresh nonce challenge at a time after
readiness. The parent requires an exact response within one second before and
after every sensitive call. Acknowledgements run on the native subscriber's
event loop after draining coverage; a stopped or stalled loop cannot continue
to attest to a valid session. Challenges never extend the 300-second lifetime.
See [WATCH-SESSION.md](WATCH-SESSION.md) for strict framing and terminal rules.

## Native protections and boundaries

OpenDirectory queries exactly `UniqueID == getuid()`, rejects multiple records,
reads `GeneratedUID` and `UniqueID` in one details call on the same record,
validates the GUID and exact numeric UID, and rechecks real/effective UID. The
account is read again around sensitive operations. No profile field or username
is accepted as identity and no Root/Admin key is enumerated or automatically
selected. The six agreed slot names are explicit local handles, not role proofs.

Lock detection requires a matching active GUI console session and a successful
non-interactive read of the installation's
`WhenUnlockedThisDeviceOnly` Keychain sentinel. Missing/unknown console state
means locked; unavailable/invalid Keychain state either means locked or an
error. A lock after secret retrieval suppresses the response. The parent still
owns proof invalidation and the five-minute session limit. Its retained
`watch-session` child continuously listens to the authenticated ES monitor;
ordinary short-lived calls still perform their own boundary checks.

Operator/Admin/Root (and any custom Ed25519 slot except `writer-signing`) have
Keychain `.userPresence` access control; signing requires `presence:true`.
A new LAContext has zero Touch-ID reuse duration and explicitly evaluates
`deviceOwnerAuthentication` once. Subsequent Keychain calls cannot prompt.
Writer signing and database/draft secrets remain restricted to the unlocked
account and the separate excluded marker wrapping key. Native dialogs may use
Touch ID, Watch or the OS-owned password fallback; no OS password enters the
helper. The policy is documented by
[Apple](https://developer.apple.com/documentation/localauthentication/lapolicy/deviceownerauthentication).

Keychain stores only ChaChaPoly ciphertexts of Ed25519 seeds and secret32
values. The independent excluded-marker key, per-item fresh nonce and
authenticated installation/account/slot/kind/public-key metadata are required
for decryption. Public-key lookup reads metadata only. Ed25519 seeds are
CryptoKit software keys protected by Keychain and the marker; they are not
claimed as Secure Enclave Ed25519 keys. File mode 0600 plus a required native
Keychain is the macOS account protection for the marker scheme.

Full same-device snapshots, retained markers during in-place restores,
malicious same-account processes, privileged debugging, process-memory copies
and APFS historical snapshots are not solved by this helper. Follow the reset
and reidentification procedure in INTERFACE.md. In particular, Apple's
[ThisDeviceOnly semantics](https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility)
permit same-device restore, and
[backup exclusion](https://developer.apple.com/documentation/foundation/optimizing-your-app-s-data-for-icloud-backup)
is a policy rather than anti-rollback hardware. Keychain restoration without the
excluded secret marker key cannot decrypt the application ciphertexts.

## Additional official API references

- [OpenDirectory](https://developer.apple.com/documentation/opendirectory)
- [CGSessionCopyCurrentDictionary](https://developer.apple.com/documentation/coregraphics/cgsessioncopycurrentdictionary())
- [Data-protection Keychain selection](https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain)
- [Keychain user-presence access control](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [CryptoKit Ed25519 private keys](https://developer.apple.com/documentation/cryptokit/curve25519/signing/privatekey)
- [ChaChaPoly authenticated encryption](https://developer.apple.com/documentation/cryptokit/chachapoly)

The design and ADR sources read for this implementation are §6.8, the canonical
macOS account section of the v0.1 wire addendum, ADR 0001 and ADR 0002. ADR 0003
was absent when implementation started; the parent owns that dependency ADR.

## Original provider verification record: 2026-09-06

On this Mac: macOS 27.0, arm64, Apple Swift 6.4
(`swiftlang-6.4.0.20.104`, clang `2100.3.20.102`).

- `rtk proxy sh crates/ea-admin/native/macos/build.sh`: exit 0; optimized
  `build/ea-native-operator` is a Mach-O 64-bit arm64 executable.
- `rtk proxy sh crates/ea-admin/native/macos/verify.sh`: exit 0 with authorized
  read-only OpenDirectory access; Swift 6 typecheck with warnings as errors,
  **89 self-test assertions** and **26 production-binary protocol cases** passed.
- The default execution sandbox denied OpenDirectory (`account-unavailable`);
  the successful account test used the same sources outside that sandbox.

The real native Keychain mutation, fresh-presence dialog, physical screen-lock,
distribution entitlement/profile and backup/restore acceptance tests were not
performed. They require the parent's coordinated signed installation and a
controlled account. Simulated provider tests are not reported as those native
acceptance results. No production marker or Keychain was created/reset by this
verification. The excluded marker's full-snapshot/in-place-restore limitation
remains as documented in INTERFACE.md.

The original counts above predate the watcher extension and fixture separation.
On 2026-09-06 the updated `verify.sh` exited 0 in the default sandbox with
**182 self-tests (91 provider + 91 watcher), 33 production protocol cases,
8 watch-pipe cases, and 10 release tests**. The provider count retains the
original 89 assertions, using synthetic account values for its account checks,
and adds two positive backup-policy invocation checks. No provider algorithm
test was skipped. The manual live-account/exclusion suite was compile-checked,
not executed. Further deployment and acceptance evidence is in
[WATCH-SESSION.md](WATCH-SESSION.md).

The subsequent independent-review fixes have a final sandbox exit **0** with
**234 self-tests (91 provider + 143 watcher/monitor), 33 production protocol
cases, 23 watch-pipe scenarios and 12 release fixture tests**. The original
queued-terminal, heartbeat-gap and relative-output requirement probes now pass.
Challenge acknowledgements also pass stopped-process and stalled-native-loop
fixtures. Exact commands, scopes and remaining acceptance are recorded in
[VERIFICATION.md](VERIFICATION.md).
