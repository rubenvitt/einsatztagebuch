# macOS provider verification

Run from the repository root:

```sh
sh crates/ea-admin/native/macos/build.sh
sh crates/ea-admin/native/macos/verify.sh
```

The final implementation and independent review runs on 2026-09-06 exited
successfully. The build produced the optimized helper and monitor for arm64,
macOS 13, with Swift 6 warnings treated as errors. The monitor was not launched.

| Verification | Passing assertions or scenarios |
| --- | ---: |
| Provider policies, CryptoKit and disposable marker fixtures | 91 |
| Watch state, framing, timing and invalidation | 143 |
| Production request protocol | 33 |
| Retained-pipe watch processes | 23 |
| Release scripts with synthetic compiler/signature/profile fixtures | 12 |

The watch checks cover a queued terminal event behind heartbeat traffic,
coverage expiry before heartbeat replacement, delayed source timestamps,
fresh challenge handling on the actual event loop, replay, malformed and
partial input, stopped processes and a fixed lifetime that ACKs cannot extend.
Three additional independent integration probes accepted a healthy challenge
and rejected queued run-loop invalidation and queued terminal monitor state.

Release fixtures exercise absolute and relative CLI/profile/output paths and
reject symlink inputs. Their signature/profile substitutes are test data;
successful fixtures do not mean that a release was actually signed.

The complete challenge and deployment contract is in
[WATCH-SESSION.md](WATCH-SESSION.md). The portable checks also run in the
[native operator CI workflow](../../../../.github/workflows/native-operator.yml).

## Native acceptance

These results do not cover actual entitled EndpointSecurity delivery and
latency, physical lock/switch/suspend, deployed signed peers, production
Keychain/presence, or authorized installation and restore. Those checks require
the signed release, real accounts and the restricted ES entitlement. Neither
unmanaged full-device snapshot rollback protection nor completed native
operational acceptance is claimed.
