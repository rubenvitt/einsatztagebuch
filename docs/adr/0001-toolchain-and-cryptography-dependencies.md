# ADR 0001: Toolchain and cryptography dependencies

- Status: Accepted
- Decision date: 2026-08-13
- Evidence retrieved: 2026-08-13; timezone evidence refreshed 2026-08-14

## Context

Einsatzarchiv needs reproducible developer gates and a deliberately small Rust
trust core. Suite 1 requires deterministic CBOR, COSE Sign1, SHA-256, Ed25519,
ChaCha20-Poly1305, and HPKE Base Mode with X25519/HKDF-SHA-256/
ChaCha20-Poly1305. Production code remains on a stable MSRV, while libFuzzer
requires a separately pinned Nightly and `cargo-fuzz` executable.

All version requirements in `[workspace.dependencies]` are exact. A dependency
is inherited by a member only when that member has real code or tests that use
it. Consequently, Task 1's `Cargo.lock` resolves the `toml` parser used by
`xtask` and the system-test package; the predeclared Suite 1 dependencies enter
the lockfile only when their concrete crates are added. This avoids dummy uses
while keeping the reviewed decisions centralized.

## Toolchain decision

| Tool | Exact pin | Evidence and rationale |
| --- | --- | --- |
| Rust production toolchain | `1.95.0` | Installed `rustc 1.95.0 (59807616e 2026-04-14)` and `cargo 1.95.0 (f2d3ce0bd 2026-03-21)` were verified locally. `rust-toolchain.toml` also installs `rustfmt` and `clippy`; the workspace MSRV is `1.95`. |
| Node.js | `26.7.0` | Installed `node v26.7.0` was verified locally and is pinned in `.node-version` plus `package.json`. |
| pnpm | `11.20.0` | Installed pnpm `11.20.0` was verified locally and is pinned by `packageManager` plus the package engine. |
| Fuzz Nightly | `nightly-2026-08-13` | The [official dated Rust distribution manifest](https://static.rust-lang.org/dist/2026-08-13/channel-rust-nightly.toml) and its [SHA-256 file](https://static.rust-lang.org/dist/2026-08-13/channel-rust-nightly.toml.sha256) exist. Installation resolved `rustc 1.99.0-nightly (c98d0cb27 2026-08-12)`. A date is used so fuzz builds never drift with ambient `nightly`. |
| cargo-fuzz | `0.13.2` | The [crates.io release](https://crates.io/crates/cargo-fuzz/0.13.2), [official sparse-index record](https://index.crates.io/ca/rg/cargo-fuzz), and [upstream project](https://github.com/rust-fuzz/cargo-fuzz/) identify this non-yanked release. It was installed with `cargo install cargo-fuzz --version 0.13.2 --locked`, and `cargo +nightly-2026-08-13 fuzz --version` returned `cargo-fuzz 0.13.2`. |

`.cargo/fuzz-toolchain.toml` is the machine-readable source for the last two
pins. `xtask test-fuzz` validates the installed `cargo-fuzz` version, requires
`fuzz/Cargo.lock`, proves the fuzz manifest resolves with `cargo metadata
--locked`, reads targets from `fuzz/Cargo.toml`, and invokes
`cargo +nightly-2026-08-13 fuzz` without a shell. Its default smoke duration is
60 seconds; callers may select `--smoke-seconds` and `--target`.

## Format and cryptography decision

Crate metadata, MSRV, features, repository, and license were checked in the
official crates.io records linked below. Every selected release supports Rust
1.95. The [RustSec advisory database](https://github.com/RustSec/advisory-db)
is the vulnerability source for the supply-chain gate; `deny.toml` denies
yanked crates and unknown registries or Git sources. This review is a
dependency-risk decision, not a claim that every crate has received an
independent formal audit.

| Dependency | Exact pin and enabled features | Role, maintenance, and security rationale |
| --- | --- | --- |
| [`minicbor`](https://crates.io/crates/minicbor/2.3.0) | `2.3.0`; `derive`, `std` | The [upstream project](https://github.com/twittner/minicbor) provides a small, actively released low-level CBOR codec. It is wrapped by Einsatzarchiv's bounded deterministic decoder; upstream decoding is never treated as sufficient validation. `std` supplies allocation support and `derive` is limited to non-security-sensitive data shapes. |
| [`coset`](https://crates.io/crates/coset/0.4.2) | `0.4.2`; `std` | Google's [upstream COSE types](https://github.com/google/coset) track RFC 9052 structures and report MSRV 1.81. Einsatzarchiv uses the types and algorithm identifiers, but signs and verifies exact deterministic bytes through its own format boundary. |
| [`sha2`](https://crates.io/crates/sha2/0.11.0) | `0.11.0`; defaults off, `zeroize` | The maintained [RustCrypto hashes project](https://github.com/RustCrypto/hashes) supplies SHA-256 required by Suite 1 and reports MSRV 1.85. Defaults are disabled to omit unused OID/allocation support; zeroization integration is retained for sensitive intermediate state. |
| [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek/3.0.0) | `3.0.0`; defaults `fast`, `zeroize`, plus `rand_core` | The maintained [dalek upstream](https://github.com/dalek-cryptography/curve25519-dalek/tree/main/ed25519-dalek) supplies Suite 1 signatures and reports MSRV 1.85. Zeroization stays enabled; `rand_core` supports generated signing keys. Hazardous and legacy-compatibility features remain disabled. |
| [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305/0.11.0) | `0.11.0`; defaults `alloc`, `getrandom`, plus `zeroize` | The maintained [RustCrypto AEAD implementation](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305) implements RFC 8439 ChaCha20-Poly1305 and reports MSRV 1.85. The selected features support fresh keys/nonces and clear sensitive state; reduced-round variants remain disabled. |
| [`hpke`](https://crates.io/crates/hpke/0.14.0) | `0.14.0`; defaults off, `alloc`, `getrandom`, `x25519`, `chacha` | The active [rust-hpke upstream](https://github.com/rozbb/rust-hpke) implements RFC 9180 and reports MSRV 1.85. `x25519` brings HKDF-SHA-256; only the exact Suite 1 KEM/KDF/AEAD is enabled. Default ML-KEM, SHAKE, NIST curves, and AES are intentionally excluded. |
| [`getrandom`](https://crates.io/crates/getrandom/0.4.3) | `0.4.3`; defaults on, plus `wasm_js` | The maintained [rust-random upstream](https://github.com/rust-random/getrandom) supplies the operating system entropy source used by the single production call site `crates/ea-crypto/src/hpke.rs`. It is also pulled in transitively by `chacha20poly1305` and `hpke`. The `wasm_js` feature selects the Web Crypto backend required to compile for `wasm32-unknown-unknown`, which the Web-Reader design (`docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §9-§10) makes a binding target for the shared verification pipeline. The feature is a host no-op: upstream gates `wasm-bindgen` and `js-sys` behind `cfg(all(target_family = "wasm", …))`, so enabling it adds two lockfile edges and no packages. The `--cfg getrandom_backend` mechanism belongs to `getrandom 0.3` and is deliberately NOT used; for 0.4.3 the feature alone is sufficient, which keeps the selection in the manifest instead of in silently overridable `RUSTFLAGS`. |
| [`zeroize`](https://crates.io/crates/zeroize/1.9.0) | `1.9.0`; default `alloc`, plus `derive` | The maintained [RustCrypto utilities project](https://github.com/RustCrypto/utils) guarantees compiler-resistant memory clearing and reports MSRV 1.85. Derive support makes secret-owning types fail visibly if their clearing contract is removed. Zeroization reduces residual-memory exposure but does not promise protection from swapping, crash dumps, or copied buffers. |
| [`toml`](https://crates.io/crates/toml/0.8.23) | `0.8.23`; defaults `parse`, `display` | The [toml-rs upstream](https://github.com/toml-rs/toml) parser supports the brief's required `str.parse::<toml::Value>()` document API and reports MSRV 1.66. Releases 0.9.8 and 1.1.4 were rejected after the prescribed smoke API failed on a complete manifest; 0.8.23 is therefore the latest verified compatible line, not merely the numerically newest release. It is tooling-only and outside the wire-format trust boundary. |
| [`jiff`](https://docs.rs/crate/jiff/0.2.35) | `0.2.35`; defaults off, `std`, `tzdb-bundle-always` | The [published 0.2.35 manifest](https://docs.rs/crate/jiff/0.2.35/source/Cargo.toml.orig) defines `tzdb-bundle-always` as the explicit embedded-database feature and depends on `jiff-tzdb` 0.1.8. Upstream documents MSRV 1.70, so the release is compatible with the workspace's Rust 1.95. Only an explicitly constructed `TimeZoneDatabase::bundled()` is permitted for payload validation; global/system lookup APIs are not. |
| [`jiff-tzdb`](https://docs.rs/crate/jiff-tzdb/0.1.8) | `0.1.8` | This exact direct pin prevents the bundled IANA data from drifting under Jiff's compatible dependency range. Jiff's [upstream changelog](https://docs.rs/jiff/0.2.35/jiff/_documentation/changelog/index.html#0232-2026-07-08) records tzdb `2026c`; the crate embeds TZif data. Its [`get`](https://docs.rs/jiff-tzdb/0.1.8/jiff_tzdb/fn.get.html) API returns the stored canonical capitalization even though lookup is ASCII-case-insensitive, permitting fail-closed exact-name comparison before parsing. The crate reports MSRV 1.70 and is compatible with Rust 1.95. |
| [`argon2`](https://crates.io/crates/argon2/0.6.0) | `0.6.0`; defaults off, `zeroize` | The maintained [RustCrypto password-hashes project](https://github.com/RustCrypto/password-hashes/tree/master/argon2) implements RFC 9106 Argon2id in pure Rust and reports MSRV 1.85, compatible with the workspace's Rust 1.95. It is the passphrase KDF of the recovery key container `EINSATZARCHIV-KEY-CONTAINER-v1` (`crates/ea-recovery/src/encrypted_container.rs`) and nothing else. Parameters are pinned in code and in the container header, and decoding accepts exactly them: `m = 65536 KiB`, `t = 3`, `p = 4` (RFC 9106 §4, second recommended option), version `0x13`, 32-byte output. Defaults are disabled: `password-hash` (PHC strings, `getrandom` via `password-hash`) is not used because the container carries salt and parameters itself in deterministic CBOR, and `alloc` stays off because it is declared as `password-hash?/alloc` and even that weak reference makes Cargo lock `password-hash` and `phc` without building them — `ea-recovery` hands the KDF its memory blocks through `hash_password_into_with_memory` instead. `zeroize` clears those blocks. `parallel` (rayon) stays off; lanes are computed sequentially with an identical result. The derived key feeds the already pinned ChaCha20-Poly1305 behind `ea_crypto::aead_seal`/`aead_open` with the container header as AAD; no second AEAD enters the graph. The reviewed feature selection is `argon2 = ["zeroize"]`. Transitively it adds `blake2 0.11.0` (same project, MIT OR Apache-2.0) to the lockfile; `base64ct` (a dependency of `argon2`) and `cpufeatures` were already present, so `blake2` is the only new crate. |

## Rejected alternatives

- Hand-written CBOR and COSE implementations were rejected because parsing and
  cryptographic structure code are high-risk. `minicbor` and `coset` are used
  behind strict local boundaries instead.
- `serde_cbor` was rejected because it is unmaintained according to
  [RUSTSEC-2021-0127](https://rustsec.org/advisories/RUSTSEC-2021-0127.html)
  and does not provide the required fail-closed deterministic validation
  boundary.
- Accepting any encoding that round-trips through a generic CBOR library was
  rejected. The wrapper must enforce depth, item, string/byte, integer, map-key,
  duplicate-key, float, indefinite-item, trailing-byte, and re-encoding rules.
- OpenSSL and `ring` as suite-wide abstractions were rejected to avoid native
  toolchain variance and opaque algorithm selection. The chosen pure-Rust
  crates expose the exact Suite 1 algorithms independently.
- AES-GCM, NIST curves, ML-KEM, SHAKE, reduced-round ChaCha, Ed25519 legacy
  compatibility, and hazardous signing APIs were rejected because Suite 1
  does not permit them. They remain feature-disabled.
- Ambient `nightly`, unpinned `cargo-fuzz`, and a fuzz build without
  `fuzz/Cargo.lock` were rejected because they cannot reproduce a historical
  fuzz result.
- Host `/usr/share/zoneinfo`, `TZ`, `TZDIR`, Jiff's global database, and
  case-insensitive acceptance were rejected for payload validation because
  they make a stored incident's local-calendar interpretation depend on the
  machine or execution date. `Etc/Unknown` is also rejected as a payload zone.
- scrypt and PBKDF2 were rejected as the passphrase KDF of the recovery key
  container in favour of Argon2id: RFC 9106 is the current IETF
  recommendation, Argon2id resists both side-channel and GPU/ASIC
  trade-off attacks that PBKDF2 does not address at all and scrypt addresses
  only partially, and the RustCrypto `argon2` crate carries it without a
  native dependency. A container that named its KDF but let the header choose
  the parameters was rejected as well: the values in the header describe, they
  do not negotiate, and decoding accepts exactly the pinned triple.

## Blocked: detached signatures over a verification report

`design.md`:1781 makes the report signature conditional: the report "is hashed
and, *if an authorized signing role is available*, signed". Suite 1 defines no
such role, so the recovery CLI accepts `--report-signing-key` and refuses the
run with exit code `21` (`Unsupported`), naming the missing element. Without the
switch the report is emitted hashed and unsigned, with `reportSignature` absent
— which is the conformant result, not a degraded one. A hand-rolled COSE_Sign1
built in `ea-recovery` from `ed25519-dalek` and the public
`ProtectedHeader::sig_structure_bytes` is explicitly rejected: it would duplicate
format-critical logic outside the cryptography boundary this ADR establishes.

Five closed-crate facts block the feature, all in `crates/ea-crypto/src/cose.rs`:

| Line | Fact |
|---:|---|
| `:25` | `ContentType` enumerates eleven signable payload kinds; none is a verification report. |
| `:97` | `TryFrom<&str> for ContentType` rejects every other media type with `CryptoError::UnsupportedSuite`, so `ea.verification-report/v1` cannot be introduced by a caller. |
| `:332` | `sign_normal` explicitly refuses `RecoveryTestDigest` and `DeviceRegistrationRequestCbor`, so repurposing an existing digest type is actively blocked, not merely inelegant. |
| `:567` | `CoseSigner::sign` is private; every public entry point is bound to a `ContentType`. |
| `:816`, `:1543` | `SignerRole` defines no report-signing role and the private `CertificateCapability` defines no report capability — so the *verification* side is missing too, and a `verify_report_signature` would have no implementable body. |

Unblocking it is a specification decision, not an implementation task, and needs
all three parts together before any code changes: a new `ContentType` for
`ea.verification-report/v1` (with its media type registered in the wire-format
addendum), a `SignerRole` authorized to sign reports, and a matching
`CertificateCapability` so signatures can be verified as well as produced. Each
extends the closed Suite 1 surface and therefore requires a new ADR, updated
schemas, and test vectors covering both directions.

### Delivery ledger for Stage-1 Task 10

Recorded here rather than in a new document because the one part that is *not*
delivered is the deferral above, and a ledger that points at its own reason from
another file drifts away from it.

Delivered, each measured by a test that starts the real binary:

| Part | Where it is measured |
|---|---|
| The closed command grammar (`verify`, `list`, `decrypt`, `report`, `export`, `--trust-anchor`, `--format text\|json`), parsed by hand without an argument-parser dependency | `apps/cli/tests/commands.rs` |
| The normative exit-code table `0/2/10/11/12/13/14/15/20/21`, smallest applicable specific code first, with the report keeping every finding | `crates/ea-recovery/tests/exit_codes.rs`, `apps/cli/tests/exit_codes.rs` |
| The canonical report document with `reportHash`, byte-identical across runs and independent of path order and of `--format` | `apps/cli/tests/determinism.rs` |
| `--include-runtime-metadata` as the only way runtime facts enter a document, appended after `reportHash` and outside its preimage | `apps/cli/tests/determinism.rs` |
| `decrypt` and `export`, both verifying in full before the first written byte, both writing only into a new or empty target with owner-only permissions | `apps/cli/tests/decrypt.rs`, `apps/cli/tests/export.rs`, `apps/cli/tests/safety_audit.rs` |

Not delivered, deliberately: the detached COSE_Sign1 signature over the report.
`--report-signing-key` is accepted and refused with exit code `21`; the reasons
and the three specification parts needed to unblock it stand in this section
above. `reportSignature` stays absent from every emitted document, which is the
conformant shape and not a degraded one.

One further limit belongs in the same ledger: the `wasm32-unknown-unknown` gate
over the positive list proves **compilability only**. It is not a runtime
result. The runtime evidence required by
`docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §14.1 —
a `wasm-bindgen` layer, `getrandom`/`wasm_js` in a real JavaScript environment,
one HPKE decapsulation and one signature check against a test vector — is still
outstanding. `ea-recovery` is exempt from that gate by design: it carries
`std::fs` and plaintext and is therefore not shared browser code.

## Historical boundary: PKCS#11 module binding

The boundary below records the original Task-7 delivery. It is superseded by
[ADR 0007](0007-offline-pkcs11-provider.md): the current resolver uses a real,
independently tested non-exporting provider within its explicit module profile.
The earlier evidence is retained here as the decision history.

`design.md` §16.1 names `pkcs11:` as a key source of the recovery CLI, and
Stage-5 Task 7 delivers its grammar in full: module path, token label and key
id are all mandatory, the PIN comes from a named file with owner-only
permissions, and nothing is defaulted, scanned or inferred from a "first
token" (`crates/ea-recovery/src/pkcs11.rs`, `src/key_source.rs`). What this
stage does NOT deliver is the binding to a module. A `pkcs11:` source is
resolved up to and including the PIN file and the existence of the module
file, and then the run refuses with exit code `21` (`Unsupported`) and the
named boundary `EA-RECOVERY-PKCS11-UNBOUND` — the same pattern as
`--report-signing-key` above: accepted, refused, named.

Three facts block the binding:

| Fact | Consequence |
|---|---|
| `cryptoki` loads a module at runtime through `cryptoki-sys` and `libloading`. | That is the same native-toolchain variance for which "Rejected alternatives" declines OpenSSL and `ring` as suite-wide abstractions (`ring` itself stays in the lockfile as a transitive dependency of `rustls`, see `deny.toml`; it is not selected as a Suite 1 primitive): a `dlopen` boundary whose behaviour depends on the host's loader, its library search path and the module's own build. |
| No PKCS#11 module exists in the tree, on the development host, or in the browsers container. | There is nothing a test could bind to; a binding without a witness would be a claim no test carries. |
| `libloading` is ISC-licensed. | `deny.toml` allows ISC only by named exception; a new crate under that licence needs its own line and its own justification. |

Unblocking it is one task with three parts that have to land together: an ADR
row for `cryptoki` (with `cryptoki-sys` and `libloading`) after primary-source
and RustSec review, plus the named ISC exception in `deny.toml` if the licence
gate requires it; SoftHSM provisioned in the browsers container as the witness
against which login, object lookup by `CKA_LABEL`/`CKA_ID`, decapsulation and
signing are measured; and the replacement of the boundary in
`crates/ea-recovery/src/key_source.rs` at exactly one place. Until then a
`pkcs11:` source is a fully validated reference that ends with `21`, never a
partial success.

## Development and test build profile

Decision date: 2026-09-14 (DRK-327, ruling by the repository owner).

The root `Cargo.toml` sets `[profile.dev] opt-level = 1` and
`[profile.dev.package."*"] opt-level = 2`. Until then the workspace had no
`[profile]` section, so every dependency — SQLCipher, the COSE, Ed25519, HPKE
and Argon2id stack — was compiled at `opt-level = 0`.

The trigger was the Stage-5 gate on `ubuntu-24.04`. The native process fixtures
in `apps/cli/tests/operator.rs` (`process_native::*`) run the real
`OperatorRuntime`, `DestructionRuntime` and administration rounds against fixed
product deadlines: an operator presence proof expires `MAX_INACTIVITY_MS`
(300 s) after issuance, and the administration fixtures wait at most 40 s for a
signed root reply. On the GitHub runner the unoptimized fixture setup crossed
both. With per-phase timestamps, `evidence_writer::adapter_lock_refuses_preview_without_reservation`
reached `start` after 134 s and failed in `resume_local` at about 305 s with
`EA-OPERATOR-PRESENCE-PROOF-INVALID` even when run alone (diagnostic run
34862813478); `separate_native_root_signs_the_exact_existing_admin_authorization_target`
crossed its 40 s reply wait in the same run. The same tests are green on the
development host. This is a test-speed gap against product constants, not a
Linux behaviour difference, and the constants are not relaxed for tests.

Measured locally on `linux/amd64` with a 4-CPU quota (the runner's core count),
same test, serial:

| Profile | `prepare` | `start` | `resume_local` | total | cold build of the `operator` target, 16 CPUs |
| --- | --- | --- | --- | --- | --- |
| no `[profile]` (before) | 31.6 s | 49.7 s | 88.1 s | 109 s | — |
| dependencies `opt-level = 2` only | 22.1 s | 37.3 s | 65.3 s | 80 s | 329 s |
| workspace `1`, dependencies `2` (selected) | 17.3 s | 29.6 s | 49.9 s | 61 s | 352 s |

Starting the fixture helper (an `exec` of the 182 MB test binary) costs 25-33 ms
per call and is not the bottleneck; the time is computation in workspace and
dependency code. Dependencies alone would leave the CI run at roughly 220 s
against the 300 s proof, too close under parallel load; the selected profile
projects to roughly 170 s.

`opt-level` does not change test semantics here: the `dev` profile keeps
`debug-assertions` and `overflow-checks` enabled regardless of optimization,
and the only `cfg(debug_assertions)` in the tree selects the Windows subsystem
in `apps/desktop/src-tauri/src/main.rs`. `release` is unchanged. The cost is a
longer cold build and a less faithful debugger view of workspace code.
Switching the gate runner to `cargo-nextest` was deferred: it runs every test
in its own process, which rebuilds the `OnceLock` archive fixtures of
`ea-reader` and `ea-system-tests` per test, and it is only reconsidered if the
gate still exceeds its 90-minute budget with this profile.

## Consequences

- Dependency upgrades, enabled-feature changes, or Suite 1 algorithm changes
  require a new ADR, fresh primary-source and RustSec review, lockfile update,
  vectors, and compatibility analysis.
- Exact pins trade automatic patch adoption for reviewed, reproducible
  upgrades. The supply-chain gate must surface advisories promptly.
- Format acceptance and cryptographic protocol correctness remain local
  responsibilities; upstream libraries provide primitives, not the complete
  Einsatzarchiv security claim.
- A tzdb update is a reviewed format/compatibility decision: update both exact
  crate pins, the documented database version, boundary fixtures, and the
  compatibility registry together. Existing payload bytes are never rewritten.
