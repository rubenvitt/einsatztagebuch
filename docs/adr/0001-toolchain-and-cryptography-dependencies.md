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
