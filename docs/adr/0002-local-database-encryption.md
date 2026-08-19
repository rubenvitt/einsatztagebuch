# ADR 0002: Local database encryption

- Status: Accepted
- Decision date: 2026-08-19
- Evidence retrieved: 2026-08-19

## Context

The offline Writer keeps drafts, master data and the local audit trail in a
SQLite database on the operator's device. `design.md`:1961 requires that these
databases are protected by SQLCipher or an equivalently reviewed **full**
database encryption, with additional per-draft keys so that a finalized draft
cannot be recovered from free database pages; `design.md`:1965 forbids plaintext
temporary files outright.

Full database encryption is a dependency class that
`docs/adr/0001-toolchain-and-cryptography-dependencies.md` did not admit. Its
rejected-alternatives list states that
OpenSSL and `ring` as suite-wide abstractions were rejected, to avoid native
toolchain variance and opaque
algorithm selection (`docs/adr/0001-toolchain-and-cryptography-dependencies.md`:75-77),
and its consequences make any dependency of a new class a new ADR with a fresh
primary-source and RustSec review, a lockfile update, vectors and a
compatibility analysis (`:152-153`). This ADR is that decision, and it is
ratified **before** the dependency is used: the crate that opens the database,
`crates/ea-local-store`, and the first `PRAGMA key` belong to the next task.

This document therefore writes no application code, creates no crate and
creates no database. It pins two crates in `[workspace.dependencies]` and
records the review that permits them. Under the inheritance rule of
`docs/adr/0001-toolchain-and-cryptography-dependencies.md`:15-20 a shared
dependency that no member inherits does not enter `Cargo.lock`, so this task
leaves the lockfile byte-identical; the lockfile obligation is named in
*Consequences* and discharged by the task that adds the member.

## Decision

The local Writer databases are encrypted in full by SQLCipher, reached from Rust
through `rusqlite` with the bundled SQLCipher amalgamation and a vendored
OpenSSL `libcrypto`.

| Dependency | Exact pin and enabled features | Role, maintenance, and security rationale |
| --- | --- | --- |
| [`rusqlite`](https://crates.io/crates/rusqlite/0.40.0) | `=0.40.0`; `default-features = false`, `bundled-sqlcipher-vendored-openssl` | The [official sparse-index record](https://index.crates.io/ru/sq/rusqlite) lists `0.40.0` as published and not yanked, and the [upstream project](https://github.com/rusqlite/rusqlite) releases it actively. It is the SQLite binding Einsatzarchiv uses for the local store; it produces no archive byte. Defaults are off, so `cache` and `ffi-sqlite-wasm-rs` stay disabled and `hashlink` and `sqlite-wasm-rs` stay out of the tree. |
| [`libsqlite3-sys`](https://crates.io/crates/libsqlite3-sys/0.38.0) | `=0.38.0`; `default-features = false`, `bundled-sqlcipher-vendored-openssl` | The [official sparse-index record](https://index.crates.io/li/bs/libsqlite3-sys) lists `0.38.0` as published and not yanked; it is released from the same [upstream project](https://github.com/rusqlite/rusqlite) as `rusqlite`. It is pinned **directly** although `rusqlite` already depends on it (`^0.38.0`), following the precedent of the direct `jiff-tzdb` pin (`docs/adr/0001-toolchain-and-cryptography-dependencies.md`:61): this crate carries the bundled SQLCipher C sources, and without a direct pin those sources drift inside `rusqlite`'s compatible range without any review. |

Every additional feature the local store turns out to need is added with its own
justification row in this table, never silently.

## Rejected alternatives

- **The reading that `docs/adr/0001-toolchain-and-cryptography-dependencies.md`:75-77
  forbids this decision.** That clause rejects
  OpenSSL and `ring` as suite-wide abstractions, to keep Suite 1's algorithm
  selection explicit and pure-Rust.
  SQLCipher is not a suite-wide abstraction and does not touch Suite 1: it
  produces no archive byte, no COSE signature, no grant, no hash-chain link and
  no object of the six frozen families. Deterministic CBOR, SHA-256, Ed25519,
  ChaCha20-Poly1305 and HPKE Base Mode remain exactly where ADR 0001 put them,
  in `minicbor`, `coset`, `sha2`, `ed25519-dalek`, `chacha20poly1305` and
  `hpke`. The scope of this decision is one local file at rest on the operator's
  device. The vendored-OpenSSL feature family is chosen precisely so that this
  crypto does **not** vary with whatever OpenSSL a host happens to carry: the
  variance ADR 0001 objected to is reduced by the choice, not introduced by it.
- **Plain SQLite with per-record AEAD**, rejected because `design.md`:1961
  requires full database encryption. Per-record AEAD leaves
  the write-ahead log, all indexes, and every temporary spill file readable,
  and the additional
  per-draft keys of the same sentence are a supplement to full encryption, not a
  substitute for it.
- **A hand-rolled page-level encryption layer over plain SQLite**, rejected for
  the same reason `docs/adr/0001-toolchain-and-cryptography-dependencies.md`:65-67
  rejects hand-written CBOR and COSE: storage-format cryptography is high-risk
  code.
- **Loading SQLCipher as a runtime SQLite extension or from a system library**
  (`rusqlite`'s `sqlcipher` feature, or `libsqlite3-sys`'s `loadable_extension`),
  rejected because the encryption of the local database would then depend on a
  component the lockfile does not pin and the gate cannot reproduce.
- **The numerically newest releases `rusqlite` 0.40.2 and `libsqlite3-sys`
  0.38.2**, rejected on MSRV grounds; the measured chain is the fourth row of
  the review below. This is the same shape of decision ADR 0001 records for
  `toml` 0.8.23: the latest verified compatible line, not merely the newest
  release.

## Primary-source and RustSec review

Carried out on 2026-08-19 as `docs/adr/0001-toolchain-and-cryptography-dependencies.md`:152-153
demands, with the rigour of the existing dependency table
(`docs/adr/0001-toolchain-and-cryptography-dependencies.md`:49-61). This is a
dependency-risk decision, not a claim that either crate has received an
independent formal audit.

### 1. Primary sources per crate

| Crate | Pinned release | crates.io record | Sparse index | Upstream project |
| --- | --- | --- | --- | --- |
| `rusqlite` | `=0.40.0`, published 2026-05-26, not yanked | <https://crates.io/crates/rusqlite/0.40.0> | <https://index.crates.io/ru/sq/rusqlite> | <https://github.com/rusqlite/rusqlite> |
| `libsqlite3-sys` | `=0.38.0`, published 2026-05-26, not yanked | <https://crates.io/crates/libsqlite3-sys/0.38.0> | <https://index.crates.io/li/bs/libsqlite3-sys> | <https://github.com/rusqlite/rusqlite> |

### 2. Verified feature names

Read out of the published manifests of the pinned releases
(<https://docs.rs/crate/rusqlite/0.40.0/source/Cargo.toml.orig> and
<https://docs.rs/crate/libsqlite3-sys/0.38.0/source/Cargo.toml.orig>, the
evidence form ADR 0001 uses for `jiff` at `:60`), not from memory — the
bundled-SQLCipher feature families partly exclude one another.

`rusqlite` 0.40.0, `[features]`:

```toml
bundled-sqlcipher-vendored-openssl = [
    "libsqlite3-sys?/bundled-sqlcipher-vendored-openssl",
    "bundled-sqlcipher",
]
```

`libsqlite3-sys` 0.38.0, `[features]`:

```toml
default = ["min_sqlite_version_3_34_1"]
bundled = ["cc", "bundled_bindings"]
bundled-sqlcipher = ["bundled"]
bundled-sqlcipher-vendored-openssl = [
    "bundled-sqlcipher",
    "openssl-sys/vendored",
]
min_sqlite_version_3_34_1 = ["pkg-config", "vcpkg"]
sqlcipher = []
```

Two exclusions follow from these lists and from `libsqlite3-sys`'s `build.rs`.
`sqlcipher` links a SQLCipher supplied by the host and, when it is enabled
without `bundled-sqlcipher`, upstream *overrides* `bundled` with a
`cargo:warning` (`build.rs`:57-69) — so `sqlcipher` and the bundled families are
not additive but competing. `bundled` alone compiles the plain SQLite
amalgamation in `sqlite3/`, whereas `bundled-sqlcipher` compiles the SQLCipher
amalgamation in `sqlcipher/`. Only `bundled-sqlcipher-vendored-openssl` yields
both a vendored SQLCipher and a vendored `libcrypto`, which is why that exact
name is the one enabled.

The reviewed selection is recorded once more in the exact form
`tools/xtask/tests/adr_gate.rs` rebuilds from `[workspace.dependencies]`, so that
enabling, removing or reordering a feature cannot reach the gate without passing
through this review — a bare mention of a feature name is not enough, because
this ADR also names features that stay *disabled*:

```
rusqlite = ["bundled-sqlcipher-vendored-openssl"]
libsqlite3-sys = ["bundled-sqlcipher-vendored-openssl"]
```

The bundled C sources of `libsqlite3-sys` 0.38.0 are **SQLCipher 4.14.0**
(`CIPHER_VERSION_NUMBER 4.14.0`, `CIPHER_VERSION_BUILD community`,
`sqlcipher/sqlite3.c`) over **SQLite 3.51.3** (`SQLITE_VERSION "3.51.3"`,
`sqlcipher/sqlite3.h`). These are the same versions the rejected 0.38.2 carries,
so the MSRV-driven step back costs no currency in the C library that performs the
encryption.

`build.rs`:146-151 compiles the amalgamation with `-DSQLITE_HAS_CODEC`,
`-DSQLITE_TEMP_STORE=2`, `-DSQLITE_EXTRA_INIT=sqlcipher_extra_init` and
`-DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown`, and `:208-211` includes the
vendored OpenSSL headers via `DEP_OPENSSL_INCLUDE` so that the static
`libcrypto` from `openssl-sys` is linked instead of a host library.

### 3. Reported MSRV

Neither `rusqlite` 0.40.0 nor `libsqlite3-sys` 0.38.0 declares `rust-version` in
its published manifest; both edition-2021 crates state their policy in the
identical README section *Minimum supported Rust version (MSRV)*: "Latest stable
Rust version at the time of release. It might compile with older versions." The
reported MSRV of a release is therefore the stable Rust of its publication date,
resolved from the official dated Rust distribution manifests
(<https://static.rust-lang.org/dist/channel-rust-1.95.0.toml> and its siblings),
which is the evidence form ADR 0001 already uses for the fuzz toolchain:

| Rust stable | Release date (`date` field of `channel-rust-<v>.toml`) |
| --- | --- |
| `1.95.0` | 2026-04-16 |
| `1.96.0` | 2026-05-28 |
| `1.96.1` | 2026-06-30 |
| `1.97.0` | 2026-07-09 |
| `1.97.1` | 2026-07-16 — current stable, `channel-rust-stable.toml` names `1.97.1 (8bab26f4f 2026-07-14)` |

| Release pair | Published | Latest stable then | Reported MSRV | Admits Rust 1.95? |
| --- | --- | --- | --- | --- |
| `rusqlite` 0.40.2 / `libsqlite3-sys` 0.38.2 | 2026-08-08 | `1.97.1` | 1.97.1 | **no** |
| `rusqlite` 0.40.1 / `libsqlite3-sys` 0.38.1 | 2026-06-06 | `1.96.0` | 1.96.0 | **no** |
| `rusqlite` 0.40.0 / `libsqlite3-sys` 0.38.0 | 2026-05-26 | `1.95.0` (1.96.0 landed two days later) | 1.95.0 | **yes** |

The workspace pins Rust `1.95.0` (`rust-toolchain.toml`:2) and declares
`rust-version = "1.95"` (`Cargo.toml`:7). `0.40.0` / `0.38.0` is therefore the
newest pair whose own MSRV policy admits the pinned compiler, and the newer
releases are rejected rather than adopted with an undeclared toolchain bump.

The transitive crates that declare an MSRV declare one below 1.95:
`openssl-sys` 0.9.117 reports `1.80.0` and `cc` 1.4.3 reports `1.65.0`.

### 4. RustSec advisory review

Queried on 2026-08-19 against the [RustSec advisory database](https://github.com/RustSec/advisory-db),
which is the vulnerability source of the supply-chain gate, by reading
`crates/<name>/` for each crate.

| Crate | Advisories found | Highest patched floor | Verdict for the pinned tree |
| --- | --- | --- | --- |
| `rusqlite` | `RUSTSEC-2020-0014`, `RUSTSEC-2021-0128` | `>= 0.26.2` (and `0.25.4`) | `0.40.0` is past both. |
| `libsqlite3-sys` | `RUSTSEC-2022-0090` | `>= 0.25.1` | `0.38.0` is past it. |
| `openssl-src` | 25 advisories, newest `RUSTSEC-2023-0013` | `>= 300.0.12` | The vendored OpenSSL crate resolves to `300.6.1+3.6.3` (OpenSSL 3.6.3) and is past all 25. |
| `openssl-sys` | none — `crates/openssl-sys/` does not exist in the database (HTTP 404) | — | An empty result, recorded as the finding it is. |

Two findings belong to this table rather than to a footnote. First, the empty
`openssl-sys` result is an absence of *recorded* advisories on 2026-08-19 and not
a statement about the crate's future. Second, `openssl-src` is the crate with by
far the longest advisory history in this tree, because it tracks upstream
OpenSSL CVEs; it is the component of this decision that will need the most
frequent reviewed pin refresh, and every such refresh is a new lockfile review
under `docs/adr/0001-toolchain-and-cryptography-dependencies.md`:152-153.

### 5. Licenses of the crates the pinned tree adds

With `default-features = false` plus `bundled-sqlcipher-vendored-openssl`, the
tree that `crates/ea-local-store` will pull in consists of the two pinned crates,
the four unconditional `rusqlite` dependencies, and the vendored-OpenSSL build
chain.

| Crate | Kind | Declared SPDX expression |
| --- | --- | --- |
| `rusqlite` 0.40.0 | direct | `MIT` |
| `libsqlite3-sys` 0.38.0 | direct | `MIT` |
| `bitflags` | normal | `MIT OR Apache-2.0` |
| `fallible-iterator` | normal | `MIT/Apache-2.0` |
| `fallible-streaming-iterator` | normal | `MIT/Apache-2.0` |
| `smallvec` | normal | `MIT OR Apache-2.0` |
| `openssl-sys` | normal | `MIT` |
| `libc` | normal | `MIT OR Apache-2.0` |
| `cc` | build | `MIT OR Apache-2.0` |
| `shlex` | build chain of `cc` | `MIT OR Apache-2.0` |
| `find-msvc-tools` | build chain of `cc` | `MIT OR Apache-2.0` |
| `openssl-src` | build | `MIT/Apache-2.0` |
| `pkg-config` | build | `MIT OR Apache-2.0` |
| `vcpkg` | build | `MIT/Apache-2.0` |

The distinct SPDX identifiers are exactly **`MIT`** and **`Apache-2.0`**. Both
already stand in the five-entry allowlist `deny.toml`:8-15, so this review adds
**no** identifier to it: an allowlist entry without a crate behind it would
weaken the very control it belongs to.

Three licenses in this tree are carried by *vendored sources* rather than
declared by a crate, so `cargo deny`'s license check, which reads declared crate
expressions, never sees them; they are recorded here instead. The SQLCipher
4.14.0 amalgamation is BSD-3-Clause style (Zetetic LLC,
`libsqlite3-sys/sqlcipher/LICENSE`) and BSD-3-Clause is already allowed; the
SQLite 3.51.3 amalgamation is public domain; and the OpenSSL 3.6.3 sources
vendored by `openssl-src` are Apache-2.0, which is already allowed.

`pkg-config` and `vcpkg` are in the table although this decision disables the
`libsqlite3-sys` default feature that requires them. The honest reason is
feature unification: `rusqlite` declares its `libsqlite3-sys` dependency with
default features **on**, so `min_sqlite_version_3_34_1` — and with it
`pkg-config` and `vcpkg` — is enabled through `rusqlite` regardless of the
`default-features = false` on our direct pin. The flag is kept because it states
our own intent and does take effect for any future member that depends on
`libsqlite3-sys` without `rusqlite`, but this ADR must not imply that the
defaults are off. What the flag does *not* have to buy back is the linkage
itself: with `bundled-sqlcipher` enabled, `build.rs`:70-79 dispatches to
`build_bundled` and the `pkg-config`/`vcpkg` search path in `build_linked` is
never entered.

### 6. Native build requirement per platform

`bundled-sqlcipher-vendored-openssl` compiles C from source, which is precisely
the "native toolchain variance"
`docs/adr/0001-toolchain-and-cryptography-dependencies.md`:75-77 warned about. It
is accepted here knowingly rather than by omission. Every supported Writer
platform inherits a C toolchain plus Perl, because `openssl-src` drives
OpenSSL's Perl `Configure` script (`openssl-src/src/lib.rs`:157-159, which runs
`OPENSSL_SRC_PERL`, `PERL`, or plain `perl`).

| Platform | Inherited build requirement |
| --- | --- |
| Windows 11 `x86_64` | MSVC C/C++ build tools for the amalgamation, plus a Perl interpreter for OpenSSL's `Configure`. `nasm` is optional: `openssl-src` auto-detects it and `OPENSSL_RUST_USE_NASM` forces the choice; without it OpenSSL is configured `no-asm`, which is slower but not less correct. |
| macOS `arm64` and `x86_64` | The Xcode command line tools (`clang`, `make`) and the system `perl`. |
| Ubuntu 24.04 LTS `x86_64` | `build-essential` (`gcc`, `make`) and `perl`. |

The variance this buys back is larger than the variance it costs: the shipped
binary contains one reviewed SQLCipher and one reviewed `libcrypto`, identical
on all three platforms, instead of whatever SQLite and OpenSSL a host carries.

One residual host influence is recorded rather than hidden. `build.rs`:52-56
reads the environment variable `LIBSQLITE3_SYS_USE_PKG_CONFIG`; if it is set to
anything but `0`, the build takes the linked path and the bundled SQLCipher is
*not* compiled in. The task that creates the database is the right place to make
that observable, and *Consequences* names it.

## Full-encryption scope

Recorded verbatim so that the task creating the database has no interpretation
left.

Full encryption covers
the write-ahead log, all indexes, and every temporary spill file.
The journal mode and the temp-store setting are configured
accordingly at open time and are checked by a test in the task that creates the
database. `-DSQLITE_TEMP_STORE=2` from `build.rs`:148 only makes memory the
*default* for temporary storage and leaves `PRAGMA temp_store` able to override
it, so the setting is stated explicitly at open time instead of being inherited
from a compile-time default.

There is **no plaintext temporary file** at any point (`design.md`:1965). The
database key travels as a `SecretVec` from the native key provider — never
through a file, an environment variable or a log line — and the additional
per-draft keys of `design.md`:1961 sit on top of full encryption so that a
finalized draft cannot be recovered from free database pages.

The Reader exception is explicit: the browser Reader's cache and search index are
**not** covered by this ADR. They use a ChaCha20-Poly1305-encrypted Rust index in
OPFS (`design.md`:1963, and
`docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §8.1), and
no SQLCipher database exists in the browser at all.

## Consequences

- The lockfile update that
  `docs/adr/0001-toolchain-and-cryptography-dependencies.md`:152-153 requires is
  completed by the task that creates `crates/ea-local-store`, when that member
  inherits both entries with `workspace = true` and the packages actually enter
  `Cargo.lock`. Under the inheritance rule
  (`docs/adr/0001-toolchain-and-cryptography-dependencies.md`:15-20) this task
  cannot discharge it: a shared dependency no member inherits resolves to
  nothing, and `Cargo.lock` stays byte-identical. Naming the owner here is what
  keeps the obligation from being asserted in one place and delivered in none.
  That same task owns the first empirical proof that the pinned pair builds and
  encrypts under Rust `1.95.0`; the MSRV chain above is a documentary result, not
  a compiled one.
- No wire format, vector or compatibility file is affected, because no byte of
  the archive format touches this dependency. Suite 1, the six frozen object
  prefixes and every frozen vector remain unchanged, and archive bytes — not the
  local database — stay authoritative.
- `cargo deny` is invoked by no gate today, so the license record in this review
  is a reviewed record and not yet an enforced control. Wiring the invocation
  into `xtask stage-gate 2` belongs to the stage-gate task and is named here so
  it cannot be silently dropped. `deny.toml` is therefore unchanged by this
  decision: the review found only `MIT` and `Apache-2.0`, both already allowed.
- The gate `tools/xtask/tests/adr_gate.rs` couples this document to
  `[workspace.dependencies]`: a database dependency that is not pinned exactly,
  or whose pinned version or enabled feature this ADR does not name, fails the
  test. It is the first test in the repository that makes an ADR load-bearing
  rather than decorative.
- A `rusqlite`, `libsqlite3-sys`, SQLCipher or OpenSSL upgrade is a new reviewed
  decision under `docs/adr/0001-toolchain-and-cryptography-dependencies.md`:152-153,
  and the MSRV table above is part of what has to be re-derived: because both
  crates report "latest stable at release", every newer release raises the
  reported MSRV, and adopting one is a toolchain decision and not a patch bump.
- The build now depends on a host C toolchain and a host Perl on all three
  supported platforms. A release build that cannot find them fails loudly, which
  is the intended behaviour; the signed min/max release proof across the four
  cross targets remains a Stage 7 obligation.
- `LIBSQLITE3_SYS_USE_PKG_CONFIG` in the build environment silently replaces the
  bundled SQLCipher with a host library. The task that creates the database must
  make the effective backend observable at runtime — a database opened against a
  plain system SQLite would accept `PRAGMA key` as an unknown pragma and store
  plaintext — so that this variable cannot turn full encryption off unnoticed.
