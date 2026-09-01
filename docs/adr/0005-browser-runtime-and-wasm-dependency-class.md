# ADR 0005: Browser runtime and wasm dependency class

- Status: Accepted
- Decision date: 2026-08-31
- Evidence retrieved: 2026-08-31

## Context

Stage 4 builds the browser Reader. `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md`
§9-§10 makes the verification pipeline shared Rust code that compiles for
`wasm32-unknown-unknown` and runs inside the browser, reached from JavaScript
through a generated bindings layer. None of this is a dependency class that
`docs/adr/0001-toolchain-and-cryptography-dependencies.md` admitted: its
inventory covers deterministic CBOR, COSE, Suite 1 cryptography, time and the
`toml` tooling parser, and its consequences (`:152-154`) make any dependency of
a new class a new ADR with a fresh primary-source and RustSec review, a
lockfile update, vectors and a compatibility analysis. This document is that
decision for the browser runtime class, and it is ratified **before** the
dependency is used.

The precedent for the shape is `docs/adr/0002-local-database-encryption.md`,
repeated by `docs/adr/0004-server-runtime-and-dependency-class.md`: each ratifies
one class exactly pinned, before the crate that consumes it exists. Like both
documents, this one writes no application code, creates no crate and compiles
nothing for `wasm32-unknown-unknown` itself: it pins five crates in
`[workspace.dependencies]`, records the review that permits them, and hands the
first empirical wasm32 build proof to the task that creates the member. This
task registers **no workspace member** — a `members` entry pointing at a
directory without a manifest fails `cargo metadata` and with it every test —
so `Cargo.lock` stays byte-identical, measured with `git diff --stat Cargo.lock`
after `cargo metadata --locked --no-deps`.
No pin is entered that no member of this stage consumes; the lockfile obligation is named in *Consequences* and discharged by the task that adds `crates/ea-reader-wasm`.

The class is not new to the dependency graph, and that measurement is the
argument that makes this task cheap: `Cargo.lock` already resolves
`wasm-bindgen 0.2.126`, `js-sys 0.3.103`, `web-sys 0.3.103`,
`wasm-bindgen-futures 0.4.76` and `wasm-bindgen-test 0.3.76` transitively today,
reached through two already-reviewed edges — `cddl` (a direct
`[workspace.dependencies]` pin used by `tools/xtask`, whose `wasm32` feature
family pulls in `wasm-bindgen`, `js-sys`, `web-sys` and `wasm-bindgen-test`) and
`reqwest` (reached through the Tauri desktop stack, whose wasm target family
pulls in `wasm-bindgen`, `js-sys`, `web-sys` and `wasm-bindgen-futures`).
Neither edge is activated for the host target this workspace builds today, but
`cargo generate-lockfile` resolves dependencies for every declared target
regardless of host, which is why the five packages already sit in the lock
file. Pinning them exactly therefore adds **no** package to the resolved
graph and changes neither `cargo deny check licenses` nor `cargo deny check
advisories`; it only turns an already-present, silently-resolved transitive
version into a reviewed, named decision that a later `cargo update` cannot
drift out from under `crates/ea-reader-wasm`.

The runtime evidence this class exists to serve is `spikes/wasm-runtime-proof/spike.sh`,
committed ahead of this task and pinned by it, not written by it: it is the
executable proof that the `wasm-bindgen` layer, `getrandom`/`wasm_js`, one HPKE
decapsulation and one signature check against a frozen vector all run —
not merely compile — under `wasm32-unknown-unknown` in a real JavaScript
environment.

## Decision

The browser runtime class is `wasm-bindgen` and its four satellite crates: the
JS interop primitives of `js-sys`, the Web platform bindings of `web-sys`, the
`Future`/`Promise` bridge of `wasm-bindgen-futures`, and the
`#[wasm_bindgen_test]` harness of `wasm-bindgen-test`. All five come from the
same upstream project and the same release train, so a version skew between
them is itself a defect class this pin removes: they are pinned to the
**same** upstream release cut (`js-sys`/`web-sys` share `0.3.103`, the
`wasm-bindgen` facade is `0.2.126`, and its two satellites are pinned to their
own compatible releases `0.4.76`/`0.3.76`).

| Dependency | Exact pin and enabled features | Role, maintenance, and security rationale |
| --- | --- | --- |
| [`js-sys`](https://crates.io/crates/js-sys/0.3.103) | `=0.3.103`; `default-features = false`, `std` | The [wasm-bindgen upstream](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/js-sys) supplies bindings for every JS global object and function (`Uint8Array`, `Promise`, `Reflect`, …) that the generated `wasm-bindgen` glue and the browser Reader's own code need to move bytes and call Web APIs. `std` is the crate's only meaningful non-default feature — it forwards to `wasm-bindgen/std` — and `unsafe-eval`, part of its default set, stays **off**: it exists to construct closures via `eval`-adjacent JS, a code-execution surface this class has no use for and does not want compiled in. |
| [`wasm-bindgen`](https://crates.io/crates/wasm-bindgen/0.2.126) | `=0.2.126`; `default-features = false`, `std` | The [upstream project](https://github.com/wasm-bindgen/wasm-bindgen) is the code generator and runtime glue the design names by name: it produces the JS module that loads the compiled `.wasm` and marshals calls across the boundary. `std` is enabled because the browser Reader's shared core already depends on the standard library; `serde-serialize`, `gg-alloc` (a non-default global allocator swap) and the two debug-only features stay off, none of them load-bearing for this class. |
| [`wasm-bindgen-futures`](https://crates.io/crates/wasm-bindgen-futures/0.4.76) | `=0.4.76`; `default-features = false` | The [upstream project](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/futures) bridges Rust `Future`s and JS `Promise`s — the shape every OPFS handle, `SubtleCrypto` operation and `fetch` call in the browser Reader returns as. It declares no feature beyond its own `default = ["std"]`/`futures-core-03-stream` pair, and this class needs neither; `default-features = false` keeps that explicit rather than inherited, which is why its reviewed selection below is the empty ledger line. |
| [`wasm-bindgen-test`](https://crates.io/crates/wasm-bindgen-test/0.3.76) | `=0.3.76`; `default-features = false`, `std` | The [upstream project](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/test) supplies `#[wasm_bindgen_test]` and the harness `wasm-bindgen-test-runner` drives, which `.cargo/config.toml`'s `[target.wasm32-unknown-unknown]` runner selects for every `cargo test --target wasm32-unknown-unknown` of this class. `std` is its only feature at all, and it is load-bearing rather than optional: under `cfg(not(feature = "std"))` the crate defines its own `#[panic_handler]` in `src/rt/mod.rs`, which on the host target collides with the one the standard library already provides. The measured consequence of leaving it off is `E0152` — duplicate lang item `panic_impl` — for the whole workspace as soon as one member declares the dependency, because `cargo test --workspace --all-targets` builds that member's test targets for the host. With `std` the crate installs a plain `std::panic::set_hook` instead. |
| [`web-sys`](https://crates.io/crates/web-sys/0.3.103) | `=0.3.103`; `default-features = false`, twenty-eight named features | The [wasm-bindgen upstream](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/web-sys) is a procedurally generated binding crate over the whole WebIDL surface of the Web platform: over 1700 features exist, one per interface, and enabling none of them by default is the crate's own design. *Enumerated web-sys features* below names each of the twenty-eight this class turns on and the specification clause it exists for; nothing wider is admitted, and a twenty-ninth feature must pass through this gate. |

`getrandom` is **deliberately absent** from the class above. Its `=0.4.3` pin
and `wasm_js` feature are already ratified in
`docs/adr/0001-toolchain-and-cryptography-dependencies.md`, which states that
getrandom 0.4.3 selects its wasm backend through the Cargo feature `wasm_js`,
not through a compiler flag, and are enforced by
`workspace_getrandom_enables_the_wasm_js_feature` in
`tools/xtask/tests/workspace.rs`. Two ADRs claiming the same pin would drift
against each other the moment either one is refreshed alone; this document
names the decision by reference and is not a second source for it.

### The sixth pin: `hkdf`, key derivation for the browser vault

The five crates above are one family. `hkdf` is not a sixth member of it, and
this section says so rather than folding it into a sentence that would then be
false: every claim above about *five* crates, one upstream project, one release
train and one publication day is a claim about `wasm-bindgen` and its four
satellites, and stays true unchanged. `hkdf` is cryptography, and it is entered
here for one reason — `tools/xtask/tests/adr_gate.rs` gates browser-facing pins
through this document, and the browser Reader is the only consumer.

The consumer is `crates/ea-reader`. The specification
`docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §6.2
prescribes the vault wrapping key as
`KEK_i = HKDF(PRF_i(fixed app salt), info = "ea-reader-vault-v1")` and forbids
the raw PRF output from being the encryption key. Three alternatives were
weighed and rejected. Writing HMAC-SHA-256 extract/expand by hand inside
`ea-crypto` would put a second, unreviewed KDF implementation next to the one
`hpke` already carries. Reusing `hpke::kdf::Kdf::extract_and_expand` fails on
its own terms: the method is `#[doc(hidden)]`, and its output is labelled with
`HPKE-v1` and a suite id, so it is not the HKDF §6.2 names. Deriving the key
from `SubtleCrypto` in JavaScript would move a security decision out of shared
Rust, which `web-reader-design.md` §9 does not permit.

| Dependency | Exact pin and enabled features | Role, maintenance, and security rationale |
| --- | --- | --- |
| [`hkdf`](https://crates.io/crates/hkdf/0.13.0) | `=0.13.0`; `default-features = false` | The [RustCrypto KDFs project](https://github.com/RustCrypto/KDFs) supplies RFC 5869 HKDF over any `hmac` implementation; `crates/ea-reader/src/envelope.rs` uses `Hkdf::<Sha256>` for the vault wrapping key and for the cache, entry-state and index keys derived from the vault key. The release declares **no** Cargo features at all — the crates.io record's `features` field is the empty object, and the only optional dependency (`kdf 0.1`) is not reachable as a feature of this release — so `default-features = false` is a no-op that records the intent, and its reviewed selection below is the empty ledger line. The crate is already in `Cargo.lock` at exactly this version, pulled by `hpke 0.14.0` (through `ea-crypto`) and by `sqlx-postgres 0.9.0`: the lockfile delta of adding it is an **edge**, not a package, so no new licence and no new `deny.toml` entry arises. It shares `hmac 0.13`/`digest 0.11.3` with the already-pinned `sha2 =0.11.0`, so no second hash tree enters either. |

## Rejected alternatives

- **A second, independently resolved `getrandom` pin inside this ADR**,
  rejected for the reason directly above: `docs/adr/0001-toolchain-and-cryptography-dependencies.md`
  already owns it, and duplicating a pin across two ADRs is exactly the drift
  this repository's exact-version discipline exists to prevent.
- **`--cfg getrandom_backend="wasm_js"` in `.cargo/config.toml`'s
  `[target.wasm32-unknown-unknown]` table**, rejected on two independent,
  each-sufficient grounds. First, it is the *wrong mechanism* for the pinned
  release: `getrandom` 0.3 selects its backend through `--cfg
  getrandom_backend`, but 0.4.3 selects it through the Cargo feature
  `wasm_js` instead, and in 0.4.3 `"wasm_js"` is not even a member of the
  permitted value list of `cfg(getrandom_backend, values(...))` any more — the
  flag would not merely be redundant, it would not compile as written.
  Second, even a *correct* `rustflags` entry in `.cargo/config.toml` is not a
  reliable pin at all: an ambient `RUSTFLAGS` environment variable silently
  **overrides** it rather than merging with it, so a developer's shell alone
  could turn the setting off without touching a single file. `.cargo/config.toml`
  therefore carries a `runner`, not a `rustflags` — see *wasm-bindgen crate and
  CLI parity* below for what it does carry and why.
- **`wasm-pack` as the build driver of `crates/ea-reader-wasm`**, rejected
  because it would introduce a *second*, independently versioned carrier of
  the same `wasm-bindgen` schema this class pins, plus its own bundled
  `chromedriver` for browser tests. The whole point of the CLI-parity gate
  below is that exactly **one** installed `wasm-bindgen-cli` speaks for the
  whole workspace; `wasm-pack` wraps `wasm-bindgen` internally and resolves
  its own compatible version independently of `mise.toml`'s
  `cargo:wasm-bindgen-cli` pin, which is precisely the drift
  `spikes/wasm-runtime-proof/spike.sh` measured and this ADR closes.
- **Enabling `js-sys`'s default `unsafe-eval` feature**, rejected because it
  exists to construct JS closures through an `eval`-adjacent code path this
  class has no call site for; leaving it disabled keeps the feature surface
  matched to actual use rather than to the crate's own convenience default.
- **A `web-sys` pin without an explicit feature list (or with `--all-features`)**,
  rejected because the crate is procedurally generated over the entire Web
  platform: with defaults off and no explicit list, the compiled surface would
  be zero; with every feature on, it would be unbounded and unreviewed. Both
  extremes are equally unaudited. *Enumerated web-sys features* names the
  twenty-eight admitted APIs and the specification clause each exists to serve.
- **Registering a workspace member in this task**, rejected because a
  `members` entry pointing at a directory without a manifest fails `cargo
  metadata` and with it every test in the repository — the same reason
  `docs/adr/0002-local-database-encryption.md` and
  `docs/adr/0004-server-runtime-and-dependency-class.md` give for the same
  choice.
- **A `.devcontainer/` for the browser test matrix**, rejected in *Browser
  provisioning* below, together with the reasons a pinned container image is
  chosen instead of installing browser engines on the development host.

## Primary-source and RustSec review

Carried out on 2026-08-31 as
`docs/adr/0001-toolchain-and-cryptography-dependencies.md`:152-154 demands,
with the rigour of the existing dependency tables
(`docs/adr/0002-local-database-encryption.md`:95-98 and
`docs/adr/0004-server-runtime-and-dependency-class.md`:150-165). This is a
dependency-risk decision, not a claim that any of these five crates has
received an independent formal audit. The [RustSec advisory
database](https://github.com/RustSec/advisory-db) is the vulnerability source
for the supply-chain gate; `deny.toml` denies yanked crates and unknown
registries or Git sources.

### 1. Primary sources per crate

Read from the official crates.io API records of the pinned releases; every one
of the five is published and **not yanked**.

| Crate | Pinned release | Published | Declared SPDX | crates.io record | Upstream project |
| --- | --- | --- | --- | --- | --- |
| `js-sys` | `=0.3.103` | 2026-06-24 | `MIT OR Apache-2.0` | <https://crates.io/crates/js-sys/0.3.103> | <https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/js-sys> |
| `wasm-bindgen` | `=0.2.126` | 2026-06-24 | `MIT OR Apache-2.0` | <https://crates.io/crates/wasm-bindgen/0.2.126> | <https://github.com/wasm-bindgen/wasm-bindgen> |
| `wasm-bindgen-futures` | `=0.4.76` | 2026-06-24 | `MIT OR Apache-2.0` | <https://crates.io/crates/wasm-bindgen-futures/0.4.76> | <https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/futures> |
| `wasm-bindgen-test` | `=0.3.76` | 2026-06-24 | `MIT OR Apache-2.0` | <https://crates.io/crates/wasm-bindgen-test/0.3.76> | <https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/test> |
| `web-sys` | `=0.3.103` | 2026-06-24 | `MIT OR Apache-2.0` | <https://crates.io/crates/web-sys/0.3.103> | <https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/web-sys> |

All five were published on the same day from the same release train — the
`wasm-bindgen` project versions its facade and its satellite crates together —
which is the upstream-side mirror of why this ADR pins them as one class
rather than five independent decisions.

### 2. Verified feature names

Read from the crates.io API's `features` field of each pinned release, which
reports the manifest Cargo actually resolves.

`js-sys` 0.3.103, `[features]`:

```toml
default = ["std", "unsafe-eval"]
futures-core-03-stream = ["dep:futures-util", "dep:futures-core"]
std = ["wasm-bindgen/std", "dep:futures-util"]
unsafe-eval = []
```

`wasm-bindgen` 0.2.126, `[features]` (non-exhaustive; the debug/spans/msrv
entries are internal to the `wasm-bindgen` project's own CI and carry no
functional surface for this class):

```toml
default = ["std"]
std = []
serde-serialize = ["serde", "serde_json", "std"]
```

`wasm-bindgen-futures` 0.4.76, `[features]`:

```toml
default = ["std"]
futures-core-03-stream = ["js-sys/futures-core-03-stream"]
std = ["wasm-bindgen/std", "js-sys/std"]
```

`wasm-bindgen-test` 0.3.76, `[features]`:

```toml
default = ["std"]
std = ["wasm-bindgen/std", "js-sys/std", "wasm-bindgen-futures/std"]
```

`web-sys` 0.3.103 declares one Cargo feature per WebIDL interface — 1707 of
them — every one of them off by default; *Enumerated web-sys features* below
names the twenty-eight this class turns on.

The reviewed selection is recorded once more in the exact form
`tools/xtask/tests/adr_gate.rs` rebuilds from `[workspace.dependencies]`, so
that enabling, removing or reordering a feature cannot reach the gate without
passing through this review — a bare mention of a feature name is not enough,
because this ADR also names features that stay *disabled* (`unsafe-eval`,
`serde-serialize`, `futures-core-03-stream`). The sixth line belongs to `hkdf`,
whose own review is *The sixth pin* above and *6. The sixth pin reviewed* below;
it is the empty ledger line because the release declares no features:

```
hkdf = []
js-sys = ["std"]
wasm-bindgen = ["std"]
wasm-bindgen-futures = []
wasm-bindgen-test = ["std"]
web-sys = ["Blob", "Crypto", "DedicatedWorkerGlobalScope", "Document", "Event", "File", "FileSystemDirectoryHandle", "FileSystemFileHandle", "FileSystemGetDirectoryOptions", "FileSystemGetFileOptions", "FileSystemReadWriteOptions", "FileSystemSyncAccessHandle", "Headers", "MessageEvent", "Navigator", "Request", "RequestInit", "Response", "ServiceWorkerGlobalScope", "StorageManager", "SubtleCrypto", "VisibilityState", "Window", "Worker", "WorkerGlobalScope", "WorkerNavigator", "XmlHttpRequest", "XmlHttpRequestResponseType"]
```

### 3. Reported MSRV

| Crate | Declared `rust-version` | Admits Rust 1.95? |
| --- | --- | --- |
| `js-sys` 0.3.103 | 1.77 | yes |
| `wasm-bindgen` 0.2.126 | 1.77 | yes |
| `wasm-bindgen-futures` 0.4.76 | 1.77 | yes |
| `wasm-bindgen-test` 0.3.76 | 1.77 | yes |
| `web-sys` 0.3.103 | 1.77 | yes |

All five declare the same MSRV, again because they release together; none is
close enough to the pinned compiler `1.95.0` to be a near-term constraint the
way `sqlx` and the two AWS crates are in
`docs/adr/0004-server-runtime-and-dependency-class.md`.

### 4. RustSec advisory review

Queried on 2026-08-31 against the RustSec advisory database by requesting
`crates/<name>` from the `RustSec/advisory-db` GitHub repository for each of
the five crates.

| Crate | Advisories found | Verdict for the pinned tree |
| --- | --- | --- |
| `js-sys` | none — `crates/js-sys/` does not exist in the database (HTTP 404) | An empty result, recorded as the finding it is. |
| `wasm-bindgen` | none — `crates/wasm-bindgen/` does not exist in the database (HTTP 404) | An empty result. |
| `wasm-bindgen-futures` | none — directory absent | An empty result. |
| `wasm-bindgen-test` | none — directory absent | An empty result. |
| `web-sys` | none — directory absent | An empty result. |

Five empty results in one row of a table is itself worth naming: it is an
absence of *recorded* advisories on 2026-08-31 and not a statement about any
of the five crates' futures, the same distinction
`docs/adr/0002-local-database-encryption.md` and
`docs/adr/0004-server-runtime-and-dependency-class.md` draw for their own
empty rows. The `cargo deny check advisories` run over this repository's
`deny.toml`, measured in *Consequences*, is the mechanical cross-check over
the resolved tree rather than the five per-crate lookups alone.

### 5. Licenses of the crates the pinned tree adds

All five declare `MIT OR Apache-2.0`, both already members of the five-entry
allowlist `deny.toml:52-58`. Pinning this class therefore adds **no** SPDX
identifier to the allowlist and, because none of the five packages is new to
the resolved graph (see *Context*), it adds no `license-exception-not-encountered`
warning either — unlike the four named exceptions
`docs/adr/0004-server-runtime-and-dependency-class.md` introduces for its own
class, this class needs none, and `deny.toml` records that absence as a
comment rather than as a new exception entry.

### 6. The sixth pin reviewed: `hkdf` 0.13.0

Carried out on 2026-08-31 with the same steps as the five above, and recorded
separately because `hkdf` is not part of the `wasm-bindgen` release train.

| Crate | Pinned release | Published | Declared SPDX | Yanked | crates.io record | Upstream project |
| --- | --- | --- | --- | --- | --- | --- |
| `hkdf` | `=0.13.0` | 2026-03-30 | `MIT OR Apache-2.0` | no | <https://crates.io/crates/hkdf/0.13.0> | <https://github.com/RustCrypto/KDFs> |

Read from the official crates.io API record of the pinned release. That record
reports `"features": {}` — the release declares no Cargo feature at all — and
`"rust_version": "1.85"`, which the pinned compiler 1.95.0 admits with room to
spare. The vendored manifest in the local registry cache agrees on all three
facts, so the ledger line `hkdf = []` above is what
`reviewed_feature_ledger_line` rebuilds and not a guess.

RustSec advisory review, queried on 2026-08-31:

| Crate | Advisories found | Verdict for the pinned tree |
| --- | --- | --- |
| `hkdf` | none — `crates/hkdf/` does not exist in the database (HTTP 404) | An empty result, recorded as the finding it is. |
| `hmac` | none — `crates/hmac/` does not exist in the database (HTTP 404) | An empty result. `hmac 0.13.0` is the one dependency `hkdf 0.13.0` declares, and it is already in the resolved tree. |

Cross-checked mechanically over the whole resolved graph rather than crate by
crate: `cargo deny check advisories` reports `advisories ok` against the
advisory database clone at commit `ba9db2a77a6a0fe93bc63a3d9b730e08b145aff5`
(2026-08-31), whose `crates/` directory holds 912 entries and none named
`hkdf`. As with the five empty rows above, this is an absence of *recorded*
advisories on 2026-08-31 and not a statement about the crate's future.

Licences: `MIT OR Apache-2.0`, both already in the five-entry allowlist of
`deny.toml`. `cargo deny check licenses` reports `licenses ok`. No SPDX
identifier and no exception entry is added, and no `GATE-*` ledger anchor is
created — for the same reason as the class above: no package is new to the
resolved graph.

## wasm-bindgen crate and CLI parity

Three places in this repository name a `wasm-bindgen` version, and
`spikes/wasm-runtime-proof/spike.sh` exists because the third of them is easy
to get silently wrong: a scratch workspace with a loosened `wasm-bindgen = "0.2"`
requirement re-resolved to `0.2.127` while the locally installed
`wasm-bindgen-cli` was `0.2.126` — Cargo happily compiled the crate, and the
mismatch only surfaced as a JS-side schema error out of `wasm-bindgen
--target web`, deep in the generator's own protocol check, rather than as a
Rust compile error. The three places are: the version `Cargo.lock` actually
resolves for the `wasm-bindgen` package, the `=0.2.126` pin this ADR enters in
`[workspace.dependencies]`, and the `cargo:wasm-bindgen-cli = "0.2.126"` tool
pin this ADR enters in `mise.toml`. `tools/xtask/tests/wasm_toolchain.rs`
reads all three independently and fails the moment any one of them drifts from
the other two.

The same package supplies **both** programs this stage needs — the library
`wasm-bindgen`, which the generated JS glue links against, and the binary
`wasm-bindgen-cli`, which both `xtask build-wasm` (to emit that glue) and
`wasm-bindgen-test-runner` (to drive `cargo test --target wasm32-unknown-unknown`)
invoke — which is why **one** pin is sufficient and correct: a second,
independently versioned tool for either role would be a second carrier of the
same schema, exactly the failure mode `wasm-pack` is rejected for above.
`xtask build-wasm` enforces the pin itself, fail-closed and without an
environment-variable bypass, through `ensure_wasm_bindgen_cli_matches_lockfile()`:
it reads the resolved `wasm-bindgen` version out of `Cargo.lock`, runs
`wasm-bindgen --version`, and on any mismatch — including a missing CLI —
names the exact version that must be installed rather than letting a
schema-mismatch surface deep in the generator's own output.

`.cargo/config.toml` gains exactly one new table:

```toml
[target.wasm32-unknown-unknown]
runner = "wasm-bindgen-test-runner"
```

What it does **not** carry is the point: no `rustflags` key. `cargo test
--locked -p ea-reader-wasm --target wasm32-unknown-unknown` — the command the
task that creates `crates/ea-reader-wasm` runs — needs a way to execute
`wasm32-unknown-unknown` test binaries at all, since the host cannot run them
directly; `runner = "wasm-bindgen-test-runner"` is that way, and it is also
why this plan uses `wasm-bindgen-test` rather than `wasm-pack test`: the
runner comes from the **same** pinned `wasm-bindgen-cli` install this section
already enforces, so no second toolchain enters the loop. A `rustflags` entry
was considered and rejected in *Rejected alternatives* above, on the
combination of being the wrong mechanism for `getrandom` 0.4.3 and being
silently overridable by an ambient `RUSTFLAGS` even when correct — which is
also why `run_process_without_rustflags()` in `tools/xtask/src/main.rs`
explicitly strips any inherited `RUSTFLAGS` with `Command::env_remove("RUSTFLAGS")`
before it invokes `cargo build --target wasm32-unknown-unknown`, rather than
relying on the environment being clean by convention.

## Enumerated web-sys features

Each `web-sys` feature gates one generated Rust binding for one WebIDL
interface; leaving it unlisted leaves that binding uncompiled. The twenty-eight
below are grouped by the specification clause of
`docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` each
one serves.

| Feature(s) | Browser API unlocked | Spec clause |
| --- | --- | --- |
| `FileSystemDirectoryHandle`, `FileSystemFileHandle`, `FileSystemGetDirectoryOptions`, `FileSystemGetFileOptions`, `FileSystemReadWriteOptions`, `FileSystemSyncAccessHandle`, `StorageManager`, `Blob`, `File` | The Origin Private File System handle family and the blob/file types its read and write calls exchange | §8.1, the encrypted OPFS byte store |
| `Navigator`, `WorkerNavigator` | `navigator.storage`/`self.navigator.storage`, the two paths `StorageManager` is reachable from — one on the main thread, one inside a worker | §8.1, same OPFS byte store, both thread contexts |
| `Worker`, `DedicatedWorkerGlobalScope`, `WorkerGlobalScope`, `MessageEvent` | Spawning a dedicated worker, its global scope, and the message channel to it | The constraint that a synchronous access handle (`FileSystemSyncAccessHandle`) exists only inside a worker, never on the main thread |
| `ServiceWorkerGlobalScope` | The service worker's own global scope | §4.2, service worker activation against a pinned, root-signed `webBundleRelease` |
| `Crypto`, `SubtleCrypto` | `globalThis.crypto` and the Web Crypto operations under it | The entropy source behind `getrandom`'s `wasm_js` backend, and the WebAuthn assertion surface of §6.2 |
| `Request`, `RequestInit`, `Response`, `Headers` | The Fetch API's request/response types | §5.1, the server-reachable mode of the Reader |
| `Document`, `VisibilityState`, `Event` | `document.visibilityState` and the `visibilitychange` event | §6.5, the shortened lock period once a tab moves to the background |
| `Window` | `web_sys::window()`, the main-thread global object every one of the bindings above that is not itself a worker-side API resolves through | Prerequisite for `Crypto`, `Document` and the main-thread half of the OPFS path above |
| `XmlHttpRequest`, `XmlHttpRequestResponseType` | A **synchronous** `XMLHttpRequest` and the `responseType` enum that makes its response body readable as an `ArrayBuffer` rather than as text | §6.6 and §9, the three enrollment endpoints: `ea-reader` builds and signs the requests synchronously and carries no host dependency, so the transport has to be synchronous too — and the only synchronous transport a browser offers exists solely inside a dedicated worker. `fetch` returns a promise, and blocking on it would stall the very event loop that has to settle it. The second feature is not decorative: without it `response()` yields a string and a CBOR body would not survive the trip, while `set_response_type` is gated on the WebIDL enum type |

Twenty-eight admitted features and no others: a twenty-ninth must be justified
against a spec clause and pass through `browser_runtime_dependency_class_is_ratified_before_use`
in `tools/xtask/tests/adr_gate.rs` the same way these did, because the
reviewed ledger line it rebuilds from `[workspace.dependencies]` is exact and
ordered.

## Browser provisioning

This section decides **where** the browser engines and the webdriver this
stage needs come from — a question the Stage 4 gate report names but, until
this revision, left unanswered: `STAGE_FOUR_HOST_SCOPE_CLAUSE` records the
three engine builds by revision but no task said how they reach the machine,
and an executing agent following that gap ended up at `playwright install`
and, for WebKit, at `playwright install-deps` under root — a precondition no
Files block declared.

**Decision: engines and webdriver come from a pinned container image, not
from an installation on the host.** Three measured reasons, each sufficient
alone. First, this repository has **no CI** — neither `.github/workflows` nor
`.forgejo` exists, and the Stage 1 web reader prerequisite work names exactly
that as the reason `verify_quick_commands()` is the one path that always runs;
whatever drives the browser matrix runs on exactly one machine, and this plan
treats measured tool state as contractual. Second, the development host today
carries **only** Chromium: `~/.cache/ms-playwright` lists `chromium-1234` and
`chromium_headless_shell-1234` and neither `firefox` nor `webkit`, while the
gate task needs all three. Third, WebKit on Linux needs system libraries that
`playwright install-deps` pulls in under root — a host mutation a test run
must not perform.

The shape is the one this repository already carries for services, and
explicitly **not** a `.devcontainer/`: a compose file beside
`ops/compose/integration.yaml`, an `xtask` subcommand in the shape of
`integration up`/`down`, the runtime pinned through `EA_CONTAINER_RUNTIME` in
`mise.toml` and justified in
`docs/adr/0004-server-runtime-and-dependency-class.md`. A development
container would pull the whole toolchain in and stand against the host
pinning of `rust-toolchain.toml`, `.node-version` and `mise.toml`; the Tauri
build of `apps/desktop` additionally needs host libraries a container cannot
supply. The container is scoped to `apps/web` and `crates/ea-reader-wasm`; the
Playwright suite of `apps/desktop` stays untouched on the host, its own
measured IPv4-loopback and `offline: true` findings recorded in its own
configuration.

**Two carriers, not one**, and this section says so explicitly: `pnpm
web:e2e` needs Playwright's own engine builds (Chromium, Firefox, WebKit);
`pnpm web:browser-test` needs a `chromedriver` for
`wasm-bindgen-test-runner`. A plain Playwright image supplies the first and
not the second; the image this stage's container task builds **must** carry
both, and this section is the record of which program comes from where — the
image itself, its measured digest and the compose file are delivered by the
task "`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher und der
Laufzeitnachweis im Gate", not by this one.

The image revision is **bound** to the `@playwright/test` pin of
`apps/web/package.json` — Playwright refuses engine builds of a foreign
version — and that pin is created by the same later task. This ADR therefore
ratifies the **rule** and the **binding** here; the compose file and its
measured image digest are delivered there, the same way Stage 3 measured its
two image digests rather than asserting them.

What the container does **not** solve, named so it creates no false
confidence: Playwright's `webkit` is not Safari, and
`WebAuthn.addVirtualAuthenticator` remains a CDP method, so the enrollment
end-to-end test stays Chromium-only — both already stand as open lines in the
Stage 4 gate report, and an image does not make either one true.

## Consequences

- The lockfile update that
  `docs/adr/0001-toolchain-and-cryptography-dependencies.md`:152-154 requires
  is completed by the task that creates `crates/ea-reader-wasm`, when that
  member inherits these five entries with `workspace = true` and the packages
  actually enter the graph as direct edges rather than transitive ones. Under
  the inheritance rule (`docs/adr/0001-toolchain-and-cryptography-dependencies.md`:15-20)
  this task cannot discharge it: `Cargo.lock` stays byte-identical, measured
  with `git diff --stat Cargo.lock`, because pinning an entry in
  `[workspace.dependencies]` is a template until a member's `workspace = true`
  edge reaches it. That same task owns the first empirical proof that the
  pinned tree builds *and runs* for `wasm32-unknown-unknown` inside this
  workspace, beyond the compilability-only claim
  `docs/adr/0001-toolchain-and-cryptography-dependencies.md`'s delivery
  ledger already records for `ea-verify` and its neighbours.
- The sixth pin, `hkdf`, discharges its own lockfile obligation in the task
  that enters it: `crates/ea-reader` inherits it with `workspace = true`, and
  the measured `Cargo.lock` delta is the `ea-reader` edge list alone — no new
  `[[package]]`, because `hpke 0.14.0` and `sqlx-postgres 0.9.0` already
  resolved `hkdf 0.13.0`. An `hkdf` upgrade independent of `hpke` is a new
  reviewed decision under
  `docs/adr/0001-toolchain-and-cryptography-dependencies.md`:152-154, because
  `hkdf`, `hmac` and `sha2` sharing one `digest 0.11.3` today is a measured
  fact and not a guarantee. Removing the last `Hkdf` call from
  `crates/ea-reader` removes the pin: this document admits no pin no member
  consumes.
- `deny.toml`'s five-entry license allowlist and its four named per-crate
  exceptions are both unchanged by this decision: all five crates of this
  class declare `MIT OR Apache-2.0`, already allowed, and none of the five is
  new to the resolved graph. No `GATE-*` ledger anchor is created, unlike the
  `v1.2` row `GATE-25` that the four Stage-3 server-class exceptions carry —
  there is nothing here for a ledger row to track.
- `mise.toml`'s `cargo:wasm-bindgen-cli` pin and the `wasm-bindgen` crate pin
  in `[workspace.dependencies]` must change **together**, in the same commit
  as `Cargo.lock`'s resolved `wasm-bindgen` version, or
  `the_wasm_bindgen_cli_pin_equals_the_locked_crate_version` in
  `tools/xtask/tests/wasm_toolchain.rs` fails before a build is attempted. A
  `js-sys`, `wasm-bindgen-futures`, `wasm-bindgen-test` or `web-sys` upgrade
  independent of `wasm-bindgen` is a new reviewed decision under
  `docs/adr/0001-toolchain-and-cryptography-dependencies.md`:152-154, because
  the five releasing together today is a measured fact and not a structural
  guarantee this ADR can assume of a future release.
- `getrandom`'s `=0.4.3` pin and `wasm_js` feature remain owned exclusively by
  `docs/adr/0001-toolchain-and-cryptography-dependencies.md` and enforced by
  `workspace_getrandom_enables_the_wasm_js_feature`; nothing in this document
  changes it, and nothing here should ever be edited to change it — a second
  edit site for the same pin is the drift this section exists to prevent.
- No wire format, vector or compatibility file is affected. Suite 1, the six
  frozen object prefixes and every frozen vector remain unchanged; this class
  moves bytes across the wasm/JS boundary and produces none of the archive's
  own bytes.
- `.cargo/config.toml`'s `[target.wasm32-unknown-unknown]` `runner` has no
  observable effect until `crates/ea-reader-wasm` exists: there is no
  `wasm32-unknown-unknown` test binary to run yet. Its presence here, ahead
  of that crate, is the same ordering `docs/adr/0004-server-runtime-and-dependency-class.md`
  uses for `integration up` ahead of `apps/server` — the command exists before
  its subject.
- The browser-provisioning decision binds a later task: the compose file
  beside `ops/compose/integration.yaml`, the `integration`-shaped `xtask`
  subcommand for the browser container, and the measured image digest are
  owned by the task "`apps/web`, die wasm-bindgen-Brücke, der OPFS-Bytespeicher
  und der Laufzeitnachweis im Gate", bound to the `@playwright/test` pin that
  task also creates.
