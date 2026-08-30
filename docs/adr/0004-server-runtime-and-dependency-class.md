# ADR 0004: Server runtime and dependency class

- Status: Accepted
- Decision date: 2026-08-28
- Evidence retrieved: 2026-08-28

## Context

Stage 3 builds the blind sync server. `docs/superpowers/specs/2026-08-13-einsatzarchiv-v0-1-design.md`:118-121
names its four moving parts: an **Axum sync server** for device requests, trust
distribution, object acceptance, chain checking, receipts, checkpoints and
evidence orders; **PostgreSQL** for technical indexes and transactional server
state only; and an **S3-kompatibler Object Store** for content-addressed binary
objects without domain metadata. None of these is a dependency class that
`docs/adr/0001-toolchain-and-cryptography-dependencies.md` admitted: its
inventory covers deterministic CBOR, COSE, Suite 1 cryptography, time and the
`toml` tooling parser, and its consequences (`:152-154`) make any dependency of
a new class a new ADR with a fresh primary-source and RustSec review, a lockfile
update, vectors and a compatibility analysis. This document is that decision for
the server class, and it is ratified **before** the dependency is used.

The precedent for the shape is `docs/adr/0002-local-database-encryption.md`,
which ratified SQLCipher before `crates/ea-local-store` existed. Like that
document, this one writes no application code, creates no crate and starts no
server: it pins eight crates in `[workspace.dependencies]`, records the review
that permits them, and hands the first empirical build proof to the task that
creates the member.

The reach of `docs/adr/0001-toolchain-and-cryptography-dependencies.md`:75-77 —
OpenSSL and `ring` as suite-wide abstractions — is **settled** and is not
reopened here. `docs/adr/0002-local-database-encryption.md`:52-64 already
rejects the wide reading verbatim as a rejected alternative: the clause keeps
Suite 1's algorithm selection explicit and pure-Rust, and a component that
produces no archive byte, no COSE signature, no grant and no hash-chain link is
not a suite-wide abstraction. The TLS stack below is therefore **named and
reviewed, not defended**.

Under the inheritance rule of
`docs/adr/0001-toolchain-and-cryptography-dependencies.md`:15-20 a shared
dependency that no member inherits does not enter `Cargo.lock`. This task
deliberately registers **no workspace member** — a `members` entry pointing at a
directory without a manifest fails `cargo metadata` and with it every test — so
`Cargo.lock` stays byte-identical, measured with `git diff --stat Cargo.lock`
after one `cargo metadata --format-version 1`. **No pin is entered that
no member of this stage consumes**; the lockfile obligation is named in
*Consequences* and discharged by the task that adds `apps/server`.

## Decision

The sync server runs on the Tokio multi-threaded runtime, serves HTTP through
Axum over hyper 1.x, reaches PostgreSQL through SQLx, reaches the
S3-compatible object store through the AWS SDK for Rust, and terminates TLS 1.3
through rustls with the `ring` cryptography provider.

| Dependency | Exact pin and enabled features | Role, maintenance, and security rationale |
| --- | --- | --- |
| [`tokio`](https://crates.io/crates/tokio/1.53.1) | `=1.53.1`; `default-features = false`, `macros`, `net`, `rt-multi-thread`, `signal`, `sync`, `time` | The [Tokio upstream](https://github.com/tokio-rs/tokio) is the async runtime every other crate of this class is built against; there is no second candidate that Axum, SQLx and the AWS SDK all support. `rt-multi-thread` plus `net` and `time` is the runtime the server binary needs, `macros` is what `#[tokio::main]` and the `#[tokio::test]` functions in `crates/ea-sync-server/tests/` resolve to, `signal` carries the ordered shutdown, and `sync` carries the shared state. `fs`, `process` and `io-std` stay disabled: the server writes no file of its own. |
| [`axum`](https://crates.io/crates/axum/0.8.9) | `=0.8.9`; `default-features = false`, `http1`, `http2`, `tokio` | The [tokio-rs upstream](https://github.com/tokio-rs/axum) is the HTTP server the design names by name. Defaults are off, which removes `form`, `query`, `json`, `matched-path`, `original-uri`, `tower-log` and `tracing` from the surface. `json` in particular is **deliberately absent**: the sync protocol carries deterministic CBOR, and a JSON extractor in the router would be a second, unreviewed decoding path into the server. `tokio` pulls the `hyper`/`hyper-util` serving glue and `tower`'s `make` layer, which is how hyper and tower enter this tree — transitively and reviewed, not as direct pins. |
| [`hyper`](https://crates.io/crates/hyper/1.11.0) | `=1.11.0`; `default-features = false`, `client`, `http1` | The [hyperium upstream](https://github.com/hyperium/hyper) is the HTTP implementation Axum already serves on, and this pin is what turns the *server* half of that tree into a reviewed **client** for `crates/ea-sync-client`: the Writer uploads its committed entries over the same protocol the server speaks, and a hand-rolled HTTP/1.1 writer in production code would be a second, unreviewed wire implementation. `client` and `http1` only — `server` is already reached transitively through `axum`, `http2` stays off because the Writer opens one short-lived connection per signed request and negotiates `http/1.1` by ALPN, and `ffi`, `capi` and `tracing` stay off. Chosen over `reqwest`, which would add a second connection pool, a second TLS selection path and a redirect/cookie surface this protocol never uses. |
| [`hyper-util`](https://crates.io/crates/hyper-util/0.1.20) | `=0.1.20`; `default-features = false`, `tokio` | The [hyperium upstream](https://github.com/hyperium/hyper-util) supplies `TokioIo`, the adapter between Tokio's `AsyncRead`/`AsyncWrite` and hyper's own I/O traits. Exactly one feature: `tokio` adds `TokioIo`, `TokioExecutor` and `TokioTimer` and nothing else. `client-legacy` — the pooled high-level client — stays **off** deliberately: it carries `socket2`, `libc` and a connection pool the Writer does not use, and the pool would keep a TLS session alive across signed requests whose freshness is the point. |
| [`http`](https://crates.io/crates/http/1.5.0) | `=1.5.0`; `default-features = false`, `std` | The [hyperium upstream](https://github.com/hyperium/http) carries `Request`, `Response`, `StatusCode` and the header types every crate of this family speaks. It is pinned **directly** rather than reached through `hyper`'s re-export, following the precedent of the direct `sqlx-core` pin: `crates/ea-sync-client` names these types in its own signatures, so the version it compiles against belongs in the reviewed table and not in a re-export chain. `std` is the crate's only feature and its default; `default-features = false` keeps the selection explicit rather than inherited. |
| [`http-body-util`](https://crates.io/crates/http-body-util/0.1.5) | `=0.1.5`; `default-features = false` | The [hyperium upstream](https://github.com/hyperium/http-body) supplies `Full` — the fully buffered request body of a signed CBOR frame — and `BodyExt::collect`, which reads the bounded response body back. Buffered and not streamed is the correct shape here and not a shortcut: every request body of this protocol is digest-covered by the RFC-9421 signature (`crates/ea-sync-protocol/src/http_signature.rs`), so the bytes must exist in full before the request can be signed at all. Its `channel` feature — the only one it declares — stays off, which is why its reviewed selection below is the empty ledger line. |
| [`sqlx`](https://crates.io/crates/sqlx/0.9.0) | `=0.9.0`; `default-features = false`, `postgres`, `runtime-tokio`, `tls-rustls-ring-webpki` | The [launchbadge upstream](https://github.com/launchbadge/sqlx) is the async PostgreSQL driver. Defaults are off, which removes `any` — the runtime driver multiplexer — so a connection string cannot silently select MySQL or SQLite. `postgres` is the only backend, `runtime-tokio` the only runtime, and `tls-rustls-ring-webpki` selects the same `ring` provider as the rest of this class. **`macros` and `migrate` are deliberately NOT enabled on the facade**, and that is a measured constraint rather than a preference: both features carry weak references `sqlx-sqlite?/offline` respectively `sqlx-sqlite?/migrate`. A weak reference does not activate the dependency, but Cargo must still resolve a version for it, and `sqlx-sqlite 0.9.0` requires `libsqlite3-sys >=0.30.1, <0.38.0` while `docs/adr/0002-local-database-encryption.md` pins `=0.38.0`. Both declare `links = "sqlite3"`, so the whole workspace stops resolving with `failed to select a version for libsqlite3-sys`. Reproduced in a bare scratch package outside this workspace, so it is a property of the two pins and not of this repository. The consequence is recorded rather than hidden: `#[sqlx::test]` is unreachable here — `sqlx::test` sits behind `#[cfg(feature = "macros")]` and `sqlx::testing`, where its generated code lands, behind `#[cfg(feature = "migrate")]` (`sqlx-0.9.0/src/lib.rs`:83, :88) — and every `apps/server` integration test target of this stage therefore brings its own disposable database in `apps/server/tests/common/mod.rs`. The backend, runtime and TLS feature families are mutually exclusive upstream, which is why the selection is recorded verbatim below. |
| [`sqlx-core`](https://crates.io/crates/sqlx-core/0.9.0) | `=0.9.0`; `default-features = false`, `migrate` | The same upstream release as `sqlx`, pinned **directly** for exactly one reason: it carries `sqlx_core::migrate::Migrator`, the directory-based migration runner, and — unlike the facade's `migrate` feature — it does not depend on `sqlx-sqlite` at all, so it never drags `libsqlite3-sys` into resolution. Enabling it here keeps the migration bookkeeping table `_sqlx_migrations` and the resolved-at-run-time `migrations/` directory, so Stage 3 invents **no** migration machinery of its own — which is what `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-3-blind-sync.md` reserves for Stage 7. It resolves to the same `sqlx-core` instance the facade already uses, so the types unify. |
| [`sqlx-postgres`](https://crates.io/crates/sqlx-postgres/0.9.0) | `=0.9.0`; `default-features = false`, `migrate` | Same release again, and pinned directly for the mirror reason: `Migrator::run` requires `A::Connection: Migrate`, and the `Migrate` implementation for `PgConnection` lives behind `sqlx-postgres`'s own `migrate` feature (`migrate = ["sqlx-core/migrate", "dep:crc"]`). Without this edge the migrator compiles but cannot run against PostgreSQL. `sqlx-postgres` carries no `sqlx-sqlite` dependency either. The facade's `postgres` feature already activates this crate, so this entry adds a feature and not a second copy. |
| [`aws-sdk-s3`](https://crates.io/crates/aws-sdk-s3/1.144.0) | `=1.144.0`; `default-features = false`, `behavior-version-latest`, `http-1x`, `rt-tokio` | The [AWS SDK for Rust](https://github.com/awslabs/aws-sdk-rust) is the S3 client; the spec says only `S3-kompatibler Object Store`, so this ADR names the crate. Its operation surface carries `put_bucket_versioning`, `get_bucket_versioning` and `list_object_versions`, which is what makes **bucket versioning** — a requirement of this stage — administrable from Rust rather than only from an operator console. `default-features = false` is load-bearing: the default set enables `rustls` and `default-https-client`, and those pull a *legacy* hyper 0.14 / rustls 0.21 connector and `aws-lc-sys` respectively. `behavior-version-latest` fixes the SDK's own behaviour contract, `http-1x` and `rt-tokio` bind it to hyper 1.x and Tokio, and `sigv4a` stays off because a single-region S3-compatible endpoint does not use multi-region access points. |
| [`aws-smithy-http-client`](https://crates.io/crates/aws-smithy-http-client/1.4.0) | `=1.4.0`; `default-features = false`, `rustls-ring` | Pinned **directly** although `aws-sdk-s3` already depends on it, following the precedent of the direct `libsqlite3-sys` pin (`docs/adr/0002-local-database-encryption.md`:45): this crate decides which TLS provider the S3 client uses, and reaching it only through the SDK's own `rustls` feature would silently select the legacy hyper 0.14 stack. `rustls-ring` is the one feature that yields hyper 1.x plus rustls 0.23 on `ring`, so the whole class shares one TLS implementation and one certificate parser. The connector is built explicitly in the server and handed to `aws_sdk_s3::Config::http_client`. |
| [`rustls`](https://crates.io/crates/rustls/0.23.43) | `=0.23.43`; `default-features = false`, `logging`, `ring`, `std` | The [rustls upstream](https://github.com/rustls/rustls) is the TLS implementation. Defaults are off for two separate reasons. `tls12` is **omitted**, which makes this a TLS 1.3-only stack by construction rather than by configuration. `aws_lc_rs` and `prefer-post-quantum` (which requires it) are omitted in favour of `ring`, so the tree carries no `aws-lc-sys` and no CMake/NASM build requirement; the resulting native-toolchain footprint is smaller than the one `docs/adr/0002-local-database-encryption.md`:269-287 already accepted for SQLCipher. |
| [`tokio-rustls`](https://crates.io/crates/tokio-rustls/0.26.4) | `=0.26.4`; `default-features = false`, `logging`, `ring` | The [rustls upstream](https://github.com/rustls/tokio-rustls) supplies the `TlsAcceptor` that terminates inbound TLS in front of Axum. Its feature set mirrors the `rustls` pin one to one — `tls12` omitted, `ring` selected — because a mismatch between the two would enable TLS 1.2 on the listening side only. |
| [`async-trait`](https://crates.io/crates/async-trait/0.1.92) | `=0.1.92`; `default-features = false` | The [dtolnay upstream](https://github.com/dtolnay/async-trait) supplies object-safe async traits. Native `async fn` in traits is stable in Rust 1.95 but is **not** dyn-compatible, and the storage and object-store boundaries of `crates/ea-sync-server` are exactly the seams that need a `Box<dyn …>` so a test double can replace the real service. The crate declares no features at all, which is why its reviewed selection below is the empty ledger line. |

Every additional feature the server crates turn out to need is added with its
own justification row in this table, never silently.

## Rejected alternatives

- **`object_store`** as the S3 client, rejected on measurement. Its `aws`
  feature unconditionally enables `aws-lc-rs` and `reqwest`, so it would pull a
  second TLS provider and a second HTTP client into a tree that already has
  one; and it is a portability abstraction over several clouds whose surface
  does not expose bucket-versioning administration at all, which this stage
  requires.
- **`rust-s3`**, rejected because it implements SigV4 request signing itself in
  a crate with a far smaller maintenance base than the AWS SDK. Hand-rolled
  request signing is the same class of risk that
  `docs/adr/0001-toolchain-and-cryptography-dependencies.md`:65-67 rejects for
  hand-written CBOR and COSE.
- **`aws-sdk-s3` with its default features**, rejected after resolving both
  trees. The defaults add `aws-lc-sys` (through `default-https-client`) and a
  legacy hyper 0.14 / rustls 0.21 / h2 0.3 connector (through `rustls`): 263
  packages with duplicated TLS and HTTP stacks, against 249 packages with a
  single rustls 0.23 and a single hyper 1.x under the selection above.
- **`aws-config`**, rejected as unnecessary. Static credentials for an
  S3-compatible endpoint are constructed through `aws_sdk_s3::config::Credentials`,
  which the SDK re-exports; `aws-config` exists to discover credentials from
  the ambient environment, EC2 metadata and profile files, which is exactly the
  host variance this project avoids.
- **`aws_lc_rs` as the rustls provider**, rejected because `aws-lc-sys` vendors
  OpenSSL-licensed sources and requires CMake and, on Windows, NASM. `ring` is
  reviewed below and carries neither.
- **`native-tls`/`openssl` for the PostgreSQL and S3 connections**, rejected
  because the TLS implementation would then depend on a host library the
  lockfile does not pin — the same reason
  `docs/adr/0002-local-database-encryption.md`:75-78 rejects a system
  SQLCipher.
- **Enabling `tls12`**, rejected because the stage needs TLS 1.3 and a version
  that is compiled in can be re-enabled by configuration. Omitting the feature
  makes the absence structural.
- **Enabling `sqlx`'s `any` feature (part of its defaults)**, rejected because
  it resolves the driver from the connection string at runtime; a typo in
  `DATABASE_URL` would then pick a different database engine instead of failing.
- **`tls-rustls-ring-native-roots` for SQLx**, rejected in favour of
  `tls-rustls-ring-webpki`. Native roots make the trust anchors of a server
  connection depend on the host trust store; the webpki variant pins the
  Mozilla root set in `Cargo.lock`, which is the same reproducibility argument
  `docs/adr/0002-local-database-encryption.md`:285-287 makes for vendored
  sources. The price is one named license exception (`webpki-roots`,
  CDLA-Permissive-2.0), recorded below.
- **Podman and colima as the container runtime**, rejected for this stage
  because neither is installed on the development host, so pinning one would
  pin something unmeasured. The pin is recorded in `mise.toml` and can be
  revisited when a second runtime is actually in use.
- **SeaweedFS, LocalStack and Garage as the S3-compatible service**, rejected
  on the bucket-versioning requirement: Garage does not implement object
  versioning, LocalStack is a mock rather than a storage engine, and SeaweedFS
  implements the versioning surface only partially. MinIO implements
  `PutBucketVersioning` and `ListObjectVersions` and is used below.
- **Registering a workspace member in this task**, rejected because a `members`
  entry pointing at a directory without a manifest fails `cargo metadata` and
  with it every test in the repository.

## Primary-source and RustSec review

Carried out on 2026-08-28 as
`docs/adr/0001-toolchain-and-cryptography-dependencies.md`:152-154 demands,
with the rigour of the existing dependency tables
(`docs/adr/0001-toolchain-and-cryptography-dependencies.md`:49-61 and
`docs/adr/0002-local-database-encryption.md`:95-98). This is a
dependency-risk decision, not a claim that any of these crates has received an
independent formal audit.

### 1. Primary sources per crate

Read from the official crates.io records of the pinned releases for the ten
rows of the server class: every one of those releases is published and **not
yanked**. The four rows of the HTTP client family carry `not retrieved` in the
publication column, and for them this sentence is expressly NOT claimed — see
the paragraph above.

| Crate | Pinned release | Published | Declared SPDX | crates.io record | Upstream project |
| --- | --- | --- | --- | --- | --- |
| `tokio` | `=1.53.1` | 2026-07-20 | `MIT` | <https://crates.io/crates/tokio/1.53.1> | <https://github.com/tokio-rs/tokio> |
| `axum` | `=0.8.9` | 2026-04-14 | `MIT` | <https://crates.io/crates/axum/0.8.9> | <https://github.com/tokio-rs/axum> |
| `hyper` | `=1.11.0` | not retrieved | `MIT` | <https://crates.io/crates/hyper/1.11.0> | <https://github.com/hyperium/hyper> |
| `hyper-util` | `=0.1.20` | not retrieved | `MIT` | <https://crates.io/crates/hyper-util/0.1.20> | <https://github.com/hyperium/hyper-util> |
| `http` | `=1.5.0` | not retrieved | `MIT OR Apache-2.0` | <https://crates.io/crates/http/1.5.0> | <https://github.com/hyperium/http> |
| `http-body-util` | `=0.1.5` | not retrieved | `MIT` | <https://crates.io/crates/http-body-util/0.1.5> | <https://github.com/hyperium/http-body> |
| `sqlx` | `=0.9.0` | 2026-05-21 | `MIT OR Apache-2.0` | <https://crates.io/crates/sqlx/0.9.0> | <https://github.com/launchbadge/sqlx> |
| `sqlx-core` | `=0.9.0` | 2026-05-21 | `MIT OR Apache-2.0` | <https://crates.io/crates/sqlx-core/0.9.0> | <https://github.com/launchbadge/sqlx> |
| `sqlx-postgres` | `=0.9.0` | 2026-05-21 | `MIT OR Apache-2.0` | <https://crates.io/crates/sqlx-postgres/0.9.0> | <https://github.com/launchbadge/sqlx> |
| `aws-sdk-s3` | `=1.144.0` | 2026-08-25 | `Apache-2.0` | <https://crates.io/crates/aws-sdk-s3/1.144.0> | <https://github.com/awslabs/aws-sdk-rust> |
| `aws-smithy-http-client` | `=1.4.0` | 2026-08-19 | `Apache-2.0` | <https://crates.io/crates/aws-smithy-http-client/1.4.0> | <https://github.com/smithy-lang/smithy-rs> |
| `rustls` | `=0.23.43` | 2026-07-29 | `Apache-2.0 OR ISC OR MIT` | <https://crates.io/crates/rustls/0.23.43> | <https://github.com/rustls/rustls> |
| `tokio-rustls` | `=0.26.4` | 2025-09-26 | `MIT OR Apache-2.0` | <https://crates.io/crates/tokio-rustls/0.26.4> | <https://github.com/rustls/tokio-rustls> |
| `async-trait` | `=0.1.92` | 2026-08-08 | `MIT OR Apache-2.0` | <https://crates.io/crates/async-trait/0.1.92> | <https://github.com/dtolnay/async-trait> |

The four rows of the HTTP **client family** — `hyper`, `hyper-util`, `http`,
`http-body-util` — were added on 2026-08-29 by the task that created
`crates/ea-sync-client`, and their provenance is recorded exactly as far as it
was actually retrieved. Their declared SPDX expressions, their `rust-version`
values and their complete feature tables were read from the **published
manifests** of the pinned releases as they lie in the local registry source
(`~/.cargo/registry/src/index.crates.io-*/<name>-<version>/Cargo.toml`) — the
same manifests Cargo resolves. Their **publication dates** and their **RustSec
advisory histories** were **not** independently retrieved in that task and are
marked accordingly below; the crates.io and advisory-database review of these
four rows is therefore an open obligation and not a completed one. The `cargo
deny check advisories` run over the resolved workspace answered `advisories ok`
with no new `ignore` entry, which is a statement about the *resolved tree* and
not a substitute for the per-crate reading the sections below otherwise record.

### 2. Verified feature names

Read out of the published manifests of the pinned releases — the `.crate`
archives from <https://static.crates.io/crates/>, which carry the manifest
Cargo actually resolves — and not from memory, because three of the five
families below are mutually exclusive upstream.

`sqlx` 0.9.0 selects one backend, one runtime and one TLS family, and its
default set is `["any", "macros", "migrate", "json"]`:

```toml
tls-rustls = ["tls-rustls-ring"]
tls-rustls-ring = ["tls-rustls-ring-webpki"]
tls-rustls-ring-webpki = ["sqlx-core/_tls-rustls-ring-webpki", "sqlx-macros?/_tls-rustls-ring-webpki"]
tls-rustls-ring-native-roots = ["sqlx-core/_tls-rustls-ring-native-roots", "sqlx-macros?/_tls-rustls-ring-native-roots"]
tls-rustls-aws-lc-rs = ["sqlx-core/_tls-rustls-aws-lc-rs", "sqlx-macros?/_tls-rustls-aws-lc-rs"]
tls-native-tls = ["sqlx-core/_tls-native-tls", "sqlx-macros?/_tls-native-tls"]
tls-none = []
```

`rustls` 0.23.43 selects one cryptography provider, and `prefer-post-quantum`
— part of its default set — silently requires `aws_lc_rs`:

```toml
default = ["aws_lc_rs", "logging", "prefer-post-quantum", "std", "tls12"]
aws_lc_rs = ["dep:aws-lc-rs", "webpki/aws-lc-rs", "aws-lc-rs/aws-lc-sys", "aws-lc-rs/prebuilt-nasm"]
prefer-post-quantum = ["aws_lc_rs"]
ring = ["dep:ring", "webpki/ring"]
tls12 = []
```

`aws-sdk-s3` 1.144.0 reaches its HTTP client through two features that are not
what their names suggest — `rustls` routes to a *legacy* connector and
`default-https-client` to `aws-lc-rs`:

```toml
default = ["sigv4a", "http-1x", "rustls", "default-https-client", "rt-tokio"]
rustls = ["aws-smithy-runtime/tls-rustls"]                 # -> aws-smithy-http-client/legacy-rustls-ring (hyper 0.14)
default-https-client = ["aws-smithy-runtime/default-https-client"]  # -> aws-smithy-http-client/rustls-aws-lc
```

which is why the connector is selected directly on `aws-smithy-http-client`
1.4.0 instead:

```toml
rustls-ring = ["__rustls", "rustls?/ring"]
rustls-aws-lc = ["__rustls", "rustls?/aws_lc_rs", "rustls?/prefer-post-quantum"]
```

The reviewed selection is recorded once more in the exact form
`tools/xtask/tests/adr_gate.rs` rebuilds from `[workspace.dependencies]`, so
that enabling, removing or reordering a feature cannot reach the gate without
passing through this review — a bare mention of a feature name is not enough,
because this ADR also names features that stay *disabled*:

```
async-trait = []
aws-sdk-s3 = ["behavior-version-latest", "http-1x", "rt-tokio"]
aws-smithy-http-client = ["rustls-ring"]
axum = ["http1", "http2", "tokio"]
http = ["std"]
http-body-util = []
hyper = ["client", "http1"]
hyper-util = ["tokio"]
rustls = ["logging", "ring", "std"]
sqlx = ["postgres", "runtime-tokio", "tls-rustls-ring-webpki"]
sqlx-core = ["migrate"]
sqlx-postgres = ["migrate"]
tokio = ["macros", "net", "rt-multi-thread", "signal", "sync", "time"]
tokio-rustls = ["logging", "ring"]
```

### 3. Reported MSRV

Every pinned release declares `rust-version` in its published manifest, so this
class needs no derivation from release dates.

| Crate | Declared `rust-version` | Admits Rust 1.95? |
| --- | --- | --- |
| `tokio` 1.53.1 | 1.71 | yes |
| `axum` 0.8.9 | 1.80 | yes |
| `hyper` 1.11.0 | 1.63 | yes |
| `hyper-util` 0.1.20 | 1.64 | yes |
| `http` 1.5.0 | 1.57.0 | yes |
| `http-body-util` 0.1.5 | 1.61 | yes |
| `sqlx` 0.9.0 | 1.94.0 | yes |
| `sqlx-core` 0.9.0 | 1.94.0 | yes |
| `sqlx-postgres` 0.9.0 | 1.94.0 | yes |
| `aws-sdk-s3` 1.144.0 | 1.94.1 | yes |
| `aws-smithy-http-client` 1.4.0 | 1.94.1 | yes |
| `rustls` 0.23.43 | 1.71 | yes |
| `tokio-rustls` 0.26.4 | 1.71 | yes |
| `async-trait` 0.1.92 | 1.71 | yes |

`sqlx` and the two AWS crates sit closest to the pinned compiler; a newer
release of either is a toolchain decision under
`docs/adr/0001-toolchain-and-cryptography-dependencies.md`:152-154 and not a
patch bump.

### 4. RustSec advisory review

Queried on 2026-08-28 against the [RustSec advisory database](https://github.com/RustSec/advisory-db)
by reading `crates/<name>/` for each crate of the SERVER class, and confirmed
mechanically by resolving the selection above in a scratch package and running
`cargo deny check advisories` against this repository's `deny.toml`, which
answered `advisories ok` with no new `ignore` entry. The four rows of the HTTP
client family were NOT read that way — they carry `not retrieved`, and the only
statement this document makes about them is the `cargo deny` result over the
resolved tree.

| Crate | Advisories found | Highest patched floor | Verdict for the pinned tree |
| --- | --- | --- | --- |
| `tokio` | `RUSTSEC-2021-0072`, `RUSTSEC-2021-0124`, `RUSTSEC-2023-0001`, `RUSTSEC-2023-0005`, `RUSTSEC-2025-0023` | `>= 1.44.2` | `1.53.1` is past all five. |
| `axum` | none — `crates/axum/` does not exist in the database | — | An empty result, recorded as the finding it is. |
| `hyper` | not retrieved — see the note above §2 | — | Covered only by the `cargo deny check advisories` run over the resolved tree. |
| `hyper-util` | not retrieved — see the note above §2 | — | Covered only by the `cargo deny check advisories` run over the resolved tree. |
| `http` | not retrieved — see the note above §2 | — | Covered only by the `cargo deny check advisories` run over the resolved tree. |
| `http-body-util` | not retrieved — see the note above §2 | — | Covered only by the `cargo deny check advisories` run over the resolved tree. |
| `sqlx` | `RUSTSEC-2024-0363` | `>= 0.8.1` | `0.9.0` is past it. |
| `sqlx-core` | `RUSTSEC-2024-0363` (recorded against the `sqlx` family) | `>= 0.8.1` | `0.9.0` is past it; it is the same upstream release as the facade. |
| `sqlx-postgres` | none — directory absent | — | Empty result; it ships in the same release as `sqlx`. |
| `aws-sdk-s3` | none — directory absent | — | Empty result. |
| `aws-smithy-http-client` | none — directory absent | — | Empty result. |
| `rustls` | `RUSTSEC-2024-0336`, `RUSTSEC-2024-0399` | `>= 0.23.18` | `0.23.43` is past both. |
| `tokio-rustls` | `RUSTSEC-2020-0019` | `>= 0.22.0` | `0.26.4` is past it. |
| `async-trait` | none — directory absent | — | Empty result. |
| `ring` (transitive, `0.17.14`) | `RUSTSEC-2025-0007`, `RUSTSEC-2025-0009`, `RUSTSEC-2025-0010` | `>= 0.17.12` | Past the one real advisory. See the note below. |
| `rustls-webpki` (transitive, `0.103.15`) | `RUSTSEC-2023-0053`, `RUSTSEC-2026-0049`, `RUSTSEC-2026-0098`, `RUSTSEC-2026-0099`, `RUSTSEC-2026-0104` | `>= 0.103.13` | `0.103.15` is past all five. |
| `untrusted` (transitive, `0.9.0`) | `RUSTSEC-2018-0001` | `>= 0.6.2` | `0.9.0` is past it. |
| `webpki-roots` (transitive, `1.0.9`) | none — directory absent | — | Empty result. |

Three findings belong in this table rather than in a footnote.

First, the five empty results are an absence of *recorded* advisories on
2026-08-28 and not a statement about those crates' futures. The four rows of
the HTTP client family are **not** among them: they are marked `not retrieved`,
which is a different statement and deliberately not the friendlier one.

Second, `ring` carries two `informational = "unmaintained"` entries that are
**not** current defects of the pinned release, and saying so precisely matters
because `ring` is the cryptography provider of the whole TLS stack.
`RUSTSEC-2025-0007` ("*ring* is unmaintained") was **withdrawn on 2025-02-22**;
its own text records that the rustls team took over maintenance and that the
situation is "back to normal". `RUSTSEC-2025-0010` declares `unaffected = [">= 0.17"]`
and concerns the abandoned 0.16 line only. `RUSTSEC-2025-0009` is the one real
advisory — an overflow panic in AES functions — and is patched at `>= 0.17.12`,
below the resolved `0.17.14`.

Third, `rustls-webpki` is the crate in this tree with the most active advisory
history — four entries in 2026 alone — because it is the certificate path
parser. It is the component of this decision that will need the most frequent
reviewed pin refresh, and every such refresh is a new lockfile review under
`docs/adr/0001-toolchain-and-cryptography-dependencies.md`:152-154. It is also
one of the four named license exceptions below, so both controls point at the
same crate.

### 5. Licenses of the crates the pinned tree adds

Measured, not recalled: the selection above was resolved in a scratch package
outside this workspace and checked with `cargo deny check licenses` against
this repository's `deny.toml`. The resolved tree is **249 packages**. Exactly
four of them carry an SPDX expression that the five-entry allowlist does not
satisfy.

| Crate | Declared SPDX expression | Why the allowlist does not cover it | Path into the graph |
| --- | --- | --- | --- |
| `ring` 0.17.14 | `Apache-2.0 AND ISC` | The expression is a conjunction: `Apache-2.0` alone does not satisfy it, `ISC` must be allowed as well. | `rustls` (feature `ring`) → `ring` |
| `rustls-webpki` 0.103.15 | `ISC` | `ISC` is not in the allowlist. | `rustls` → `rustls-webpki`; also `sqlx` → … → `rustls-webpki` |
| `untrusted` 0.9.0 | `ISC` | `ISC` is not in the allowlist. | `ring` → `untrusted`; `rustls-webpki` → `untrusted` |
| `webpki-roots` 1.0.9 | `CDLA-Permissive-2.0` | A permissive **data** licence over the bundled Mozilla root certificate set, not a code licence, and not in the allowlist. | `sqlx` (feature `tls-rustls-ring-webpki`) → `webpki-roots` |

All four are permissive and none is copyleft, so no obligation attaches to
Einsatzarchiv's own source. They are entered in `deny.toml` as **named
per-crate exceptions**, and the five-entry allowlist stays at five entries —
`Apache-2.0`, `BSD-3-Clause`, `BlueOak-1.0.0`, `MIT`, `Unicode-3.0` — because
the comment above that block states verbatim that "eine neue Crate unter
derselben Lizenz wird weiterhin abgewiesen, und das ist der Unterschied
zwischen einer Ausnahme und einer stillschweigenden Erweiterung". Each
exception has a ledger anchor: the `v1.2` row `GATE-25` on stage 7 in
`docs/traceability/v0.1-requirements.csv`, which names all four crates and
makes the re-assessment a release obligation. An exception without an anchor
enforces nothing.

One consequence of the no-member rule is visible here and is recorded rather
than hidden: until a member inherits this class, none of the four crates is in
the graph, so `cargo deny check licenses` reports each of them as
`license-exception-not-encountered` — a **warning**, not an error. The measured
run of `cargo deny check` on this repository answers
`advisories ok, bans ok, licenses ok, sources ok` with those four warnings.

`[bans] multiple-versions = "warn"` produces eleven duplicate-version warnings
in the resolved scratch tree (`http`, `http-body`, `digest`, `sha2`,
`getrandom`, `syn` and five more), all of them the usual 0.x/1.x straddle of a
large SDK. They are warnings by existing configuration and are recorded here so
that the task adding the member does not meet them as a surprise.

### 6. Native build requirement per platform

`ring` compiles a small amount of C and pre-generated assembly, so this class
inherits a C compiler — which every supported platform already has, because
`docs/adr/0002-local-database-encryption.md`:269-284 established the same
requirement for the vendored SQLCipher and OpenSSL. It adds **no** new
requirement beyond that: unlike `aws-lc-sys`, `ring` needs neither CMake nor
NASM, and its assembly is pre-generated rather than assembled at build time.
That asymmetry is the practical half of the argument for `ring` in *Rejected
alternatives*.

## Container runtime

Measured on the development host on 2026-08-28: CLI `Docker version 29.7.2`
(`docker --version`) against engine `29.4.0` (`docker info`, `ServerVersion`).
Neither podman nor colima is installed. The pin is `docker@29.4.0` — the
**engine**, because the engine is what runs the containers and the CLI is
replaceable — and it lives in `mise.toml` under `[env]` as
`EA_CONTAINER_RUNTIME`, not under `[tools]`, because mise has no backend that
installs or starts a container daemon.

`docs/adr/0001-toolchain-and-cryptography-dependencies.md`:26-30 pins Rust,
Node.js, pnpm, the fuzz nightly and `cargo-fuzz` and has carried no line for a
container runtime until now; this section is that line. The same `mise.toml`
also stops the pnpm pin from drifting: the file was excluded through
`.gitignore` until this task and therefore carried a different content on every
machine, which stood against
`docs/adr/0001-toolchain-and-cryptography-dependencies.md`:28 and `package.json`:4.

## Integration services

`ops/compose/integration.yaml` starts exactly two services, both pinned by tag
**and** digest, because a tag alone is overwritten upstream and an
`integration up` that starts a different PostgreSQL tomorrow than today proves
nothing.

| Service | Image, tag and digest | Reason |
| --- | --- | --- |
| PostgreSQL | `postgres:18.6-bookworm@sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af` | The official Debian-based image of the current PostgreSQL 18 line, published on Docker Hub. |
| Object store | `minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e` | **MinIO** is the S3-compatible service, chosen by name. It implements `PutBucketVersioning` and `ListObjectVersions`, which the bucket-versioning requirement of this stage needs; SeaweedFS, LocalStack and Garage are rejected above. The image also ships `mc` at `/usr/bin/mc`, so readiness (`mc ready local`) and bucket setup need no third container. |

MinIO's server is AGPL-3.0-licensed. That is a licence of a *service run in a
development container*, not of a Rust crate in the dependency graph and not of
anything Einsatzarchiv distributes, so it is outside the reach of `deny.toml`
and creates no obligation here. It is named because a reader is entitled to
know it.

`cargo run --locked -p xtask -- integration up` starts both services, waits for
their health checks, creates the bucket `einsatzarchiv-objects` with versioning
enabled, and prints two `eval`-able lines on stdout — `export DATABASE_URL=…`
and `export EA_OBJECT_STORE_ENDPOINT=…` — because the disposable-database
harness of `apps/server/tests/common/mod.rs` reads `DATABASE_URL` at run time.
(The plans of this stage still say `#[sqlx::test]` there; see the `sqlx` row of
the Decision table for why that macro is unreachable in this workspace.) Compose's own output goes to stderr so that the
`eval` sees only those two lines. Both subcommands are idempotent.
`verify-quick` refuses to run while either service is silent, with an
instruction and without an environment-variable bypass.

## OCI base image

The release container for `apps/server` is built `FROM
gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f`,
resolved on 2026-08-28.

The `cc` variant is the smallest distroless image that carries what a
dynamically linked Rust binary needs — glibc plus `libgcc_s` for unwinding —
and nothing else: no shell, no package manager, no `curl`. That removes the
usual post-exploitation toolbox from an image that, by the design of this
stage, holds no readable payload anyway. The `nonroot` tag runs as UID 65532,
so the server does not start as root.

The image is named with tag and digest here for the same reason the two
integration images are, and it is a **decision, not a delivery**: this task
writes no `Dockerfile` and builds no image. The task that creates `apps/server`
builds against this pin, and the release hardening of stage 7
(`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-7-release-hardening.md`)
owns the signed, reproducible image itself.

## Consequences

- The lockfile update that
  `docs/adr/0001-toolchain-and-cryptography-dependencies.md`:152-154 requires is
  completed by the task that creates `apps/server` and the three `ea-sync-*`
  crates, when those members inherit these entries with `workspace = true` and
  the packages actually enter `Cargo.lock`. Under the inheritance rule
  (`docs/adr/0001-toolchain-and-cryptography-dependencies.md`:15-20) this task
  cannot discharge it: a shared dependency no member inherits resolves to
  nothing, and `Cargo.lock` stays byte-identical, which was measured. Naming
  the owner here is what keeps the obligation from being asserted in one place
  and delivered in none. That same task owns the first empirical proof that the
  pinned tree builds under Rust `1.95.0` *inside this workspace*; the proof
  recorded above was produced in a scratch package with exactly these pins and
  features, which is a resolution result, not a workspace build.
- The same task resolves the four `license-exception-not-encountered` warnings
  of `cargo deny check` by putting the crates into the graph they already have
  exceptions for.
- No wire format, vector or compatibility file is affected. Suite 1, the six
  frozen object prefixes and every frozen vector remain unchanged; the server
  moves archive bytes it cannot read and produces none of them.
- `#![forbid(unsafe_code)]` stays intact for Einsatzarchiv's own crates. Every
  crate in this class contains `unsafe` internally — a Tokio runtime and a TLS
  implementation cannot be written without it — and none of it appears at the
  edge of code written here; no `libc` dependency is introduced into our own
  crates.
- **`sqlx`'s `macros` and `migrate` features stay off the facade, permanently.**
  Both carry weak feature references — `sqlx-sqlite?/offline` respectively
  `sqlx-sqlite?/migrate` — and a weak reference does not activate the optional
  dependency but still forces Cargo to resolve a version for it. `sqlx-sqlite`
  0.9.0 requires `libsqlite3-sys >=0.30.1, <0.38.0`, while
  `docs/adr/0002-local-database-encryption.md` pins `=0.38.0`; both declare
  `links = "sqlite3"`, so enabling either feature makes the whole workspace stop
  resolving with `failed to select a version for libsqlite3-sys`. Measured in a
  bare scratch package outside this workspace, so it is a property of the two
  pins and not of this repository. The migration capability therefore sits on
  `sqlx-core` and `sqlx-postgres`, and the consequence for tests is recorded
  rather than hidden: `#[sqlx::test]` is unreachable here — `sqlx::test` sits
  behind `#[cfg(feature = "macros")]` and `sqlx::testing`, where its generated
  code lands, behind `#[cfg(feature = "migrate")]` (`sqlx-0.9.0/src/lib.rs`:83,
  :88) — so every `apps/server` integration test target of this stage takes its
  disposable database from the harness in `apps/server/tests/common/mod.rs` (a
  directory module, deliberately not a test target). **No later task may re-add
  `macros` or `migrate` to the facade**; doing so reintroduces the conflict, and
  `tools/xtask/tests/adr_gate.rs` fails on the changed ledger line before the
  build does. Resolving it the other way would mean downgrading ADR 0002's
  SQLCipher class to `libsqlite3-sys =0.37.0` / `rusqlite =0.39.0`, which is
  expressly out of scope for this stage.
- A `tokio`, `axum`, `sqlx`, `sqlx-core`, `sqlx-postgres`, `aws-sdk-s3`,
  `aws-smithy-http-client`, `rustls`, `tokio-rustls`, `hyper`, `hyper-util`,
  `http`, `http-body-util` or `async-trait` upgrade is
  a new reviewed decision under
  `docs/adr/0001-toolchain-and-cryptography-dependencies.md`:152-154. So is a
  change to any of the three mutually exclusive feature families: swapping
  `ring` for `aws_lc_rs`, adding `tls12`, or changing the SQLx backend,
  runtime or TLS feature each change what this document ratified.
- `verify-quick` now depends on two running containers. That is deliberate and
  fail-closed: from this stage on, a green quick run that never reached a
  database would be a false green. The cost is that a developer runs
  `xtask integration up` once per session, and the check names that command in
  its own error message.
- The two integration images and the base image are pinned by digest, so a
  rebuild of an upstream tag does not silently change what the gate measures.
  Refreshing any of the three digests is a reviewed change to this document,
  not a routine edit of a YAML file.
