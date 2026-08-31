# `spikes/wasm-runtime-proof` — Laufzeitnachweis nach web-reader-design.md §14.1

Dieser Spike existiert, um genau eine Blockade aufzuloesen. In
`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md` steht:

> BLOCKIERT — Laufzeitnachweis nach web-reader-design.md 14.1. Die Ueberarbeitung
> dieses Plans darf erst beginnen, wenn ein ausfuehrbarer Spike vorliegt:
> wasm-bindgen-Schicht, getrandom mit wasm_js in einer echten JS-Umgebung, eine
> HPKE-Entkapselung und eine Signaturpruefung gegen einen bestehenden Testvektor.

Der bestehende Gate-Kommentar in `tools/xtask/src/main.rs:91-95` sagt dasselbe von
der anderen Seite: das dortige `cargo check --target wasm32-unknown-unknown`
belegt „ausschliesslich UEBERSETZBARKEIT … nicht Lauffaehigkeit". Uebersetzbarkeit
ist seit Stufe 1 bewiesen und reicht ausdruecklich nicht.

Hier laufen die vier Elemente wirklich — in `wasm32-unknown-unknown`, in Node.

## Ausfuehren

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd /home/rubeen/dev/einsatztagebuch/spikes/wasm-runtime-proof
./spike.sh --clean     # echter Kaltstart: target/ und pkg/ weg, alles neu
./spike.sh             # idempotenter Wiederholungslauf
```

`spike.sh` faehrt acht Schritte und bricht bei jedem Fehler mit `set -euo
pipefail` ab:

| # | Schritt | Kommando |
|---|---|---|
| 1 | Werkzeuge feststellen | `rustc --version`, `cargo --version`, `node --version`, `rustup target list --installed` |
| 2 | wasm-bindgen-Version ableiten | aus `Cargo.lock` des Spikes, Gegenprobe gegen `../../Cargo.lock` |
| 3 | CLI beschaffen (idempotent, nur mit `SPIKE_ALLOW_INSTALL=1`) | `cargo install wasm-bindgen-cli --version 0.2.126 --locked` |
| 4 | Native Gegenprobe | `cargo test --locked` + `cargo run --locked --bin native_baseline` |
| 5 | wasm bauen | `env -u RUSTFLAGS cargo build --locked --target wasm32-unknown-unknown --lib` |
| 6 | Glue erzeugen | `wasm-bindgen --target nodejs --out-dir pkg --out-name ea_wasm_runtime_proof target/wasm32-unknown-unknown/debug/ea_wasm_runtime_proof.wasm` |
| 7 | Treiber fahren | `/usr/bin/node js/driver.mjs` |
| 8 | Gegenkontrolle fahren | `/usr/bin/node js/negative-control-no-webcrypto.mjs` |

Zusaetzlich, von Hand:

```bash
node js/negative-control-no-webcrypto.mjs   # Element 2 gegengeprueft
```

## Gemessene Werkzeugversionen

Gemessen am 2026-08-30 auf `Linux 6.8.0-138-generic x86_64`:

| Werkzeug | Version |
|---|---|
| `rustc` | `1.95.0 (59807616e 2026-04-14)` — aus `rust-toolchain.toml`, greift auch hier, weil rustup ab CWD aufwaerts sucht |
| `cargo` | `1.95.0 (f2d3ce0bd 2026-03-21)` |
| `wasm-bindgen` (Crate) | `0.2.126` — identisch mit `/home/rubeen/dev/einsatztagebuch/Cargo.lock` |
| `wasm-bindgen-cli` | `0.2.126` (`wasm-bindgen --version` → `wasm-bindgen 0.2.126`) |
| `node` | `v26.8.1` (`/usr/bin/node`), `linux/x64` |
| Target | `wasm32-unknown-unknown` |
| `getrandom` | `0.4.3`, Feature `wasm_js` |
| Krypto-Kanten | `hpke 0.14.0`, `ed25519-dalek 3.0.0`, `x25519-dalek 3.0.0`, `chacha20poly1305 0.11.0`, `curve25519-dalek 5.0.0`, `sha2 0.11.0` — alle zeichengleich mit dem Repo-Lockfile |

## Wiederholung unter dem gepinnten Node 26.7.0

Der obige Lauf protokolliert `node v26.8.1`, waehrend `.node-version` und die
`engines.node`-Zeile von `package.json` auf `26.7.0` stehen — der Vorlauf
DRK-253 (Stufe-4-Vorlauf, `docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-4-reader.md`)
behandelt gemessene Werkzeugstaende als vertraglich und wiederholt den Nachweis
deshalb ausdruecklich unter dem GEPINNTEN Node, statt den Pin anzuheben, um die
Abweichung verschwinden zu lassen. Gefahren am 2026-08-31 mit:

```bash
NODE_BIN=/home/rubeen/.local/share/mise/installs/node/26.7.0/bin/node spikes/wasm-runtime-proof/spike.sh
```

`spike.sh` liest `NODE_BIN` direkt (Zeile 20, Standardwert `/usr/bin/node`
sofern die Variable fehlt); der obenstehende Aufruf erzwingt die gepinnte
Fassung, ohne den Skripttext zu aendern. Gemessenes Ergebnis:

- **Exitcode: 0.**
- **Vom Lauf selbst gemeldete Node-Fassung:** `node v26.7.0 on linux/x64`
  (Treiberausgabe von Schritt 7) — zeichengleich mit `.node-version` und
  `package.json`s `engines.node`.
- **Alle vier Elemente aus §14.1 erneut AUSGEFUEHRT:** die wasm-bindgen-Schicht
  (Glue exportiert `run_runtime_proof`/`echo_from_js`, ein Zeichenkettenargument
  ueberquert die Bruecke in beiden Richtungen); `getrandom` mit `wasm_js` in
  einer echten JS-Umgebung (zwei 32-Byte-Ziehungen, die sich unterscheiden und
  nicht null sind, ≥ 40 verschiedene Bytewerte auf 64 Byte — gemessen 56 —,
  eine 100000-Byte-Ziehung ueber die 65536-Byte-Chunkgrenze, zwei echte
  `ea_crypto::hpke_seal`-Aufrufe mit je frischer ephemerer Entropie); eine
  HPKE-Entkapselung (der eingefrorene Empfaenger- und HPKE-Vektor, der
  RFC-7748-6.1-abgeleitete Public Key, die Entkapselung liefert `c0×32`, beide
  manipulierten Vektoren mit `EA-CRYPTO-HPKE-OPEN` abgewiesen); eine
  Signaturpruefung (der RFC-8032-§7.1-TEST-1-Vektor wird angenommen,
  `flipped-signature.bin` mit `EA-TRUST-SIGNATURE-INVALID` abgewiesen).
- **Gegenkontrolle ohne `globalThis.crypto` hielt erneut:** `getrandom:
  getrandom::fill failed: Web Crypto API is unavailable`.

**Keine Abweichung vom Lauf unter Node v26.8.1**: derselbe Exitcode, dieselben
vier ausgefuehrten Elemente, dieselben Fehlercodes an beiden Negativfaellen.
Der einzige Unterschied ist die Node-Fassung selbst — genau die Variable, die
dieser Wiederholungslauf pruefen sollte. `distinctByteValuesAcross64Bytes` maß
in diesem Lauf 56 (zuvor 55 bzw. 58 fuer die beiden Ziehungen); das ist eine
Anwesenheitsprobe und keine Statistik (siehe *Was dieser Spike NICHT beweist*)
und schwankt erwartungsgemaess zwischen Laeufen, ohne die Aussage zu aendern.

## Was bewiesen ist

### 1. wasm-bindgen-Schicht — AUSGEFUEHRT

`src/lib.rs` exportiert zwei `#[wasm_bindgen]`-Funktionen unter
`#[cfg(target_arch = "wasm32")]`: `run_runtime_proof() -> String` und
`echo_from_js(&str) -> String`. `wasm-bindgen --target nodejs` erzeugt daraus
CommonJS-Glue, die der Treiber per `createRequire` laedt. Der Treiber prueft
beide Richtungen der Bruecke: er schickt `"hello from node"` hinein und erwartet
`"wasm received: hello from node"` zurueck — ein reiner Rueckgabewert haette
nicht belegt, dass Argumente ankommen.

### 2. getrandom mit `wasm_js` in einer echten JS-Umgebung — AUSGEFUEHRT

Im wasm laufen: zwei `getrandom::fill`-Ziehungen à 32 B (muessen sich
unterscheiden, duerfen nicht null sein, ≥ 40 verschiedene Bytewerte auf 64 B —
gemessen 55 bzw. 58), eine Ziehung ueber 100 000 B (kreuzt den
`MAX_BUFFER_SIZE = 65536`-Chunker aus
`getrandom-0.4.3/src/backends/wasm_js.rs:14-23`), und **zwei echte
`ea_crypto::hpke_seal`-Aufrufe**. Letztere sind der eigentliche Punkt:
`crates/ea-crypto/src/hpke.rs:32` ist der einzige RNG-Aufruf in `ea-crypto`, und
beide Kapselungen liefern verschiedene ephemere Schluessel; die erste wird
anschliessend per `hpke_open` wieder geoeffnet und ergibt den CEK zurueck.

Die erzeugte Glue enthaelt den Beweis, dass die Entropie aus dem Host kommt und
nicht einkompiliert ist (`pkg/ea_wasm_runtime_proof.js:49-51`):

```js
__wbg_getRandomValues_cc7f052a444bb2ce: function() { return handleError(function (arg0, arg1) {
    globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
}, arguments); },
```

**Gegenkontrolle** (`js/negative-control-no-webcrypto.mjs`): mit
`globalThis.crypto = undefined` meldet dasselbe Modul

```
ok=false
errors=getrandom: getrandom::fill failed: Web Crypto API is unavailable
```

Damit ist ausgeschlossen, dass die „Zufallszahlen" ein einkompiliertes Muster
sind.

### 3. HPKE-Entkapselung — AUSGEFUEHRT

Gegen `vectors/crypto/suite-1/hpke/base-mode-wrapped-cek.bin`, per
`include_bytes!` einkompiliert (das wasm hat kein Dateisystem). Geprueft wird im
wasm:

- SHA-256 der einkompilierten Bytes == `fileSha256` des Manifests
  (`35db387d…f1ea`) — beweist, dass wirklich die eingefrorene Datei drinsteckt;
- `infoDigest` und `aadDigest` == Manifest (`dc2a2769…`, `485e08ef…`), gerechnet
  ueber die ebenfalls eingefrorenen `domain-context/hpke-info.bin` (46 B) und
  `hpke-aad.bin` (45 B);
- `recipientPublicKeyThumbprint` == Manifest (`923bd3c4…`);
- RFC 7748 §6.1: aus dem privaten Bob-Schluessel leitet der KEM den
  veroeffentlichten `rfc7748-recipient-public-key.bin` ab;
- **die Entkapselung selbst**: `hpke_open` liefert
  `c0c0…c0` (32 × 0xc0);
- **zwei Negativfaelle**: `flipped-encapsulated-key.bin` und
  `flipped-wrapped-cek.bin` unterscheiden sich in genau einem Byte und werden
  beide mit `EA-CRYPTO-HPKE-OPEN` abgewiesen.

### 4. Signaturpruefung gegen einen bestehenden Testvektor — AUSGEFUEHRT

Gegen `vectors/crypto/suite-1/ed25519/rfc8032-test1.bin` (RFC 8032 §7.1 TEST 1,
leere Nachricht). Geprueft: Datei-SHA-256 == Manifest, `signerThumbprint` ==
Manifest (`866eefbd…`), `CanonicalPublicCoseKey::verify_ed25519_strict` nimmt die
Signatur an — **und** `flipped-signature.bin` (genau ein gekipptes Byte) wird mit
`EA-TRUST-SIGNATURE-INVALID` abgewiesen. Ein Spike, der nur den Gutfall zeigt,
zeigt zu wenig; ein Verifizierer, der immer `Ok` sagt, faellt erst am Negativfall
auf.

## Herkunft der Erwartungswerte

Kein Wert ist hier neu hergeleitet.

| Wert | Quelle |
|---|---|
| Erwarteter CEK `c0×32` | `manifest.json`, `inputBytes` von `hpke/base-mode-wrapped-cek`; identisch mit `ea_testkit::TEST_ENTROPY_CONTENT_ENCRYPTION_KEY` (`crates/ea-testkit/src/lib.rs:206`), das der native Test ueber `opened.matches(...)` prueft |
| Empfaengerschluessel `b0×32` | `ea_testkit::TEST_ENTROPY_RECIPIENT_X25519_SEED` (`crates/ea-testkit/src/lib.rs:203`) |
| Ed25519-Public-Key | `ea_testkit::ED25519_RFC8032_TEST1_PUBLIC_KEY` (`crates/ea-testkit/src/lib.rs:127`) |
| RFC-7748-Privatschluessel | `manifest.json`, `inputBytes` von `hpke/rfc7748-recipient-public-key` |
| Alle Digests/Thumbprints/Dateihashes | `vectors/crypto/suite-1/manifest.json`, woertlich |
| Gegenprobe der Vektoren selbst | `cargo test --locked -p ea-system-tests --test conformance_golden_vectors crypto_suite_one_vectors_reproduce_every_primitive_and_domain_string` → `ok`, vor diesem Spike gefahren |

`ea-testkit` ist **kein** Abhaengiger dieses Spikes: es steht mit Begruendung in
`WASM32_EXEMPT_CRATES` (`tools/xtask/src/main.rs:187`, `std::fs`-Vektorausgabe).
Seine Konstanten sind darum woertlich mit Fundstelle eingetragen. Einziger
Pfad-Abhaengiger ist `ea-crypto`.

## Was NICHT funktioniert hat, und was daraus wurde

### a) `wasm-bindgen-cli` war nicht installiert

`which wasm-bindgen` lieferte nichts. Behoben mit
`cargo install wasm-bindgen-cli --version 0.2.126 --locked` (Netzzugriff noetig).
`spike.sh` Schritt 3 macht das idempotent: liegt die richtige Version schon vor,
passiert nichts.

### b) Das eigene Lockfile driftet auf wasm-bindgen 0.2.127 — nachgemessen

Der Spike ist eine eigene Workspace-Wurzel und bekommt darum ein **eigenes**
`Cargo.lock`. Was das Repo nur transitiv aufloest, wird hier neu aufgeloest.
Gemessen, indem der Pin testweise zu `wasm-bindgen = "0.2"` gelockert und
`cargo generate-lockfile` gefahren wurde:

```
version = "0.2.127"
```

Das haette gegen `wasm-bindgen-cli 0.2.126` einen Schema-Mismatch gegeben.
Workaround, jetzt fest im Manifest: `wasm-bindgen = "=0.2.126"`, also der
Wert aus `/home/rubeen/dev/einsatztagebuch/Cargo.lock`. `spike.sh` liest die
noetige CLI-Version aus dem Lockfile statt sie fest zu verdrahten und warnt, wenn
Spike- und Repo-Lockfile auseinanderlaufen. Alle Krypto-Kanten (`hpke`,
`ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `curve25519-dalek`, `sha2`)
sind dagegen durch die `=`-Pins des Repos gebunden und stimmen ueberein — geprueft.

### c) `opened.with_exposed(hex::encode)` uebersetzt nicht

```
error: implementation of `FnOnce` is not general enough
   --> src/lib.rs:302:21
    |
302 |     let recovered = opened.with_exposed(hex::encode);
    |                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ implementation of `FnOnce` is not general enough
    = note: `fn(&'2 [u8; 32]) -> String {encode::<&'2 [u8; 32]>}` must implement `FnOnce<(&'1 [u8; 32],)>`, for any lifetime `'1`...
    = note: ...but it actually implements `FnOnce<(&'2 [u8; 32],)>`, for some specific lifetime `'2`
```

`SecretBytes::with_exposed` verlangt eine hoehere Lebensdauerbindung, die die
Funktionszeigerform von `hex::encode` nicht erfuellt. Behoben mit einem
expliziten Closure: `opened.with_exposed(|bytes| hex::encode(bytes))`. Kein
Krypto-Belang, reine Typisierung.

### d) Leerer `[workspace]`-Tisch ist Pflicht

`/home/rubeen/dev/einsatztagebuch/Cargo.toml` fuehrt eine explizite
`members`-Liste ohne Globs. Ohne eigenen `[workspace]`-Tisch bricht Cargo mit
*„current package believes it's in a workspace when it's not"* ab. Der leere Tisch
in `Cargo.toml` macht den Spike zu seiner eigenen Wurzel; Repo-`Cargo.toml` und
Repo-`Cargo.lock` bleiben unberuehrt (`git status --porcelain` zeigt nur `?? spikes/`).

Folge davon: der Spike liegt ausserhalb von `cargo xtask`, `deny.toml` und dem
wasm32-Gate. Er gehoert **nicht** auf die Positivliste in
`tools/xtask/src/main.rs`: die Liste waechst nur um Mitglieder unter
`crates/`, und `tools/xtask/tests/workspace.rs:160` haelt sie als MENGE gegen
die Kommandozeile des Stufe-1-Plans. Der Spike ist kein Workspace-Mitglied und
liegt bewusst nicht unter `crates/`, wo derselbe Test eine Klassifikation
erzwingen wuerde.

### e) Kein `RUSTFLAGS`, kein `.cargo/config.toml` im Spike

Der Aufgabenzettel liess offen, ob `--cfg getrandom_backend="wasm_js"` gebraucht
wird. Wird es **nicht**, und es waere in 0.4.x sogar falsch: die Backendwahl fuer
wasm ist dort ein Cargo-Feature (`getrandom-0.4.3/src/backends.rs:170-183`), und
`"wasm_js"` steht in 0.4.3 nicht einmal mehr in der erlaubten Werteliste von
`cfg(getrandom_backend, values(...))`. Ein gesetztes `--cfg
getrandom_backend=...` wuerde das Feature laut CHANGELOG sogar ueberstimmen.
Deshalb gibt es hier **kein** `.cargo/config.toml`, und `spike.sh` baut mit
`env -u RUSTFLAGS` und warnt, wenn `RUSTFLAGS` von aussen gesetzt ist.

`-C target-feature=+atomics` ist bewusst aus: nur der Nicht-Atomics-Pfad
schreibt direkt in den linearen Speicher und braucht kein `js-sys`.

## Gegenkontrollen (damit „gruen" etwas heisst)

1. **Vektortausch.** Wird `ED25519_SIGNATURE_VECTOR` testweise auf
   `flipped-signature.bin` gezeigt, neu gebaut und der Treiber gefahren, meldet er
   9 fehlgeschlagene Zusicherungen und beendet sich mit `1`. Der Treiber kann also
   ueberhaupt rot werden. (Quelle wurde danach unveraendert wiederhergestellt.)
2. **Kein WebCrypto.** Siehe oben, `js/negative-control-no-webcrypto.mjs`.
3. **Native Gegenprobe.** `cargo test --locked` im Spike laeuft dieselben drei
   Elemente auf dem Host. Ist sie gruen und wasm rot, ist das Problem eindeutig
   wasm-seitig.
4. **Manifest-Gegenprobe.** Der Upstream-Test
   `crypto_suite_one_vectors_reproduce_every_primitive_and_domain_string` wurde
   vor dem Spike gefahren und ist gruen; die Erwartungswerte sind also nicht vom
   Spike erfunden.

## Was dieser Spike NICHT beweist

- **Keinen Browser.** Der Nachweis laeuft in Node v26.8.1. §14.1 verlangt „eine
  echte JS-Umgebung"; Node ist eine, aber der Reader zielt auf den Browser. Die
  einzige benutzte Host-Schnittstelle ist `globalThis.crypto.getRandomValues`,
  die im Browser dieselbe ist — geprueft ist sie hier trotzdem nur unter Node.
  Ein `wasm-bindgen-test --headless --chrome`-Lauf steht aus.
- **Kein Release-Profil, kein `wasm-opt`.** Gebaut wird `debug` (14,5 MB `.wasm`,
  nach `wasm-bindgen` 1,0 MB). Groesse und Verhalten unter `--release` +
  `wasm-opt` sind nicht gemessen.
- **Nur `ea-crypto`.** `ea-verify`, `ea-archive`, `ea-chain`, `ea-format`,
  `ea-trust` uebersetzen laut Gate fuer wasm32, laufen aber hier nicht. Der
  Reader-Pfad als Ganzes ist nicht ausgefuehrt.
- **Keine COSE-Kette.** Geprueft ist `verify_ed25519_strict` auf einem rohen
  RFC-8032-Vektor, nicht `parse_cose_sign1`/`verify_cose_sign1` gegen ein echtes
  Archiv.
- **Keine Aussage zur RNG-Qualitaet.** „Zwei Ziehungen unterscheiden sich" und
  „≥ 40 verschiedene Bytewerte" sind Anwesenheitsproben, keine statistischen
  Tests.
