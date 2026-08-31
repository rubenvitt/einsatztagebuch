#!/usr/bin/env bash
# Laufzeitnachweis nach docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md 14.1.
#
# Vollstaendige Kette aus dem Kaltstart: Werkzeuge feststellen, passende
# wasm-bindgen-cli beschaffen, native Gegenprobe, wasm32 bauen, wasm-bindgen
# fahren, Node-Treiber ausfuehren.
#
# Idempotent: jeder Schritt prueft erst, ob sein Ergebnis schon vorliegt.
#   ./spike.sh          normaler Lauf
#   ./spike.sh --clean  vorher target/ und pkg/ loeschen (echter Kaltstart)
#
# Beendet sich mit != 0, sobald irgendein Schritt scheitert.
set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"

SPIKE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SPIKE_DIR"

NODE_BIN="${NODE_BIN:-/usr/bin/node}"
CRATE_UNDERSCORE="ea_wasm_runtime_proof"
WASM="target/wasm32-unknown-unknown/debug/${CRATE_UNDERSCORE}.wasm"

step=0
say() {
  step=$((step + 1))
  printf '\n=== [%d] %s\n' "$step" "$*"
}

if [[ "${1:-}" == "--clean" ]]; then
  say "CLEAN: target/ und pkg/ entfernen"
  rm -rf target pkg
  echo "removed target/ and pkg/"
fi

# ---------------------------------------------------------------------------
say "Werkzeuge feststellen"
# ---------------------------------------------------------------------------
echo "rustc:  $(rustc --version)"
echo "cargo:  $(cargo --version)"
echo "node:   $("$NODE_BIN" --version)  ($NODE_BIN)"
echo "uname:  $(uname -srm)"

if ! rustup target list --installed | grep -qx wasm32-unknown-unknown; then
  echo "FEHLER: Target wasm32-unknown-unknown fehlt. rustup target add wasm32-unknown-unknown" >&2
  exit 1
fi
echo "target: wasm32-unknown-unknown installiert"

# ---------------------------------------------------------------------------
say "Erforderliche wasm-bindgen-Version aus dem Lockfile ableiten"
# ---------------------------------------------------------------------------
# Ohne Lockfile zuerst aufloesen, damit die Version ueberhaupt feststeht.
if [[ ! -f Cargo.lock ]]; then
  echo "Cargo.lock fehlt, loese auf ..."
  cargo generate-lockfile
fi
REQUIRED_WB="$(awk '/^name = "wasm-bindgen"$/ {getline; gsub(/[version ="]/, "", $0); print; exit}' Cargo.lock)"
if [[ -z "$REQUIRED_WB" ]]; then
  echo "FEHLER: wasm-bindgen steht nicht in Cargo.lock" >&2
  exit 1
fi
echo "wasm-bindgen (Crate, aus Cargo.lock): $REQUIRED_WB"

# Gegenprobe: dieselbe Version muss im Repo-Lockfile stehen, sonst weicht der
# Spike von dem ab, was die Positivliste in tools/xtask/src/main.rs uebersetzt.
REPO_WB="$(awk '/^name = "wasm-bindgen"$/ {getline; gsub(/[version ="]/, "", $0); print; exit}' ../../Cargo.lock)"
echo "wasm-bindgen (Repo-Cargo.lock):       $REPO_WB"
if [[ "$REQUIRED_WB" != "$REPO_WB" ]]; then
  # FAIL-CLOSED und nicht als Warnung: eine Abweichung heisst, dass der
  # Laufzeitnachweis eine andere wasm-bindgen-Fassung faehrt als die, die die
  # Positivliste in tools/xtask/src/main.rs uebersetzt. Ein gruener Lauf wuerde
  # dann etwas belegen, das im Repo so nicht gebaut wird.
  echo "FEHLER: Spike ($REQUIRED_WB) und Repo ($REPO_WB) weichen ab." >&2
  echo "        Der Nachweis gilt nur fuer die Fassung des Repo-Lockfiles." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
say "wasm-bindgen-cli $REQUIRED_WB beschaffen (idempotent)"
# ---------------------------------------------------------------------------
have_cli=""
if command -v wasm-bindgen >/dev/null 2>&1; then
  have_cli="$(wasm-bindgen --version | awk '{print $2}')"
fi
if [[ "$have_cli" == "$REQUIRED_WB" ]]; then
  echo "wasm-bindgen-cli $have_cli liegt schon vor, nichts zu tun"
else
  # Ein Nachweislauf veraendert die Maschine nicht von sich aus: cargo install
  # schreibt nach ~/.cargo/bin und zieht aus dem Netz. Das passiert nur auf
  # ausdrueckliche Ansage.
  if [[ "${SPIKE_ALLOW_INSTALL:-0}" != "1" ]]; then
    echo "FEHLER: wasm-bindgen-cli $REQUIRED_WB fehlt (gefunden: '${have_cli:-nichts}')." >&2
    echo "        Entweder selbst installieren:" >&2
    echo "          cargo install wasm-bindgen-cli --version $REQUIRED_WB --locked" >&2
    echo "        oder diesen Lauf ausdruecklich dazu ermaechtigen:" >&2
    echo "          SPIKE_ALLOW_INSTALL=1 ./spike.sh" >&2
    exit 1
  fi
  echo "gefunden: '${have_cli:-nichts}', benoetigt: $REQUIRED_WB -> installiere (dauert einige Minuten)"
  cargo install wasm-bindgen-cli --version "$REQUIRED_WB" --locked
fi
echo "wasm-bindgen-cli: $(wasm-bindgen --version)"

# ---------------------------------------------------------------------------
say "Native Gegenprobe (damit ein wasm-Fehlschlag eindeutig ein wasm-Fehler ist)"
# ---------------------------------------------------------------------------
cargo test --locked
cargo run --locked --quiet --bin native_baseline >/dev/null

# ---------------------------------------------------------------------------
say "cargo build --target wasm32-unknown-unknown"
# ---------------------------------------------------------------------------
# Ausdruecklich OHNE RUSTFLAGS: getrandom 0.4.3 waehlt das JS-Backend ueber das
# Cargo-Feature "wasm_js"; ein --cfg getrandom_backend=... waere in 0.4 falsch
# und wuerde das Feature sogar ueberstimmen.
if [[ -n "${RUSTFLAGS:-}" ]]; then
  echo "WARNUNG: RUSTFLAGS ist gesetzt ('$RUSTFLAGS'); der Nachweis laeuft ohne." >&2
fi
env -u RUSTFLAGS cargo build --locked --target wasm32-unknown-unknown --lib
ls -l "$WASM"

# ---------------------------------------------------------------------------
say "wasm-bindgen --target nodejs"
# ---------------------------------------------------------------------------
rm -rf pkg
wasm-bindgen --target nodejs --out-dir pkg --out-name "$CRATE_UNDERSCORE" "$WASM"
ls -l pkg

# ---------------------------------------------------------------------------
say "Node-Treiber ausfuehren"
# ---------------------------------------------------------------------------
"$NODE_BIN" js/driver.mjs

# ---------------------------------------------------------------------------
say "Gegenkontrolle: ohne globalThis.crypto MUSS getrandom scheitern"
# ---------------------------------------------------------------------------
# Diese Kontrolle traegt den staerksten Teil des Nachweises fuer Element 2: sie
# zeigt, dass die Entropie aus dem JS-Wirt kommt und nicht im Modul steckt.
# Deshalb haengt sie am Ausgangswert des Laufs und nicht an einem Handgriff.
"$NODE_BIN" js/negative-control-no-webcrypto.mjs

printf '\n=== SPIKE ERFOLGREICH: alle vier Elemente aus web-reader-design.md 14.1 sind AUSGEFUEHRT worden.\n'
