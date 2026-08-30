# Das Releasebild von `apps/server`.
#
# Zwei Stufen: ein Builder, der die Toolchain aus `rust-toolchain.toml` SELBST
# mitbringt, und ein Laufzeitbild ohne Shell, ohne Paketverwalter und ohne
# `curl`. Beide Basen stehen mit Tag UND Digest, aus demselben Grund, aus dem
# `ops/compose/integration.yaml` seine zwei Dienste so pinnt: ein Tag allein
# wird stromaufwaerts ueberschrieben, und ein Bau, der morgen einen anderen
# Compiler zieht als heute, belegt nichts.
#
# NUR `amd64`. Es gibt in diesem Repository keinen Host-Cross-Bau:
# `rust-toolchain.toml` stellt neben dem Host ausschliesslich
# `wasm32-unknown-unknown` bereit (gepinnt in
# `tools/xtask/tests/workspace.rs::rust_toolchain_declares_wasm32_and_no_release_target`),
# und diese Datei aendert daran nichts. Der Bau laeuft deshalb NATIV im
# amd64-Container: beide Stufen tragen `--platform=${BUILD_PLATFORM}` mit der
# Vorgabe `linux/amd64`, damit ein Aufruf auf einem arm64-Host nicht still eine
# andere Architektur baut.
#
# Aufruf (aus der Wurzel des Arbeitsbereichs, weil der Kontext den ganzen
# Workspace umfasst — `Cargo.lock`, `crates/`, `apps/server`):
#
#     docker build --platform=linux/amd64 -f ops/container/Dockerfile -t einsatzarchiv-server:dev .
#
# Lauf mit den vier Haertungen, die KEINE Dockerfile-Direktive ausdruecken
# kann — sie sind Laufzeiteigenschaften und stehen deshalb hier als der
# verbindliche Aufruf und nicht als Prosa anderswo:
#
#     docker run --platform=linux/amd64 \
#       --read-only \
#       --cap-drop=ALL \
#       --security-opt=no-new-privileges \
#       --user 65532:65532 \
#       --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
#       --mount type=bind,source=/run/secrets/einsatzarchiv,target=/run/secrets/einsatzarchiv,readonly \
#       einsatzarchiv-server:dev
#
# Die Signiergeheimnisse werden VON AUSSEN eingespielt und liegen in keiner
# Schicht dieses Bildes: `EA_SERVER_SIGNING_KEY_HEX`,
# `EA_TLS_PRIVATE_KEY_PEM`, `EA_OBJECT_STORE_SECRET_ACCESS_KEY` und
# `DATABASE_URL` kommen aus der Umgebung beziehungsweise aus dem
# schreibgeschuetzt eingehaengten Geheimnisverzeichnis. Kein `ARG` und kein
# `ENV` dieser Datei nimmt eines von ihnen entgegen — ein `ARG` landete in der
# Bildhistorie. Das einzige `ARG` ist `BUILD_PLATFORM`, und es traegt eine
# Architektur.
#
# Der signierte, reproduzierbare Release-Bau und der Plattformnachweis
# schliessen in Stufe 7
# (`docs/superpowers/plans/2026-08-13-einsatzarchiv-stage-7-release-hardening.md`).
# Diese Datei ist die BAUEINGABE, nicht das Release.

# Der Builder traegt die in `rust-toolchain.toml` gepinnte Toolchain 1.95.0
# bereits im Bild. Damit erzeugt kein zweiter, ungepinnter Compiler
# Produktionsbytes. Der Digest ist der amd64-Manifestdigest des Tags
# `1.95.0-bookworm`, aufgeloest am 2026-08-30.
#
# `--platform` steht ueber ein `ARG` mit Vorgabe `linux/amd64` und nicht als
# Konstante: BuildKit lehnt eine Konstante an dieser Stelle mit der Regel
# `FromPlatformFlagConstDisallowed` ab, und die Vorgabe erzwingt amd64
# trotzdem, ohne dass der Aufrufer eine Fahne setzen muesste. Der
# ADR-0004-Digest ist ein Multi-Arch-INDEX (gemessen: fuenf Plattformen), also
# waere die Architektur ohne diese Angabe die des Bauwirts — auf einem
# arm64-Rechner also still arm64.
ARG BUILD_PLATFORM=linux/amd64
FROM --platform=${BUILD_PLATFORM} docker.io/library/rust:1.95.0-bookworm@sha256:4c2fd73ef19c5ef9d54bee03b06b2839a392604fbfcd578ed948b71b37c1d7fb AS builder

WORKDIR /workspace

# Der ganze Arbeitsbereich, weil `apps/server` ein Mitglied ist und seine
# Pfadabhaengigkeiten unter `crates/` liegen.
# `ops/container/Dockerfile.dockerignore` haelt `target/` und `node_modules/`
# heraus; BuildKit liest diesen Namen vorrangig vor einem `.dockerignore` an
# der Kontextwurzel.
COPY . .

# `--locked` ist die gleiche Zusage wie ueberall sonst in diesem Repository:
# der Bau nimmt exakt die Aufloesung aus `Cargo.lock` und loest nichts neu auf.
# Das Binaerteil wird `strip`t, weil die Symbole im Laufzeitbild nichts
# belegen und der distroless-Rahmen keinen Debugger traegt, der sie laese.
RUN cargo build --locked --release -p einsatzarchiv-server \
    && strip target/release/einsatzarchiv-server

# Das Laufzeitbild. Der Digest steht WOERTLICH so in
# `docs/adr/0004-server-runtime-and-dependency-class.md`, Abschnitt
# `OCI base image`, aufgeloest am 2026-08-28. `cc` ist die kleinste
# distroless-Variante, die ein dynamisch gelinktes Rust-Binaerteil braucht
# (glibc plus `libgcc_s`), und traegt keine Shell, keinen Paketverwalter und
# kein `curl`. Der Tag `nonroot` laeuft als UID 65532.
ARG BUILD_PLATFORM=linux/amd64
FROM --platform=${BUILD_PLATFORM} gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

# Ausdruecklich noch einmal, obwohl der Tag `nonroot` es schon tut: eine
# spaetere Basisaenderung soll die Nichtwurzel-Ausfuehrung nicht still
# verlieren.
USER 65532:65532

COPY --from=builder /workspace/target/release/einsatzarchiv-server /usr/local/bin/einsatzarchiv-server
# Die Migration wird zur Laufzeit gelesen und nie geschrieben.
COPY --from=builder /workspace/apps/server/migrations /usr/local/share/einsatzarchiv/migrations
ENV EA_MIGRATIONS_DIRECTORY=/usr/local/share/einsatzarchiv/migrations

# Die EINZIGEN Pfade, an denen der Prozess schreiben darf. Das Wurzeldateisystem
# selbst laeuft schreibgeschuetzt (`--read-only`), deshalb muessen sie als
# eigene Einhaengungen kommen; ohne sie startet der Prozess nicht, statt
# unbemerkt in eine Schicht zu schreiben.
VOLUME ["/tmp"]

EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/einsatzarchiv-server"]
