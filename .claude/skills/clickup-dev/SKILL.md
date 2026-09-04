---
name: clickup-dev
description: Use when a request names a DRK-### ticket or says "ClickUp dev drk-###", asks to pick up, implement, or close a task from the Einsatztagebuch board, or asks for a ticket "in neuem Worktree mit PR als Ergebnis". Also use when a ClickUp call in this repo returns "Team not authorized" or the session says the ClickUp connector needs authentication.
---

# ClickUp Dev (Einsatztagebuch)

## Überblick

Ein DRK-Ticket wird in einem eigenen Worktree auf dem **neuesten `origin/main`** umgesetzt, mit
Subagents gebaut und geprüft, und endet als PR — nicht als Merge. TDD, Planausführung und Review
kommen aus den superpowers-Skills; hier steht nur, was Board und Repo zusätzlich verlangen.

## Wo die Tickets liegen

| | |
|---|---|
| Workspace | `9015920204` |
| Space | `901510125552` |
| Liste **Einsatztagebuch** | `901525380889` |
| Präfix | `DRK-` — den Präfix teilen andere Listen; **die Liste** trennt die Projekte |
| Epics | `[Epic] … Stufe N …` (DRK-249 = Stufe 4); die Beschreibung nennt den Plan unter `docs/superpowers/plans/` |
| Task-Titel | `S4-T12 — …` = Überschrift `### Task 12:` im Stufe-4-Plan; Ledger-Zeilen (`FR-104`, `WR-082`) stehen am Ende der Beschreibung |

**Der Connector funktioniert.** Die Session-Start-Warnung „ClickUp requires authentication" ist
falsch; `mcp__claude_ai_ClickUp__*` liest und schreibt. Ein Ticket wird **gelesen**, nie aus
Branchnamen oder PR-Nummern erschlossen:

```
clickup_get_task(task_id: "DRK-264", workspace_id: "9015920204",
                 include: ["description"], expand_statuses: true)
```

Ohne `workspace_id` antwortet die Custom-ID-Auflösung mit `{"error":"Team not authorized"}` —
ein fehlendes Argument, kein Auth-Problem; im Zweifel `clickup_get_workspace_hierarchy` sondieren.

## Status-Spur (exakt so, klein geschrieben)

```
idee → geplant → aktiv → blockiert → review → erledigt → archiviert
```

| Moment | `clickup_update_task(task_id, workspace_id, status: …)` |
|---|---|
| Ticket aufgenommen, Worktree steht | `aktiv` |
| Harte Sperre, die nur der Mensch lösen kann | `blockiert` + `clickup_create_task_comment` mit dem Grund |
| PR eröffnet | `review` + `clickup_create_task_comment` mit der PR-URL |
| Nach dem Merge (Mensch oder spätere Session auf Zuruf) | `erledigt` |

Nur vorwärts, nie redundant. Der Epic bleibt `aktiv`, bis seine Subtasks durch sind.

## Ablauf

1. **Ticket und Epic lesen.** `clickup_get_task` für das Ticket, danach für `parent`. Der
   Plan-Abschnitt (Task-Nummer aus dem Titel) ist der Vertrag, dazu die Global Constraints des
   Plans; das Ticket ist die Kurzfassung und nennt die Ledger-Zeilen.
2. **Doppelarbeit ausschließen.** `git branch -a --list 'drk-<nr>-*'` und `git worktree list`
   prüfen. Gibt es schon einen Branch zu dieser Nummer, **anhalten und melden** (Status bleibt,
   wie er ist) — nicht mit anderem Slug daneben bauen. Fremde und gelockte Worktrees bleiben
   unangetastet.
3. **Worktree auf `origin/main`.** Erst fetchen, dann branchen — das lokale `main` hängt
   regelmäßig Merges hinterher und wird **nicht** vorgespult:
   ```bash
   git -C ~/dev/einsatztagebuch fetch origin
   git -C ~/dev/einsatztagebuch worktree add .worktrees/drk-<nr>-<slug> -b drk-<nr>-<slug> origin/main
   ```
   Branch und Ordner heißen gleich, ohne Typpräfix, Slug 2–4 englische Wörter
   (`drk-262-encrypted-index`). Verlangt der Auftrag einen neuen Worktree, gilt das auch, wenn
   die Session bereits in einem Harness-Worktree (`.claude/worktrees/bridge-*`) sitzt.
4. **Setup:** `pnpm install --frozen-lockfile`, dann `.superpowers/env.sh` aus „Umgebung" anlegen
   (`.superpowers/` ist ignoriert). Danach Status `aktiv`.
5. **Plan gegen den Arbeitsbaum messen.** Jeder Task wurde geschrieben, bevor seine Nachbarn
   ausgeliefert haben. Ein Explore-Agent prüft jeden Namen, jede Signatur, jede Datei des
   Abschnitts gegen den Baum und meldet Abweichungen mit `Datei:Zeile`. Ändert sich der
   Plantext, ist das der **erste, eigene Commit**:
   `docs(plan): correct the <task> task against the shipped <surface>`. Befunde, die den Text
   nicht bewegen, kommen in den PR-Body.
6. **Umsetzen mit Agents.** **REQUIRED SUB-SKILL:** superpowers:subagent-driven-development;
   jeder Implementierungsagent arbeitet nach superpowers:test-driven-development. Schnitt
   entlang der Files des Abschnitts: unabhängige Scheiben parallel, abhängige nacheinander
   (Bridge-Crate nach Rust-Kern, `apps/web` nach `pnpm build:wasm`). Jeder Agent bekommt den
   Abschnitt wörtlich, die betreffenden Global-Constraint-Zeilen und `source .superpowers/env.sh`;
   er fährt nur eigene Ziele (`cargo test --locked -p <crate> --test <name>`), nie `--workspace`
   und nie die Integrationsklammer. Kommt eine Arbeitsbereichskante hinzu, ist
   `cargo metadata --format-version 1` das eine Kommando ohne `--locked`, das `Cargo.lock` schreibt.
   Die Scheiben werden **einmal** committet, samt der Checkbox-Haken des Abschnitts:
   `feat(reader): <was es zusagt>`; danach muss `git status --short` leer sein.
7. **Review.** Zwei bis drei Review-Agents mit je einer Linse (Korrektheit mit Mutationsproben;
   Zeugengüte gegen den Plan; bei Reader-Tasks Klartextdisziplin/Kryptografie). Jeden schweren
   Fund adversariell zu widerlegen versuchen; nur Bestätigtes einarbeiten, Widerlegtes und
   benannte Grenzen im PR-Body nennen. Commit `fix(reader): address the review findings on
   <thema>`, oder `test(reader): …`, wenn nur Zeugen sich bewegen.
8. **Gates fahren, Zahlen ablesen.** Billig → teuer, über die berührten Crates `<P>`:
   ```bash
   cargo fmt --all --check
   cargo clippy --locked <P> --all-targets --all-features -- -D warnings
   cargo test --locked <P>
   cargo test --locked <P> --doc                      # einziger Lauf der compile_fail-Doctests
   cargo check --locked --target wasm32-unknown-unknown <P>   # nur Crates der wasm32-Positivliste
   cargo test --locked -p xtask                       # Fault-Points, Plan-Pins, Ledger
   cargo deny check                                   # bei Cargo.lock-Änderung
   ```
   `xtask stage-gate <n>` existiert nur für Stufen 1–3; für spätere Stufen im PR als „nicht
   ausgeführt, Gate entsteht im Gate-Task der Stufe" führen. Zuletzt, auf dem Endstand nach dem
   Review-Commit, einmal die CI-Klammer (~15 min):
   ```bash
   env=$(cargo run --locked -p xtask -- integration up | grep '^export ') && eval "$env"
   pnpm verify:quick; cargo run --locked -p xtask -- integration down
   ```
   Exitcode, `passed/failed`, Laufzeit **abschreiben**. Was nicht lief, steht mit Grund als
   „nicht ausgeführt" im PR — kein Gate wird schöngeschrieben.
   **REQUIRED SUB-SKILL:** superpowers:verification-before-completion.
9. **Push und PR.** `git push -u origin drk-<nr>-<slug>`, dann
   `gh pr create --base main --title … --body-file …`. Danach Status `review` und PR-URL als
   Ticketkommentar. **Nicht mergen** — das entscheidet der Mensch nach der CI (25–75 min); die
   Session endet mit der Meldung von PR-URL, Gate-Zahlen und offenen Grenzen.

## Commit- und PR-Form

Commit-Betreff englisch, Conventional Commits, Scope = Crate-Familie (`reader`, `plan`, `gate`);
Body deutsch und nennt das Gemessene und die Entscheidung, nicht die Dateiliste.

PR-Titel: `DRK-<nr>: <Tickettitel>` ohne `S4-Txx` und ohne `(alt N)`. PR-Body deutsch; die
Abschnitte, soweit zutreffend, in dieser Reihenfolge:

1. Eine Zeile: `Stufe-N-Task M (<Planpfad>), ClickUp DRK-<nr>.` plus die Paragraphen der
   Spec unter `docs/superpowers/specs/`, die der Abschnitt zitiert (`web-reader-design.md` §6.5).
2. `## Zwei Commits` / `## Drei Commits` — Hash, Typ, ein Halbsatz je Commit.
3. `## Was <die Sache> zusagt` — die tragenden Entscheidungen als **fette Leitsätze**, je mit
   Beleg (Typaussage, Zeuge, Messung).
4. `## <N> Stellen, an denen der Plan gegen den Arbeitsbaum falsch war` — aus Schritt 5.
5. `## Gates` — Kommandos und abgelesene Zahlen; Nicht-Gelaufenes mit Grund.
6. `## Review` — bestätigte Funde, widerlegte Funde, benannte Grenzen.
7. `## Ledger` — welche Zeilen in `docs/traceability/v0.1-requirements.csv` sich bewegen und
   welche **bewusst nicht**. Die Global Constraints des Plans weisen die Statusbewegung meist
   dem Gate-Task der Stufe zu; ein früherer Wechsel macht das Stufengate rot.

Vorbilder: PR #7 (DRK-262) und PR #8 (DRK-263).

## Umgebung (gemessen)

| Symptom | Ursache | Ausweg |
|---|---|---|
| Exit 127, `cargo: not found` | nicht-interaktive Shell ohne `~/.cargo/bin`, `~/.local/bin` | `env.sh` |
| `verify:quick` Exit 2: „wasm32-unknown-unknown is not installed for the active toolchain" | unter `mise activate`/`mise exec` steht `RUSTUP_TOOLCHAIN=stable` und überstimmt `rust-toolchain.toml` (1.95.0) | `env.sh` (kein `mise exec`) |
| pnpm warnt „Unsupported engine … wanted 26.7.0" | `mise` löst `node` global auf `latest` statt auf `.node-version` | `env.sh` pinnt über `.node-version` |
| `cargo check --workspace` bricht an `ea-desktop`: „`frontendDist` … doesn't exist" | frischer Worktree ohne `apps/desktop/dist` | paketweise `-p` prüfen; `verify:quick` baut den Ordner selbst (zweiter Schritt) |
| Servertests: `DATABASE_URL` fehlt | `integration up` **druckt** die Exporte nur | `eval` wie in Schritt 8 |
| `web:browser-test` oder `web:e2e` finden keinen Browser/Treiber | Browser und chromedriver liegen im Container | `xtask browsers up` → `eval` der Exporte → Test → `browsers down`; weder CI noch `verify:quick` fahren sie |
| `wasm-bindgen-test` hängt: „Failed to detect test as having been run" | zweiter `OpfsBlobStore` auf einem Schlüssel, den der Testfall noch hält | ersten Speicher vor dem zweiten `open` fallen lassen |

`.superpowers/env.sh`, einmal je Worktree angelegt. Shell-Zustand überlebt keinen Tool-Aufruf,
also steht vor **jedem** Kommando `source .superpowers/env.sh &&`:

```bash
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"                 # cargo, mise, wasm-bindgen
export PATH="$(mise where pnpm):$(mise where node@$(cat .node-version))/bin:$PATH"
unset RUSTUP_TOOLCHAIN
```

## Rote Flaggen

- „Der ClickUp-Connector ist nicht autorisiert, ich leite das Ticket aus dem Branch ab."
- „Der fremde Worktree hat null Commits, den kann ich entfernen."
- „Ich spule kurz `main` vor" / „Ich branche vom lokalen `main`."
- „`stage-gate 4` ging nicht, ich lasse die Zeile weg."
- „Ich merge gleich, die CI ist grün."
