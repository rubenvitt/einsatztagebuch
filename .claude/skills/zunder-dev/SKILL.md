---
name: zunder-dev
description: Use when a request names a Zunder task (UUID or `zunder.rubeen.dev` link) or an old DRK-### ticket, asks to pick up, implement, or close a task from the Einsatztagebuch board, or asks for a ticket "in neuem Worktree mit PR als Ergebnis".
---

# Zunder Dev (Einsatztagebuch)

## Überblick

Ein Ticket wird in einem eigenen Worktree auf dem **neuesten `origin/main`** umgesetzt, mit
Subagents gebaut und geprüft, und endet als PR — nicht als Merge. TDD, Planausführung und Review
kommen aus den superpowers-Skills; hier steht nur, was Board und Repo zusätzlich verlangen.

## Wo die Tickets liegen

| | |
|---|---|
| Bereich | `DRK Bereitschaft` — `f22114c8-7f6d-5b51-8696-0cca72f2e9b9` |
| Projekt **Einsatztagebuch** (Dev, `rubenvitt/einsatztagebuch`) | `1e51337d-9b35-58eb-aafe-32ccfacc7bfa` |
| Projektstatus | `completed` — `list_structure` zeigt es nur mit `include_archived: true` |
| Epics | `[Epic] … Stufe N …` (DRK-249 = Stufe 4); die Beschreibung nennt den Plan unter `docs/superpowers/plans/` |
| Task-Titel | `S4-T12 — …` = Überschrift `### Task 12:` im Stufe-4-Plan; Ledger-Zeilen (`FR-104`, `WR-082`) stehen am Ende der Beschreibung |

Seit 12.10.2026 liegen die Tickets in **Zunder** (`https://zunder.rubeen.dev`), Connector
`mcp__claude_ai_Zunder__*`. Ein Ticket wird **gelesen**, nie aus Branchnamen oder PR-Nummern
erschlossen:

```
get_task(task_id: "<uuid>")          # Beschreibung und Unteraufgaben-Baum
```

## Ticket-IDs

Zunder hat keine sprechenden Nummern; eine Aufgabe heißt über ihre UUID.

- **Verweis** (Commit-Body, PR-Body): `Zunder: https://zunder.rubeen.dev/#/aufgabe/<uuid>`
- **Branch**: die ersten 8 Hex-Zeichen der UUID statt der Nummer, `<8hex>-<slug>`.
- **Alte Tickets** (`DRK-###` in Commits, Plänen, PRs) bleiben als Historie gültig. Zunder löst die
  Custom-ID nicht auf; nur die numerische ID aus dem alten ClickUp-Link geht
  (`get_task(clickup_id: "…")`, Web `https://zunder.rubeen.dev/#/clickup/<clickup_id>`), sonst
  `search` nach dem Titel.

## Status (exakt diese Codes)

```
open → in_progress → review → done        dazu blocked, dropped
```

| Moment | `update_task(task_id, …)` |
|---|---|
| Ticket aufgenommen, Worktree steht | `claim_task(task_id, agent)` + `status: "in_progress"`, `branch` |
| Harte Sperre, die nur der Mensch lösen kann | `blocked` + Grund als `## Notizen` mit Datum in `description` (vorher `get_task`, nichts überschreiben) |
| PR eröffnet | `review` + `pr_url`, danach `release_task(task_id, agent)` |
| Nach dem Merge (Mensch oder spätere Session auf Zuruf) | `done` |
| Bewusst nicht umgesetzt | `dropped` — nie `delete_task` |

Nur vorwärts, nie redundant. Der Epic bleibt `in_progress`, bis seine Subtasks durch sind.
`claim_task` gilt 120 Minuten; erneut aufrufen verlängert. Neue Subtasks: `create_task` mit
`parent_id`, mehrere auf einmal `decompose_task`.

## Ablauf

1. **Ticket und Epic lesen.** `get_task` für das Ticket, danach für `parent_id`. Der
   Plan-Abschnitt (Task-Nummer aus dem Titel) ist der Vertrag, dazu die Global Constraints des
   Plans; das Ticket ist die Kurzfassung und nennt die Ledger-Zeilen.
2. **Doppelarbeit ausschließen.** `git branch -a --list '<8hex>-*'`, `git worktree list` und
   `claimed_by` im Ticket prüfen. Gibt es schon einen Branch zu dieser Aufgabe, **anhalten und
   melden** (Status bleibt, wie er ist) — nicht mit anderem Slug daneben bauen. Fremde und
   gelockte Worktrees bleiben unangetastet.
3. **Worktree auf `origin/main`.** Erst fetchen, dann branchen — das lokale `main` hängt
   regelmäßig Merges hinterher und wird **nicht** vorgespult:
   ```bash
   git -C ~/dev/einsatztagebuch fetch origin
   git -C ~/dev/einsatztagebuch worktree add .worktrees/<8hex>-<slug> -b <8hex>-<slug> origin/main
   ```
   Branch und Ordner heißen gleich, ohne Typpräfix, Slug 2–4 englische Wörter
   (`de51bfbf-encrypted-index`). Verlangt der Auftrag einen neuen Worktree, gilt das auch, wenn
   die Session bereits in einem Harness-Worktree (`.claude/worktrees/bridge-*`) sitzt.
4. **Setup:** `pnpm install --frozen-lockfile`, dann `.superpowers/env.sh` aus „Umgebung" anlegen
   (`.superpowers/` ist ignoriert). Danach `claim_task` und Status `in_progress`.
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
9. **Push und PR.** `git push -u origin <8hex>-<slug>`, dann
   `gh pr create --base main --title … --body-file …`. Danach Status `review`, `pr_url` setzen und
   `release_task`. **Nicht mergen** — das entscheidet der Mensch nach der CI (25–75 min); die
   Session endet mit der Meldung von PR-URL, Gate-Zahlen und offenen Grenzen.

## Commit- und PR-Form

Commit-Betreff englisch, Conventional Commits, Scope = Crate-Familie (`reader`, `plan`, `gate`);
Body deutsch und nennt das Gemessene und die Entscheidung, nicht die Dateiliste; letzte Zeile
`Zunder: https://zunder.rubeen.dev/#/aufgabe/<uuid>`.

PR-Titel: `<Tickettitel>` ohne `S4-Txx` und ohne `(alt N)`. PR-Body deutsch; die
Abschnitte, soweit zutreffend, in dieser Reihenfolge:

1. Eine Zeile: `Stufe-N-Task M (<Planpfad>).` und darunter
   `Zunder: https://zunder.rubeen.dev/#/aufgabe/<uuid>`, plus die Paragraphen der
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

- „Der Zunder-Connector antwortet nicht, ich leite das Ticket aus dem Branch ab."
- „Der fremde Worktree hat null Commits, den kann ich entfernen."
- „Ich spule kurz `main` vor" / „Ich branche vom lokalen `main`."
- „`stage-gate 4` ging nicht, ich lasse die Zeile weg."
- „Ich merge gleich, die CI ist grün."
