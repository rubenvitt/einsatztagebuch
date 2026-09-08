# DRK-250 – Umsetzung und Verifikation

Stand: in Bearbeitung. Dieses Artefakt ist noch keine Stufe-5-Abnahme.

Auftrag: alle Unteraufgaben von [DRK-250](https://app.clickup.com/t/123zgebzv1k),
isolierter Worktree, Umsetzung und unabhängige Reviews mit Subagents, neuer PR.
Verbindlicher Vertrag ist der
[Stufe-5-Plan](../superpowers/plans/2026-08-13-einsatzarchiv-stage-5-administration-recovery.md)
mit seinen Global Constraints und den referenzierten Spezifikationen.

## Arbeitsstand

- Branch: `drk-250-stage-five`.
- Worktree: `.worktrees/drk-250-stage-five`.
- Frisch geholte Basis: `1e5e7deeeed661ad8b82b7213d5a3d6a4c147329`.
- Plankorrektur: `a141639`; unbelegte Haken in Tasks 8–14 entfernt und
  fehlende Integrationsflächen gegen den ausgelieferten Baum benannt.
- Der ursprüngliche Checkout und bestehende fremde Worktrees bleiben erhalten.

## Anforderungsnachweise

| Ticket | Umfang | Aktueller Nachweis |
|---|---|---|
| DRK-269 / T01 | Admin-Autorisierung, Root-Ziel, Einmaligkeit und Audit | Bestehende Lieferung; Gesamtprüfung offen |
| DRK-270 / T02 | Bootstrap, unabhängige Anchor, Recovery-Sperre | Bestehende Lieferung; Gesamtprüfung offen |
| DRK-271 / T03 | Operator, tatsächliches OS-Konto, Sitzung und Widerruf | Bestehende Lieferung; Host-/Postureprüfung offen |
| DRK-272 / T04 | Policy, Registry, Widerruf, Lease und Clock Release | Bestehende Lieferung; Gesamtprüfung offen |
| DRK-273 / T05 | Writer-Wechsel und Restore-Blockade | Bestehende Lieferung; Gesamtprüfung offen |
| DRK-274 / T06 | Administration, Fingerprints, Policy, Go-live | UI vorhanden; produktive Host-Komposition offen |
| DRK-275 / T07 | Offline-Schlüsselquellen und CLI-Grammatik | Bestehende Lieferung; Folgeworkflow-Integration offen |
| DRK-276 / T08 | Zwei-Personen-Re-grant bis zum erneuten Öffnen | Umsetzung offen |
| DRK-277 / T09 | Vollständiger Recovery-Test, Inventar, dauerhafter Status | Umsetzung offen |
| DRK-278 / T10 | Nachtrag durch normale Writer-Pipeline | Umsetzung offen |
| DRK-279 / T11 | Vernichtungsautorisierung, Datenschutz-Gate und Zustände | Umsetzung offen |
| DRK-280 / T12 | Dauerhafte Stubs, Replikattestierungen, Resume und Evidence | Umsetzung offen |
| DRK-281 / T13 | Produktiver Vernichtungsassistent mit exakter Statussprache | Umsetzung offen |
| DRK-282 / T14 | Kumulatives Stufe-5-Gate und 19 Ledgerzeilen | Umsetzung und Abnahme offen |

Zusätzliche verbindliche Global Constraints bleiben Bestandteil der Lieferung:
Reader-KEM-Escrow beim Enrollment, getrennte Zwei-Approver-Öffnungszeremonie mit
gebundenem Transport-Key, gemeinsamer v1.1-Cutover, signierte dauerhafte
Einmal-Quittung für Stale Registry sowie administrative Auflösung/Diagnose der
widersprüchlichen Abschlussmarke und verwaister Sperren.

## Bisher ausgeführte Prüfungen

Diese Baseline-Prüfungen belegen vorhandene Funktionen, nicht die vollständige
Umsetzung der oben offenen Anforderungen.

| Befehl | Ergebnis | Rohbeleg im Worktree |
|---|---|---|
| `pnpm install --frozen-lockfile --store-dir .superpowers/pnpm-store` | Exit 0; 7,6 s | Tool-Ausgabe dieser Sitzung |
| `cargo test --locked -p xtask --test stage_gate` | 18 bestanden, 0 fehlgeschlagen, 0 ignoriert | `.superpowers/baseline-stage-gate.log` |
| `cargo test --locked -p ea-recovery` | 61 bestanden, 0 fehlgeschlagen, 0 ignoriert | `.superpowers/baseline-recovery.log` |
| `cargo test --locked -p xtask` nach Plankorrektur | 114 bestanden, 0 fehlgeschlagen, 0 ignoriert | `.superpowers/plan-correction-xtask.log` |

Die vollständigen Endstand-Gates, adversariellen Reviews und PR-/CI-Belege
werden nach der Umsetzung ergänzt. `verify:quick` ersetzt weder Browser-E2E
noch das separate Stufe-5-Gate.

## Abgrenzung zu Stufe 7

Native Minimum-/Maximum-Releasefälle, quartalsweise organisatorische Übungen,
die tatsächliche externe Datenschutzfreigabe und die Verwahrung produktiver
Schlüssel bleiben Stufe 7. Fehlende Softwareimplementierung wird dadurch nicht
aus dem Stufe-5-Auftrag entfernt. Ledgerstatus wird erst nach vollständiger
Stufe-5-Evidenz auf `implemented` oder `integrated` gesetzt.
