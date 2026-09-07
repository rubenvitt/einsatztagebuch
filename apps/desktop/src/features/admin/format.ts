/**
 * Ein Zeitpunkt als ISO-8601 in UTC.
 *
 * Eindeutig und deterministisch: keine Zeitzone des Rechners, kein
 * Gebietsschema. Die Verwaltungsflaeche zeigt Ablaeufe, Eingaenge und
 * Wanduhren — Werte, die der Bediener mit einem Protokoll oder einer zweiten
 * Uhr VERGLEICHT, und ein Vergleich verlangt eine Gestalt, die auf jedem
 * Geraet dieselbe ist.
 */
export function formatInstant(milliseconds: number): string {
  return new Date(milliseconds).toISOString()
}
