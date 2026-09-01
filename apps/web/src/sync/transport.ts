// Der Transport des Lesestapels — und NICHTS darueber hinaus.
//
// Diese Datei baut keine Kopfzeile, rechnet keinen Hash, bildet keine Signatur
// und liest keinen Status als Vertrauensaussage. Sie nimmt einen Request, den
// geteiltes Rust FERTIG signiert hat, ruft `fetch` und gibt die Antwortbytes
// zurueck. `web-reader-design.md` §9 laesst Kryptographie ausschliesslich in
// geteiltem Rust zu, und eine Signaturkopfzeile ist Kryptographie.
//
// # Warum der Status NICHT herauskommt
//
// Weil es sonst eine zweite Stelle gaebe, an der ueber Vertrauen entschieden
// wird. Ein `200` sagt ueber einen Lesestapel gar nichts — die Antwort ist erst
// dann ein Batch, wenn `readerSyncAcceptBatch` sie als `reader-batch-v1`
// dekodiert, den Startkopf gegen den eigenen Cursor stellt und die Kette gegen
// den gepinnten Anker rechnet. Eine HTML-Fehlerseite mit Status 200 und ein
// Batch mit Status 500 sind hier deshalb dasselbe: Bytes. Ueber ihre Bedeutung
// entscheidet Rust, und der Ausgang ist im schlimmsten Fall
// `EA-READER-PROTOCOL` — fail-closed und ohne Cursorfortschritt.

/**
 * Der Request, so wie `readerSyncNextRequest` ihn herausgibt.
 *
 * Die Form ist die von `ea_reader::ReaderRequestV1`. Sie wird hier NICHT
 * ergaenzt: `headers` ist die vollstaendige Kopfzeilenmenge, `target` der Pfad
 * samt Abfragezeichenkette, `authority` die Herkunft daneben.
 */
export type ReaderSyncRequestV1 = {
  readonly method: string
  readonly authority: string
  readonly target: string
  readonly headers: readonly (readonly [string, string])[]
  readonly bodyHex: string
}

/**
 * Der `fetch`, den dieser Transport benutzt.
 *
 * Als Parameter und nicht als globaler Zugriff, damit `transport.test.ts` den
 * ABGESCHICKTEN Request lesen kann. Ein Zeuge, der nur das Ergebnis saehe,
 * bliebe gruen, wenn diese Datei eine Kopfzeile hinzufuegte.
 */
export type FetchLike = (input: string, init: RequestInit) => Promise<Response>

/**
 * Bytes aus einer Hexzeichenkette.
 *
 * Der Koerper des Lesestapels ist leer — `GET /v1/chains/{chainId}/entries`
 * traegt keinen —, und die Funktion steht trotzdem hier, weil die Form von
 * `ReaderRequestV1` einen Koerper vorsieht und ein hier weggelassenes Feld eine
 * stille Abweichung von der Rust-Seite waere.
 *
 * Der Rueckgabetyp nennt `ArrayBuffer` ausdruecklich: unter
 * `exactOptionalPropertyTypes` und den TypeScript-7-Bibliotheken ist
 * `Uint8Array<ArrayBufferLike>` kein `BodyInit`, weil ein `SharedArrayBuffer`
 * dahinterstehen koennte. `new Uint8Array(laenge)` liefert genau die engere
 * Form; sie hier zu benennen ist billiger als eine Typzusicherung an der
 * Aufrufstelle.
 */
function bytesFromHex(hex: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(hex.length / 2)
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

/**
 * Schickt einen fertig signierten Lesestapel-Request ab und gibt die
 * Antwortbytes zurueck.
 *
 * Die Zieladresse entsteht aus `authority` und `target` und nicht aus einer
 * hier gefuehrten Konfiguration: welcher Server gefragt wird, hat der Aufrufer
 * beim Signieren bereits gebunden — `@authority` und `@target-uri` stehen in
 * der Signaturbasis. Ein hier umgeschriebenes Ziel machte die Signatur
 * ungueltig, statt heimlich woanders hinzugehen.
 */
export async function sendReaderSyncRequest(
  request: ReaderSyncRequestV1,
  fetchImpl: FetchLike,
): Promise<Uint8Array> {
  const body = bytesFromHex(request.bodyHex)
  const response = await fetchImpl(`https://${request.authority}${request.target}`, {
    method: request.method,
    // WOERTLICH die Kopfzeilen des Requests. Kein `Content-Type`, kein
    // `Accept`, kein `Authorization` — was nicht signiert wurde, wird nicht
    // gesendet.
    headers: request.headers.map(([name, value]) => [name, value]),
    ...(body.length > 0 ? { body } : {}),
  })
  return new Uint8Array(await response.arrayBuffer())
}
