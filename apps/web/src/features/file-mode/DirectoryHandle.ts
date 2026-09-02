// Der Verzeichnisdurchlauf des Datei-Modus und die Brücke darunter.
//
// Diese Datei ENTSCHEIDET nichts (`web-reader-design.md` §9). Sie zählt keine
// Blobs, vergleicht keine Deckel, prüft keine Magie und leitet aus keinem
// Dateinamen ab, was in einer Datei steht: Klassifiziert wird in Rust, am
// 9-Byte-Präfix des Objekts beziehungsweise an der Magie des Containers. Was
// hier geschieht, ist Bytes tragen — und die EINE Ordnung herstellen, die der
// Browser nicht mitliefert.
//
// # Warum der Durchlauf sortiert
//
// `FileSystemDirectoryHandle.entries()` gibt keine Reihenfolge zu. Ohne eine
// festgelegte hinge der Ablauf des Durchlaufs — und damit die Reihenfolge
// jeder Meldung und der Zählstand beim Anschlagen eines Deckels — am Zufall
// der Browserimplementierung, und derselbe Ordner ergäbe in zwei Engines zwei
// verschiedene Abbrüche. Sortiert wird je Ebene lexikografisch aufsteigend
// nach dem Namen; rekursiv abgestiegen wird an Ort und Stelle.
//
// Was diese Ordnung AUSDRÜCKLICH nicht herstellt, ist die des Containers: der
// sortiert streng über die vollen Adressbytes, und ebenenweise ist nicht
// dasselbe — `a-b.txt` steht global vor `a/z.txt`, weil `0x2D` vor `0x2F`
// kommt, ebenenweise aber dahinter. Der Bericht braucht die globale Ordnung
// nicht: jedes seiner Sammelfelder ist eine Karte über Hashes, und kein Feld
// nennt einen Pfadhinweis. Deshalb sortiert `DirectoryHandleSource` in Rust
// auch nicht nach.
//
// # Warum jede Bytefolge EINZELN über die Brücke geht
//
// Die zwei Deckel — Blobzahl und Bytesumme — fallen in Rust, an
// `DirectoryHandleSource::push_blob`, bevor die Quelle ihre Kopie anlegt. Ein
// Sammelaufruf hätte den ganzen Ordner ein zweites Mal im JavaScript-Heap
// gehalten, und der Deckel hätte erst geschützt, als es nichts mehr zu
// schützen gab.
//
// # Der Abbruch gehört Rust
//
// Ein Ordner, dem die Berechtigung entzogen wurde, meldet das erst beim
// NÄCHSTEN Zugriff. Diese Datei erfindet dafür keinen Code: sie vermerkt den
// Ausfall über `fileModeDirectoryUnavailable` und lässt das Öffnen danach den
// stabilen Code liefern. Ein Deckelcode aus `push-blob` reist unverändert
// weiter — er wird hier weder gefangen noch übersetzt.

import type { FileModeArchiveView } from '../../bridge/generated-contracts'
import type { EaOpfsResponse } from '../../bridge/opfs-worker'
import type { ReaderWorkerMessage } from '../../vault/webauthn-prf'
import { callReaderWorker, unlockReaderVaultSession } from '../../vault/webauthn-prf'

declare global {
  // `showDirectoryPicker` steht in der File-System-Access-Fassung des
  // Fensters, in `lib.dom.d.ts` (TypeScript 7.0.2) aber überhaupt nicht — die
  // Methode ist kein Standard, und genau deshalb gibt es diesen Modus in zwei
  // Wegen. Die Erweiterung deklariert das eine Feld nach und erfindet keine
  // weitere Fläche; sie ist OPTIONAL, damit die Fähigkeitsabfrage der Fläche
  // überhaupt etwas zu fragen hat.
  interface Window {
    showDirectoryPicker?: () => Promise<FileModeDirectoryHandleV1>
  }
}

/**
 * Das Wirtsobjekt, an dem die Fläche ihre Fähigkeitsabfrage stellt.
 *
 * `showDirectoryPicker` ist OPTIONAL, und das ist die ganze Aussage dieses
 * Typs: in Safari und Firefox gibt es die Methode nicht. Abgefragt wird die
 * FÄHIGKEIT (`'showDirectoryPicker' in host`) und nie eine Browserkennung —
 * eine Kennungsliste veraltet still, eine Fähigkeitsabfrage nicht.
 *
 * Der Wirt wird ÜBERGEBEN und nicht aus `globalThis` gelesen: nur so kann ein
 * Zeuge die Abwesenheit doubeln, und nur so steht in der Fläche kein Zugriff
 * auf ein Fenster, das sie nicht kennt.
 */
export type FileModeHost = {
  readonly showDirectoryPicker?: () => Promise<FileModeDirectoryHandleV1>
}

/**
 * Die von diesem Durchlauf benutzte Fläche eines `FileSystemDirectoryHandle`.
 *
 * Sie steht hier ausgeschrieben, weil `lib.dom.d.ts` sie in dieser Form nicht
 * führt: `entries()` liegt in `DOM.AsyncIterable`, das `tsconfig.json` nicht
 * lädt, und `queryPermission` ist überhaupt nicht standardisiert. Ein
 * strukturell beschriebener Ausschnitt ist hier ausserdem das ehrlichere
 * Mittel — er benennt genau das, was der Durchlauf anfasst, und ein Zeuge kann
 * ihn ohne Browser erfüllen.
 */
export type FileModeDirectoryHandleV1 = {
  readonly kind: 'directory'
  readonly entries: () => AsyncIterable<readonly [string, FileModeEntryV1]>
  /**
   * Der Berechtigungsstand, falls der Wirt ihn anbietet.
   *
   * Fehlt die Methode, wird der Ordner als liefernd behandelt — die Alternative
   * wäre, einen Ausfall zu behaupten, den niemand gemeldet hat.
   */
  readonly queryPermission?: (options: { readonly mode: 'read' }) => Promise<string>
}

/** Die von diesem Durchlauf benutzte Fläche eines `FileSystemFileHandle`. */
export type FileModeFileHandleV1 = {
  readonly kind: 'file'
  readonly getFile: () => Promise<{ readonly arrayBuffer: () => Promise<ArrayBuffer> }>
}

/** Ein Eintrag einer Ebene: entweder eine Datei oder ein weiterer Ordner. */
export type FileModeEntryV1 = FileModeDirectoryHandleV1 | FileModeFileHandleV1

/**
 * Die Senke EINER Bytefolge samt ihrem Pfadhinweis.
 *
 * Sie steht als eigener Typ, damit [`walkDirectoryHandle`] ohne Brücke, ohne
 * Worker und ohne wasm-Modul bezeugt werden kann: der Durchlauf ist die
 * einzige Stelle dieser Aufgabe, an der TypeScript überhaupt etwas herstellt.
 */
export type FileModePushPort = (pathHint: string, bytes: Uint8Array) => Promise<void>

/**
 * Die FORM der Brücke des Datei-Modus.
 *
 * Drei Glieder und kein viertes. `bundleExtension` ist synchron, weil der
 * Dateidialog seinen Filter beim Rendern braucht; die zwei öffnenden Glieder
 * sind es nicht, weil sie über den Worker laufen.
 */
export type FileModeBridge = {
  readonly bundleExtension: () => string
  readonly openBundle: (bytes: Uint8Array) => Promise<FileModeArchiveView>
  readonly openDirectory: (handle: FileModeDirectoryHandleV1) => Promise<FileModeArchiveView>
}

/**
 * Läuft den Ordner rekursiv ab und reicht jede Datei EINZELN an `push`.
 *
 * Je Ebene lexikografisch aufsteigend nach Namen, und der Vergleich ist der
 * über die UTF-16-Codeeinheiten und keine Gebietsschema-Sortierung: ein
 * `localeCompare` hinge an der Umgebung des Lesers und wäre damit genau die
 * Unbestimmtheit, gegen die hier sortiert wird.
 *
 * Der Pfadhinweis ist der Weg von der Wurzel, mit `/` verbunden. Er ist ein
 * HINWEIS: kein Berichtsfeld nennt ihn, und ob eine Bytefolge ein Archivobjekt
 * ist, entscheidet ihr Präfix und nicht ihr Name.
 */
export async function walkDirectoryHandle(
  handle: FileModeDirectoryHandleV1,
  push: FileModePushPort,
  prefix = '',
): Promise<void> {
  const level: [string, FileModeEntryV1][] = []
  for await (const [name, entry] of handle.entries()) {
    level.push([name, entry])
  }
  level.sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))

  for (const [name, entry] of level) {
    const pathHint = prefix.length === 0 ? name : `${prefix}/${name}`
    if (entry.kind === 'directory') {
      await walkDirectoryHandle(entry, push, pathHint)
    } else {
      const file = await entry.getFile()
      await push(pathHint, new Uint8Array(await file.arrayBuffer()))
    }
  }
}

/**
 * Ob der Ordner nach eigener Auskunft noch liefert.
 *
 * Gefragt wird VOR und NACH dem Durchlauf, und beides ist nötig: ein
 * `FileSystemDirectoryHandle` meldet eine entzogene Berechtigung erst beim
 * nächsten Zugriff, also mitten im Durchlauf und nicht an seinem Anfang.
 */
async function stillDelivers(handle: FileModeDirectoryHandleV1): Promise<boolean> {
  if (handle.queryPermission === undefined) {
    return true
  }
  return (await handle.queryPermission({ mode: 'read' })) === 'granted'
}

/**
 * Der Weg EINER Nachricht zum Worker und zurück.
 *
 * Er steht als eigener Typ aus demselben Grund wie [`FileModePushPort`]: das
 * ZUSAMMENSETZEN unten — anfangen, durchlaufen, den Ausfall vermerken, öffnen
 * — ist die einzige Entscheidungsfolge dieser Datei, und ohne einen Port wäre
 * sie nur über einem echten Worker samt wasm-Modul zu fahren und damit von
 * keinem Zeugen erreichbar. Der Port ist der Aufruf und nicht die Brücke: er
 * kennt weder Sitzung noch Ordnerkennung.
 */
export type FileModeWorkerPort = (request: ReaderWorkerMessage) => Promise<EaOpfsResponse>

/** Eine Nachricht ohne Antwortwert; ein Fehlschlag reist als stabiler Code. */
async function callVoid(call: FileModeWorkerPort, request: ReaderWorkerMessage): Promise<void> {
  raise(await call(request))
}

/** Eine Nachricht, deren Antwort einen Text trägt — DTO, Kennung oder Endung. */
async function callForText(
  call: FileModeWorkerPort,
  request: ReaderWorkerMessage,
): Promise<string> {
  const response = raise(await call(request))
  if (response.status === undefined) {
    throw new Error('Der Worker hat auf eine Datei-Modus-Nachricht keinen Wert geliefert.')
  }
  return response.status
}

/**
 * Der stabile Code eines Fehlschlags, unverändert geworfen.
 *
 * Kein Wirtstext und keine eigene Übersetzung: `EA-BUNDLE-MALFORMED`,
 * `EA-ARCHIVE-UNAVAILABLE` und die zwei Deckelcodes sind Aussagen von Rust,
 * und die Fläche darüber soll dieselbe Aussage lesen, die ein Zeuge in Rust
 * liest.
 */
function raise(response: EaOpfsResponse): Extract<EaOpfsResponse, { ok: true }> {
  if (!response.ok) {
    throw new Error(response.code)
  }
  return response
}

/**
 * Der Komfortweg als GANZER Zug: anfangen, durchlaufen, den Ausfall vermerken,
 * öffnen.
 *
 * Die Reihenfolge ist die ganze Aussage dieser Funktion, und jeder ihrer vier
 * Schritte trägt seinen Grund:
 *
 * - Gefragt wird VOR und NACH dem Durchlauf, weil ein `FileSystemDirectoryHandle`
 *   eine entzogene Berechtigung erst beim nächsten Zugriff meldet — also mitten
 *   im Durchlauf und nicht an seinem Anfang. Ohne die zweite Frage klassifizierte
 *   Rust einen TEILbestand, und weil eine Abschneidung am Kettenende keine Lücke
 *   erzeugt, stünde über einem halben Archiv „vollständig geprüft".
 * - Der Ausfall wird VERMERKT und nicht übersetzt: den stabilen Code
 *   (`EA-ARCHIVE-UNAVAILABLE`) gibt danach das Öffnen heraus, in Rust.
 * - Der Griff wird auch nach einem Abbruch EINGELÖST, denn das Öffnen ist der
 *   einzige Zug, der die angefangene Quelle aus der Tabelle des Workers nimmt;
 *   ohne ihn bliebe ein Teilbestand dort liegen. Sein Ergebnis interessiert
 *   dann niemanden — geworfen wird der ursprüngliche Code, unverändert.
 */
export async function openDirectoryOverPort(
  handle: FileModeDirectoryHandleV1,
  session: number,
  call: FileModeWorkerPort,
): Promise<FileModeArchiveView> {
  const directory = Number(await callForText(call, { kind: 'file-mode-begin-directory' }))
  const open = async (): Promise<string> =>
    callForText(call, {
      kind: 'file-mode-open-directory',
      session,
      handle: directory,
      effectiveNowMs: BigInt(Date.now()),
    })

  try {
    if (await stillDelivers(handle)) {
      await walkDirectoryHandle(handle, async (pathHint, bytes) => {
        await callVoid(call, { kind: 'file-mode-push-blob', handle: directory, pathHint, bytes })
      })
    }
    if (!(await stillDelivers(handle))) {
      await callVoid(call, { kind: 'file-mode-directory-unavailable', handle: directory })
    }
  } catch (reason) {
    await callVoid(call, { kind: 'file-mode-directory-unavailable', handle: directory }).catch(
      () => undefined,
    )
    await open().catch(() => undefined)
    throw reason
  }

  return JSON.parse(await open()) as FileModeArchiveView
}

/**
 * Die entsperrte Tresorsitzung, EINMAL je Seitenlauf geholt.
 *
 * Jede Brückenausfuhr des Datei-Modus verlangt sie, weil der gepinnte Anker im
 * Tresor liegt und nirgendwo sonst — das ist §5.3 als Konstruktionsregel.
 * Zwischengehalten wird sie, damit nicht jedes Öffnen eine neue
 * Authenticator-Zeremonie auslöst.
 */
let openSession: number | undefined

async function readerSession(): Promise<number> {
  openSession ??= await unlockReaderVaultSession()
  return openSession
}

/**
 * Die Endung, die der Dateidialog als Filter anbietet.
 *
 * Sie kommt aus `ea_archive::BUNDLE_FILE_EXTENSION_V1` über die Brücke und
 * steht deshalb nirgends in TypeScript. Der Abruf ist asynchron, das Glied ist
 * es nicht — also wird der Wert beim ersten Blick angefordert und ab dem
 * zweiten geliefert.
 *
 * BENANNTE FOLGE: solange er unterwegs ist, trägt das Feld KEINEN Filter. Das
 * kostet nichts, denn die Endung ist ein Hinweis und kein Tor — eine
 * umbenannte Datei fällt an der Magie des Containers und nicht am Namen. Ein
 * Eingabefeld, das auf die Endung WARTETE, wäre der schlechtere Tausch: es
 * machte ausgerechnet den universellen Weg von einem Brückenaufruf abhängig.
 */
let knownBundleExtension = ''
let extensionRequest: Promise<void> | undefined

/** Die echte Brücke: drei Glieder, jedes eine Nachricht an den EINEN Worker. */
export const fileModeBridge: FileModeBridge = {
  bundleExtension: () => {
    extensionRequest ??= callForText(callReaderWorker, { kind: 'file-mode-bundle-extension' }).then(
      extension => {
        knownBundleExtension = extension
      },
    )
    return knownBundleExtension
  },

  openBundle: async bytes => {
    const status = await callForText(callReaderWorker, {
      kind: 'file-mode-open-bundle',
      session: await readerSession(),
      bytes,
      // Die Uhr tritt als WERT ein, genau wie beim Abschluss des Enrollments:
      // `wasm32-unknown-unknown` hat keinen Wirt für `SystemTime::now()`, und
      // `ea_reader::ReaderVerifier` reicht den Wert wortwörtlich an
      // `VerifyOptions::new` durch. `BigInt`, weil `wasm_bindgen` `i64` so
      // abbildet.
      effectiveNowMs: BigInt(Date.now()),
    })
    return JSON.parse(status) as FileModeArchiveView
  },

  openDirectory: async handle =>
    openDirectoryOverPort(handle, await readerSession(), callReaderWorker),
}
