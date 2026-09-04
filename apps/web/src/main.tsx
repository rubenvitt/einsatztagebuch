// Die Stilquelle ZUERST: `app.css` zieht `static-antd.css` in seine
// Kaskadenschicht, und `vite build` macht daraus ein gehashtes, lokales
// Beiwerk. Es gibt keinen Webfont und keine entfernte Stilquelle — unter
// `style-src 'self'` und `font-src 'self'` gaebe es fuer beide keinen Weg.
import './design/app.css'

import { App, ConfigProvider, Layout, Typography } from 'antd'
import deDE from 'antd/locale/de_DE'
import { StrictMode, useState } from 'react'
import type { ReactElement } from 'react'
import { createRoot } from 'react-dom/client'

import type { ReaderTrustAgeView } from './bridge/generated-contracts'
import { readerBridge } from './bridge/reader-bridge'
import { DecorativeIcon } from './design/icons'
import { eaRuntimeTheme } from './design/tokens'
import { EnrollmentPage } from './features/enrollment/EnrollmentPage'
import { SingleExport } from './features/export/SingleExport'
import { fileModeBridge } from './features/file-mode/DirectoryHandle'
import { OpenArchivePanel } from './features/file-mode/OpenArchivePanel'
import { ReaderPage } from './features/reader/ReaderPage'
import { readerSessionBridge } from './features/session/reader-session'
import { TrustAgeBanner } from './features/trust-age/TrustAgeBanner'

/**
 * Ein Eintrag der Routentabelle: der Pfad, sein Wortlaut im Verweis und — seit
 * dem Browser-Enrollment — die Flaeche, die er montiert.
 *
 * `render` ist OPTIONAL, und der dritte Platz ist eine oeffentliche
 * Formaenderung: der Typ ist exportiert. Ohne ihn rendert die Schale fuer jede
 * Route denselben Platzhalterkoerper, und ein Aufruf von `/enrollment` faende
 * eine Route, die niemand montiert hat.
 */
export type EaWebRoute = {
  readonly path: string
  readonly label: string
  readonly render?: () => ReactElement
}

/**
 * Die Routentabelle des Browser-Readers.
 *
 * Sie entsteht HIER und mit genau EINEM Eintrag, und jede spaetere Flaeche
 * dieses Plans haengt ihren Eintrag an — `/enrollment`, `/datei` und die volle
 * Reader-Flaeche unter `/` — statt eine zweite Tabelle aufzumachen. Der Grund
 * ist der Besitz: ohne Eintrag laeuft der Browserlauf der jeweiligen Aufgabe
 * gegen eine Route, die niemand montiert hat.
 *
 * Es gibt KEINEN Router als Abhaengigkeit. Die Auswahl ist ein Vergleich ueber
 * eine Liste, genau wie in der Desktop-Schale; eine Bibliothek dafuer waere
 * eine Abhaengigkeit mehr fuer einen `find`-Aufruf.
 */
export const EA_WEB_ROUTES: readonly EaWebRoute[] = [
  // Die volle Reader-Flaeche unter `/` — die Zeile bestand seit der Schale,
  // ihr `render` kam mit der Flaeche. `bridge` wird GESTELLT und ist kein
  // Vorgabewert, aus demselben Grund wie beim Datei-Modus darunter: die echte
  // Bruecke spricht mit dem dedizierten Worker, und ein Zeuge rendert die
  // Flaeche mit einem Doppel.
  { path: '/', label: 'Reader', render: () => <ReaderPage bridge={readerBridge} /> },
  { path: '/enrollment', label: 'Enrollment', render: () => <EnrollmentPage /> },
  // ANGEHAENGT und keine zweite Tabelle. `host` ist das echte Fenster, weil
  // die Faehigkeitsabfrage der Flaeche genau hier ihren Wirt bekommt; `bridge`
  // wird ausdruecklich GESTELLT und ist kein Vorgabewert der Flaeche, damit
  // ein Zeuge sie rendern kann, ohne den dedizierten Worker zu erzeugen.
  {
    path: '/datei',
    label: 'Datei-Modus',
    render: () => <OpenArchivePanel host={window} bridge={fileModeBridge} />,
  },
  // ANGEHAENGT, aus demselben Grund und in derselben Form wie `/datei`: der
  // Wirt ist das echte Fenster, weil die Zielwahl dort `showSaveFilePicker`
  // erfragt, und die Sitzungsbruecke wird GESTELLT, damit ein Zeuge die
  // Flaeche ohne den dedizierten Worker rendern kann.
  {
    path: '/export',
    label: 'Einzelexport',
    render: () => <SingleExport bridge={readerSessionBridge} host={window} />,
  },
]

/**
 * Die Schale, die die Tabelle montiert.
 *
 * Sie fuehrt den deutschen `ConfigProvider` und `eaRuntimeTheme` — also
 * `zeroRuntime: true` —, weil die Komponentenregeln aus `static-antd.css`
 * kommen und die CSP jede zur Laufzeit eingespritzte Regel blockiert. Das Ant
 * `App`-Element liegt darin und nicht daneben: es traegt den Kontext, aus dem
 * spaetere Flaechen ihre Ueberlagerungen beziehen, und ohne ihn faellt der
 * erste `modal.confirm` mit einer Konsolenwarnung statt mit einer Flaeche.
 *
 * In dieser Aufgabe ist die Flaeche LEER. Das ist kein Platzhalter, sondern der
 * Umfang: dieser Task legt das Fundament und keine Reader-Funktion.
 */
export function EaWebApp({
  routes = EA_WEB_ROUTES,
  initialPath = '/',
  trustAge,
}: {
  readonly routes?: readonly EaWebRoute[]
  readonly initialPath?: string
  /**
   * Das Alter des zuletzt bezogenen Trust-Standes.
   *
   * OPTIONAL, und das ist der Umfang dieser Aufgabe: der Wert entsteht in
   * `ea_reader::reader_trust_age_view` und kommt ueber die Bruecke, sobald ein
   * Bezug stattgefunden hat. Ein Geraet, das nie bezogen hat, zeigt KEINEN
   * Streifen — `undefined` heisst „nie bezogen" und ist nicht dasselbe wie ein
   * Alter von null.
   */
  readonly trustAge?: ReaderTrustAgeView
} = {}): ReactElement {
  const [path, setPath] = useState(initialPath)
  const active = routes.find((route) => route.path === path) ?? routes[0]

  return (
    <ConfigProvider locale={deDE} theme={eaRuntimeTheme}>
      <App>
        <Layout>
          <Layout.Header>
            <Typography.Text strong>Einsatzarchiv — Reader</Typography.Text>
          </Layout.Header>
          <Layout.Content>
            {trustAge === undefined ? null : <TrustAgeBanner view={trustAge} />}
            <nav aria-label="Hauptbereiche">
              {routes.map((route) => (
                <a
                  key={route.path}
                  href={route.path}
                  aria-current={route.path === path ? 'page' : undefined}
                  onClick={(event) => {
                    event.preventDefault()
                    setPath(route.path)
                  }}
                >
                  {route.label}
                </a>
              ))}
            </nav>
            {active === undefined ? null : (
              <section aria-label={active.label}>
                {active.render === undefined ? (
                  <>
                    <DecorativeIcon name="locked" />
                    <Typography.Title level={2}>{active.label}</Typography.Title>
                  </>
                ) : (
                  active.render()
                )}
              </section>
            )}
          </Layout.Content>
        </Layout>
      </App>
    </ConfigProvider>
  )
}

const container = document.getElementById('root')
if (container === null) {
  throw new Error('Der Wurzelknoten der Anwendung fehlt.')
}

// NUR die Montage liest die Adresse. Der Vorgabewert im Bauteil bleibt `'/'`,
// damit es fuer `vitest` deterministisch und ohne Wirtsbezug bleibt.
createRoot(container).render(
  <StrictMode>
    <EaWebApp initialPath={window.location.pathname} />
  </StrictMode>,
)

// Die drei Haken der Sitzungssperre nach `web-reader-design.md` §6.5.
//
// Sie MELDEN und entscheiden nichts: `visibilitychange` traegt den Wechsel in
// den Hintergrund samt der Uhr der Seite zur Sitzung, `pointerdown` und
// `keydown` tragen eine Eingabe. Die Fristen — fuenf Minuten ohne Eingabe,
// dreissig Sekunden nach dem Wechsel in den Hintergrund — rechnet
// `ReaderSession::state_at` in Rust bei JEDEM Zugriff nach.
//
// Ein TIMER ist ausdruecklich NICHT der Mechanismus, und das ist gemessen,
// nicht Vorliebe: Hintergrundtabs werden gedrosselt und schlafen gelegt, ein
// `setTimeout` auf dreissig Sekunden feuert dort irgendwann oder nie, und die
// Sperre hinge damit an dem Tab, den §6.5 gerade als gefaehrdet ansieht. Der
// Zeitwert kommt deshalb als Argument mit — Rust liest keine Uhr —, und die
// Sperre faellt beim naechsten Zugriff, egal wann der stattfindet.
//
// `pointerdown` und `keydown` sind gedrosselt, hoechstens eine Meldung je
// Sekunde: jede Meldung ist eine Nachricht an den Worker, und eine
// Tastenwiederholung sind hundert davon. Die Drossel verkuerzt keine Frist —
// eine Eingabe innerhalb der Sekunde nach der letzten ist fuer eine
// Fuenfminutenfrist dieselbe Eingabe.
document.addEventListener('visibilitychange', () => {
  void readerSessionBridge.noteVisibility(document.visibilityState === 'hidden', Date.now())
})

let lastActivityNotedAt = Number.NEGATIVE_INFINITY

function noteActivity(): void {
  const now = Date.now()
  if (now - lastActivityNotedAt < 1_000) {
    return
  }
  lastActivityNotedAt = now
  void readerSessionBridge.noteActivity(now)
}

document.addEventListener('pointerdown', noteActivity, { passive: true })
document.addEventListener('keydown', noteActivity, { passive: true })

// Der Service Worker, RELATIV adressiert und als MODUL.
//
// `./service-worker.js` und nicht `/service-worker.js`: `vite.config.ts` setzt
// `base: './'`, weil ein absoluter Pfad das Buendel an genau einen Origin
// baende und die Auslieferungstrennung nach §4.1 unbenutzbar machte. Der Name
// ist ungehasht, damit der Registrierungspfad ueber Baeue hinweg derselbe
// bleibt — ein gehashter waere ein Aktivierungspfad, den die Pinnung nicht
// sieht.
//
// `type: 'module'`, weil der Worker die wasm-bindgen-Glue importiert — sie ist
// ein ES-Modul, und nur so kann er die Aktivierung SELBST pruefen, statt eine
// fertige Entscheidung entgegenzunehmen.
//
// Die Registrierung ist bewusst folgenlos, wenn sie fehlschlaegt: der Reader
// ist ohne Service Worker benutzbar, und ein harter Abbruch hier naehme einem
// Leser den Zugriff wegen einer Cachefrage.
if ('serviceWorker' in navigator) {
  void navigator.serviceWorker.register('./service-worker.js', { type: 'module' }).catch(() => {
    // Ausdruecklich still: siehe oben.
  })
}
