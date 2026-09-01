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
import { DecorativeIcon } from './design/icons'
import { eaRuntimeTheme } from './design/tokens'
import { EnrollmentPage } from './features/enrollment/EnrollmentPage'
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
  { path: '/', label: 'Reader' },
  { path: '/enrollment', label: 'Enrollment', render: () => <EnrollmentPage /> },
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
