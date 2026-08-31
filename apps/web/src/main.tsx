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

import { DecorativeIcon } from './design/icons'
import { eaRuntimeTheme } from './design/tokens'

/** Ein Eintrag der Routentabelle: der Pfad und sein Wortlaut im Verweis. */
export type EaWebRoute = {
  readonly path: string
  readonly label: string
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
export const EA_WEB_ROUTES: readonly EaWebRoute[] = [{ path: '/', label: 'Reader' }]

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
}: {
  readonly routes?: readonly EaWebRoute[]
  readonly initialPath?: string
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
                <DecorativeIcon name="locked" />
                <Typography.Title level={2}>{active.label}</Typography.Title>
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

createRoot(container).render(
  <StrictMode>
    <EaWebApp />
  </StrictMode>,
)
