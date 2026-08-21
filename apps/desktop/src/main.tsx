// Die Stilquelle ZUERST: `app.css` zieht `static-antd.css` in seine
// Kaskadenschicht, und `vite build` macht daraus ein gehashtes, lokales
// Beiwerk. Es gibt keinen Webfont und keine entfernte Stilquelle — unter
// `style-src 'self'` und `font-src 'self'` gaebe es fuer beide keinen Weg.
import './design/app.css'

import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import { EaDesktopApp } from './app/AppShell'

const container = document.getElementById('root')
if (container === null) {
  throw new Error('Der Wurzelknoten der Anwendung fehlt.')
}

createRoot(container).render(
  <StrictMode>
    <EaDesktopApp />
  </StrictMode>,
)
