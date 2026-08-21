import { extractStyle } from '@ant-design/static-style-extract'
import { App, ConfigProvider } from 'antd'
import deDE from 'antd/locale/de_DE'

import { eaAction, eaDanger, eaExtractionTheme, eaInk, eaSurface, eaVerified, eaWarning } from './tokens'

/**
 * Der Merkmalsblock, den `static-antd.css` VOR der Ant-Ausgabe traegt.
 *
 * Er entsteht aus denselben sechs Konstanten und traegt kein eigenes Literal.
 */
export const EA_CUSTOM_PROPERTY_BLOCK =
  `:root{--ea-ink:${eaInk};--ea-surface:${eaSurface};--ea-action:${eaAction};` +
  `--ea-danger:${eaDanger};--ea-verified:${eaVerified};--ea-warning:${eaWarning}}`

/**
 * Der UMFANG der Extraktion.
 *
 * `Modal`, `message` und `notification` stehen zusaetzlich zu den Komponenten
 * der Schale darin, weil sie erst in Task 16 gerendert werden und eine
 * unformatierte, nicht uebergehbare Bestaetigung genau dort die falsche
 * Ueberraschung waere.
 *
 * `ConfigProvider` gehoert NICHT hierher: `@ant-design/static-style-extract`
 * fuehrt ihn samt `Grid` auf seiner eigenen Sperrliste
 * (`es/index.js`: `defaultBlackList`) und liesse ihn stillschweigend fallen.
 *
 * Der Zeuge gegen das Veralten dieser Liste steht in `static-css.test.ts`: jede
 * Ant-Komponente, die eine handgeschriebene Quelle importiert, muss hier
 * stehen.
 */
export const EXTRACTED_COMPONENTS: readonly string[] = [
  'Alert',
  'App',
  'Button',
  'Checkbox',
  'Descriptions',
  'Input',
  'Layout',
  'Modal',
  'Radio',
  'Result',
  'Space',
  'Spin',
  'Tag',
  'Tooltip',
  'Typography',
  'message',
  'notification',
]

/**
 * Die Bytes von `static-antd.css`.
 *
 * Die ausdrueckliche Komponentenform: `customTheme` legt genau die
 * `ConfigProvider`-Konfiguration der laufenden Schale um den Knoten, den
 * `includes` aufspannt. Die argumentfreie Form haette den GANZEN Katalog
 * genommen (1,39 MB gegen 207 kB gemessen) und den Umfang der Entscheidung
 * entzogen.
 *
 * Die Datei selbst wird von der Driftschranke in `static-css.test.ts`
 * geschrieben und bewacht. Neu erzeugt wird sie mit
 *
 *     pnpm --dir apps/desktop test --run -u
 */
export function extractStaticCss(): string {
  const antd = extractStyle({
    customTheme: (node) => (
      <ConfigProvider locale={deDE} theme={eaExtractionTheme}>
        <App>{node}</App>
      </ConfigProvider>
    ),
    includes: [...EXTRACTED_COMPONENTS],
  })
  return `${EA_CUSTOM_PROPERTY_BLOCK}${antd}`
}
