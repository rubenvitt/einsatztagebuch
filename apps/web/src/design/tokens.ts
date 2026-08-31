import type { ThemeConfig } from 'antd'

// Die SECHS Farbwerte von `design.md`:163-170. Sie sind die Quelle, und jeder
// Ant-Alias unten leitet sich aus ihnen ab; kein Alias wird je aus einem
// Literal gesetzt.
export const eaInk = '#172033'
export const eaSurface = '#F5F7FA'
export const eaAction = '#245EA8'
export const eaDanger = '#C6352B'
export const eaVerified = '#187255'
export const eaWarning = '#A65F00'

/**
 * Die EINE Eingabe von `ConfigProvider` und von `extract-static-css.tsx`.
 *
 * `colorInfo` und `colorLink` nehmen `eaAction`, weil `Alert`, `Tag` und
 * `Result` (`design.md`:151) sie aufloesen und der eingefrorene Farbvertrag
 * keinen siebten Wert hat; ein siebtes Hexliteral entsteht dadurch nicht.
 *
 * `fontFamily` steht ABSICHTLICH nicht darin: die Prosaschrift ist der native
 * UI-Sans-Serif-Stapel und stellt `design/app.css` unlayered ein. Der hier
 * erklaerte Monospace-Stapel gilt nur fuer Hashes, Fingerabdruecke und
 * technische Kennungen.
 */
export const eaTokens = {
  colorText: eaInk,
  colorBgLayout: eaSurface,
  colorPrimary: eaAction,
  colorError: eaDanger,
  colorSuccess: eaVerified,
  colorWarning: eaWarning,
  colorInfo: eaAction,
  colorLink: eaAction,
  fontFamilyCode: 'ui-monospace, SFMono-Regular, Consolas, monospace',
} as const

/**
 * Das Thema, mit dem die statische Datei ERZEUGT wird.
 *
 * Zwei Schalter tragen die Umgebungsunabhaengigkeit der erzeugten Bytes, und
 * beide sind gemessen und nicht gefolgert:
 *
 * - `hashed: false` — mit dem Vorgabewert `true` traegt jeder Selektor die
 *   Themenpruefsumme, und in einem Entwicklungsbau lautet sie
 *   `css-dev-only-do-not-override-…`. Die erzeugte Datei haette dann in
 *   `vitest` andere Bytes als im Produktionsbau, und die Driftschranke von
 *   `static-css.test.ts` waere nicht aufstellbar.
 * - `cssVar.key` — ohne festen Schluessel vergibt `antd` ihn ueber
 *   `React.useId()` (`config-provider/hooks/useTheme.js`), und die Variablen
 *   landen unter `.css-var-_R_0_`, also unter einem Wert, der von der Gestalt
 *   des Rendezweigs abhaengt. Zur Laufzeit stuende dort eine ANDERE Kennung,
 *   und keine einzige `var(--ant-…)`-Referenz loeste auf.
 *
 * `zeroRuntime` fehlt hier ABSICHTLICH: unter `zeroRuntime: true` kehrt
 * `@ant-design/cssinjs-utils` vor `useStyleRegister` zurueck, und die
 * Extraktion liefert dann keine einzige Komponentenregel.
 */
export const eaExtractionTheme = {
  hashed: false,
  cssVar: { key: 'ea-theme' },
  token: eaTokens,
} as const satisfies ThemeConfig

/**
 * Das Thema der laufenden Schale — dasselbe Thema plus `zeroRuntime`.
 *
 * `zeroRuntime: true` unterdrueckt die Komponentenregeln zur Laufzeit; sie
 * kommen aus `static-antd.css`. Was Ant Design 6 trotzdem einspritzt, sind die
 * CSS-Variablenbloecke, der `.anticon`-Block und die Keyframes; die CSP
 * blockiert sie, und `AppShell.test.tsx` belegt, dass die eingecheckte Datei
 * jeden dieser Texte schon enthaelt.
 */
export const eaRuntimeTheme = {
  ...eaExtractionTheme,
  zeroRuntime: true,
} as const satisfies ThemeConfig
