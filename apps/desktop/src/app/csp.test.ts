import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, it } from 'vitest'

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')

// Die Zielrichtlinie, Position fuer Position. Sie steht hier als LITERAL und
// nicht abgeleitet: dieser Test IST der Pin, und eine abgeleitete Erwartung
// koennte mit der Richtlinie gemeinsam wandern.
const EXPECTED_DIRECTIVES = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "style-src-elem 'self'",
  "style-src-attr 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self' ipc: http://ipc.localhost",
  "frame-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
]

type TauriConfig = {
  readonly build?: { readonly frontendDist?: unknown; readonly devUrl?: unknown }
  readonly app?: { readonly security?: { readonly csp?: unknown } }
}

function tauriConfig(): TauriConfig {
  return JSON.parse(readFileSync(path.join(packageRoot, 'src-tauri/tauri.conf.json'), 'utf8')) as TauriConfig
}

function directives(): string[] {
  const csp = tauriConfig().app?.security?.csp
  expect(typeof csp).toBe('string')
  return String(csp)
    .split(';')
    .map((directive) => directive.trim())
    .filter((directive) => directive.length > 0)
}

it('pins the content security policy directive list position by position', () => {
  expect(directives()).toEqual(EXPECTED_DIRECTIVES)
})

// Die drei Stilrichtlinien einzeln, weil sie die TRAGENDE Entscheidung dieses
// Tasks sind: `style-src` und `style-src-elem` auf `'self'` verbieten jede
// eingespritzte und jede entfernte Stilregel, waehrend `style-src-attr` auf
// `'unsafe-inline'` bleibt, weil React und Ant Design Elementattribute setzen —
// ein Stilattribut laedt nichts und spritzt kein Regelwerk ein.
it('forbids injected and remote style sheets while allowing the style attribute', () => {
  const list = directives()
  expect(list).toContain("style-src 'self'")
  expect(list).toContain("style-src-elem 'self'")
  expect(list).toContain("style-src-attr 'unsafe-inline'")
  const styleRules = list.filter((directive) => /^style-src(-elem)? /.test(directive))
  expect(styleRules).toHaveLength(2)
  for (const rule of styleRules) {
    expect(rule).not.toContain('unsafe-inline')
    expect(rule).not.toContain('http')
  }
})

it('allows no script evaluation and no inline script', () => {
  const script = directives().find((directive) => directive.startsWith('script-src '))
  expect(script).toBe("script-src 'self'")
  expect(directives().join('; ')).not.toContain('unsafe-eval')
})

// Der Kanal, ohne den kein `#[tauri::command]` erreichbar waere. Steht er nicht
// drin, ist die Schale unter der eigenen Richtlinie stumm.
it('keeps the Tauri command channel reachable and nothing else', () => {
  const connect = directives().find((directive) => directive.startsWith('connect-src '))
  expect(connect).toBe("connect-src 'self' ipc: http://ipc.localhost")
})

it('serves the frontend from the local bundle and from no development server', () => {
  const config = tauriConfig()
  expect(config.build?.devUrl).toBeUndefined()
  expect(typeof config.build?.frontendDist).toBe('string')
  expect(String(config.build?.frontendDist)).not.toMatch(/^https?:/)
})

type Capability = {
  readonly windows?: unknown
  readonly permissions?: unknown
  readonly local?: unknown
  readonly remote?: unknown
}

function capability(): Capability {
  return JSON.parse(
    readFileSync(path.join(packageRoot, 'src-tauri/capabilities/default.json'), 'utf8'),
  ) as Capability
}

function strings(value: unknown, field: string): string[] {
  expect(Array.isArray(value), field).toBe(true)
  const list = value as unknown[]
  expect(list.length, field).toBeGreaterThan(0)
  for (const entry of list) {
    expect(typeof entry, field).toBe('string')
  }
  return list as string[]
}

// Die ACL, ohne die die Sperrpflicht nicht haengt. Fehlt die Erklaerung, ist
// `src-tauri/gen/schemas/capabilities.json` genau `{}` — eine LEERE ACL —, und
// `listen()` aus `@tauri-apps/api/event` ist das Kernplugin-Kommando
// `core:event:allow-listen` und damit verweigert. Die Kommandos aus
// `generate_handler!` umgehen die ACL, das Ereignisplugin nicht.
it('grants the main window the event permission the lock duty needs', () => {
  const permissions = strings(capability().permissions, 'permissions')
  const grantsListen = permissions.some((permission) =>
    ['core:default', 'core:event:default', 'core:event:allow-listen'].includes(permission),
  )
  expect(permissions.join(' ')).toBeTruthy()
  expect(grantsListen, `keine Erlaubnis fuer core:event:allow-listen: ${permissions.join(', ')}`).toBe(true)
})

// Die Erklaerung deckt das Fenster, das die Konfiguration erklaert — Quelle
// gegen Quelle. Deckte sie ein anderes, waere die ACL des erzeugten Fensters
// leer, ohne dass irgendetwas rot wird.
it('covers exactly the window the configuration declares', () => {
  const config = tauriConfig() as TauriConfig & {
    readonly app?: { readonly windows?: readonly { readonly label?: unknown }[] }
  }
  const declared = config.app?.windows
  expect(Array.isArray(declared)).toBe(true)
  const labels = (declared ?? []).map((window) => window.label)
  expect(labels.length).toBeGreaterThan(0)
  const covered = strings(capability().windows, 'windows')
  for (const label of labels) {
    // AUSGESCHRIEBEN und nicht der Vorgabewert von Tauri: dieser Vergleich soll
    // nichts raten.
    expect(typeof label).toBe('string')
    expect(covered).toContain(label)
  }
})

// Rein lokal: eine Faehigkeitserklaerung mit `remote` liesse ein entferntes
// Fenster dieselben Kommandos rufen.
it('declares no remote origin', () => {
  expect(capability().remote).toBeUndefined()
  expect(capability().local).not.toBe(false)
})
