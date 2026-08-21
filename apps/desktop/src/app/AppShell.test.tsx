import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { act, render, screen, waitFor } from '@testing-library/react'
import { expect, it } from 'vitest'

import { AppShell, EaDesktopApp } from './AppShell'
import type { EaDesktopBridge } from './AppShell'
import { validateResume } from './StartupRecovery'
import { routeTable } from './role-gate'
import type { VerifiedSession } from './role-gate'
import {
  INVALIDATE_SESSION_COMMAND,
  SESSION_LOCK_EVENT,
  validateSession,
  watchSessionLock,
} from './session-lock'
import type { SessionBridge, SessionLockHandlers } from './session-lock'
import type {
  FinalizationPreviewView,
  PendingFinalizationResumeView,
} from '../bridge/generated-contracts'

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

/** Die EINGECHECKTEN Bytes der extrahierten Ant-Design-Regeln. */
function loadedStaticCss(): string {
  return readFileSync(path.join(sourceRoot, 'design/static-antd.css'), 'utf8')
}

/**
 * JEDE handgeschriebene Quelle unter `src` — keine Liste von Hand.
 *
 * Eine aufgezaehlte Liste haette genau die Dateien geprueft, an die ihr
 * Verfasser gedacht hat; `main.tsx` entscheidet aber, was `EaDesktopApp`
 * ueberhaupt erreicht, und jede Datei eines spaeteren Tasks liegt ausserhalb
 * einer solchen Aufzaehlung.
 */
function handWrittenSources(): [string, string][] {
  return readdirSync(sourceRoot, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => path.join(entry.parentPath, entry.name))
    .filter((file) => /\.tsx?$/.test(file))
    .filter((file) => !/\.test\.tsx?$/.test(file))
    .sort()
    .map((file) => [path.relative(sourceRoot, file), readFileSync(file, 'utf8')] as [string, string])
}

const writerSession: VerifiedSession = { role: 'writer', capabilities: ['capture'] }

const resumed: PendingFinalizationResumeView = {
  phase: 'ReversibleDraft',
  irreversible: false,
  outcomeCode: 'NothingPending',
  outcomeSequence: null,
}

/** Eine Bruecke, die nichts an das Betriebssystem gibt. */
function bridgeDouble(overrides: Partial<EaDesktopBridge> = {}): EaDesktopBridge {
  return {
    loadSession: () => Promise.resolve(writerSession),
    recover: () => Promise.resolve(resumed),
    watchLock: () => Promise.resolve(() => undefined),
    ...overrides,
  }
}

it('enables the Writer link only from the verified session, never from local configuration', async () => {
  const { rerender } = render(<AppShell session={{ role: 'reader', capabilities: [] }} />)
  expect(screen.queryByRole('link', { name: /einsatz erfassen/i })).not.toBeInTheDocument()
  localStorage.setItem('role', 'writer')
  rerender(<AppShell session={{ role: 'reader', capabilities: [] }} />)
  expect(screen.queryByRole('link', { name: /einsatz erfassen/i })).not.toBeInTheDocument()
  rerender(<AppShell session={{ role: 'writer', capabilities: ['capture'] }} />)
  expect(screen.getByRole('link', { name: /einsatz erfassen/i })).toBeVisible()
})

// ZWEI unabhaengige Bedingungen, und der Brieftest oben trennt sie nicht: seine
// Lesersitzung traegt AUCH keine Faehigkeit. Ohne diese beiden Zusicherungen
// bliebe eine Schale gruen, die nur die Faehigkeit prueft — und dann genuegte
// ein Faehigkeitseintrag in einer Lesersitzung.
it('requires the verified role AND the capability, not either one', () => {
  const { rerender } = render(<AppShell session={{ role: 'reader', capabilities: ['capture'] }} />)
  expect(screen.queryByRole('link', { name: /einsatz erfassen/i })).not.toBeInTheDocument()
  rerender(<AppShell session={{ role: 'writer', capabilities: [] }} />)
  expect(screen.queryByRole('link', { name: /einsatz erfassen/i })).not.toBeInTheDocument()
})

it('offers no Reader and no Administration surface at all', () => {
  render(<AppShell session={{ role: 'writer', capabilities: ['capture'] }} />)
  expect(screen.queryByRole('link', { name: /archiv (lesen|öffnen)/i })).not.toBeInTheDocument()
  expect(screen.queryByRole('link', { name: /verwaltung|administration/i })).not.toBeInTheDocument()
  expect(routeTable().map((route) => route.path)).toEqual(['/', '/einsatz'])
})

// Der Zeuge, der `routeTable()` von einer Konstante zu einer MESSUNG macht: die
// Schale rendert AUS dieser Tabelle. Ohne ihn vergleicht der Brieftest oben eine
// Konstante mit einer Konstante und bliebe gruen, auch wenn die Schale eine
// vierte, nicht aufgefuehrte Flaeche anbietet.
it('renders its navigation from the route table and from nowhere else', () => {
  render(<AppShell session={writerSession} />)
  const links = screen.getAllByRole('link')
  expect(links.map((link) => link.getAttribute('href'))).toEqual(
    routeTable().map((route) => route.path),
  )
  for (const route of routeTable()) {
    expect(screen.getByRole('link', { name: route.label })).toBeVisible()
  }
})

it('ships extracted styles and creates no runtime style tags', () => {
  render(<AppShell session={writerSession} />)
  expect(loadedStaticCss()).toContain('--ea-ink')
  // BRIEFGEPINNT und fuer sich allein wirkungslos: `@ant-design/cssinjs`
  // kennzeichnet seine Stilelemente mit `data-css-hash` (`StyleContext.js:7`),
  // also waehlt dieser Selektor nie etwas aus. Die Zusicherung darunter ist die,
  // die fallen kann.
  expect(document.querySelectorAll('style[data-ant-cssinjs]').length).toBe(0)
})

// DIE Zusicherung ueber das Verhaeltnis von Laufzeit und Datei, und sie ist
// gemessen: Ant Design 6 spritzt unter `zeroRuntime: true` weiterhin seine
// CSS-Variablenbloecke, den `.anticon`-Block und die Keyframes ein
// (`cssinjs/es/hooks/useCacheToken.js:120-134` laeuft NICHT hinter der
// zeroRuntime-Abkuerzung von `cssinjs-utils/es/util/genStyleUtils.js:123`).
// Unter `style-src-elem 'self'` blockiert die CSP jede dieser Einspritzungen —
// harmlos, WENN und nur wenn die eingecheckte Datei denselben Text schon
// enthaelt. Genau das prueft dieser Zeuge, und er faellt, sobald die Schale eine
// Komponente rendert, die nicht extrahiert wurde, oder die Themenkonfiguration
// zwischen Extraktion und Laufzeit auseinanderlaeuft.
it('carries every style the running shell injects in the checked-in file', () => {
  render(<AppShell session={writerSession} />)
  const injected = [...document.querySelectorAll('style')]
  expect(injected.length).toBeGreaterThan(0)
  const staticCss = loadedStaticCss()
  for (const tag of injected) {
    const text = tag.textContent ?? ''
    expect(text.length).toBeGreaterThan(0)
    expect(staticCss, `nicht extrahiert: ${text.slice(0, 80)}`).toContain(text)
  }
})

// Die Zusage „kein lokales Rollen-Upgrade" als QUELLENaussage. Der Brieftest
// oben setzt `localStorage` und rendert neu — er bliebe aber auch gruen, wenn
// die Schale den Schluessel nur bei der ERSTEN Montage lesen wuerde.
it('reads no local configuration source at all', () => {
  const forbidden =
    /localStorage|sessionStorage|indexedDB|document\.cookie|import\.meta\.env|process\.env/
  const sources = handWrittenSources()
  // Ohne diesen Zeugen laeuft die Schleife darunter ueber die leere Menge und
  // bleibt gruen — dieselbe Lehre wie in `no-hand-written-contracts.test.ts`.
  expect(sources.length).toBeGreaterThan(0)
  expect(sources.map(([file]) => file)).toContain('main.tsx')
  for (const [file, text] of sources) {
    expect(text, file).not.toMatch(forbidden)
  }
})

it('renders no Writer route until the startup recovery has returned', async () => {
  let release: ((view: PendingFinalizationResumeView) => void) | undefined
  const pending = new Promise<PendingFinalizationResumeView>((resolve) => {
    release = resolve
  })
  render(<AppShell session={writerSession} recover={() => pending} initialPath="/einsatz" />)
  // Der Verweis steht — die Sichtbarkeit des Verweises haengt an der Rolle, der
  // INHALT der Route an der Wiederaufnahme.
  expect(screen.getByRole('link', { name: /einsatz erfassen/i })).toBeVisible()
  expect(screen.queryByRole('region', { name: /erfassung/i })).not.toBeInTheDocument()
  expect(screen.getByText(/wiederaufnahme läuft/i)).toBeVisible()
  release?.(resumed)
  await waitFor(() => {
    expect(screen.getByRole('region', { name: /erfassung/i })).toBeVisible()
  })
})

it('keeps the Writer route closed when the startup recovery fails', async () => {
  render(
    <AppShell
      session={writerSession}
      recover={() => Promise.reject(new Error('port unavailable'))}
      initialPath="/einsatz"
    />,
  )
  await waitFor(() => {
    expect(screen.getByText(/wiederaufnahme nicht abgeschlossen/i)).toBeVisible()
  })
  expect(screen.queryByRole('region', { name: /erfassung/i })).not.toBeInTheDocument()
})

it('shows no surface at all without a verified session', async () => {
  render(<EaDesktopApp bridge={bridgeDouble({ loadSession: () => Promise.reject(new Error('none')) })} />)
  await waitFor(() => {
    expect(screen.getByText(/keine geprüfte sitzung/i)).toBeVisible()
  })
  expect(screen.queryAllByRole('link')).toHaveLength(0)
})

it('drops the whole surface when the native lock event arrives', async () => {
  let lock: SessionLockHandlers | undefined
  render(
    <EaDesktopApp
      bridge={bridgeDouble({
        watchLock: (handlers) => {
          lock = handlers
          return Promise.resolve(() => undefined)
        },
      })}
    />,
  )
  await waitFor(() => {
    expect(screen.getByRole('link', { name: /einsatz erfassen/i })).toBeVisible()
  })
  lock?.onLocked()
  await waitFor(() => {
    expect(screen.queryByRole('link', { name: /einsatz erfassen/i })).not.toBeInTheDocument()
  })
  expect(screen.getByText(/keine geprüfte sitzung/i)).toBeVisible()
})

// Die Sperre, deren Entwertung im Wirt NICHT bestaetigt ist, ist die
// gefaehrlichere Haelfte: die Oberflaeche schliesst zwar, aber `SessionState` im
// Wirt kann gueltig geblieben sein, und ein Neuladen der Webview bekaeme wieder
// eine Sitzung. Deshalb ist der Wortlaut ein anderer — Neustart und nicht bloss
// Anmeldung — und der Uebergang ist monoton: aus der bestaetigten Sperre wird
// die unbestaetigte, nie umgekehrt.
it('names the restart obligation when the host does not confirm the invalidation', async () => {
  let lock: SessionLockHandlers | undefined
  render(
    <EaDesktopApp
      bridge={bridgeDouble({
        watchLock: (handlers) => {
          lock = handlers
          return Promise.resolve(() => undefined)
        },
      })}
    />,
  )
  await waitFor(() => {
    expect(screen.getByRole('link', { name: /einsatz erfassen/i })).toBeVisible()
  })
  lock?.onLocked()
  lock?.onUnconfirmed()
  await waitFor(() => {
    expect(screen.getByText('Sperre nicht bestätigt')).toBeVisible()
  })
  expect(screen.getByText(/beenden sie die anwendung/i)).toBeVisible()
  expect(screen.queryAllByRole('link')).toHaveLength(0)
})

// Der Zeuge zu I-1: haengt die Sperrpflicht nicht an — und genau das tut sie
// ohne Faehigkeitserklaerung, weil `core:event:allow-listen` dann von der ACL
// verweigert wird —, dann darf ueberhaupt keine Sitzung geladen werden. Vorher
// wurde der Fehlschlag verschluckt und die Schale zeigte ihre Flaeche weiter.
it('loads no session at all when the lock duty cannot be attached', async () => {
  let loadCalls = 0
  render(
    <EaDesktopApp
      bridge={bridgeDouble({
        loadSession: () => {
          loadCalls += 1
          return Promise.resolve(writerSession)
        },
        watchLock: () => Promise.reject(new Error('acl refused core:event:allow-listen')),
      })}
    />,
  )
  await waitFor(() => {
    expect(screen.getByText('Sperrpflicht nicht eingehängt')).toBeVisible()
  })
  expect(loadCalls).toBe(0)
  expect(screen.queryAllByRole('link')).toHaveLength(0)
})

// Die Monotonie als MESSUNG: die Sitzungsantwort trifft NACH dem Sperrereignis
// ein. Ohne die Klammer um den Anfangszustand oeffnete sie die Flaeche wieder —
// eine Sperre, die ein spaeter eintreffendes Versprechen aufhebt.
it('does not reopen the surface when the session answer arrives after the lock', async () => {
  let lock: SessionLockHandlers | undefined
  let release: ((session: VerifiedSession) => void) | undefined
  let loadCalls = 0
  const pending = new Promise<VerifiedSession>((resolve) => {
    release = resolve
  })
  render(
    <EaDesktopApp
      bridge={bridgeDouble({
        loadSession: () => {
          loadCalls += 1
          return pending
        },
        watchLock: (handlers) => {
          lock = handlers
          return Promise.resolve(() => undefined)
        },
      })}
    />,
  )
  await waitFor(() => {
    expect(loadCalls).toBe(1)
  })
  lock?.onLocked()
  await waitFor(() => {
    expect(screen.getByText(/keine geprüfte sitzung/i)).toBeVisible()
  })
  // `act` und nicht ein blosser Mikrotask: ohne das Ausspuelen der Effekte waere
  // die Zusicherung darunter gruen, weil der Baum noch nicht neu gezeichnet ist —
  // sie wuerde dann nichts ueber die Monotonie sagen (gemessen: die Zusicherung
  // hielt auch OHNE die Klammer, bis dieses `act` hier stand).
  await act(async () => {
    release?.(writerSession)
  })
  expect(screen.queryByRole('link', { name: /einsatz erfassen/i })).not.toBeInTheDocument()
  expect(screen.getByText(/keine geprüfte sitzung/i)).toBeVisible()
})

/** Eine Bruecke ohne Wirt, die das Sperrereignis von Hand ausloest. */
function lockBridgeDouble(invocation: (command: string) => Promise<unknown>): {
  readonly bridge: SessionBridge
  readonly events: string[]
  readonly commands: string[]
  readonly fire: () => void
} {
  const events: string[] = []
  const commands: string[] = []
  let fire: (() => void) | undefined
  const bridge: SessionBridge = {
    invoke: (command) => {
      commands.push(command)
      return invocation(command)
    },
    listen: (event, handler) => {
      events.push(event)
      fire = handler
      return Promise.resolve(() => undefined)
    },
  }
  return {
    bridge,
    events,
    commands,
    fire: () => {
      if (fire === undefined) {
        throw new Error('das Sperrereignis wurde nie abonniert')
      }
      fire()
    },
  }
}

// Der Zeuge zu I-2 an der Naht selbst: das Abonnement traegt GENAU das Ereignis,
// das der Wirt meldet, die Meldung an die Oberflaeche kommt sofort, und die
// Verstaerkung im Wirt wird verlangt. Bestaetigt der Wirt, bleibt es bei der
// Sperre.
it('closes the surface at once and asks the host to invalidate', async () => {
  const locked: string[] = []
  const double = lockBridgeDouble(() => Promise.resolve(undefined))
  await watchSessionLock(
    {
      onLocked: () => locked.push('locked'),
      onUnconfirmed: () => locked.push('unconfirmed'),
    },
    double.bridge,
  )
  expect(double.events).toEqual([SESSION_LOCK_EVENT])
  double.fire()
  expect(locked).toEqual(['locked'])
  expect(double.commands).toEqual([INVALIDATE_SESSION_COMMAND])
  await Promise.resolve()
  await Promise.resolve()
  expect(locked).toEqual(['locked'])
})

// Und der Fehlschlag wird NICHT verschluckt: vorher stand hier
// `.catch(() => undefined)`, und eine fehlgeschlagene Entwertung war von einer
// gelungenen nicht zu unterscheiden.
it('escalates when the invalidation command fails', async () => {
  const locked: string[] = []
  const double = lockBridgeDouble(() => Promise.reject(new Error('blocking work lost')))
  await watchSessionLock(
    {
      onLocked: () => locked.push('locked'),
      onUnconfirmed: () => locked.push('unconfirmed'),
    },
    double.bridge,
  )
  double.fire()
  await waitFor(() => {
    expect(locked).toEqual(['locked', 'unconfirmed'])
  })
})

// Die zwei Validierer sind die Grenze, an der eine Wirtsantwort zu einem
// Ansichtsmodell wird. Ohne Zeugen waere „hands on a validated view model" eine
// Behauptung: ein Validierer, der alles durchlaesst, faellt in keinem der
// Zeugen darueber auf, weil dort nur wohlgeformte Doppel eingehen.
it('accepts only a session whose role stands in the contract', () => {
  expect(validateSession({ role: 'writer', capabilities: ['capture'] })).toEqual(writerSession)
  expect(validateSession({ role: 'reader', capabilities: [] }).capabilities).toEqual([])
  expect(() => validateSession(null)).toThrow()
  expect(() => validateSession({ capabilities: [] })).toThrow()
  // Die GROSSSCHREIBUNG des Kontraktliterals ist keine Sitzungskennung.
  expect(() => validateSession({ role: 'Writer', capabilities: [] })).toThrow()
  expect(() => validateSession({ role: 'root', capabilities: [] })).toThrow()
  expect(() => validateSession({ role: 'writer', capabilities: 'capture' })).toThrow()
  expect(() => validateSession({ role: 'writer', capabilities: [7] })).toThrow()
})

it('accepts only a resume view whose phase stands in the contract', () => {
  expect(validateResume(resumed)).toEqual(resumed)
  expect(() => validateResume(null)).toThrow()
  expect(() => validateResume({ ...resumed, phase: 'Erledigt' })).toThrow()
  // Die unwiderrufliche Grenze ist ein Wahrheitswert und keine Zeichenkette.
  expect(() => validateResume({ ...resumed, irreversible: 'true' })).toThrow()
  expect(() => validateResume({ ...resumed, outcomeSequence: '7' })).toThrow()
  expect(() => validateResume({ ...resumed, outcomeCode: 7 })).toThrow()
})

// Der Vertrauensalterstand nennt seinen Wortlaut AUSDRUECKLICH und verlaesst
// sich nicht auf Symbol oder Farbe: Alter und Policyfrist stehen als zwei
// getrennte Zahlen da, und die Ueberschreitung ist eine Warnung mit Text.
it('states trust age, policy deadline, and the stale decision in words', () => {
  const preview: FinalizationPreviewView = {
    proposedSequence: 3,
    bindsPredecessor: true,
    effectiveNow: 1_760_000_000_000,
    trustAgeMs: 50 * 60 * 60 * 1000,
    readerTrustRefreshMs: 24 * 60 * 60 * 1000,
    trustRefreshOverdue: true,
    staleDecision: 'StaleAcknowledgeable',
  }
  render(<AppShell session={writerSession} preview={preview} />)
  expect(screen.getByText(/Alter des gebundenen Vertrauensbestands: 2 d 2 h/)).toBeVisible()
  expect(screen.getByText(/Auffrischungsfrist der Policy: 1 d 0 h/)).toBeVisible()
  expect(screen.getByText(/ausdrückliche Bestätigung/)).toBeVisible()
  expect(screen.getByText('Auffrischungsfrist überschritten')).toBeVisible()
})

it('says so in words when no preview has been taken yet', () => {
  render(<AppShell session={writerSession} />)
  expect(screen.getByText(/Vertrauensbestand: noch nicht geprüft/)).toBeVisible()
})
