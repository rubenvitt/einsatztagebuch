import { App, ConfigProvider, Layout, Result, Space, Typography } from 'antd'
import deDE from 'antd/locale/de_DE'
import { useEffect, useState } from 'react'
import type { ReactElement } from 'react'

import { StartupRecovery, startupRecovery } from './StartupRecovery'
import { TrustAgeStatus } from './TrustAgeStatus'
import { enabledRoutes } from './role-gate'
import type { EaRoute, VerifiedSession } from './role-gate'
import { verifiedSession, watchSessionLock } from './session-lock'
import type { SessionLockHandlers } from './session-lock'
import type { FinalizationPreviewView, PendingFinalizationResumeView } from '../bridge/generated-contracts'
import { WriterSurface } from '../features/writer/WriterPage'
import { DecorativeIcon } from '../design/icons'
import { eaRuntimeTheme } from '../design/tokens'

/** Alles, was die Schale vom Wirt braucht — und nichts darueber hinaus. */
export type EaDesktopBridge = {
  readonly loadSession: () => Promise<VerifiedSession>
  readonly recover: () => Promise<PendingFinalizationResumeView>
  readonly watchLock: (handlers: SessionLockHandlers) => Promise<() => void>
}

export const eaDesktopBridge: EaDesktopBridge = {
  loadSession: () => verifiedSession(),
  recover: () => startupRecovery(),
  watchLock: (handlers) => watchSessionLock(handlers),
}

function RouteSurface({ route }: { readonly route: EaRoute }): ReactElement {
  return (
    <section aria-label={route.path === '/' ? 'Übersicht' : 'Erfassung'}>
      <Space direction="vertical" size="middle">
        <Space size="small">
          <DecorativeIcon name={route.icon} />
          <Typography.Title level={2}>{route.label}</Typography.Title>
        </Space>
        {route.path === '/' ? (
          <Typography.Paragraph>
            Dieses Gerät führt genau einen Writer und genau einen Entwurf. Der Verlauf und die
            abgeschlossenen Inhalte sind hier nicht einsehbar.
          </Typography.Paragraph>
        ) : (
          // Die Erfassung selbst. Sie baut ihre Bruecke zum Wirt und zeigt
          // erst danach ein Formular: ohne gelesenen Entwurf gaebe es einen
          // zweiten aktiven Entwurf, und es gibt genau einen.
          <WriterSurface />
        )}
      </Space>
    </section>
  )
}

/**
 * Die Schale — Navigation aus der Routentabelle, Inhalt hinter der
 * Wiederaufnahme.
 *
 * Die Trennung ist die Entscheidung dieses Tasks: der VERWEIS auf die Erfassung
 * haengt allein an der geprueften Sitzung und erscheint deshalb sofort, der
 * INHALT jeder Route erst, wenn `WriterService::recover_pending` zurueckgekehrt
 * ist. Eine Schale, die auch ihre Navigation erst nach einem Wirtsaufruf
 * zeigt, waere ohne Wirt stumm; eine Erfassungsflaeche vor der Wiederaufnahme
 * duerfte es nicht geben.
 */
export function AppShell({
  session,
  preview = null,
  recover = eaDesktopBridge.recover,
  initialPath = '/',
}: {
  readonly session: VerifiedSession
  readonly preview?: FinalizationPreviewView | null
  readonly recover?: () => Promise<PendingFinalizationResumeView>
  readonly initialPath?: string
}): ReactElement {
  const [path, setPath] = useState(initialPath)
  const routes = enabledRoutes(session)
  const active = routes.find((route) => route.path === path) ?? routes[0]

  return (
    <ConfigProvider locale={deDE} theme={eaRuntimeTheme}>
      <App>
        <Layout>
          <Layout.Header>
            <Space direction="vertical" size="small">
              <Typography.Text strong>Einsatzarchiv — Writer</Typography.Text>
              <TrustAgeStatus preview={preview} />
            </Space>
          </Layout.Header>
          <Layout.Content>
            <nav aria-label="Hauptbereiche">
              <Space size="middle">
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
              </Space>
            </nav>
            <StartupRecovery recover={recover}>
              {active === undefined ? null : <RouteSurface route={active} />}
            </StartupRecovery>
          </Layout.Content>
        </Layout>
      </App>
    </ConfigProvider>
  )
}

/**
 * Der Grund, aus dem die Schale KEINE Flaeche zeigt.
 *
 * Vier Gruende und nicht einer: „der Wirt nennt keine Sitzung" ist eine andere
 * Aussage als „eine Sperre ist eingetreten, und der Wirt hat die Entwertung
 * nicht bestaetigt". Der zweite Fall verlangt einen Neustart, der erste bloss
 * eine Anmeldung — und beide stehen im Wortlaut da, nicht in einer Farbe.
 */
export type ShellClosure = 'no-session' | 'locked' | 'lock-watch-refused' | 'lock-unconfirmed'

/**
 * Die Schwere der vier Gruende.
 *
 * Sie steigt und sinkt nie: eine Sitzungsantwort, die NACH dem Sperrereignis
 * eintrifft, darf die Aussage nicht abmildern, und eine bestaetigte Sperre darf
 * eine unbestaetigte nicht ueberschreiben.
 */
const CLOSURE_SEVERITY: Record<ShellClosure, number> = {
  'no-session': 0,
  locked: 1,
  'lock-watch-refused': 2,
  'lock-unconfirmed': 3,
}

const CLOSURE_NOTICE: Record<ShellClosure, { readonly title: string; readonly subTitle: string }> = {
  'no-session': {
    title: 'Keine geprüfte Sitzung',
    subTitle:
      'Dieses Gerät hat keine gültige Bedienerbindung mit frischer Präsenz. Melden Sie sich ' +
      'über die Anmeldung des Betriebssystems erneut an; die Erfassung bleibt bis dahin ' +
      'geschlossen.',
  },
  locked: {
    title: 'Keine geprüfte Sitzung',
    subTitle:
      'Eine Sperre des Betriebssystems hat die Sitzung entwertet, und der Wirt hat die ' +
      'Entwertung bestätigt. Melden Sie sich über die Anmeldung des Betriebssystems erneut an; ' +
      'die Erfassung bleibt bis dahin geschlossen.',
  },
  'lock-watch-refused': {
    title: 'Sperrpflicht nicht eingehängt',
    subTitle:
      'Das Sperr- und Sitzungsereignis des Betriebssystems konnte nicht abonniert werden. Ohne ' +
      'dieses Abonnement überlebte eine Sitzung die Sperre des Bildschirms, deshalb wird keine ' +
      'Sitzung geladen und keine Fläche geöffnet. Starten Sie die Anwendung neu.',
  },
  'lock-unconfirmed': {
    title: 'Sperre nicht bestätigt',
    subTitle:
      'Eine Sperre des Betriebssystems ist eingetreten, der Wirt hat die Entwertung der Sitzung ' +
      'aber nicht bestätigt. Die Erfassung bleibt geschlossen. Beenden Sie die Anwendung und ' +
      'starten Sie sie neu, bevor Sie weiterarbeiten.',
  },
}

/**
 * Die Flaeche OHNE gepruefte Sitzung.
 *
 * Kein Verweis, keine Route, kein Kommando — und ausdruecklicher Text statt
 * einer leeren Seite. Sie erscheint vor der ersten Antwort des Wirts, nach jeder
 * Sperre und immer dann, wenn die Sperrpflicht selbst nicht haengt.
 */
function LockedNotice({ closure }: { readonly closure: ShellClosure }): ReactElement {
  const notice = CLOSURE_NOTICE[closure]
  return (
    <ConfigProvider locale={deDE} theme={eaRuntimeTheme}>
      <App>
        <Result
          icon={<DecorativeIcon name="locked" size={48} />}
          title={notice.title}
          subTitle={notice.subTitle}
        />
      </App>
    </ConfigProvider>
  )
}

type ShellState =
  | { readonly kind: 'starting' }
  | { readonly kind: 'active'; readonly session: VerifiedSession }
  | { readonly kind: 'closed'; readonly closure: ShellClosure }

/**
 * Der Einstieg: Sperrpflicht einhaengen, DANN gepruefte Sitzung holen, dann
 * Schale zeigen.
 *
 * Die Reihenfolge ist die Zusage, und sie ist die Antwort auf zwei Loecher: ohne
 * eingehaengtes Sperrereignis darf keine Sitzung geladen werden (sonst
 * ueberlebte sie die Sperre des Bildschirms), und ohne bestaetigte Entwertung im
 * Wirt ist die Sperre keine erledigte Sache, sondern eine Neustartpflicht. Ein
 * Fehlschlag beim Holen, JEDES Sperrereignis und ein Abonnement, das nicht
 * haengt, fuehren zu KEINER Flaeche — jeder mit seinem eigenen Wortlaut.
 *
 * Die Uebergaenge sind monoton: die Schwere steigt und sinkt nie, und eine
 * Flaeche geht nur aus dem Anfangszustand auf.
 */
export function EaDesktopApp({
  bridge = eaDesktopBridge,
}: {
  readonly bridge?: EaDesktopBridge
}): ReactElement {
  const [state, setState] = useState<ShellState>({ kind: 'starting' })

  useEffect(() => {
    let live = true
    let stop: (() => void) | undefined
    const open = (session: VerifiedSession): void => {
      if (!live) {
        return
      }
      setState((current) => (current.kind === 'starting' ? { kind: 'active', session } : current))
    }
    const close = (closure: ShellClosure): void => {
      if (!live) {
        return
      }
      setState((current) =>
        current.kind === 'closed' && CLOSURE_SEVERITY[current.closure] >= CLOSURE_SEVERITY[closure]
          ? current
          : { kind: 'closed', closure },
      )
    }

    bridge
      .watchLock({
        onLocked: () => {
          close('locked')
        },
        onUnconfirmed: () => {
          close('lock-unconfirmed')
        },
      })
      .then(
        (unlisten) => {
          if (!live) {
            unlisten()
            return
          }
          stop = unlisten
          bridge.loadSession().then(open, () => {
            close('no-session')
          })
        },
        () => {
          close('lock-watch-refused')
        },
      )

    return () => {
      live = false
      stop?.()
    }
  }, [bridge])

  if (state.kind !== 'active') {
    return <LockedNotice closure={state.kind === 'starting' ? 'no-session' : state.closure} />
  }
  return <AppShell session={state.session} />
}
