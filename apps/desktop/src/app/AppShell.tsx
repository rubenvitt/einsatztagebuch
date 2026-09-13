import { App, Button, ConfigProvider, Layout, Result, Space, Typography } from 'antd'
import deDE from 'antd/locale/de_DE'
import { useEffect, useRef, useState } from 'react'
import type { ReactElement } from 'react'

import { StartupRecovery, startupRecovery } from './StartupRecovery'
import { TrustAgeStatus } from './TrustAgeStatus'
import { enabledRoutes } from './role-gate'
import type { EaRoute, SessionRole, VerifiedSession } from './role-gate'
import { loginSession, verifiedSession, watchSessionLock } from './session-lock'
import type { SessionLockHandlers } from './session-lock'
import type { FinalizationPreviewView, PendingFinalizationResumeView } from '../bridge/generated-contracts'
import { AdminSurface } from '../features/admin/AdminPage'
import { DestructionSurface } from '../features/admin/DestructionSurface'
import { RecoverySurface } from '../features/admin/RecoverySurface'
import { WriterSurface } from '../features/writer/WriterPage'
import { DecorativeIcon } from '../design/icons'
import { eaRuntimeTheme } from '../design/tokens'

/** Alles, was die Schale vom Wirt braucht — und nichts darueber hinaus. */
export type EaDesktopBridge = {
  readonly loadSession: () => Promise<VerifiedSession>
  readonly login?: () => Promise<VerifiedSession>
  readonly recover: () => Promise<PendingFinalizationResumeView>
  readonly watchLock: (handlers: SessionLockHandlers) => Promise<() => void>
}

export const eaDesktopBridge: EaDesktopBridge = {
  loadSession: () => verifiedSession(),
  login: () => loginSession(),
  recover: () => startupRecovery(),
  watchLock: (handlers) => watchSessionLock(handlers),
}

/** Was die Schale ueber einer Route zeigt: die Landmarke und ihren Inhalt. */
type Surface = {
  readonly ariaLabel: string
  readonly body: ReactElement
}

/**
 * Die Tabelle Pfad → Flaeche, deckungsgleich mit `EA_ROUTES`.
 *
 * Eine Tabelle und keine Verzweigung: jede Route der Schale hat hier GENAU
 * einen Eintrag, und eine Route ohne Eintrag zeigt nichts — nicht die Flaeche
 * einer anderen Route. Die Erfassung und die Verwaltung bauen ihre Bruecke zum
 * Wirt selbst und zeigen erst danach etwas: ohne gelesenen Entwurf gaebe es
 * einen zweiten aktiven Entwurf, ohne gelesene Go-live-Liste eine Verwaltung
 * ohne Aussage.
 */
const ROUTE_SURFACES: Record<string, Surface> = {
  '/': {
    ariaLabel: 'Übersicht',
    body: (
      <Typography.Paragraph>
        Diese Schale zeigt ausschließlich die Flächen, die die geprüfte Sitzung freischaltet. Der
        Verlauf und die abgeschlossenen Inhalte sind hier nicht einsehbar.
      </Typography.Paragraph>
    ),
  },
  '/einsatz': { ariaLabel: 'Erfassung', body: <WriterSurface /> },
  '/verwaltung': { ariaLabel: 'Verwaltung', body: <Space direction="vertical" size="large" style={{ width: '100%' }}><AdminSurface /><RecoverySurface /><DestructionSurface /></Space> },
}

/**
 * Der Zusatz im Kopf der Schale je Rolle — erschoepfend ueber die
 * Sitzungsrollen, damit eine Admin-Sitzung nicht unter einem Writer-Titel
 * arbeitet. Eine Lesersitzung erreicht die Schale nicht mit einer Flaeche, ihr
 * Eintrag steht der Vollstaendigkeit halber.
 */
const ROLE_TITLE: Record<SessionRole, string> = {
  writer: 'Writer-Gerät',
  reader: 'Lesegerät',
  organizationadmin: 'Verwaltung',
}

function RouteSurface({ route }: { readonly route: EaRoute }): ReactElement | null {
  const surface = ROUTE_SURFACES[route.path]
  if (surface === undefined) {
    return null
  }
  return (
    <section aria-label={surface.ariaLabel}>
      <Space direction="vertical" size="middle" style={{ width: '100%' }}>
        <Space size="small">
          <DecorativeIcon name={route.icon} />
          <Typography.Title level={2}>{route.label}</Typography.Title>
        </Space>
        {surface.body}
      </Space>
    </section>
  )
}

/**
 * Die Schale — Navigation aus der Routentabelle, Writer-Inhalt hinter der
 * Wiederaufnahme.
 *
 * Der Verweis auf die Erfassung haengt an der geprueften Sitzung; der Inhalt
 * einer Writer-Route wartet auf WriterService::recover_pending. Admin-Sitzungen
 * haben keinen Writer-Startup-Port. Ihre drei Verwaltungsdienste pruefen jeweils
 * selbst ihre aktuelle native Zulassung und zeigen fehlende Dienste als Fehler.
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
  const surface = active === undefined ? null : <RouteSurface route={active} />

  return (
    <ConfigProvider locale={deDE} theme={eaRuntimeTheme}>
      <App>
        <Layout>
          <Layout.Header className="ea-shell-header">
            <Space direction="vertical" size="small">
              <Typography.Text strong>{`Einsatzarchiv — ${ROLE_TITLE[session.role]}`}</Typography.Text>
              <TrustAgeStatus preview={preview} />
            </Space>
          </Layout.Header>
          <Layout.Content className="ea-shell-content">
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
            {session.role === 'writer'
              ? <StartupRecovery recover={recover}>{surface}</StartupRecovery>
              : surface}
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

// „Fläche" und nicht „Erfassung": der Hinweis steht vor JEDER Rolle, und eine
// Admin-Sitzung hat keine Erfassung, die geschlossen bleiben koennte.
const CLOSURE_NOTICE: Record<ShellClosure, { readonly title: string; readonly subTitle: string }> = {
  'no-session': {
    title: 'Keine geprüfte Sitzung',
    subTitle:
      'Dieses Gerät hat keine gültige Bedienerbindung mit frischer Präsenz. Melden Sie sich ' +
      'über die Anmeldung des Betriebssystems erneut an; die Fläche bleibt bis dahin ' +
      'geschlossen.',
  },
  locked: {
    title: 'Keine geprüfte Sitzung',
    subTitle:
      'Eine Sperre des Betriebssystems hat die Sitzung entwertet, und der Wirt hat die ' +
      'Entwertung bestätigt. Melden Sie sich über die Anmeldung des Betriebssystems erneut an; ' +
      'die Fläche bleibt bis dahin geschlossen.',
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
      'aber nicht bestätigt. Die Fläche bleibt geschlossen. Beenden Sie die Anwendung und ' +
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
function LockedNotice({ closure, login, busy = false, failed = false }: {
  readonly closure: ShellClosure
  readonly login?: (() => void) | undefined
  readonly busy?: boolean
  readonly failed?: boolean
}): ReactElement {
  const notice = CLOSURE_NOTICE[closure]
  return (
    <ConfigProvider locale={deDE} theme={eaRuntimeTheme}>
      <App>
        <Result
          icon={<DecorativeIcon name="locked" size={48} />}
          title={notice.title}
          subTitle={notice.subTitle}
          extra={login === undefined ? undefined : <Space direction="vertical">
            <Button type="primary" loading={busy} onClick={login}>Mit Betriebssystem anmelden</Button>
            {failed && <Typography.Text role="alert">Die Anmeldung wurde nicht bestätigt. Prüfen Sie die Gerätefreigabe und versuchen Sie es erneut.</Typography.Text>}
          </Space>}
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
  const [watchReady, setWatchReady] = useState(false)
  const [loginBusy, setLoginBusy] = useState(false)
  const [loginFailed, setLoginFailed] = useState(false)
  const generation = useRef(0)

  useEffect(() => {
    generation.current += 1
    setWatchReady(false)
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
          generation.current += 1
          close('locked')
        },
        onUnconfirmed: () => {
          generation.current += 1
          setWatchReady(false)
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
          setWatchReady(true)
          bridge.loadSession().then(open, () => {
            close('no-session')
          })
        },
        () => {
          close('lock-watch-refused')
        },
      )

    return () => {
      generation.current += 1
      live = false
      stop?.()
    }
  }, [bridge])

  const login = async (): Promise<void> => {
    if (!watchReady || loginBusy || bridge.login === undefined) return
    const started = generation.current
    setLoginBusy(true)
    setLoginFailed(false)
    try {
      const session = await bridge.login()
      if (generation.current === started) setState({ kind: 'active', session })
    } catch {
      if (generation.current === started) setLoginFailed(true)
    } finally {
      setLoginBusy(false)
    }
  }

  if (state.kind !== 'active') {
    const closure = state.kind === 'starting' ? 'no-session' : state.closure
    const canLogin = watchReady && bridge.login !== undefined &&
      (closure === 'no-session' || closure === 'locked')
    return <LockedNotice closure={closure} login={canLogin ? () => { void login() } : undefined}
      busy={loginBusy} failed={loginFailed} />
  }
  return <AppShell session={state.session} />
}
