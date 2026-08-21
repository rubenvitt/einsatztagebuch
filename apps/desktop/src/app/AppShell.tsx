import { App, ConfigProvider, Layout, Result, Space, Typography } from 'antd'
import deDE from 'antd/locale/de_DE'
import { useCallback, useEffect, useState } from 'react'
import type { ReactElement } from 'react'

import { StartupRecovery, startupRecovery } from './StartupRecovery'
import { TrustAgeStatus } from './TrustAgeStatus'
import { enabledRoutes } from './role-gate'
import type { EaRoute, VerifiedSession } from './role-gate'
import { verifiedSession, watchSessionLock } from './session-lock'
import type { FinalizationPreviewView, PendingFinalizationResumeView } from '../bridge/generated-contracts'
import { DecorativeIcon } from '../design/icons'
import { eaRuntimeTheme } from '../design/tokens'

/** Alles, was die Schale vom Wirt braucht — und nichts darueber hinaus. */
export type EaDesktopBridge = {
  readonly loadSession: () => Promise<VerifiedSession>
  readonly recover: () => Promise<PendingFinalizationResumeView>
  readonly watchLock: (onLocked: () => void) => Promise<() => void>
}

export const eaDesktopBridge: EaDesktopBridge = {
  loadSession: () => verifiedSession(),
  recover: () => startupRecovery(),
  watchLock: (onLocked) => watchSessionLock(onLocked),
}

function RouteSurface({ route }: { readonly route: EaRoute }): ReactElement {
  return (
    <section aria-label={route.path === '/' ? 'Übersicht' : 'Erfassung'}>
      <Space direction="vertical" size="middle">
        <Space size="small">
          <DecorativeIcon name={route.icon} />
          <Typography.Title level={2}>{route.label}</Typography.Title>
        </Space>
        <Typography.Paragraph>
          {route.path === '/'
            ? 'Dieses Gerät führt genau einen Writer und genau einen Entwurf. Der Verlauf und die abgeschlossenen Inhalte sind hier nicht einsehbar.'
            : 'Die Erfassungsmaske ist in dieser Ausbaustufe noch nicht freigeschaltet. Der Kettenzustand dieses Geräts ist geprüft.'}
        </Typography.Paragraph>
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
 * Die Flaeche OHNE gepruefte Sitzung.
 *
 * Kein Verweis, keine Route, kein Kommando — und ausdruecklicher Text statt
 * einer leeren Seite. Sie erscheint vor der ersten Antwort des Wirts und nach
 * jeder Sperre.
 */
function LockedNotice(): ReactElement {
  return (
    <ConfigProvider locale={deDE} theme={eaRuntimeTheme}>
      <App>
        <Result
          icon={<DecorativeIcon name="locked" size={48} />}
          title="Keine geprüfte Sitzung"
          subTitle={
            'Dieses Gerät hat keine gültige Bedienerbindung mit frischer Präsenz. Melden Sie sich ' +
            'über die Anmeldung des Betriebssystems erneut an; die Erfassung bleibt bis dahin ' +
            'geschlossen.'
          }
        />
      </App>
    </ConfigProvider>
  )
}

/**
 * Der Einstieg: geprueft Sitzung holen, Sperrpflicht einhaengen, Schale zeigen.
 *
 * Ein Fehlschlag beim Holen und JEDES Sperrereignis fuehren zur selben Flaeche,
 * und das ist die Zusage: nach der Sperre ist die Sitzung fort, nicht bloss ein
 * Verweis ausgegraut. Die Rueckkehr aus der Sperre ist damit eine
 * Wiederanmeldepflicht.
 */
export function EaDesktopApp({
  bridge = eaDesktopBridge,
}: {
  readonly bridge?: EaDesktopBridge
}): ReactElement {
  const [session, setSession] = useState<VerifiedSession | null>(null)
  const lock = useCallback(() => {
    setSession(null)
  }, [])

  useEffect(() => {
    let live = true
    bridge.loadSession().then(
      (loaded) => {
        if (live) {
          setSession(loaded)
        }
      },
      () => {
        if (live) {
          setSession(null)
        }
      },
    )
    return () => {
      live = false
    }
  }, [bridge])

  useEffect(() => {
    let stop: (() => void) | undefined
    let live = true
    bridge.watchLock(lock).then(
      (unlisten) => {
        if (live) {
          stop = unlisten
        } else {
          unlisten()
        }
      },
      () => undefined,
    )
    return () => {
      live = false
      stop?.()
    }
  }, [bridge, lock])

  if (session === null) {
    return <LockedNotice />
  }
  return <AppShell session={session} />
}
