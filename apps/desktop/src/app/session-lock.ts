import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'

import { SESSION_ROLES } from './role-gate'
import type { SessionRole, VerifiedSession } from './role-gate'

/** Das Kommando, das die geprueften Sitzungsangaben liefert. */
export const VERIFIED_SESSION_COMMAND = 'verified_session'

/** Das Kommando, das den `OperatorSessionProof` entwertet. */
export const INVALIDATE_SESSION_COMMAND = 'invalidate_session_on_lock'

/**
 * Das Ereignis, mit dem der Wirt eine Sperre oder einen Sitzungswechsel des
 * Betriebssystems meldet.
 *
 * Windows-Sitzungswechsel, macOS-Screen-Lock-Notification,
 * Ubuntu-Sitzungsmanager — die drei Plattformzweige liegen im Wirt und
 * muenden in dieses EINE Ereignis.
 */
export const SESSION_LOCK_EVENT = 'ea://session-lock'

/**
 * Der Ausschnitt der Tauri-Bruecke, den dieses Modul braucht.
 *
 * Als Parameter und nicht als Import, damit die Entscheidung „sperren heisst
 * entwerten" ohne Wirt messbar ist.
 */
export type SessionBridge = {
  readonly invoke: (command: string) => Promise<unknown>
  readonly listen: (event: string, handler: () => void) => Promise<() => void>
}

export const tauriSessionBridge: SessionBridge = {
  invoke: (command) => invoke(command),
  listen: (event, handler) =>
    listen(event, () => {
      handler()
    }),
}

function isSessionRole(value: unknown): value is SessionRole {
  return typeof value === 'string' && SESSION_ROLES.includes(value as SessionRole)
}

/**
 * Prueft die Antwort des Wirts, statt ihr zu glauben.
 *
 * Fail-closed: eine Rollenkennung, die nicht im Kontrakt steht, und eine
 * Faehigkeitsliste, die keine Liste von Zeichenketten ist, sind KEINE Sitzung.
 * Ohne diese Pruefung waere jeder spaetere Rollenvergleich eine Behauptung
 * ueber einen ungeprueften Wert.
 */
export function validateSession(raw: unknown): VerifiedSession {
  if (typeof raw !== 'object' || raw === null) {
    throw new Error('Die Sitzungsantwort ist kein Objekt.')
  }
  const candidate = raw as { role?: unknown; capabilities?: unknown }
  if (!isSessionRole(candidate.role)) {
    throw new Error('Die Sitzungsantwort nennt keine Rolle des Kontrakts.')
  }
  if (
    !Array.isArray(candidate.capabilities) ||
    candidate.capabilities.some((capability) => typeof capability !== 'string')
  ) {
    throw new Error('Die Sitzungsantwort nennt keine Liste von Faehigkeiten.')
  }
  return { role: candidate.role, capabilities: [...(candidate.capabilities as string[])] }
}

/** Holt die geprueften Sitzungsangaben und validiert sie. */
export async function verifiedSession(
  bridge: SessionBridge = tauriSessionBridge,
): Promise<VerifiedSession> {
  return validateSession(await bridge.invoke(VERIFIED_SESSION_COMMAND))
}

/**
 * Die zwei Nachrichten, die eine Sperre auslöst.
 *
 * `onLocked` ist die unbedingte: die Fläche schließt, sobald das Ereignis
 * ankommt. `onUnconfirmed` ist die ESKALATION und kommt nur, wenn der Wirt die
 * Entwertung nicht bestätigt hat — die Schwere steigt damit immer nur, nie
 * sinkt sie.
 */
export type SessionLockHandlers = {
  readonly onLocked: () => void
  readonly onUnconfirmed: () => void
}

/**
 * Haengt die Sperrpflicht ein.
 *
 * Die Reihenfolge ist die Zusage: ZUERST entwertet der Wirt den
 * `OperatorSessionProof` (`ea_desktop::honor_session_lock` entwertet VOR dem
 * `emit`, und `OperatorSessionProof::invalidate_on_lock` nimmt `self`, also
 * bleibt kein gueltiger Stand daneben liegen), DANN erfaehrt die Oberflaeche
 * davon. Das Kommando hier ist deshalb die VERSTAERKUNG und nicht die einzige
 * Wirkung. Das Fuenfminutenfenster der Untaetigkeit liegt im Nachweis selbst
 * (`ea-operator`: `MAX_INACTIVITY_MS`) und wird hier nicht nachgebaut; die
 * Sperre kommt zusaetzlich und sofort.
 *
 * Der Fehlschlag des Kommandos wird NICHT verschluckt. Er ist die Aussage
 * „der Wirt hat die Entwertung nicht bestaetigt", und die ist strenger als die
 * Sperre selbst: wer sie ignoriert, laesst eine Oberflaeche zu, die nach einem
 * Neuladen der Webview wieder eine gueltige Sitzung bekommen koennte.
 */
export async function watchSessionLock(
  handlers: SessionLockHandlers,
  bridge: SessionBridge = tauriSessionBridge,
): Promise<() => void> {
  return bridge.listen(SESSION_LOCK_EVENT, () => {
    handlers.onLocked()
    void bridge.invoke(INVALIDATE_SESSION_COMMAND).catch(() => {
      handlers.onUnconfirmed()
    })
  })
}
