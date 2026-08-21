import { OPERATOR_ROLE_V1_VALUES } from '../bridge/generated-contracts'
import type { OperatorRoleV1 } from '../bridge/generated-contracts'
import type { EaIconName } from '../design/icons'

/**
 * Die Rollenkennung, wie die GEPRUEFTE Sitzung sie ueber die Bruecke liefert.
 *
 * Sie ist die Kleinschreibung der geschlossenen Stufe-1-Aufzaehlung und kein
 * zweiter Namensraum: `Lowercase<…>` bindet sie an den emittierten Kontrakt, und
 * eine Rolle, die dort nicht steht, ist hier kein Typ.
 */
export type SessionRole = Lowercase<OperatorRoleV1>

/**
 * Die Wandlung an der EINEN Stelle, an der sie noetig ist: `toLowerCase` ist in
 * TypeScript als `string` typisiert, `Lowercase<T>` traegt die Literale.
 */
function slug(role: OperatorRoleV1): SessionRole {
  return role.toLowerCase() as SessionRole
}

/** Die drei zulaessigen Rollenkennungen, aus dem Kontrakt abgeleitet. */
export const SESSION_ROLES: readonly SessionRole[] = OPERATOR_ROLE_V1_VALUES.map(slug)

/**
 * Die EINZIGE Rolle, die im Desktop eine Flaeche freischaltet.
 *
 * Die Typannotation ist der Pin: schriebe hier jemand eine Kennung, die keine
 * Kleinschreibung einer Kontraktrolle ist, uebersetzt die Datei nicht.
 */
export const WRITER_ROLE: SessionRole = 'writer'

/**
 * Die Faehigkeit, die die Erfassung freischaltet.
 *
 * Sie steht NEBEN der Rolle und nicht in ihr: die Rolle sagt, wer das Geraet
 * bedient, die Faehigkeit, was das Zertifikat dieses Geraets zulaesst
 * (`DeviceCertificateFieldsV1::capabilities`).
 */
export const CAPTURE_CAPABILITY = 'capture'

/**
 * Die geprueften Angaben EINER Sitzung.
 *
 * Sie kommen ausschliesslich aus der Rust-Antwort. Es gibt in diesem Modul
 * keinen Zugriff auf eine lokale Ablage, eine Konfigurationsdatei oder eine
 * Umgebungsvariable — ein lokales Rollen-Upgrade ist deshalb nicht bloss
 * verboten, sondern nicht formulierbar.
 */
export type VerifiedSession = {
  readonly role: SessionRole
  readonly capabilities: readonly string[]
}

/** Eine Flaeche der Schale. */
export type EaRoute = {
  readonly path: string
  readonly label: string
  /** `null` heisst: die Flaeche haengt an keiner Faehigkeit. */
  readonly requiredCapability: string | null
  readonly icon: EaIconName
}

/**
 * Die VOLLSTAENDIGE Routentabelle der Schale.
 *
 * Zwei Eintraege, und das ist die Aussage: Task 15 schaltet ausschliesslich den
 * Writer frei. Der Reader ist eine Browser-PWA
 * (`2026-08-15-einsatzarchiv-web-reader-design.md`:51-56, :466) und die
 * Verwaltung ist Stufe 5 (`design.md`:2177) — die Schale traegt fuer beide
 * keine Route, keine Ansicht und kein Kommando. `AppShell` rendert AUS dieser
 * Tabelle, also faellt der Zeuge in `AppShell.test.tsx`, wenn hier eine dritte
 * Flaeche einzieht.
 */
const EA_ROUTES: readonly EaRoute[] = [
  { path: '/', label: 'Übersicht', requiredCapability: null, icon: 'verified' },
  { path: '/einsatz', label: 'Einsatz erfassen', requiredCapability: CAPTURE_CAPABILITY, icon: 'capture' },
]

export function routeTable(): readonly EaRoute[] {
  return EA_ROUTES
}

/**
 * Ob `session` `route` betreten darf.
 *
 * BEIDE Bedingungen sind notwendig: die geprueften Rolle UND die Faehigkeit des
 * Geraetezertifikats. Eine Lesersitzung mit einem Faehigkeitseintrag bekommt
 * die Erfassung deshalb nicht.
 */
export function isRouteEnabled(session: VerifiedSession, route: EaRoute): boolean {
  if (route.requiredCapability === null) {
    return true
  }
  return session.role === WRITER_ROLE && session.capabilities.includes(route.requiredCapability)
}

export function enabledRoutes(session: VerifiedSession): readonly EaRoute[] {
  return routeTable().filter((route) => isRouteEnabled(session, route))
}
