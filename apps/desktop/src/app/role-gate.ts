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
 * Die Rolle, die die Erfassung freischaltet.
 *
 * Die Typannotation ist der Pin: schriebe hier jemand eine Kennung, die keine
 * Kleinschreibung einer Kontraktrolle ist, uebersetzt die Datei nicht.
 */
export const WRITER_ROLE: SessionRole = 'writer'

/**
 * Die Rolle, die die Verwaltung freischaltet (Stufe 5, Task 6).
 *
 * Derselbe Pin wie beim Writer. Ein Organisationsadmin bekommt damit die
 * Root-Zeremonien, die Richtlinie und die Registry — und ausdruecklich KEINEN
 * Fachinhalt: die Admin-Rolle allein oeffnet nie einen Eintrag.
 */
export const ADMIN_ROLE: SessionRole = 'organizationadmin'

/**
 * Die Faehigkeit, die die Erfassung freischaltet.
 *
 * Sie steht NEBEN der Rolle und nicht in ihr: die Rolle sagt, wer das Geraet
 * bedient, die Faehigkeit, was das Zertifikat dieses Geraets zulaesst
 * (`DeviceCertificateFieldsV1::capabilities`).
 */
export const CAPTURE_CAPABILITY = 'capture'

/** Die Faehigkeit, die die Verwaltung freischaltet (`session.rs::capabilities_of`). */
export const ADMINISTRATION_CAPABILITY = 'administration'

/**
 * Welcher Rolle eine Faehigkeit GEHOERT.
 *
 * Die Tabelle ist die Rollengrenze: eine Faehigkeit schaltet ihre Flaeche nur
 * frei, wenn die gepruefte Sitzung die Rolle traegt, zu der die Faehigkeit
 * gehoert. Eine Writer-Sitzung mit einem Eintrag `administration` bekommt die
 * Verwaltung deshalb nicht, und eine Admin-Sitzung mit einem Eintrag `capture`
 * nicht die Erfassung — sonst genuegte ein Eintrag im Zertifikat, um die
 * Grenze zu verschieben.
 */
const CAPABILITY_ROLE: Record<string, SessionRole> = {
  [CAPTURE_CAPABILITY]: WRITER_ROLE,
  [ADMINISTRATION_CAPABILITY]: ADMIN_ROLE,
}

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
 * Drei Eintraege, und das ist die Aussage: die Erfassung (Stufe 2, Task 15) und
 * die Verwaltung (Stufe 5, Task 6), je an ihre Rolle gebunden. Der Reader ist
 * eine Browser-PWA (`2026-08-15-einsatzarchiv-web-reader-design.md`:51-56,
 * :466) — die Schale traegt fuer ihn keine Route, keine Ansicht und kein
 * Kommando. `AppShell` rendert AUS dieser Tabelle, also faellt der Zeuge in
 * `AppShell.test.tsx`, wenn hier eine vierte Flaeche einzieht.
 */
const EA_ROUTES: readonly EaRoute[] = [
  { path: '/', label: 'Übersicht', requiredCapability: null, icon: 'verified' },
  { path: '/einsatz', label: 'Einsatz erfassen', requiredCapability: CAPTURE_CAPABILITY, icon: 'capture' },
  {
    path: '/verwaltung',
    label: 'Verwaltung',
    requiredCapability: ADMINISTRATION_CAPABILITY,
    icon: 'administration',
  },
]

export function routeTable(): readonly EaRoute[] {
  return EA_ROUTES
}

/**
 * Ob `session` `route` betreten darf.
 *
 * BEIDE Bedingungen sind notwendig: die gepruefte Rolle, zu der die Faehigkeit
 * GEHOERT, UND die Faehigkeit im Geraetezertifikat. Eine Lesersitzung mit einem
 * Faehigkeitseintrag bekommt die Erfassung deshalb nicht, und eine Faehigkeit,
 * die in [`CAPABILITY_ROLE`] keiner Rolle gehoert, schaltet nichts frei.
 */
export function isRouteEnabled(session: VerifiedSession, route: EaRoute): boolean {
  if (route.requiredCapability === null) {
    return true
  }
  const owner = CAPABILITY_ROLE[route.requiredCapability]
  return (
    owner !== undefined &&
    session.role === owner &&
    session.capabilities.includes(route.requiredCapability)
  )
}

export function enabledRoutes(session: VerifiedSession): readonly EaRoute[] {
  return routeTable().filter((route) => isRouteEnabled(session, route))
}
