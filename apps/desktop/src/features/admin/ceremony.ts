import {
  TRUST_CEREMONY_KIND_VALUES,
  TRUST_CEREMONY_STEP_VALUES,
} from '../../bridge/generated-contracts'
import type { TrustCeremonyKind, TrustCeremonyStep } from '../../bridge/generated-contracts'

/**
 * Die vier Arten einer Root-Zeremonie, AUS der emittierten Vereinigung.
 *
 * Die Zerlegung traegt die Deklarationsreihenfolge von
 * `ea_admin::ceremony_steps::TrustCeremonyKind` (`admin-ui-contract.md` §1) und
 * kein Literal dieser Datei: `no-hand-written-contracts.test.ts` verbietet jedes
 * Kontraktliteral in handgeschriebenem TSX.
 */
export const [DEVICE_APPROVE_KIND, DEVICE_REVOKE_KIND, POLICY_CHANGE_KIND, WRITER_TRANSITION_KIND] =
  TRUST_CEREMONY_KIND_VALUES

/** Die sechs Schritte, in der Reihenfolge, in der der Wirt sie fortschreibt. */
export const [
  PENDING_REQUEST_STEP,
  FINGERPRINT_CONFIRMED_STEP,
  ADMIN_AUTHORIZED_STEP,
  ROOT_REQUEST_EXPORTED_STEP,
  ROOT_REPLY_IMPORTED_STEP,
  REGISTRY_PUBLISHED_STEP,
] = TRUST_CEREMONY_STEP_VALUES

/**
 * Der WORTLAUT je Schritt — als erschoepfende Abbildung mit UNZITIERTEN
 * Schluesseln (Muster `TrustAgeStatus.tsx`).
 *
 * „Gerät aktiv" ist der EINZIGE Eintrag, der „aktiv" sagt: ein Geraet ist erst
 * aktiv, wenn das Root-signierte Registry-Ereignis veroeffentlicht ist
 * (`design.md`:1351-1355), und kein frueherer Schritt darf das behaupten.
 */
export const TRUST_CEREMONY_STEP_TEXT: Record<TrustCeremonyStep, string> = {
  PendingRequest: 'Anfrage ausstehend',
  FingerprintConfirmed: 'Fingerprint bestätigt',
  AdminAuthorized: 'Admin-Autorisierung erteilt',
  RootRequestExported: 'Root-Anfrage exportiert',
  RootReplyImported: 'Root-Antwort importiert',
  RegistryPublished: 'Gerät aktiv',
}

/** Der Name der Zeremonie ueber dem Stepper. */
export const TRUST_CEREMONY_KIND_TEXT: Record<TrustCeremonyKind, string> = {
  DeviceApprove: 'Gerätefreigabe',
  DeviceRevoke: 'Widerruf',
  PolicyChange: 'Richtlinienänderung',
  WriterTransition: 'Writer-Wechsel',
}

/**
 * Ob eine Art den Fingerprint-Schritt DURCHLAEUFT.
 *
 * Nur die Geraetefreigabe vergleicht einen Geraetefingerprint ueber den zweiten
 * Kanal; die drei anderen Arten ueberspringen genau diesen Schritt
 * (`ea_admin::ceremony_steps::next_step`). Als Abbildung und nicht als
 * Vergleich, damit eine fuenfte Art die Uebersetzung bricht statt still einen
 * Vorgabefall zu bekommen.
 */
const COMPARES_FINGERPRINT: Record<TrustCeremonyKind, boolean> = {
  DeviceApprove: true,
  DeviceRevoke: false,
  PolicyChange: false,
  WriterTransition: false,
}

/** Die Schritte, die eine Zeremonie dieser Art tatsaechlich hat, in Reihenfolge. */
export function visibleSteps(kind: TrustCeremonyKind): readonly TrustCeremonyStep[] {
  return COMPARES_FINGERPRINT[kind]
    ? TRUST_CEREMONY_STEP_VALUES
    : TRUST_CEREMONY_STEP_VALUES.filter((step) => step !== FINGERPRINT_CONFIRMED_STEP)
}

/**
 * Der Schritt, an dem die Admin-Autorisierung die naechste Handlung ist.
 *
 * Mit Fingerprint-Schritt ist das der bestaetigte Fingerprint, ohne ihn die
 * ausstehende Anfrage selbst.
 */
export function authorizationStep(kind: TrustCeremonyKind): TrustCeremonyStep {
  return COMPARES_FINGERPRINT[kind] ? FINGERPRINT_CONFIRMED_STEP : PENDING_REQUEST_STEP
}
