import {
  FINGERPRINT_SUBJECT_V1_VALUES,
  TRUST_CEREMONY_ROUND_V1_VALUES,
  CLOCK_RELEASE_AVAILABILITY_VALUES,
  CLOCK_RELEASE_JUSTIFICATION_V1_VALUES,
  GO_LIVE_REQUIREMENT_STATUS_VALUES,
  REVOCATION_TARGET_CLASS_VALUES,
  STALE_DECISION_VALUES,
  TRUST_CEREMONY_KIND_VALUES,
  TRUST_CEREMONY_STEP_VALUES,
  WRITER_TRANSITION_PHASE_VALUES,
} from '../../bridge/generated-contracts'
import { ACTIVATE_REGISTRY_ROUND, ISSUE_TARGET_ROUND, REGISTRY_PUBLISHED_STEP, TARGET_PUBLISHED_STEP } from './ceremony'
import type {
  ClockReleaseOfferView,
  ClockReleaseOutcomeView,
  GoLiveChecklistView,
  PendingDeviceRequestView,
  PolicyProfileView,
  RegistryHealthView,
  RevocationEffectView,
  TrustCeremonyView,
  WriterTransitionView,
} from '../../bridge/generated-contracts'

/**
 * Die Pruefungen an der Grenze, an der eine Wirtsantwort zu einem
 * Ansichtsmodell wird — statt ihr zu glauben (Muster `validateSyncState`,
 * `validateResume`).
 *
 * Geprueft wird jede Position einer geschlossenen Aufzaehlung: eine
 * Zeichenkette, die nicht in der emittierten Werteliste steht, ist KEIN
 * Schritt, KEINE Phase, KEIN Status. Dazu jeder Wahrheitswert, aus dem die
 * Flaeche einen Sicherheitssatz ableitet, und jede Zahl, die sie als Frist
 * oder Zeitpunkt zeigt: ein fehlendes Bit ist keine Zusage, und eine fehlende
 * Zahl ist kein „nicht genannt", wenn der Kontrakt sie verlangt.
 */

/**
 * Der Name, an dem die Schale einen Kontraktverstoss erkennt.
 *
 * Kein Wirtscode: `CommandError` ist `{ code }`, und ein Code, den der Wirt
 * nie genannt hat, waere eine Erfindung der Schale. Stattdessen traegt der
 * Fehler diesen Namen, und `refusalCode` uebersetzt ihn in den Satz „Antwort
 * außerhalb des Kontrakts" — die Flaeche bleibt trotzdem geschlossen.
 */
export const CONTRACT_VIOLATION_NAME = 'ContractViolation'

export class ContractViolation extends Error {
  constructor(message: string) {
    super(message)
    this.name = CONTRACT_VIOLATION_NAME
  }
}

export function isContractViolation(error: unknown): boolean {
  return error instanceof Error && error.name === CONTRACT_VIOLATION_NAME
}

/** Die Verfuegbarkeit, deren ERSTE Position das Angebot ist. */
const [OFFERED] = CLOCK_RELEASE_AVAILABILITY_VALUES

/** Zeichen, die einen Pfad und keinen Dateinamen kennzeichnen. */
const PATH_MARK = /[\\/]|\.\./

function record(raw: unknown, what: string): Record<string, unknown> {
  if (typeof raw !== 'object' || raw === null) {
    throw new ContractViolation(`${what} ist kein Objekt.`)
  }
  return raw as Record<string, unknown>
}

function oneOf<T extends string>(values: readonly T[], raw: unknown, what: string): T {
  const found = values.find((value) => value === raw)
  if (found === undefined) {
    throw new ContractViolation(`${what} nennt keinen Wert des Kontrakts.`)
  }
  return found
}

function bool(raw: unknown, what: string): boolean {
  if (typeof raw !== 'boolean') {
    throw new ContractViolation(`${what} ist kein Wahrheitswert.`)
  }
  return raw
}

function num(raw: unknown, what: string): number {
  if (typeof raw !== 'number' || Number.isNaN(raw)) {
    throw new ContractViolation(`${what} ist keine Zahl.`)
  }
  return raw
}

function numOrNull(raw: unknown, what: string): number | null {
  return raw === null ? null : num(raw, what)
}

/**
 * Der Name der Austauschdatei — ein NAME und kein Pfad.
 *
 * Die Flaeche zeigt ihn dem Bediener als das, was er auf dem Austauschmedium
 * suchen soll. Ein Wirt, der einen Pfad meldet (Trennzeichen oder `..`),
 * spricht ausserhalb des Kontrakts; die Schale kuerzt ihn nicht zurecht.
 */
function fileNameOrNull(raw: unknown, what: string): string | null {
  if (raw === null) {
    return null
  }
  if (typeof raw !== 'string' || raw === '' || PATH_MARK.test(raw)) {
    throw new ContractViolation(`${what} ist kein Dateiname.`)
  }
  return raw
}

export function validateCeremony(raw: unknown): TrustCeremonyView {
  const candidate = record(raw, 'Die Zeremonie')
  const round = oneOf(TRUST_CEREMONY_ROUND_V1_VALUES, candidate.round, 'Die Objektrunde')
  const step = oneOf(TRUST_CEREMONY_STEP_VALUES, candidate.step, 'Der Zeremonieschritt')
  const fingerprintSubject = candidate.fingerprintSubject === null ? null : oneOf(FINGERPRINT_SUBJECT_V1_VALUES, candidate.fingerprintSubject, 'Der Fingerprint-Bezug')
  const targetFingerprint = candidate.targetFingerprint === null ? null : fingerprint(candidate.targetFingerprint)
  const ceremonyId = identifier(candidate.ceremonyId)
  const linkedCeremonyId = candidate.linkedCeremonyId === null ? null : identifier(candidate.linkedCeremonyId)
  if ((fingerprintSubject === null) !== (targetFingerprint === null)
    || (step === REGISTRY_PUBLISHED_STEP && round !== ACTIVATE_REGISTRY_ROUND)
    || (step === TARGET_PUBLISHED_STEP && round !== ISSUE_TARGET_ROUND)
    || linkedCeremonyId === ceremonyId) throw new ContractViolation('Die Zeremonierunde ist widersprüchlich.')
  return {
    ceremonyId, round, linkedCeremonyId, fingerprintSubject, targetFingerprint,
    kind: oneOf(TRUST_CEREMONY_KIND_VALUES, candidate.kind, 'Die Zeremonieart'),
    step,
    exchangeFileName: fileNameOrNull(candidate.exchangeFileName, 'Die Austauschdatei'),
  }
}

function identifier(raw: unknown): string {
  if (typeof raw !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(raw)) throw new ContractViolation('Die Vorgangskennung ist ungültig.')
  return raw
}

export function validateOpenCeremonies(raw: unknown): readonly TrustCeremonyView[] {
  if (!Array.isArray(raw) || raw.length > 1024) throw new ContractViolation('Die gespeicherten Runden sind keine begrenzte Liste.')
  const rounds = raw.map(validateCeremony)
  if (new Set(rounds.map(round => round.ceremonyId)).size !== rounds.length
    || rounds.some(round => round.step === REGISTRY_PUBLISHED_STEP || round.step === TARGET_PUBLISHED_STEP)) {
    throw new ContractViolation('Die Liste offener Runden enthält doppelte oder abgeschlossene Vorgänge.')
  }
  return rounds
}
function fingerprint(raw: unknown): string {
  if (typeof raw !== 'string' || !/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(raw)) throw new ContractViolation('Der Fingerprint ist ungültig.')
  return raw
}

export function validateChecklist(raw: unknown): GoLiveChecklistView {
  const candidate = record(raw, 'Die Go-live-Liste')
  if (!Array.isArray(candidate.requirements)) {
    throw new ContractViolation('Die Go-live-Liste nennt keine Anforderungen.')
  }
  return {
    requirements: candidate.requirements.map((row: unknown) => {
      const requirement = record(row, 'Die Go-live-Anforderung')
      return {
        ...(requirement as unknown as GoLiveChecklistView['requirements'][number]),
        status: oneOf(GO_LIVE_REQUIREMENT_STATUS_VALUES, requirement.status, 'Der Go-live-Status'),
      }
    }),
    // Ein fehlendes oder fremdes Bit ist KEIN Ja.
    productionReady: bool(candidate.productionReady, 'Die Produktionsbereitschaft'),
  }
}

export function validateRegistryHealth(raw: unknown): RegistryHealthView {
  const candidate = record(raw, 'Der Registry-Zustand')
  return {
    ...(candidate as unknown as RegistryHealthView),
    staleDecision: oneOf(STALE_DECISION_VALUES, candidate.staleDecision, 'Die Frischeentscheidung'),
  }
}

export function validateWriterTransition(raw: unknown): WriterTransitionView {
  const candidate = record(raw, 'Der Writer-Wechsel')
  const phase = oneOf(WRITER_TRANSITION_PHASE_VALUES, candidate.phase, 'Die Wechselphase')
  const ceremonyId = candidate.ceremonyId === null ? null : identifier(candidate.ceremonyId)
  const [, prepared] = WRITER_TRANSITION_PHASE_VALUES
  if (ceremonyId !== null && phase !== prepared) {
    throw new ContractViolation('Die gespeicherte Runde gehört zu keinem offenen Writer-Wechsel.')
  }
  return {
    ...(candidate as unknown as WriterTransitionView),
    phase,
    ceremonyId,
  }
}

/**
 * Das Zeitfreigabeangebot.
 *
 * Bietet der Wirt eine Freigabe an, MUSS er Floor, Wanduhr, signiertes Limit
 * und Ablauf nennen — der Bediener vergleicht genau diese vier Zahlen gegen
 * seine zweite Uhr, bevor er begruendet. Ein Angebot mit einer Luecke ist
 * kein Angebot, sondern eine Antwort ausserhalb des Kontrakts. Ohne Angebot
 * duerfen die vier fehlen.
 */
export function validateClockReleaseOffer(raw: unknown): ClockReleaseOfferView {
  const candidate = record(raw, 'Das Zeitfreigabeangebot')
  if (!Array.isArray(candidate.justifications)) {
    throw new ContractViolation('Das Zeitfreigabeangebot nennt keine Begründungen.')
  }
  const availability = oneOf(
    CLOCK_RELEASE_AVAILABILITY_VALUES,
    candidate.availability,
    'Die Verfügbarkeit der Zeitfreigabe',
  )
  const numbers =
    availability === OFFERED
      ? {
          floorMs: num(candidate.floorMs, 'Der Zeit-Floor des Angebots'),
          observedWallClockMs: num(candidate.observedWallClockMs, 'Die Wanduhr des Angebots'),
          maxFutureClockSkewMs: num(candidate.maxFutureClockSkewMs, 'Das Limit des Angebots'),
          expiresAtMs: num(candidate.expiresAtMs, 'Der Ablauf des Angebots'),
        }
      : {
          floorMs: numOrNull(candidate.floorMs, 'Der Zeit-Floor'),
          observedWallClockMs: numOrNull(candidate.observedWallClockMs, 'Die Wanduhr'),
          maxFutureClockSkewMs: numOrNull(candidate.maxFutureClockSkewMs, 'Das Limit'),
          expiresAtMs: numOrNull(candidate.expiresAtMs, 'Der Ablauf'),
        }
  return {
    ...(candidate as unknown as ClockReleaseOfferView),
    availability,
    ...numbers,
    // Nur die drei erlaubten Begruendungen sind waehlbar.
    justifications: candidate.justifications.map((value: unknown) =>
      oneOf(CLOCK_RELEASE_JUSTIFICATION_V1_VALUES, value, 'Die Begründung'),
    ),
  }
}

/**
 * Der Ausgang einer Zeitfreigabe: drei Wahrheitswerte, aus denen die Flaeche
 * ihre „geändert: nein"-Zeilen — oder ihre Warnung — ableitet. Ein fehlendes
 * Bit ist weder ein Nein noch ein Ja.
 */
export function validateClockReleaseOutcome(raw: unknown): ClockReleaseOutcomeView {
  const candidate = record(raw, 'Der Zeitfreigabeausgang')
  return {
    ...(candidate as unknown as ClockReleaseOutcomeView),
    expiresAtMs: num(candidate.expiresAtMs, 'Der Ablauf der Freigabe'),
    changesTimeFloor: bool(candidate.changesTimeFloor, 'Die Änderung des Zeit-Floors'),
    changesRegistryExpiry: bool(candidate.changesRegistryExpiry, 'Die Änderung des Registry-Ablaufs'),
    changesLease: bool(candidate.changesLease, 'Die Änderung der Sequenz-Lease'),
  }
}

export function validateRevocationEffect(raw: unknown): RevocationEffectView {
  const candidate = record(raw, 'Die Widerrufswirkung')
  return {
    ...(candidate as unknown as RevocationEffectView),
    targetClass: oneOf(REVOCATION_TARGET_CLASS_VALUES, candidate.targetClass, 'Die Zielart'),
    // Beide Rueckrufbits werden als WAHRHEITSWERT verlangt: die Flaeche leitet
    // aus ihnen die Saetze zu design.md:1462 ab, und ein fehlendes Bit ist
    // keine Zusage in irgendeine Richtung.
    recallsIssuedGrants: bool(candidate.recallsIssuedGrants, 'Der Rückruf erteilter Grants'),
    recallsDecryptedPlaintext: bool(
      candidate.recallsDecryptedPlaintext,
      'Der Rückruf entschlüsselter Inhalte',
    ),
  }
}

/**
 * Das Richtlinienprofil: lauter Zahlen und Wahrheitswerte, die die Flaeche
 * als Fristen, Sequenzen und „erlaubt / nicht erlaubt" zeigt. Eine
 * Zeichenkette an Stelle einer Frist wuerde `formatDuration` zu `NaN h`
 * machen, ein fehlendes Bit „nicht zugelassen" behaupten — beides ist keine
 * Aussage ueber die Richtlinie. Die Mindestaufbewahrung ist die einzige
 * Zahl, die fehlen DARF (`null`: nicht festgelegt).
 */
export function validatePolicyProfile(raw: unknown): PolicyProfileView {
  const candidate = record(raw, 'Das Richtlinienprofil')
  return {
    operatingProfile: num(candidate.operatingProfile, 'Das Betriebsprofil'),
    maxRegistryAgeMs: num(candidate.maxRegistryAgeMs, 'Das Höchstalter der Registry'),
    maxFutureClockSkewMs: num(candidate.maxFutureClockSkewMs, 'Der zulässige Zukunftsversatz'),
    registryExpiryBehavior: num(candidate.registryExpiryBehavior, 'Das Verhalten bei Registry-Ablauf'),
    evidenceMaxDelayMs: num(candidate.evidenceMaxDelayMs, 'Der Evidence-Höchstverzug'),
    readerInactivityMs: num(candidate.readerInactivityMs, 'Die Reader-Inaktivität'),
    readerTrustRefreshMs: num(candidate.readerTrustRefreshMs, 'Die Reader-Vertrauensauffrischung'),
    readerHistoryAccessAllowed: bool(
      candidate.readerHistoryAccessAllowed,
      'Der historische Zugriff für Reader',
    ),
    backupFrequencyMs: num(candidate.backupFrequencyMs, 'Die Backupfrequenz'),
    restoreTestIntervalMs: num(candidate.restoreTestIntervalMs, 'Das Restore-Testintervall'),
    minimumRetentionMs: numOrNull(candidate.minimumRetentionMs, 'Die Mindestaufbewahrung'),
    destructionEnabled: bool(candidate.destructionEnabled, 'Die autorisierte Vernichtung'),
    effectiveFromSequence: num(candidate.effectiveFromSequence, 'Die Wirksamkeitssequenz'),
    leaseValidThroughSequence: num(candidate.leaseValidThroughSequence, 'Die Sequenz-Lease'),
    notAfterMs: num(candidate.notAfterMs, 'Der Ablauf der Richtlinie'),
  }
}

export function validatePendingRequests(raw: unknown): readonly PendingDeviceRequestView[] {
  if (!Array.isArray(raw)) {
    throw new ContractViolation('Die Geräteanfragen sind keine Liste.')
  }
  return raw.map((row: unknown) => {
    const candidate = record(row, 'Die Geräteanfrage')
    return {
      requestId: identifier(candidate.requestId),
      certificateKindCode: identifier(candidate.certificateKindCode),
      fingerprint: fingerprint(candidate.fingerprint),
      fingerprintSubject: oneOf(FINGERPRINT_SUBJECT_V1_VALUES, candidate.fingerprintSubject, 'Der Fingerprint-Bezug'),
      receivedAtMs: num(candidate.receivedAtMs, 'Der Anfrageeingang'),
    }
  })
}
