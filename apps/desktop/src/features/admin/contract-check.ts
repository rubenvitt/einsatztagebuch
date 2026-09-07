import {
  CLOCK_RELEASE_AVAILABILITY_VALUES,
  CLOCK_RELEASE_JUSTIFICATION_V1_VALUES,
  GO_LIVE_REQUIREMENT_STATUS_VALUES,
  REVOCATION_TARGET_CLASS_VALUES,
  STALE_DECISION_VALUES,
  TRUST_CEREMONY_KIND_VALUES,
  TRUST_CEREMONY_STEP_VALUES,
  WRITER_TRANSITION_PHASE_VALUES,
} from '../../bridge/generated-contracts'
import type {
  ClockReleaseOfferView,
  GoLiveChecklistView,
  PendingDeviceRequestView,
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
 * Schritt, KEINE Phase, KEIN Status. Die uebrigen Felder sind Zahlen, Hashes
 * und Wahrheitswerte, deren Gestalt der Typ traegt; ihre Pruefung bleibt auf
 * das beschraenkt, was eine Sicherheitsaussage verschieben koennte.
 */

function record(raw: unknown, what: string): Record<string, unknown> {
  if (typeof raw !== 'object' || raw === null) {
    throw new Error(`${what} ist kein Objekt.`)
  }
  return raw as Record<string, unknown>
}

function oneOf<T extends string>(values: readonly T[], raw: unknown, what: string): T {
  const found = values.find((value) => value === raw)
  if (found === undefined) {
    throw new Error(`${what} nennt keinen Wert des Kontrakts.`)
  }
  return found
}

function bool(raw: unknown, what: string): boolean {
  if (typeof raw !== 'boolean') {
    throw new Error(`${what} ist kein Wahrheitswert.`)
  }
  return raw
}

export function validateCeremony(raw: unknown): TrustCeremonyView {
  const candidate = record(raw, 'Die Zeremonie')
  return {
    ...(candidate as unknown as TrustCeremonyView),
    kind: oneOf(TRUST_CEREMONY_KIND_VALUES, candidate.kind, 'Die Zeremonieart'),
    step: oneOf(TRUST_CEREMONY_STEP_VALUES, candidate.step, 'Der Zeremonieschritt'),
  }
}

export function validateChecklist(raw: unknown): GoLiveChecklistView {
  const candidate = record(raw, 'Die Go-live-Liste')
  if (!Array.isArray(candidate.requirements)) {
    throw new Error('Die Go-live-Liste nennt keine Anforderungen.')
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
  return {
    ...(candidate as unknown as WriterTransitionView),
    phase: oneOf(WRITER_TRANSITION_PHASE_VALUES, candidate.phase, 'Die Wechselphase'),
  }
}

export function validateClockReleaseOffer(raw: unknown): ClockReleaseOfferView {
  const candidate = record(raw, 'Das Zeitfreigabeangebot')
  if (!Array.isArray(candidate.justifications)) {
    throw new Error('Das Zeitfreigabeangebot nennt keine Begründungen.')
  }
  return {
    ...(candidate as unknown as ClockReleaseOfferView),
    availability: oneOf(
      CLOCK_RELEASE_AVAILABILITY_VALUES,
      candidate.availability,
      'Die Verfügbarkeit der Zeitfreigabe',
    ),
    // Nur die drei erlaubten Begruendungen sind waehlbar.
    justifications: candidate.justifications.map((value: unknown) =>
      oneOf(CLOCK_RELEASE_JUSTIFICATION_V1_VALUES, value, 'Die Begründung'),
    ),
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

export function validatePendingRequests(raw: unknown): readonly PendingDeviceRequestView[] {
  if (!Array.isArray(raw)) {
    throw new Error('Die Geräteanfragen sind keine Liste.')
  }
  return raw.map((row: unknown) => record(row, 'Die Geräteanfrage') as unknown as PendingDeviceRequestView)
}
