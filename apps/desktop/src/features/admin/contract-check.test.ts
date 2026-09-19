import { expect, it } from 'vitest'

import {
  CONTRACT_VIOLATION_NAME,
  validateCeremony,
  validateOpenCeremonies,
  validateChecklist,
  validateClockReleaseOffer,
  validateClockReleaseOutcome,
  validatePendingRequests,
  validatePolicyProfile,
  validateRegistryHealth,
  validateRevocationEffect,
  validateWriterTransition,
} from './contract-check'

// Die Grenze, an der eine Wirtsantwort zum Ansichtsmodell wird: jede Pruefung
// nimmt die Drahtform AN, wenn sie im Kontrakt steht, und WIRFT sonst — mit
// einem Fehler, dessen Name die Schale erkennt (`ContractViolation`), damit die
// Flaeche „Antwort außerhalb des Kontrakts" sagt und keinen Wirtscode erfindet.

const ceremony = () => ({
  ceremonyId: 'zeremonie-1',
  kind: 'DeviceApprove',
  step: 'PendingRequest',
  targetFingerprint: null,
  exchangeFileName: null,
  round: 'ActivateRegistry',
  linkedCeremonyId: null,
  fingerprintSubject: null,
})

it('accepts exact open rounds but refuses duplicate identifiers, completed rounds and invalid lists', () => {
  const open = ceremony()
  expect(validateOpenCeremonies([open])).toEqual([open])
  for (const input of [null, {}, [open, open], [{ ...open, step: 'RegistryPublished' }],
    [{ ...open, round: 'IssueTarget', step: 'TargetPublished' }], Array(1025).fill(open)]) {
    violates(() => validateOpenCeremonies(input))
  }
})

const checklist = () => ({
  requirements: [
    { requirementCode: 'EA-GOLIVE-POLICY', status: 'Confirmed', evidenceCode: 'EA-GOLIVE-POLICY-EVIDENCE', decisionDocumentHash: null },
  ],
  productionReady: true,
})

const registryHealth = () => ({
  registryVersion: 4,
  headHash: 'CC'.repeat(32),
  registryAgeMs: 1,
  maxRegistryAgeMs: 2,
  leaseValidThroughSequence: 120,
  nextSequence: 87,
  notAfterMs: 3,
  staleDecision: 'Fresh',
})

const transition = () => ({
  phase: 'Prepared',
  ceremonyId: null,
  currentWriterHash: 'AA'.repeat(32),
  newWriterHash: 'BB'.repeat(32),
  effectiveFromSequence: 88,
})

it('requires a valid saved writer-round identifier and rejects one on an already completed transition', () => {
  expect(validateWriterTransition({ ...transition(), ceremonyId: 'saved-round-1' }).ceremonyId).toBe('saved-round-1')
  for (const ceremonyId of [undefined, '', '../other', 12]) {
    violates(() => validateWriterTransition({ ...transition(), ceremonyId }))
  }
  for (const phase of ['NoTransition', 'Activated']) {
    violates(() => validateWriterTransition({ ...transition(), phase, ceremonyId: 'saved-round-1' }))
  }
})

const offered = () => ({
  availability: 'Offered',
  floorMs: 1_771_000_000_000,
  observedWallClockMs: 1_771_000_900_000,
  maxFutureClockSkewMs: 300_000,
  expiresAtMs: 1_771_003_600_000,
  justifications: ['OperatorVerifiedWallClock'],
})

const notBlocked = () => ({
  availability: 'NotBlocked',
  floorMs: null,
  observedWallClockMs: null,
  maxFutureClockSkewMs: null,
  expiresAtMs: null,
  justifications: [],
})

const outcome = () => ({
  releaseId: 'freigabe-0001',
  expiresAtMs: 1_771_003_600_000,
  changesTimeFloor: false,
  changesRegistryExpiry: false,
  changesLease: false,
})

const effect = () => ({
  targetClass: 'NonAdminDevice',
  targetHash: 'DD'.repeat(32),
  stopsNewGrantsFromSequence: 91,
  recallsIssuedGrants: false,
  recallsDecryptedPlaintext: false,
})

const policy = () => ({
  operatingProfile: 0,
  maxRegistryAgeMs: 1,
  maxFutureClockSkewMs: 2,
  registryExpiryBehavior: 0,
  evidenceMaxDelayMs: 3,
  readerInactivityMs: 4,
  readerTrustRefreshMs: 5,
  readerHistoryAccessAllowed: false,
  backupFrequencyMs: 6,
  restoreTestIntervalMs: 7,
  minimumRetentionMs: 8,
  destructionEnabled: false,
  effectiveFromSequence: 12,
  leaseValidThroughSequence: 120,
  notAfterMs: 9,
})

/** Der Wurf muss ein `ContractViolation` sein — kein nackter `Error`, kein Wirtscode. */
function violates(act: () => unknown): void {
  let thrown: unknown = null
  try {
    act()
  } catch (error) {
    thrown = error
  }
  expect(thrown).toBeInstanceOf(Error)
  expect((thrown as Error).name).toBe(CONTRACT_VIOLATION_NAME)
  expect(thrown).not.toHaveProperty('code')
}

it('accepts every valid fixture unchanged', () => {
  expect(validateCeremony(ceremony())).toEqual(ceremony())
  expect(validateCeremony({ ...ceremony(), exchangeFileName: 'root-anfrage-0001.json' })).toEqual({
    ...ceremony(),
    exchangeFileName: 'root-anfrage-0001.json',
  })
  expect(validateChecklist(checklist())).toEqual(checklist())
  expect(validateRegistryHealth(registryHealth())).toEqual(registryHealth())
  expect(validateWriterTransition(transition())).toEqual(transition())
  expect(validateClockReleaseOffer(offered())).toEqual(offered())
  expect(validateClockReleaseOffer(notBlocked())).toEqual(notBlocked())
  expect(validateClockReleaseOutcome(outcome())).toEqual(outcome())
  expect(validateRevocationEffect(effect())).toEqual(effect())
  expect(validatePolicyProfile(policy())).toEqual(policy())
  expect(validatePolicyProfile({ ...policy(), minimumRetentionMs: null })).toEqual({
    ...policy(),
    minimumRetentionMs: null,
  })
  expect(validatePendingRequests([])).toEqual([])
})

it('rejects a literal outside the emitted union', () => {
  violates(() => validateCeremony({ ...ceremony(), round: 'Done' }))
  violates(() => validateCeremony({ ...ceremony(), round: undefined }))
  violates(() => validateCeremony({ ...ceremony(), fingerprintSubject: undefined }))
  violates(() => validateCeremony({ ...ceremony(), linkedCeremonyId: undefined }))
  violates(() => validateCeremony({ ...ceremony(), linkedCeremonyId: '../private' }))
  violates(() => validateCeremony({ ...ceremony(), step: 'RegistryPublished', round: 'IssueTarget' }))
  violates(() => validateCeremony({ ...ceremony(), step: 'TargetPublished' }))
  violates(() => validateCeremony({ ...ceremony(), fingerprintSubject: 'RegistrationRequest' }))
  violates(() => validateCeremony({ ...ceremony(), step: 'Done' }))
  violates(() => validateCeremony({ ...ceremony(), kind: 'Bootstrap' }))
  violates(() =>
    validateChecklist({
      ...checklist(),
      requirements: [{ ...checklist().requirements[0], status: 'Green' }],
    }),
  )
  violates(() => validateRegistryHealth({ ...registryHealth(), staleDecision: 'Ok' }))
  violates(() => validateWriterTransition({ ...transition(), phase: 'Live' }))
  violates(() => validateClockReleaseOffer({ ...notBlocked(), availability: 'Maybe' }))
  violates(() => validateClockReleaseOffer({ ...offered(), justifications: ['BecauseISaidSo'] }))
  violates(() => validateRevocationEffect({ ...effect(), targetClass: 'Root' }))
})

it('rejects a non-boolean where the contract carries a boolean', () => {
  violates(() => validateChecklist({ ...checklist(), productionReady: 'yes' }))
  violates(() => validateRevocationEffect({ ...effect(), recallsIssuedGrants: undefined }))
  violates(() => validateRevocationEffect({ ...effect(), recallsDecryptedPlaintext: 0 }))
  violates(() => validateClockReleaseOutcome({ ...outcome(), changesTimeFloor: 1 }))
  violates(() => validateClockReleaseOutcome({ ...outcome(), changesLease: 'nein' }))
  violates(() => validatePolicyProfile({ ...policy(), destructionEnabled: 'nein' }))
  violates(() => validatePolicyProfile({ ...policy(), readerHistoryAccessAllowed: 1 }))
})

it('rejects a policy profile whose numbers are not numbers', () => {
  violates(() => validatePolicyProfile({ ...policy(), maxRegistryAgeMs: '7d' }))
  violates(() => validatePolicyProfile({ ...policy(), minimumRetentionMs: undefined }))
  violates(() => validatePolicyProfile({ ...policy(), minimumRetentionMs: '3650d' }))
  violates(() => validatePolicyProfile({ ...policy(), notAfterMs: null }))
})

// F4: ein Angebot OHNE seine vier Zahlen ist kein Angebot. Der Wirt meldet
// Floor, Wanduhr, Limit und Ablauf genau dann, wenn er eine Freigabe anbietet;
// fehlt eine, ist die Antwort ausserhalb des Kontrakts und nicht „nicht genannt".
it('rejects an offered clock release without its four numbers', () => {
  violates(() => validateClockReleaseOffer({ ...offered(), floorMs: null }))
  violates(() => validateClockReleaseOffer({ ...offered(), observedWallClockMs: null }))
  violates(() => validateClockReleaseOffer({ ...offered(), maxFutureClockSkewMs: null }))
  violates(() => validateClockReleaseOffer({ ...offered(), expiresAtMs: null }))
  violates(() => validateClockReleaseOffer({ ...offered(), expiresAtMs: '2026-02-13' }))
  // Ohne Angebot duerfen die vier fehlen.
  expect(validateClockReleaseOffer(notBlocked()).availability).toBe('NotBlocked')
})

// F9: der Austauschdateiname ist ein NAME und kein Pfad. Ein Wirt, der einen
// Pfad meldet, spricht ausserhalb des Kontrakts — die Schale zeigt ihn nicht.
it('rejects an exchange file name that is a path', () => {
  violates(() => validateCeremony({ ...ceremony(), exchangeFileName: '../root-anfrage.json' }))
  violates(() => validateCeremony({ ...ceremony(), exchangeFileName: 'austausch/root-anfrage.json' }))
  violates(() => validateCeremony({ ...ceremony(), exchangeFileName: 'austausch\\root-anfrage.json' }))
  violates(() => validateCeremony({ ...ceremony(), exchangeFileName: 42 }))
})

it('rejects a non-object or a non-list where the contract carries one', () => {
  violates(() => validateCeremony(null))
  violates(() => validateCeremony('zeremonie'))
  violates(() => validateChecklist({ requirements: 'alle', productionReady: true }))
  violates(() => validateClockReleaseOffer({ ...notBlocked(), justifications: 'keine' }))
  violates(() => validatePendingRequests({}))
  violates(() => validatePendingRequests([null]))
})
