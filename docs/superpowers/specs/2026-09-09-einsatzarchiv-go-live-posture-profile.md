# Go-live posture documentation — internal profile v1

Decision: 2026-09-09, Stage 5 device operability review of main design §18.4. This controller-approved profile documents prerequisites that reliable native measurements cannot establish. It is a separately signed internal operational document, never an ExactObject, Trust Registry record or archive authorization. Measurements remain Pass / Fail / Unknown without reinterpretation.

## Exact bytes

The core is deterministic CBOR with exactly twenty items:

```cddl
go-live-posture-core-internal-v1 = [
  "EINSATZARCHIV-GOLIVE-POSTURE-v1", 1,
  organization-id: bstr .size 16,
  chain-id: bstr .size 16,
  target-installation-id: bstr .size 32,
  target-os-account-binding-hash: bstr .size 32,
  target-device-id: bstr .size 16,
  target-device-certificate-hash: bstr .size 32,
  target-operator-binding-hash: bstr .size 32,
  os-family: 1 / 2 / 3,
  os-build-identity-hash: bstr .size 32,
  documented-unknown-mask: 1..15,
  public-evidence-reference-hash: bstr .size 32,
  issuer-admin-certificate-hash: bstr .size 32,
  issuer-admin-binding-hash: bstr .size 32,
  registry-version: uint,
  registry-head-hash: bstr .size 32,
  issued-sequence: uint,
  issued-at-effective: int,
  valid-until-exclusive: int
]
go-live-posture-envelope-internal-v1 = [
  exact-core: bstr,
  exact-cose-sign1: bstr
]
```

Family codes: 1 macOS, 2 Ubuntu, 3 Windows. Mask bits in existing PostureRequirement order: 1 full-disk encryption, 2 locked/non-shared account, 4 automatic screen lock, 8 supported patch level. The mask documents only Unknown prerequisites; a measured Fail and a provider error cannot be overridden.

The signature payload is raw SHA-256 over UTF-8 EINSATZARCHIV-GOLIVE-POSTURE-v1, one zero byte, and the exact core. COSE ContentType is application/vnd.einsatzarchiv.go-live-posture-digest, with normal protected key thumbprint and issuer Admin certificate hash. The protected certificate must equal the core issuer certificate and the verified current OrganizationAdmin authority. Typed signing/verification operations fix the domain, content type, arity, field widths and version; no generic signature-purpose or digest escape is introduced.

All referenced byte hashes use the existing object_hash domain. Public evidence reference is only a hash of the separately maintained operational document: no names, narratives, paths, account names or private values enter the signed core.

## Native OS identity

The target derives the build identity from reliable local platform sources, independently at export, import and admission. It never accepts a caller or environment version as native fact.

- macOS: bounded exact build version from fixed /usr/bin/sw_vers -buildVersion.
- Ubuntu: bounded native /etc/os-release ID and VERSION_ID together with /usr/bin/uname -r; unexpected or ambiguous fields fail closed.
- Windows: fixed HKLM Windows NT CurrentVersion CurrentBuildNumber and UBR, through the existing bounded fixed-command runner.

The build hash commits to a deterministic CBOR tuple with domain EINSATZARCHIV-OS-BUILD-v1, family code and the exact accepted platform components. Missing, malformed or unsafe OS identity prevents documentation use. This identifies the current build; it does not assert that the build conforms to an organizational patch policy.

## Issuance and import

A target context is exported from the actual local runtime. Its public exchange representation is not an authority source: import remeasures and compares every target field against the real installation, native account, device, exact active binding, organization/chain and native OS identity.

Only an active OrganizationAdmin may issue the document, after fresh native GoLivePostureDocumentation reauthentication. This purpose-limited preproduction path preserves current Registry/lease, trusted time, account binding, instance-key possession, continuous session watcher and durable signed Login/failed-reauth audit. It does not return authority for ordinary production operations, and no ordinary service accepts this new purpose. The signed document itself is the durable evidence record; existing AdminRootCeremony audit fields are not overloaded.

Issuance validates the selected target certificate/binding against the Admin's verified current Registry, binds the exact Registry hash/version and sequence, and signs only the exact closed core. The public target description never authorizes a local admission. The actual target imports only after verifying the complete signature, issuer role/binding, target context, native measurements, time and Registry state. Store the exact envelope in SQLCipher using migration 0013; storage failure prevents admission. First import requires the documented mask to equal the independently measured current Unknown mask; public target claims cannot pre-authorize currently passing requirements. Exact duplicate imports are idempotent and do not extend expiry.

## Freshness and admission

Require issuedAt < validUntil, validUntil - issuedAt <= 24 hours and validUntil <= the selected Registry head's notAfter. validUntil is exclusive: effectiveNow < validUntil. issuedAt is derived from existing verified/fresh runtime time, not a supplied timestamp. Enforce native wall-clock and monotonic freshness against rollback and recheck after blocking native work.

For every admission, independently verify the current native measurement and OS build, exact installation/account/device/certificate/binding/org/chain, live native watcher, current issuer Admin certificate and binding, exact Registry version/head, original issuedSequence <= current sequence, and current trusted time within the validity interval. Any Registry-head change invalidates the document, even if its nominal time window remains open. Missing, corrupt, expired, mismatched or unverifiable stored bytes deny use.

A measured Fail or provider error always denies production admission. Every current Unknown prerequisite must be covered by a valid matching document; newly unknown uncovered requirements require new evidence. Automatically measured Pass remains independent. An opaque VerifiedPostureAdmission carries verified documentation metadata separately; it never mutates DevicePostureReport.

## Reporting

Display native measurement status and documented confirmation as separate facts, with document/reference hash and exclusive expiry. Unknown remains visibly Unknown. A prerequisite may have valid documented confirmation under §18.4 without claiming an automatic Pass. Compute production admission in Rust from the actual measurement plus verified evidence; no frontend/config/environment boolean grants it.

This document records the approved implementation profile. It is not an implementation, independent review or production-readiness claim.

