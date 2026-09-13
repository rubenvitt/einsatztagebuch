# Native Writer restart after Registry expiry

Runtime composition for the existing R62 acknowledgement contract. No archived
format, signature domain or general Registry selection rule changes.

The native host currently cannot open after `notAfter`: ordinary selection
correctly refuses a stale Registry, but the Writer's signed Standard/warn policy
permits explicit acknowledged finalization. Keeping a formerly fresh object in
RAM does not implement restart and cannot justify selecting at a past time.

The trust layer supplies a separate opaque `StaleWriterRegistryHead`, minted
only for the exact persistent current pin after normal authenticated catch-up.
Its real observed time passes the existing time evaluation and persistent CAS.
The sequence lease, known successor boundary, future-clock guard, complete
dependency chain and active Writer/operator bindings remain mandatory.
Evidence Grade and signed block policy refuse this context. Ordinary
`select_registry_head` still refuses expiry. Historical verification cannot
convert to this context. No public conversion, dereference or accessor exposes
it as `SelectedRegistryHead`.

A sealed current-or-stale Writer view carries the common immutable fields used
by Writer finalization and its operator verification. Stale native sessions are
Writer-only and may issue only Finalize, RegistryStaleFinalize and DiscardDraft
presence proofs. Administrative operations, Go-live, re-grant, destruction,
profile migration and plaintext export retain ordinary current authority.

The native host reopens from actual committed archive bytes, measured wall time,
native installation/account, SQLCipher pin/time and current sequence for every
action. Preview retention commits its original exact preview time and input;
independent fresh context checks do not replace that hash. A changed Registry,
sequence, account, installation, successor or policy invalidates previews and
all purpose proofs. Native presence is checked before and after its dialog.

The stale exception requires measured passing device posture. An existing
signed document for unknown posture is bounded by the Registry's `notAfter`
and cannot admit this expired context. Its lifetime is not extended by the
Writer exception. Ordinary current authority continues to use the documented
posture admission rules.

The existing signed one-use acknowledgement remains mandatory for stale
finalization. A stale Writer view alone does not authorize finalization or
relax receipt consumption, rollback, external checkpoint, native-key or archive
durability gates. Recovery publishes only the already prepared exact bytes
after confirmed DEK absence; it never silently creates a new transaction.

Acceptance requires real native restart at expired wall time, explicit visible
preview warning and separate purpose-bound presence, durable one-use receipt,
normal Incident/Amendment publication, and independent review. Negatives cover
Standard/block, Evidence Grade, sequence expiry, effective/future successor,
revoked Writer/binding, account or installation change, persistent time/pin
conflict, delayed presence and replay. This specification is not acceptance.
