#![forbid(unsafe_code)]
//! Die Reader-Crate des Web-Readers.
//!
//! `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §12
//! macht `ea-reader` wasm32-faehig; die Crate steht deshalb auf der
//! wasm32-Positivliste von `verify_quick_commands()` und ausdruecklich NICHT
//! auf `WASM32_EXEMPT_CRATES` — dessen Kriterium ist der Griff ueber
//! `ea-verify` hinaus in das Wirtbetriebssystem, und geteilter Browsercode ist
//! genau das Gegenteil davon.
//!
//! # Kein Skelett mehr: hier liegt der Tresor
//!
//! Bis zur Aufgabe „Browser-Vault: PRF-Envelopes, Schlüsselprofil und die
//! Verwahrung von Anchor und KEM-Schlüssel" trug die Crate zwei Betriebsarten,
//! den Re-Export der Gate-Reihenfolge und den Byteport. Seither traegt sie den
//! Speicher, den §11.3 an die Stelle des ERSATZLOS gestrichenen nativen
//! Reader-Key-Providers setzt: [`ReaderVault`] mit seinen PRF-Envelopes,
//! [`ReaderKeyProfile`] als fail-closed-Pruefung des Reader-Zertifikats und
//! die zwei verschluesselten Speicher [`ReaderObjectCache`] und
//! [`ReaderEntryStateStore`] darueber.
//!
//! Seit der Aufgabe „Inkrementeller Reader-Sync und verifizierter
//! Cursor-Fortschritt in OPFS" kommt der SERVER-MODUS dazu:
//! [`ReaderSyncService`] gibt einen fertig signierten Lesestapel-Request
//! heraus, nimmt die Antwortbytes zurueck und bewegt [`ConfirmedCursor`] erst,
//! wenn jedes Objektbyte dauerhaft ist UND die Kette bis zum Batchende
//! verifiziert.
//!
//! Der Lesestapel laeuft `verify_archive_observed` weiterhin OHNE
//! Empfaengerschluessel und entschluesselt nichts. Das URTEIL UEBER EINEN
//! EINTRAG kommt seit der Aufgabe „Verifikation vor Entschluesselung" aus
//! [`ReaderVerifier::classify`]: es faehrt dieselben neun Gates MIT dem
//! Schluessel der Sitzung, uebersetzt den Bericht in die Zustandssprache aus
//! `design.md` §17.4 und gibt je Eintrag hoechstens ein Zeugenpaar
//! [`VerifiedEncryptedEntry`]/[`VerifiedGrantForRecipient`] heraus — die
//! einzigen Werte, mit denen [`decrypt_verified`] ueberhaupt formulierbar ist.
//!
//! Seit der Aufgabe „Datei-Modus: Einzeldatei-Bündel, Verzeichnis-Handle, kein
//! Cursor" steht der ZWEITE Betriebsmodus daneben, und er ist durch seine
//! ABWESENHEIT definiert: [`ReaderFileMode`] oeffnet EINE exportierte Datei
//! oder einen angebundenen Ordner, ohne jeden Serveraufruf, ohne OPFS-I/O und
//! ohne Cursor. Beide Wege muenden ueber [`ReaderArchiveSourceV1`] in
//! denselben Byteport und in denselben [`ReaderVerifier::classify`]; es
//! entsteht weder ein zweiter Archivparser noch ein zweites Gate.
//!
//! # Die Reihenfolge ist Absicht
//!
//! Der Tresor steht VOR jeder Verifikation, weil er ihre EINGABEN besitzt: den
//! gepinnten Anker fuer Gate `trust` und den privaten X25519-Empfaengerschluessel
//! samt seinem Abdruck fuer Gate `recipient-grant` und die nachfolgende
//! Entkapselung. Beide Werte entstehen ausschliesslich in [`UnlockedVault`].
//!
//! # Der Bytespeicher ist ein PORT und kein Wirt
//!
//! [`ReaderBlobStore`] beschreibt das Ablegen und Holen von Bytefolgen und
//! sonst nichts; [`InMemoryReaderBlobStore`] ist das Doppel, mit dem jeder
//! Wirtstest ohne Browser laeuft. Die OPFS-Implementierung liegt in
//! `crates/ea-reader-wasm`, weil sie synchrone Zugriffshandles braucht und die
//! es nur im dedizierten Worker gibt. Cache und Zustandsspeicher legen
//! ausschliesslich Chiffrat darin ab und adressieren hexadezimal — die
//! Schluesselliste verlaesst den Port im Klartext.
//!
//! Seit der Aufgabe „Nachtragsreferenzen und Original/Nachtrag-Projektion"
//! steht ueber [`decrypt_verified`] die eine Projektion, die zwei Datensaetze
//! zueinander in Beziehung setzt: [`ReaderEntryThread`] verbindet ein Original
//! mit seinen Nachtraegen und ERSETZT dabei nichts. Sie rechnet keine
//! Kryptografie, oeffnet keine Datei und macht keinen Netzaufruf; sie
//! vergleicht vier Referenzfelder jedes Kandidaten gegen das VERIFIZIERTE
//! Original und ordnet nach `(chain_sequence, entry_hash)`. Eine Abweichung
//! ist ein PRUEFPROBLEM und kein Fehlschlag: der Kandidat wandert mit seiner
//! Adresse nach [`ReaderEntryThread::rejected`], und das Original behaelt
//! Bytes, Eintragshash und Sichtbarkeit. Es gibt AUSDRUECKLICH keine Methode,
//! die ein Original als „ueberholt" kennzeichnet oder einen
//! zusammengefuehrten „aktuellen Stand" berechnet — §12 und die
//! Produktinvariante „amendment-only corrections" lassen dazu keinen zweiten
//! Weg zu.
//!
//! # Die Gate-Reihenfolge wird RE-EXPORTIERT
//!
//! [`GATE_ORDER_V1`] kommt aus `ea-verify` und wird hier nicht ein zweites Mal
//! geschrieben. `crates/ea-verify/src/gates.rs` ist die EINZIGE Quelle dieser
//! neun Zeichenketten, und `tools/xtask/tests/spec_completeness.rs` haelt sie
//! gegen `design.md` §14.1; eine zweite Liste daneben waere die Stelle, an der
//! die Reihenfolge des Browsers von der des Wirts abweichen koennte. Dieselbe
//! Regel gilt fuer die Statusbegriffe: `VerificationStatus`, `EntryStatus` und
//! `ServerConfirmationV1` werden importiert und nie nachgebaut.
//!
//! # Was in der SIGNATUR steht, wird ebenfalls RE-EXPORTIERT
//!
//! [`ReaderEnrollment::begin`] nimmt einen [`ReaderBlobStore`] — den
//! Geraetezustand, gegen den es sich weigert —, dazu [`OrganizationId`],
//! [`SubjectId`], einen
//! `TrustAnchorV1` und [`Hash32`], und der gepinnte Anker gilt nicht, weil er
//! irgendwo lag, sondern weil [`decode_trust_anchor`] seinen Bootstrap-Hash
//! beim Dekodieren NEU rechnet. Diese vier Namen gehoeren damit zur
//! OEFFENTLICHEN Flaeche dieser Crate: wer `begin` ruft, muss sie benennen
//! koennen, und `decode_trust_anchor` ist ueberdies eine FUNKTION — ohne
//! diesen Re-Export gaebe es fuer sie keinen zweiten Weg. `ea-reader-wasm`
//! ruft `begin` und traegt deshalb KEINE eigene Kante nach `ea-trust` oder
//! `ea-types`: die Bruecke rechnet nicht, sie reicht Bytes weiter, und die
//! Begriffe, mit denen sie das tut, kommen aus DER Crate, deren Signatur sie
//! bedient.
//!
//! Dieselbe Regel traegt [`HttpMethod`]: es steht als Feld in
//! [`ReaderRequestV1`], und wer den Request liest — die Bruecke tut es —, muss
//! die Methode benennen koennen, ohne eine eigene Kante nach `ea-sync-protocol`
//! zu ziehen.
//!
//! Dieselbe Regel traegt die Flaeche von [`ReaderVerifier::classify`] und
//! [`decrypt_verified`]: [`ArchiveSource`], [`GateObserver`] samt seinen zwei
//! Doppeln, [`VerificationReportV1`] mit den Typen seiner Accessoren, die
//! Statusbegriffe [`VerificationStatus`] und [`EntryStatus`], die Hashtypen
//! [`EntryHash`], [`ObjectHash`] und [`KeyThumbprint`], [`TrustAnchorV1`] als
//! Rueckgabe von [`PinnedTrustAnchor::as_trust_anchor`] sowie
//! [`SchemaRegistry`] und [`PayloadV1`] stehen in einer dieser Signaturen und
//! werden deshalb hier re-exportiert, statt der Bruecke vier weitere Kanten
//! zu geben.
//!
//! Dieselbe Regel zieht [`ReaderBundlePin::from_trust_objects`] und
//! [`reader_trust_age_view`] nach: die eine nimmt eine [`RegistryVersion`], die
//! andere zwei [`UnixMillis`], und beide werden von der Bruecke gerufen. Die
//! zwei Namen stehen deshalb ebenfalls in der oeffentlichen Flaeche, statt
//! `crates/ea-reader-wasm` eine Kante nach `ea-types` zu geben, die es bis
//! heute nicht hat.
//!
//! Und dieselbe Regel holt [`RecordId`] nach. Der Typ stand bis zur
//! Original/Nachtrag-Projektion in KEINER Signatur dieser Crate;
//! [`CorrectionReference`] traegt ihn als oeffentliches Feld, und wer die
//! Korrekturreferenz an den Writer-Import der Stufe 5 weiterreicht, muss ihn
//! benennen koennen.
//!
//! Und dieselbe Regel weitet den Re-Export aus `ea-archive` von
//! [`ArchiveSource`] auf acht weitere Namen aus. [`ArchiveBundleSource`] und
//! [`DirectoryHandleSource`] sind die zwei Arme von [`ReaderArchiveSourceV1`],
//! [`BundleError`] ist ein Arm von [`ReaderFileModeError`], [`ArchiveError`]
//! ist die Rueckgabe von [`DirectoryHandleSource::push_blob`] und
//! [`ArchiveBlob`] steht in der Signatur, die [`ReaderArchiveSourceV1`]
//! erfuellt; [`MAX_ARCHIVE_BLOBS_V1`] und [`MAX_TOTAL_ARCHIVE_BYTES_V1`] sind
//! die zwei Deckel, die `push_blob` durchsetzt, und
//! [`BUNDLE_FILE_EXTENSION_V1`] samt [`BUNDLE_MAGIC_V1`] sind der
//! Dialogfilter und das, was ihn ueberstimmt. `ea-archive` steht in
//! `crates/ea-reader-wasm/Cargo.toml` ausschliesslich unter
//! `[dev-dependencies]`; ohne diese Re-Exporte koennte eine Produktionsquelle
//! der Bruecke `ea_archive::` gar nicht schreiben, und eine neue Kante ginge
//! in den wasm32-Lib-Graphen, wo ein Re-Export nichts kostet.

mod amendment;
mod anchor;
mod archive_source;
mod batch;
mod blob_store;
mod bundle_release;
mod cache;
mod cursor;
mod decrypt;
mod enrollment;
mod enrollment_endpoints;
mod entry_state;
mod envelope;
mod file_mode;
mod grant;
mod http;
mod key_profile;
mod mode;
mod search;
mod sync;
mod trust_state;
mod vault;
mod verify;

pub use amendment::{
    AmendmentJoinErrorV1, CorrectionReference, ReaderEntryThread, RejectedAmendment,
};
pub use anchor::PinnedTrustAnchor;
pub use archive_source::{DirectoryHandleSource, ReaderArchiveSourceV1};
pub use batch::VerifiedSyncBatch;
pub use blob_store::{InMemoryReaderBlobStore, ReaderBlobError, ReaderBlobKey, ReaderBlobStore};
pub use bundle_release::{
    BundleActivationDecisionV1, BundleRejectionCodeV1, ReaderBundleError, ReaderBundlePin,
};
pub use cache::{ExactObjectVisitor, ReaderObjectCache};
pub use cursor::{
    ConfirmedCursor, MAX_CACHED_OBJECTS_V1, READER_SYNC_CURSOR_BLOB_KEY_V1,
    READER_SYNC_OBJECTS_BLOB_KEY_V1,
};
pub use decrypt::{VerifiedDecryptedRecord, decrypt_verified};
pub use ea_archive::{
    ArchiveBlob, ArchiveBundleSource, ArchiveError, ArchiveSource, BUNDLE_FILE_EXTENSION_V1,
    BUNDLE_MAGIC_V1, BundleError, MAX_ARCHIVE_BLOBS_V1, MAX_TOTAL_ARCHIVE_BYTES_V1,
};
pub use ea_crypto::HpkeRecipientPrivateKey;
pub use ea_schema::{PayloadV1, SchemaRegistry};
pub use ea_sync_protocol::HttpMethod;
pub use ea_trust::{TrustAnchorV1, decode_trust_anchor};
pub use ea_types::{
    ChainSequence, DestructionId, EntryHash, EntryStatus, Hash32, KeyThumbprint, ObjectHash,
    OrganizationId, RecordId, RegistryVersion, SubjectId, UnixMillis, VerificationStatus,
};
pub use ea_verify::{
    AuthorizedDestructionV1, ChainGapV1, DECAPSULATION_EVENT_V1, DestructionStateV1, GATE_ORDER_V1,
    Gate, GateObserver, ObjectErrorV1, ObjectResultKindV1, ObjectResultV1, QuarantinedObjectV1,
    RecordingObserver, ServerConfirmationV1, SilentObserver, VerificationReportV1, VerifyError,
};
pub use enrollment::{
    AttestedAuthenticatorV1, AuthenticatorRecordV1, AuthenticatorTransportProfileV1,
    DeviceTrustStateV1, ENROLLMENT_SIGNATURE_WINDOW_SECONDS_V1, EnrolledReaderV1, EnrollmentError,
    EnrollmentFingerprintsV1, EnrollmentRequestContextV1, FingerprintConfirmationV1,
    MIN_ENROLLED_AUTHENTICATORS_V1, READER_VAULT_BLOB_KEY_V1, ReaderEnrollment, VAULT_PRF_SALT_V1,
    recover_and_unlock_vault,
};
pub use enrollment_endpoints::{
    EnrollmentCallV1, EnrollmentEndpointError, EnrollmentEndpoints, EnrollmentRequestV1,
    InMemoryEnrollmentEndpoints,
};
pub use entry_state::{ReaderEntryStateStore, ReaderEntryStateV1};
pub use envelope::{
    AuthenticatorPrfV1, VAULT_INDEX_INFO_V1, VAULT_KEK_INFO_V1, VaultEnvelopeV1, derive_kek_v1,
};
pub use file_mode::{OpenedArchiveV1, ReaderFileMode, ReaderFileModeError};
pub use grant::{VerifiedEncryptedEntry, VerifiedGrantForRecipient};
pub use http::ReaderRequestV1;
pub use key_profile::{ReaderKeyProfile, ReaderKeyProfileError};
pub use mode::ReaderMode;
pub use search::{ReaderSearch, indexable_record};
pub use sync::{
    READER_SYNC_SIGNATURE_WINDOW_SECONDS_V1, ReaderSyncError, ReaderSyncFaultPoint,
    ReaderSyncService,
};
pub use trust_state::{
    ReaderTrustAgeV1, ReaderTrustStateStore, ReaderTrustStateV1, reader_trust_age_view,
};
pub use vault::{ReaderVault, ReaderVaultError, SealedVaultV1, UnlockedVault, VaultContentsV1};
pub use verify::{ReaderClassification, ReaderError, ReaderVerifier};
