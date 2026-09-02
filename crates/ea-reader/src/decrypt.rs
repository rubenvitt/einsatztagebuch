//! Die Entkapselung hinter dem neunten Gate — und die vollstaendige Flaeche,
//! ueber die der Klartext danach erreichbar ist.
//!
//! # KEIN zehntes Gate
//!
//! `design.md` §14.1 kennt neun Gates; die Entkapselung folgt AUF das neunte,
//! und keine Verifikationsentscheidung haengt an ihr. [`decrypt_verified`] ruft
//! `observer.on_decapsulation()` deshalb direkt auf dem Trait und niemals
//! `on_gate` — ein frischer `RecordingObserver` traegt danach genau
//! `["hpke-open"]` ohne Gate-Praefix.
//!
//! # Die Rechnung ist die von `ea_verify::open_entry`, Schritt fuer Schritt
//!
//! `exact_grant_context()`, `HpkeSealed::from_parts`, `hpke_open` ueber
//! `hpke_info`/`hpke_aad` DERSELBEN Kontextbytes, dann `aead_open` mit dem
//! Nonce aus `manifest().fields().nonce` und `payload_aad` ueber
//! `manifest().exact_bytes()` — den Manifest-KERN und nicht das signierte
//! Manifest. Die Kontextbytes werden hier NICHT ein drittes Mal
//! zusammengeschnitten: `ea_format::GrantBodyV1::exact_grant_context` gibt sie
//! oeffentlich heraus, und ihr Waechter beweist den Schnitt, statt ihn zu
//! raten.
//!
//! Der EINZIGE Unterschied zu `open_entry` ist der, den der Reader braucht:
//! `open_entry` verwirft den Klartext mit `drop(plaintext)`, weil `ea-verify`
//! ihn nie herausgeben darf, und der Reader muss ihn anzeigen. Genau das kostet
//! die zweite Entkapselung: `claim_own_grants` faehrt bereits archivweit N
//! HPKE-Entkapselungen und N AEAD-Oeffnungen, deren Klartext verworfen wird,
//! und je angezeigtem Eintrag kommt eine weitere dazu. Das ist der Preis dafuer,
//! dass der Klartext die Grenze von `ea-verify` nicht ueberschreitet.
//!
//! # Die Schemabestimmung laeuft durch PROBIEREN
//!
//! `SchemaRegistry::validate` und `::derive_view` nehmen `schema_id` und
//! `schema_version` als EINGABE; `decode_common_header` ist dort `pub(crate)`,
//! und weder `ManifestCoreFieldsV1` noch `GrantBodyFieldsV1` traegt ein
//! Schemafeld. Es gibt also keinen Schnueffelweg. [`decrypt_verified`] laeuft
//! deshalb `SchemaRegistry::schemas()` in der gelieferten Reihenfolge durch;
//! der erste Erfolg gewinnt, und das ist deterministisch, weil `schemas()` ein
//! `&'static [SchemaDescriptor]` fester Reihenfolge liefert. Eine
//! `sniff`-Funktion in `ea-schema` waere billiger, hiesse aber eine
//! abgeschlossene Stufe-1-Crate anzufassen. Ein zweiter CBOR-Parser entsteht in
//! dieser Crate ausdruecklich NICHT.

use core::fmt;

use ea_crypto::{
    AEAD_NONCE_SIZE, HpkeSealed, SecretBytes, SecretVec, aead_open, hpke_aad, hpke_info, hpke_open,
    payload_aad,
};
use ea_format::{
    EntryPackageV1, FormatError, GrantV1, Parsed, ParsedArchiveObject, decode_exact_object,
};
use ea_schema::{PayloadV1, SchemaRegistry};
use ea_types::{ChainSequence, EntryHash, ObjectHash, UnixMillis};
use ea_verify::{DecryptionErrorV1, GateObserver};

use crate::grant::{VerifiedEncryptedEntry, VerifiedGrantForRecipient};
use crate::vault::UnlockedVault;
use crate::verify::ReaderError;

/// Oeffnet GENAU EINEN Eintrag.
///
/// Die zwei Zeugen sind die ganze Zugangsbedingung: sie entstehen nur in
/// [`crate::ReaderClassification`], nur paarweise und nur fuer einen Eintrag,
/// den der Bericht als `ObjectResultKindV1::Valid` fuehrt, den kein Fehlerfeld
/// nennt und dessen eigener Grant weder isoliert ist noch einen Befund traegt.
///
/// # Die Frischepruefung ist EXAKT und ohne Toleranz
///
/// Ein Zeuge gilt fuer den Lauf, in dem er entstand, weil Gate
/// `recipient-grant` seine Nutzungsfrist gegen genau diesen `effectiveNow`
/// gemessen hat. Eine Toleranz waere hier keine Milde, sondern die Behauptung,
/// eine ANDERE Frist gemessen zu haben als die, die tatsaechlich gemessen
/// wurde.
///
/// # Ein gekreuztes Zeugenpaar faellt an der AEAD-Bindung
///
/// Ein Grant, der einen anderen Eintrag benennt, wird hier nicht gesondert
/// abgewiesen und braucht auch keinen eigenen Code: `payload_aad` laeuft ueber
/// den Manifest-KERN DIESES Eintrags, der entkapselte CEK gehoert aber zu einem
/// anderen — `aead_open` faellt dann mit
/// `EA-VERIFY-DECRYPT-PAYLOAD-OPEN-FAILED`. Die Bindung ist die Pruefung.
///
/// # Errors
///
/// [`ReaderError::StaleWitness`] mit `EA-READER-WITNESS-STALE`, wenn
/// `effective_now` von dem Lauf abweicht, in dem die Zeugen entstanden.
/// [`ReaderError::UnsupportedSchema`] mit `EA-READER-SCHEMA-UNSUPPORTED`, wenn
/// keine der Schemabestimmungen den Klartext traegt. Ausserdem
/// `EA-VERIFY-DECRYPT-CEK-UNWRAP-FAILED` und
/// `EA-VERIFY-DECRYPT-PAYLOAD-OPEN-FAILED` als DURCHGEREICHTE Codes, sowie der
/// Code von `ea_format::decode_exact_object`.
pub fn decrypt_verified(
    entry: &VerifiedEncryptedEntry,
    grant: &VerifiedGrantForRecipient,
    session: &UnlockedVault,
    schemas: &SchemaRegistry,
    effective_now: UnixMillis,
    observer: &mut dyn GateObserver,
) -> Result<VerifiedDecryptedRecord, ReaderError> {
    if entry.minted_at() != effective_now || grant.minted_at() != effective_now {
        return Err(ReaderError::StaleWitness);
    }

    let entry_package = decoded_entry(entry)?;
    let grant_object = decoded_grant(grant)?;
    let body = grant_object.value().grant_body();
    // DER ERSTE SCHRITT, und er ist keiner, den man ueberspringt: der
    // `grant-context-v1` wird aus dem Rumpf HERAUSGESCHNITTEN, und der Waechter
    // in `ea-format` weist einen Rumpf ab, dessen Schwanz nicht exakt zu seinen
    // dekodierten Feldern passt. Eine Entkapselung auf geratenen Kontextbytes
    // gibt es hier nicht.
    let context = body
        .exact_grant_context()
        .ok_or(DecryptionErrorV1::CekUnwrapFailed)?;
    let fields = body.fields();
    let sealed = HpkeSealed::from_parts(fields.encapsulated_key, fields.wrapped_cek)
        .map_err(|_| DecryptionErrorV1::CekUnwrapFailed)?;
    let cek = hpke_open(
        session.kem_private_key(),
        &sealed,
        &hpke_info(context),
        &hpke_aad(context),
    )
    .map_err(|_| DecryptionErrorV1::CekUnwrapFailed)?;
    let manifest = entry_package.value().manifest();
    let nonce: SecretBytes<AEAD_NONCE_SIZE> = SecretBytes::new(manifest.fields().nonce);
    let plaintext = aead_open(
        &cek,
        &nonce,
        entry_package.value().ciphertext(),
        &payload_aad(manifest.exact_bytes()),
    )
    .map_err(|_| DecryptionErrorV1::PayloadOpenFailed)?;

    // HPKE-OPEN, KEIN GATE. Erst hier, hinter dem neunten, und genau einmal.
    observer.on_decapsulation();

    // Die vier Schemaspalten werden HERAUSGEZOGEN und die `DerivedView` faellt
    // noch INNERHALB der Ausleihe. Sie haelt ein `ea_schema::ValidatedPayload`,
    // und dessen `exact_bytes: Vec<u8>` ist eine zweite, NICHT ueberschriebene
    // Kopie des Klartexts — siehe die benannte Restfrage an
    // [`VerifiedDecryptedRecord`]. Je kuerzer diese Kopie lebt, desto kleiner
    // bleibt die Luecke.
    let schema = plaintext.with_exposed(|bytes| determined_schema(schemas, bytes))?;

    Ok(VerifiedDecryptedRecord {
        plaintext,
        entry_hash: entry.entry_hash(),
        chain_sequence: entry.chain_sequence(),
        object_hash: entry.object_hash(),
        minted_at: effective_now,
        schema,
    })
}

/// Die vier Schemaspalten EINES Klartexts.
#[derive(Clone, Copy, Eq, PartialEq)]
struct SchemaColumnsV1 {
    source_schema_id: &'static str,
    source_schema_version: u64,
    target_schema_id: &'static str,
    target_schema_version: u64,
}

/// Der geoeffnete Eintrag: Herkunftsspalten und ein Klartext, der nur
/// AUSGELIEHEN wird.
///
/// # Der Klartext hat KEINEN Fluchtweg
///
/// Es gibt ausdruecklich KEIN `exact_plaintext_bytes() -> &[u8]` und KEIN
/// `payload() -> &PayloadV1`, kein `Deref`, kein `Clone` und kein abgeleitetes
/// `Debug`. Ein Zugriff, der eine Ausleihe auf die Bytes ODER auf die geparste
/// Nutzlast HERAUSGIBT, ist ein Klartext-Fluchtweg aus einem
/// [`ea_crypto::SecretVec`]: der Aufrufer koennte sie beliebig lange halten,
/// kopieren, in ein `Vec` heben und ablegen, und `ZeroizeOnDrop` griffe auf die
/// Kopie nie. Genau das verbieten `WR-082` (keine Zwischenablage-, Log- oder
/// Telemetriewege fuer entschluesselte Inhalte), `FR-105` (Einzelexport mit
/// bewusster Zielwahl statt beliebiger Herausgabe) und die Produktinvariante
/// „no decrypted content enters OPFS bytes in the clear".
///
/// Die Ausleihform macht die Reichweite des Klartexts zu einer TYPAUSSAGE: er
/// lebt genau so lange wie der Aufruf. ACHT Zugriffe, davon zwei ausleihend,
/// und jede spaetere Aufgabe dieses Plans benutzt AUSSCHLIESSLICH sie.
///
/// # Benannte Restfrage: `ea_schema::ValidatedPayload` loescht sich nicht
///
/// [`Self::with_payload`] dekodiert die Nutzlast bei JEDEM Aufruf neu und laesst
/// sie mit der Ausleihe fallen; der Typ haelt sie nicht in einem Feld. Was dabei
/// entsteht, ist trotzdem nicht ueberschrieben: `ValidatedPayload.exact_bytes`
/// ist ein gewoehnlicher `Vec<u8>`, dazu kommen die Rueckprobe-Kopie in
/// `SchemaRegistry::validate` und die dekodierten Zeichenketten in
/// [`PayloadV1`]. `ea_schema::DerivedView` besitzt dagegen KEINEN eigenen
/// Puffer — es haelt ein `ValidatedPayload`. Diese Werte zeroize-faehig zu
/// machen hiesse, eine abgeschlossene Stufe-1-Crate anzufassen; die Aufgabe
/// „Sitzungssperre, Zeroize, authenticator-bestätigter Einzelexport und
/// signiertes lokales Audit" besitzt die Zeroize-Zusage der Sitzung und
/// entscheidet dort, ob die Luecke geschlossen oder als dokumentierte
/// SOLL-Abweichung gefuehrt wird.
pub struct VerifiedDecryptedRecord {
    plaintext: SecretVec,
    entry_hash: EntryHash,
    chain_sequence: ChainSequence,
    object_hash: ObjectHash,
    minted_at: UnixMillis,
    schema: SchemaColumnsV1,
}

impl VerifiedDecryptedRecord {
    /// Der Eintragshash des geoeffneten Eintrags.
    #[must_use]
    pub const fn entry_hash(&self) -> EntryHash {
        self.entry_hash
    }

    /// Seine Kettensequenz.
    #[must_use]
    pub const fn chain_sequence(&self) -> ChainSequence {
        self.chain_sequence
    }

    /// Der Objekthash seines Eintragspakets.
    #[must_use]
    pub const fn object_hash(&self) -> ObjectHash {
        self.object_hash
    }

    /// Der Lauf, in dem die Zeugen entstanden.
    ///
    /// Die Frischepruefung von [`decrypt_verified`] misst gegen genau diesen
    /// Wert.
    #[must_use]
    pub const fn minted_at(&self) -> UnixMillis {
        self.minted_at
    }

    /// Schema-Kennung und -Fassung des QUELLDATENSATZES.
    #[must_use]
    pub const fn source_schema(&self) -> (&'static str, u64) {
        (
            self.schema.source_schema_id,
            self.schema.source_schema_version,
        )
    }

    /// Schema-Kennung und -Fassung der ABGELEITETEN Ansicht.
    ///
    /// In v1 ist die Ableitung die Identitaet, und beide Paare sind gleich; die
    /// Spalte steht trotzdem getrennt, weil sie es ab v2 nicht mehr ist.
    #[must_use]
    pub const fn target_schema(&self) -> (&'static str, u64) {
        (
            self.schema.target_schema_id,
            self.schema.target_schema_version,
        )
    }

    /// Der EINE Weg an die Klartextbytes: AUSGELIEHEN, nie herausgegeben.
    pub fn with_plaintext<R>(&self, use_it: impl FnOnce(&[u8]) -> R) -> R {
        self.plaintext.with_exposed(use_it)
    }

    /// Der EINE Weg an die geparste Nutzlast.
    ///
    /// [`PayloadV1`] wird bei JEDEM Aufruf INNERHALB der Ausleihe neu dekodiert
    /// und faellt mit ihr; der Typ haelt sie nicht in einem Feld. Das ist die
    /// Schranke, die die weitergereichte Restfrage zu `ValidatedPayload` klein
    /// haelt — und der Preis dafuer ist ein Validierungslauf je Aufruf.
    ///
    /// `SchemaRegistry` ist ein ZUSTANDSLOSER Einheitstyp mit genau einem
    /// Konstruktor; `SchemaRegistry::v1()` ist deshalb dieselbe Registrierung,
    /// die [`decrypt_verified`] bekommen hat, und kein zweiter Katalog daneben.
    ///
    /// # Panics
    ///
    /// Nie erreichbar: derselbe Klartext hat genau diese Bestimmung bereits in
    /// [`decrypt_verified`] getragen, und die Bytes liegen seither
    /// unveraendert in einem [`ea_crypto::SecretVec`], den niemand von aussen
    /// beschreiben kann.
    pub fn with_payload<R>(&self, use_it: impl FnOnce(&PayloadV1) -> R) -> R {
        self.plaintext.with_exposed(|bytes| {
            let view = SchemaRegistry::v1()
                .derive_view(
                    self.schema.source_schema_id,
                    self.schema.source_schema_version,
                    bytes,
                )
                .expect("ein bereits bestimmter Klartext traegt dieselbe Bestimmung erneut");
            use_it(view.payload())
        })
    }
}

impl fmt::Debug for VerifiedDecryptedRecord {
    /// Eintragshash, Sequenz und die Schemaspalten — und NIE eine Nutzlast.
    ///
    /// Ein abgeleitetes `Debug` waere hier unmoeglich ([`EntryHash`] traegt
    /// keins) und zugleich genau der Ausgabeweg, den `WR-082` verbietet.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedDecryptedRecord { entry_hash: ")?;
        for byte in self.entry_hash.as_bytes() {
            write!(formatter, "{byte:02x}")?;
        }
        write!(
            formatter,
            ", chain_sequence: {}, minted_at: {}, source_schema: {}/{}, target_schema: {}/{}, plaintext: <secret> }}",
            self.chain_sequence.get(),
            self.minted_at.get(),
            self.schema.source_schema_id,
            self.schema.source_schema_version,
            self.schema.target_schema_id,
            self.schema.target_schema_version,
        )
    }
}

/// Das Eintragspaket aus den exakten Bytes des Zeugen.
fn decoded_entry(entry: &VerifiedEncryptedEntry) -> Result<Parsed<EntryPackageV1>, ReaderError> {
    match decode_exact_object(entry.exact_entry_bytes())? {
        ParsedArchiveObject::Entry(parsed) => Ok(parsed),
        // UNERREICHBAR DURCH KONSTRUKTION: die Bytes kommen aus
        // `ArchiveInventory::entries()`, und dort steht, was das
        // Exact-Object-Praefix als `.eip` ausgewiesen hat. Fail-closed statt
        // `unreachable!` — eine Weigerung ist billiger als ein Abbruch im
        // Browser.
        _ => Err(ReaderError::Format(FormatError::Prefix)),
    }
}

/// Der Grant aus den exakten Bytes des Zeugen.
fn decoded_grant(grant: &VerifiedGrantForRecipient) -> Result<Parsed<GrantV1>, ReaderError> {
    match decode_exact_object(grant.exact_grant_bytes())? {
        ParsedArchiveObject::Grant(parsed) => Ok(parsed),
        _ => Err(ReaderError::Format(FormatError::Prefix)),
    }
}

/// Die erste Schemabestimmung, die diesen Klartext traegt.
///
/// Bis zu fuenf verworfene Validierungslaeufe je geoeffnetem Eintrag; das ist
/// die im Modulkommentar benannte Kosten­entscheidung.
fn determined_schema(
    schemas: &SchemaRegistry,
    plaintext: &[u8],
) -> Result<SchemaColumnsV1, ReaderError> {
    schemas
        .schemas()
        .iter()
        .find_map(|descriptor| {
            schemas
                .derive_view(
                    descriptor.schema_id(),
                    descriptor.schema_version(),
                    plaintext,
                )
                .ok()
        })
        .map(|view| SchemaColumnsV1 {
            source_schema_id: view.source_schema_id(),
            source_schema_version: view.source_schema_version(),
            target_schema_id: view.target_schema_id(),
            target_schema_version: view.target_schema_version(),
        })
        .ok_or(ReaderError::UnsupportedSchema)
}
