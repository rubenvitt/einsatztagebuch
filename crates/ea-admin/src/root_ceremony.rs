//! Der Zeremoniendienst: die Reihenfolge IST seine Zusicherung.

use ea_audit::{AuditActorProof, LocalAuditService, TypedLocalAuditEvent};
use ea_crypto::{
    CanonicalPublicCoseKey, ContentType, ProtectedHeader, VerificationContext, object_hash,
    parse_cose_sign1, trust_digest,
};
use ea_format::{
    AdminRootContextV1, DecodedTrustPayloadV1, ExactObjectBytes, LocalAuditActionV1,
    LocalAuditOutcomeV1, ParsedArchiveObject, TrustObjectV1, TrustPayloadV1, decode_exact_object,
    encode_trust,
};
use ea_key_provider::{KeyHandle, KeyProvider};
use ea_operator::{OperatorSessionProof, ReauthPurpose};
use ea_trust::{
    SelectedRegistryHead, TrustStateStore, VerifiedAdminAuthorizationIntent,
    consume_admin_authorization_intent,
};
use ea_types::{CertificateHash, ObjectHash};

use crate::error::AdminError;

/// Der Dienst, der ein autorisiertes Ziel Wurzel-signiert veroeffentlicht.
///
/// Er wird JE KOPFAUSWAHL gebaut, und das ist keine Bequemlichkeit: die Zeit,
/// gegen die der Bedienernachweis bewertet wird, ist die
/// `PreexistingEffectiveNow` des gewaehlten Kopfes, und
/// `SignedLocalAuditService::new` bindet dieselbe Zeit ebenfalls beim Bauen
/// (`crates/ea-audit/src/repository.rs`). Ein Dienst, der ueber zwei
/// Kopfauswahlen hinweg lebte, fuehrte zwei Zeiten.
///
/// Er ist SYNCHRON, wie der ganze Rust-Kern. Async lebt ausschliesslich in
/// `apps/desktop/src-tauri` ueber `spawn_blocking`
/// (`crates/ea-key-provider/src/contract.rs`).
pub struct RootCeremonyService<'a> {
    head: &'a SelectedRegistryHead,
    key_provider: &'a dyn KeyProvider,
    root_signing_handle: KeyHandle,
    root_certificate_hash: CertificateHash,
    audit: &'a dyn LocalAuditService,
    operator_binding_object_hash: ObjectHash,
}

impl<'a> RootCeremonyService<'a> {
    /// Baut den Dienst gegen genau einen gewaehlten Kopf.
    ///
    /// `root_signing_handle` ist die ADRESSE des Wurzelschluessels in dem
    /// Schluesselspeicher, den `key_provider` bedient — kein
    /// Schluesselmaterial. `ea_key_provider::SecretPurpose` kennt bewusst
    /// keinen Wurzelzweck: die vier lokalen Zwecke sind die eines
    /// WRITER-Geraets, und ein Wurzelschluessel liegt dort nie. Diese Crate
    /// erfindet deshalb keinen fuenften Zweck; sie nimmt den Griff entgegen,
    /// den der Wirt der Zeremonie — ein dediziertes Offline-Geraet — ihr gibt.
    #[must_use]
    pub const fn new(
        head: &'a SelectedRegistryHead,
        key_provider: &'a dyn KeyProvider,
        root_signing_handle: KeyHandle,
        root_certificate_hash: CertificateHash,
        audit: &'a dyn LocalAuditService,
        operator_binding_object_hash: ObjectHash,
    ) -> Self {
        Self {
            head,
            key_provider,
            root_signing_handle,
            root_certificate_hash,
            audit,
            operator_binding_object_hash,
        }
    }

    /// Signiert das BEABSICHTIGTE Ziel, verbraucht seine Autorisierung und
    /// gibt die exakten Objektbytes heraus — in genau dieser Reihenfolge.
    ///
    /// # Warum die ABSICHT und nicht das veroeffentlichte Ziel
    ///
    /// [`ea_trust::verify_authorized_trust_target`] ist die Laufzeitrichtung:
    /// sie schlaegt ihr Ziel im Katalog nach und prueft daran die VORHANDENE
    /// Wurzelsignatur. Ein Wirt, der eine Wurzelaenderung erst noch
    /// veroeffentlichen will, hat weder das Katalogobjekt noch die Signatur
    /// und bekaeme `EA-TRUST-SOURCE` — der Dienst koennte dann nur
    /// nachsignieren, was ohnehin schon da ist, und waere fuer seinen eigenen
    /// Zweck unbrauchbar. [`VerifiedAdminAuthorizationIntent`] ist die
    /// Spiegelhaelfte fuer die Zeit VOR der Signatur.
    ///
    /// # Die Reihenfolge
    ///
    /// ZUERST jede reine Pruefung, DANN erst der Verbrauch:
    ///
    /// 1. Der frische Bedienernachweis: Zweck und Gueltigkeit, die Aktivitaet
    ///    seiner Bindung am gewaehlten Kopf, und dass es die Bindung ist, fuer
    ///    die dieser Dienst handelt.
    /// 2. Die Bindung des Beweiszustands an DIESEN Kopf: Registrierungsfassung
    ///    und Kopfhash.
    /// 3. Die Autorisierungsbytes sind die, ueber die der Beweiszustand
    ///    spricht, und der Subtyp der Nutzlast ist der bewiesene.
    /// 4. Die Wurzelsignatur ueber [`VerificationContext::root_trust_digest`]
    ///    und den Schluesselport — und unmittelbar danach ihre ZUSCHREIBUNG
    ///    an die Wurzelurkunde des gewaehlten Kopfes.
    /// 5. Die Kodierung ueber [`encode_trust`] — `ExactObjectBytes::new` ist
    ///    `pub(crate)` in `ea-format`, es gibt keinen zweiten Weg.
    /// 6. **Erst jetzt** die Einmal-Nutzung ueber
    ///    [`consume_admin_authorization_intent`]. Scheitert sie, wird eine
    ///    Zeile mit dem Ausgang `failed` gebucht: der Verbrauch setzt seine
    ///    beiden Sperrdimensionen NACHEINANDER, ein Ausfall dazwischen liesse
    ///    die Autorisierung sonst ohne jede Auditspur tot zurueck.
    /// 7. Die `adminRootCeremony`-Auditzeile. Ein separates `flush` gibt es
    ///    nicht: `record_signed` kodiert, signiert, liest die COSE gegen den
    ///    Kern zurueck und bucht in EINER Transaktion, bevor es zurueckkehrt.
    /// 8. Erst danach die Bytes.
    ///
    /// # Warum der Verbrauch NACH allen Pruefungen steht
    ///
    /// Eine Administrationsautorisierung ist organisationsweit EINMAL nutzbar
    /// und wird von zwei Administratoren ausgestellt. Verbraucht der Dienst
    /// sie, bevor er weiss, ob er ueberhaupt veroeffentlichen kann, dann macht
    /// ein falsch konfigurierter Signaturgriff oder ein kurz nicht
    /// erreichbarer Schluesselspeicher sie endgueltig unbrauchbar —
    /// fail-closed, aber ein Verfuegbarkeitsloch, und ohne Auditspur nicht
    /// einmal erklaerbar. Nach dieser Reihenfolge gibt es keinen Abbruch mehr,
    /// der verbraucht und schweigt: was verbraucht, veroeffentlicht auch, oder
    /// es hinterlaesst eine Zeile mit dem Ausgang `failed`.
    ///
    /// Die Zusicherung „der Verbrauch ist atomar mit der Veroeffentlichung"
    /// bleibt erhalten. Zwischen Verbrauch und Auditzeile liegt keine
    /// Pruefung mehr, die scheitern koennte; und die Sperre selbst ist die
    /// Prueft-und-setzt-Bewegung des Speichers
    /// (`TrustStateStore::admin_authorization_consumed`), also kann ein
    /// zweiter, gleichzeitiger Verbraucher zwischen Signatur und Verbrauch
    /// nicht durchschluepfen — er faende die Sperrzeile bereits gesetzt.
    ///
    /// # Fail-closed
    ///
    /// Scheitert die Auditzeile, werden die Zielbytes NICHT freigegeben, und
    /// eine zweite Zeile mit [`LocalAuditOutcomeV1::Failed`] wird versucht —
    /// nach dem Muster von `crates/ea-archive-fs/src/profile_migration.rs`.
    /// Scheitert auch sie, bleibt der urspruengliche Fehler der gemeldete: ein
    /// zweiter Fehler darf den ersten nicht verdecken.
    ///
    /// # Was dieser Dienst NICHT feststellt
    ///
    /// Die VOLLSTAENDIGKEIT des Paares — ob das erzeugte Objekt in einem
    /// Kopfuebergang wirklich Autoritaet erlangt. Das stellt allein
    /// `ea_trust::verify_registry_candidate` fest, und es haengt an Dingen,
    /// die hier noch gar nicht entschieden sind (Sequenzfenster,
    /// Kettenfortschreibung). Die ZUSCHREIBUNG der Signatur an die
    /// Wurzelurkunde dieses Kopfes stellt er dagegen sehr wohl fest, siehe
    /// Schritt 4.
    ///
    /// # Errors
    ///
    /// [`AdminError::ReauthMismatch`], [`AdminError::BindingInactive`] und
    /// [`AdminError::BindingMismatch`] fuer den Nachweis,
    /// [`AdminError::HeadMismatch`] fuer einen Beweiszustand aus einem anderen
    /// Registrierungsstand, [`AdminError::AuthorizationMismatch`] fuer
    /// Autorisierungsbytes, die der Beweiszustand nicht nennt,
    /// [`AdminError::TargetMismatch`] fuer eine Nutzlast eines anderen
    /// Subtyps, [`AdminError::Crypto`] und [`AdminError::Key`] fuer die
    /// Signatur, [`AdminError::RootCertificateMismatch`] und
    /// [`AdminError::RootSignatureMismatch`] fuer eine Signatur, die der
    /// Wurzel dieses Kopfes nicht zuschreibbar ist,
    /// [`AdminError::Format`] fuer die Kodierung,
    /// [`AdminError::Trust`] fuer den Verbrauch — insbesondere
    /// `EA-TRUST-AUTH-REPLAY` bei der zweiten Nutzung — und
    /// [`AdminError::AuditFailed`] fuer die Auditzeile.
    pub fn publish_authorized_target(
        &self,
        intent: &VerifiedAdminAuthorizationIntent,
        target: TrustPayloadV1,
        exact_admin_authorization_object: &[u8],
        store: &mut dyn TrustStateStore,
        proof: &OperatorSessionProof,
    ) -> Result<ExactObjectBytes, AdminError> {
        // 1. Der Nachweis. `is_valid_for` prueft die Bindung ausdruecklich
        //    NICHT (`crates/ea-operator/src/session.rs`), also prueft dieser
        //    Dienst sie selbst — beides: dass die genannte Bindung am
        //    gewaehlten Kopf ueberhaupt aktiv ist, und dass es die Bindung
        //    ist, fuer die er handelt. Ohne den zweiten Vergleich ginge der
        //    Nachweis JEDER gebundenen Bedienerin derselben Organisation
        //    durch, und die Auditzeile rechnete die Zeremonie dem falschen
        //    Bediener zu.
        if !proof.is_valid_for(
            ReauthPurpose::AdminRootCeremony,
            self.head.preexisting_effective_now(),
        ) {
            return Err(AdminError::ReauthMismatch);
        }
        if self
            .head
            .active_operator_binding_fields(proof.binding_object_hash())
            .is_none()
        {
            return Err(AdminError::BindingInactive);
        }
        if proof.binding_object_hash() != self.operator_binding_object_hash {
            return Err(AdminError::BindingMismatch);
        }

        // 2. Der Beweiszustand gehoert an DIESEN Kopf. Zeit,
        //    Bedienerbindung, Wurzelzertifikat und Auditdienst kommen aus
        //    `self.head`; ein Beweis, der gegen einen anderen
        //    Registrierungsstand gefuehrt wurde, darf hier nicht wirken.
        if intent.previous_registry_version() != self.head.registry_version()
            || intent.previous_registry_head_hash().as_bytes()
                != self.head.registry_head_hash().as_bytes()
        {
            return Err(AdminError::HeadMismatch);
        }

        // 3. Die Autorisierungsbytes muessen die des Beweiszustands sein. Er
        //    nennt seinen Objekthash selbst; der Aufrufer waehlt sie nicht
        //    aus, sonst koennte er eine passendere unterschieben.
        if object_hash(exact_admin_authorization_object) != intent.authorization_object_hash() {
            return Err(AdminError::AuthorizationMismatch);
        }
        if target.subtype() != intent.target_trust_subtype() {
            return Err(AdminError::TargetMismatch);
        }
        let action_code = admin_action_code(exact_admin_authorization_object)?;

        // 4. Die Wurzelsignatur. Der Kontext ist hier die PRUEFUNG und nicht
        //    das Ergebnis: er bindet `[targetTrustSubtype, authorizedTrustCore]`
        //    an `authorizedTrustCoreHash` der Autorisierung — also an genau
        //    den Wert, den `intent.authorized_target_core_hash()` nennt, denn
        //    die Autorisierungsbytes sind eine Zeile hoeher gegen den
        //    Beweiszustand gestellt worden. Der Kernhash wird deshalb NICHT
        //    ein zweites Mal in dieser Crate gebildet: das Praefix
        //    `[targetTrustSubtype, authorizedTrustCore]` hat mit
        //    `ea_trust::exact_authorized_core_hash` und
        //    `ea_crypto::root_trust_bindings` bereits zwei Kodierer, und eine
        //    dritte Kopie waere eine dritte Wahrheit.
        VerificationContext::root_trust_digest(
            target.exact_digest_input(),
            self.root_certificate_hash,
            Some(exact_admin_authorization_object),
        )
        .map_err(AdminError::Crypto)?;
        let digest = trust_digest(target.exact_digest_input());
        let signature = self
            .key_provider
            .sign(
                &self.root_signing_handle,
                ContentType::TrustDigest,
                self.root_certificate_hash,
                digest.as_bytes(),
            )
            .map_err(AdminError::Key)?;

        // 4b. Die ZUSCHREIBUNG. Ohne sie gaebe der Dienst Bytes heraus, die
        //     nie Autoritaet erlangen koennen — und verbrauchte dafuer eine
        //     Einmal-Autorisierung und buchte eine `completed`-Zeile.
        self.require_root_attribution(signature.as_bytes(), digest.as_bytes())?;

        // 5. Die Kodierung.
        let object = TrustObjectV1::new(target, vec![signature.as_bytes().to_vec()])
            .map_err(AdminError::Format)?;
        let published = encode_trust(&object).map_err(AdminError::Format)?;
        let target_object_hash = object_hash(published.as_bytes());

        // 6. Erst jetzt der Verbrauch. Scheitert er, kann er die erste
        //    Sperrdimension bereits gesetzt haben — `consume_replay_keys` setzt
        //    sie nacheinander —, und die Autorisierung waere ohne Auditspur
        //    tot. Deshalb bucht auch dieser Pfad eine `failed`-Zeile.
        if let Err(error) = consume_admin_authorization_intent(store, intent) {
            self.book_failure(proof, intent, target_object_hash, action_code);
            return Err(AdminError::Trust(error));
        }

        // 7. Die Auditzeile, VOR der Herausgabe.
        let context = AdminRootContextV1::new(
            intent.authorization_object_hash(),
            target_object_hash,
            action_code,
        );
        if self
            .audit
            .record_signed(
                // DER GEPRUEFTE Nachweis, nicht ein mitgefuehrter: eine
                // Auditzeile, die jemand anderem zugerechnet wird als dem,
                // dessen Zweck und Bindung geprueft wurden, waere falsch
                // zugerechnet.
                AuditActorProof::OperatorSession(proof),
                TypedLocalAuditEvent {
                    action: LocalAuditActionV1::AdminRootCeremony(context),
                    outcome: LocalAuditOutcomeV1::Completed,
                },
            )
            .is_err()
        {
            self.book_failure(proof, intent, target_object_hash, action_code);
            return Err(AdminError::AuditFailed);
        }

        // 8. Erst jetzt.
        Ok(published)
    }

    /// Stellt fest, dass die frisch erzeugte COSE der Wurzelurkunde DIESES
    /// Kopfes zuschreibbar ist.
    ///
    /// Zwei Fragen, beide fail-closed:
    ///
    /// 1. Ist der Zertifikatshash, unter dem dieser Dienst signieren laesst,
    ///    ueberhaupt der der Wurzelurkunde des gewaehlten Kopfes? Er ist ein
    ///    Parameter des Aufrufers, und ein falsch konfigurierter waere sonst
    ///    unsichtbar.
    /// 2. Stammt die Signatur von dem Schluessel, den diese Urkunde nennt?
    ///    Geprueft wird BEIDES: der Abdruck im geschuetzten Kopf gegen
    ///    `rootKeyThumbprint`, und die Signatur selbst gegen den oeffentlichen
    ///    Schluessel der Urkunde. Der Abdruck allein genuegte nicht — ein
    ///    Provider, der ihn behauptet und mit einem anderen Schluessel
    ///    unterschreibt, kaeme durch.
    ///
    /// Der geschuetzte Kopf wird dafuer aus den ZURUECKGELESENEN Werten neu
    /// gebildet und nicht aus den eigenen:
    /// `ProtectedHeader::to_deterministic_cbor` ist kanonisch, also ergibt
    /// dieselbe Eingabe dieselben Bytes, und eine nicht rekonstruierbare
    /// Kodierung scheitert hier — fail-closed.
    ///
    /// # Warum das nicht `ea_crypto::verify_cose_sign1` ist
    ///
    /// Jener Weg verlangt einen `ea_crypto::SignerCertificateResolver` ueber
    /// die exakten Zertifikatsbytes; der einzige, der die Wurzellinie kennt,
    /// ist `ea_trust::PreviousHeadResolver`, und der ist crate-privat. Diese
    /// Crate liest stattdessen die zwei oeffentlichen Werte der Wurzelurkunde
    /// und prueft dieselbe Gleichung.
    fn require_root_attribution(
        &self,
        exact_cose: &[u8],
        expected_payload: &[u8],
    ) -> Result<(), AdminError> {
        if self.root_certificate_hash
            != CertificateHash::from(self.head.root_certificate_object_hash())
        {
            return Err(AdminError::RootCertificateMismatch);
        }
        let fields = self.head.root_certificate_fields();
        let parsed = parse_cose_sign1(exact_cose, &[]).map_err(AdminError::Crypto)?;
        if parsed.content_type() != ContentType::TrustDigest
            || parsed.certificate_hash() != Some(self.root_certificate_hash)
            || parsed.payload() != expected_payload
            || parsed.key_thumbprint() != fields.root_key_thumbprint
        {
            return Err(AdminError::RootSignatureMismatch);
        }
        let key = CanonicalPublicCoseKey::from_deterministic_cbor(&fields.root_public_cose_key)
            .map_err(AdminError::Crypto)?;
        let protected = ProtectedHeader::normal(
            ContentType::TrustDigest,
            parsed.key_thumbprint(),
            self.root_certificate_hash,
        );
        key.verify_ed25519_strict(
            &protected.sig_structure_bytes(expected_payload),
            parsed.signature_bytes(),
        )
        .map_err(|_| AdminError::RootSignatureMismatch)
    }

    /// Bucht die Zeile mit dem Ausgang `failed`.
    ///
    /// Ohne Rueckgabe und ohne Fehlerweg: scheitert auch sie, bleibt
    /// [`AdminError::AuditFailed`] der gemeldete Fehler. Ein zweiter Fehler
    /// darf den ersten nicht verdecken.
    fn book_failure(
        &self,
        proof: &OperatorSessionProof,
        intent: &VerifiedAdminAuthorizationIntent,
        target_object_hash: ObjectHash,
        action_code: u64,
    ) {
        let _ = self.audit.record_signed(
            AuditActorProof::OperatorSession(proof),
            TypedLocalAuditEvent {
                action: LocalAuditActionV1::AdminRootCeremony(AdminRootContextV1::new(
                    intent.authorization_object_hash(),
                    target_object_hash,
                    action_code,
                )),
                outcome: LocalAuditOutcomeV1::Failed,
            },
        );
    }
}

/// Der Aktionscode der Administrationsautorisierung.
///
/// Er wird aus DEN BYTES gelesen, die der Beweiszustand als seine
/// Autorisierung nennt, und nicht aus einem Parameter: die dritte Position von
/// `admin-root-context-v1` (`schemas/reports/v1/local-audit.cddl`) ist der
/// `action-code` der Autorisierung, und eine Auditzeile, die ihn frei
/// entgegennaehme, koennte eine Aktion behaupten, die nie autorisiert war.
///
/// # Warum das kein ZWEITER Leser ist
///
/// Es ist derselbe Leser, den die Autorisierungspruefung fuehrt:
/// `ea_trust::verify_admin_authorization` deutet die Autorisierung ueber
/// `decoded_payload`, also ueber `ea_format`, und stellt deren `action_code`
/// gegen `descriptor.required_action` aus der geschlossenen Aktionstabelle.
/// Wer einen [`VerifiedAdminAuthorizationIntent`] in der Hand haelt, weiss
/// damit bereits, dass dieser Wert der von der Tabelle geforderte ist — diese
/// Funktion liest ihn nur noch ab. `ea_crypto` liest denselben Wert an der
/// Signaturgrenze ein weiteres Mal; dass alle Leser uebereinstimmen, pinnt
/// `every_reachable_action_code_reaches_the_audit_line_unchanged`.
fn admin_action_code(exact_admin_authorization_object: &[u8]) -> Result<u64, AdminError> {
    let ParsedArchiveObject::Trust(parsed) =
        decode_exact_object(exact_admin_authorization_object).map_err(AdminError::Format)?
    else {
        return Err(AdminError::AuthorizationMismatch);
    };
    let DecodedTrustPayloadV1::OrganizationAdminAuthorization(fields) = parsed
        .value()
        .decoded_payload()
        .map_err(AdminError::Format)?
    else {
        return Err(AdminError::AuthorizationMismatch);
    };
    Ok(u64::from(fields.action_code))
}
