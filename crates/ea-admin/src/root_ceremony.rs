//! Der Zeremoniendienst: die Reihenfolge IST die Zusicherung.

use ea_audit::{AuditActorProof, LocalAuditService, TypedLocalAuditEvent};
use ea_crypto::{ContentType, VerificationContext, object_hash, trust_digest};
use ea_format::{
    AdminRootContextV1, DecodedTrustPayloadV1, ExactObjectBytes, LocalAuditActionV1,
    LocalAuditOutcomeV1, ParsedArchiveObject, TrustObjectV1, TrustPayloadV1, decode_exact_object,
    encode_trust,
};
use ea_key_provider::{KeyHandle, KeyProvider};
use ea_operator::{OperatorSessionProof, ReauthPurpose};
use ea_trust::{
    SelectedRegistryHead, TrustStateStore, VerifiedAdminAuthorization, consume_admin_authorization,
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
    /// Schluesselspeicher, den `key_provider` bedient — kein Schluesselmaterial.
    /// `ea_key_provider::SecretPurpose` kennt bewusst keinen Wurzelzweck: die
    /// vier lokalen Zwecke sind die eines WRITER-Geraets, und ein Wurzelschluessel
    /// liegt dort nie. Diese Crate erfindet deshalb keinen fuenften Zweck; sie
    /// nimmt den Griff entgegen, den der Wirt der Zeremonie — ein dediziertes
    /// Offline-Geraet — ihr gibt.
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

    /// Verbraucht die Autorisierung, signiert das Ziel und gibt seine exakten
    /// Objektbytes heraus — in genau dieser Reihenfolge.
    ///
    /// # Die Reihenfolge
    ///
    /// 1. Der frische Bedienernachweis: Zweck, Gueltigkeit UND Bindung. Vor
    ///    allem anderen, damit ein unbefugter Aufruf die Einmal-Nutzung nicht
    ///    verbrennt.
    /// 2. Die Einmal-Nutzung ueber [`consume_admin_authorization`] gegen einen
    ///    laufuebergreifenden Speicher.
    /// 3. Die Wurzelsignatur. [`VerificationContext::root_trust_digest`] setzt
    ///    die Bindung zwischen Zielkern und Autorisierung an der
    ///    Signaturgrenze durch, BEVOR der Schluesselport ueberhaupt gefragt
    ///    wird; signiert wird der `trust-digest` unter
    ///    [`ContentType::TrustDigest`], denn dieser Inhaltstyp ist ein
    ///    Digesttyp (`ContentType::is_digest`) und der Port verlangt dann genau
    ///    zweiunddreissig Nutzlastbytes.
    /// 4. Die Kodierung ueber [`encode_trust`] — `ExactObjectBytes::new` ist
    ///    `pub(crate)` in `ea-format`, es gibt keinen zweiten Weg.
    /// 5. Die `adminRootCeremony`-Auditzeile. Ein separates `flush` gibt es
    ///    nicht: `record_signed` kodiert, signiert, liest die COSE gegen den
    ///    Kern zurueck und bucht in EINER Transaktion, bevor es zurueckkehrt.
    /// 6. Erst danach die Bytes.
    ///
    /// # Warum die entstandenen Bytes gegen den Beweiszustand geprueft werden
    ///
    /// [`VerifiedAdminAuthorization`] spricht ueber EIN Zielobjekt, das im
    /// Katalog liegt und dessen Hash er nennt. Ed25519 signiert
    /// deterministisch, also ergibt dieselbe Nutzlast unter demselben
    /// Wurzelschluessel Byte fuer Byte dasselbe Objekt. Weicht der Hash ab, ist
    /// das, was hier entstuende, NICHT das autorisierte Ziel — ein fremder
    /// Schluessel, ein fremder Zertifikatshash oder eine fremde Nutzlast. Ohne
    /// diese Pruefung naennte die Auditzeile ein anderes Objekt als das, was der
    /// Aufrufer bekommt.
    ///
    /// # Fail-closed
    ///
    /// Scheitert die Auditzeile, werden die Zielbytes NICHT freigegeben, und
    /// eine zweite Zeile mit [`LocalAuditOutcomeV1::Failed`] wird versucht —
    /// nach dem Muster von `crates/ea-archive-fs/src/profile_migration.rs`.
    /// Scheitert auch sie, bleibt der urspruengliche Fehler der gemeldete: ein
    /// zweiter Fehler darf den ersten nicht verdecken.
    ///
    /// # Errors
    ///
    /// [`AdminError::ReauthMismatch`], [`AdminError::BindingMismatch`] und
    /// [`AdminError::BindingInactive`] fuer den Nachweis,
    /// [`AdminError::AuthorizationMismatch`] fuer Autorisierungsbytes, die der
    /// Beweiszustand nicht nennt, [`AdminError::Trust`] fuer den Verbrauch —
    /// insbesondere `EA-TRUST-AUTH-REPLAY` bei der zweiten Nutzung —,
    /// [`AdminError::Crypto`] und [`AdminError::Key`] fuer die Signatur,
    /// [`AdminError::Format`] fuer die Kodierung, [`AdminError::TargetMismatch`]
    /// fuer ein anderes als das autorisierte Ziel und
    /// [`AdminError::AuditFailed`] fuer die Auditzeile.
    pub fn publish_authorized_target(
        &self,
        authorization: &VerifiedAdminAuthorization,
        target: TrustPayloadV1,
        exact_admin_authorization_object: &[u8],
        store: &mut dyn TrustStateStore,
        proof: &OperatorSessionProof,
    ) -> Result<ExactObjectBytes, AdminError> {
        // 1. Der Nachweis. `is_valid_for` prueft die Bindung ausdruecklich
        //    NICHT (`crates/ea-operator/src/session.rs`), also prueft dieser
        //    Dienst sie selbst — sonst ginge jeder Nachweis desselben Zwecks
        //    durch, auch einer fuer einen anderen Bediener.
        if !proof.is_valid_for(
            ReauthPurpose::AdminRootCeremony,
            self.head.preexisting_effective_now(),
        ) {
            return Err(AdminError::ReauthMismatch);
        }
        if proof.binding_object_hash() != self.operator_binding_object_hash {
            return Err(AdminError::BindingMismatch);
        }
        if self
            .head
            .active_operator_binding_fields(self.operator_binding_object_hash)
            .is_none()
        {
            return Err(AdminError::BindingInactive);
        }

        // Die Autorisierungsbytes muessen die des Beweiszustands sein. Er nennt
        // seinen Objekthash selbst; der Aufrufer waehlt sie nicht aus, sonst
        // koennte er eine passendere unterschieben.
        if object_hash(exact_admin_authorization_object)
            != authorization.authorization_object_hash()
        {
            return Err(AdminError::AuthorizationMismatch);
        }
        let action_code = admin_action_code(exact_admin_authorization_object)?;

        // 2. Die Einmal-Nutzung, laufuebergreifend und organisationsweit.
        consume_admin_authorization(store, authorization).map_err(AdminError::Trust)?;

        // 3. Die Wurzelsignatur. Der Kontext ist hier die PRUEFUNG und nicht
        //    das Ergebnis: er bindet `[targetTrustSubtype, authorizedTrustCore]`
        //    an `authorizedTrustCoreHash` der Autorisierung und laesst die
        //    geschlossene Aktionstabelle entscheiden, ob diese Aktion diese
        //    Objektart ueberhaupt traegt.
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

        // 4. Die Kodierung.
        let object = TrustObjectV1::new(target, vec![signature.as_bytes().to_vec()])
            .map_err(AdminError::Format)?;
        let published = encode_trust(&object).map_err(AdminError::Format)?;
        let target_object_hash = object_hash(published.as_bytes());
        if target_object_hash != authorization.target_object_hash() {
            return Err(AdminError::TargetMismatch);
        }

        // 5. Die Auditzeile, VOR der Herausgabe.
        let context = AdminRootContextV1::new(
            authorization.authorization_object_hash(),
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
            self.book_failure(proof, authorization, target_object_hash, action_code);
            return Err(AdminError::AuditFailed);
        }

        // 6. Erst jetzt.
        Ok(published)
    }

    /// Bucht die Zeile mit dem Ausgang `failed`.
    ///
    /// Ohne Rueckgabe und ohne Fehlerweg: scheitert auch sie, bleibt
    /// [`AdminError::AuditFailed`] der gemeldete Fehler. Ein zweiter Fehler
    /// darf den ersten nicht verdecken.
    fn book_failure(
        &self,
        proof: &OperatorSessionProof,
        authorization: &VerifiedAdminAuthorization,
        target_object_hash: ObjectHash,
        action_code: u64,
    ) {
        let _ = self.audit.record_signed(
            AuditActorProof::OperatorSession(proof),
            TypedLocalAuditEvent {
                action: LocalAuditActionV1::AdminRootCeremony(AdminRootContextV1::new(
                    authorization.authorization_object_hash(),
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
