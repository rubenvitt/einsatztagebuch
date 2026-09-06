//! Die Geraetefreigabe: ausstehender Antrag plus externe Bestaetigung.
//!
//! # Warum eine Freigabe ZWEI Voraussetzungen hat
//!
//! Ein Zertifikat, das nur lokal entstanden ist, belegt nichts: es sagt, dass
//! diese Maschine Bytes gebaut hat, nicht dass die richtige Person das
//! richtige Geraet gemeint hat. Die zweite Voraussetzung ist deshalb ein ueber
//! einen ANDEREN Kanal zurueckgelesener Fingerprint. Erst beides zusammen ist
//! ein Antrag, der aktiviert werden darf — dieselbe Bauart wie bei den
//! Ankerbildern der Wurzelzeremonie (`crates/ea-admin/src/anchor_media.rs`),
//! wo eine Bestaetigung ebenfalls nicht frei baubar ist und genau EINEN
//! Vorgang deckt.

use ea_crypto::object_hash;
use ea_format::{
    CertificateKindV1, DecodedTrustPayloadV1, ParsedArchiveObject, RegistryEventFieldsV1,
    decode_exact_object,
};
use ea_types::ObjectHash;

use crate::{
    RegistryWindow,
    registry::{RegistryActionV1, RegistryEventFactory, RegistryWorkflowError},
};

/// Ein ausstehender Geraeteantrag: die EXAKTEN Bytes des vorbereiteten
/// Zertifikats und das, was aus ihnen folgt.
///
/// Art und Fingerprint werden aus den Bytes GELESEN und nicht danebengestellt.
/// Eine mitgefuehrte Zertifikatsart waere eine zweite Wahrheit, die von den
/// Bytes abweichen koennte.
pub struct PendingDeviceRegistration {
    exact_certificate_bytes: Vec<u8>,
    certificate_object_hash: ObjectHash,
    certificate_kind: CertificateKindV1,
}

impl PendingDeviceRegistration {
    /// Nimmt die exakten Bytes eines vorbereiteten Geraetezertifikats an.
    ///
    /// # Errors
    ///
    /// `EA-WORKFLOW-ADMIN-CERTIFICATE-LIFECYCLE`, wenn die Bytes ein
    /// Administrationszertifikat tragen: Aenderung 0 aktiviert nie eines
    /// (`crates/ea-trust/src/registry.rs:1071-1077`), dafuer gibt es Aktion 5
    /// Effekt 0. Formfehler der Bytes behalten ihren `EA-FORMAT-`-Code.
    pub fn new(exact_certificate_bytes: Vec<u8>) -> Result<Self, RegistryWorkflowError> {
        let ParsedArchiveObject::Trust(parsed) = decode_exact_object(&exact_certificate_bytes)?
        else {
            return Err(RegistryWorkflowError::TargetNotActive);
        };
        let certificate_kind = match parsed.value().decoded_payload()? {
            DecodedTrustPayloadV1::AuthorizedDevice(core) => core.fields().certificate_kind,
            DecodedTrustPayloadV1::InitialAdminDevice(fields) => fields.certificate_kind,
            _ => return Err(RegistryWorkflowError::TargetNotActive),
        };
        if certificate_kind == CertificateKindV1::OrganizationAdmin {
            return Err(RegistryWorkflowError::AdminCertificateLifecycle);
        }
        Ok(Self {
            certificate_object_hash: object_hash(&exact_certificate_bytes),
            exact_certificate_bytes,
            certificate_kind,
        })
    }

    /// Der Wert, der ueber den zweiten Kanal vorgelesen wird.
    ///
    /// Es ist der Objekthash der exakten Bytes und kein zweiter Abdruck: ein
    /// eigener Fingerprintbegriff daneben liesse offen, welcher der beiden
    /// bestaetigt wurde.
    #[must_use]
    pub const fn fingerprint(&self) -> ObjectHash {
        self.certificate_object_hash
    }

    #[must_use]
    pub const fn certificate_object_hash(&self) -> ObjectHash {
        self.certificate_object_hash
    }

    #[must_use]
    pub const fn certificate_kind(&self) -> CertificateKindV1 {
        self.certificate_kind
    }

    #[must_use]
    pub fn exact_certificate_bytes(&self) -> &[u8] {
        &self.exact_certificate_bytes
    }
}

/// Der Beleg, dass ein Mensch den Fingerprint ueber einen zweiten Kanal
/// zurueckgemeldet hat.
///
/// Ohne oeffentliche Felder und ohne oeffentlichen Konstruktor: „das hat
/// jemand bestaetigt" ist keine Behauptung, die ein Aufrufer sich selbst
/// ausstellen darf. Der Typ wird von [`plan_device_approval`] VERBRAUCHT und
/// nicht geliehen — eine Bestaetigung deckt genau EINE Freigabe.
pub struct ConfirmedDeviceFingerprint {
    certificate_object_hash: ObjectHash,
}

/// Vergleicht den zurueckgemeldeten Fingerprint gegen den des Antrags.
///
/// # Errors
///
/// `EA-WORKFLOW-FINGERPRINT-MISMATCH`, wenn die Werte abweichen.
pub fn confirm_device_fingerprint(
    pending: &PendingDeviceRegistration,
    reported_fingerprint: ObjectHash,
) -> Result<ConfirmedDeviceFingerprint, RegistryWorkflowError> {
    if pending.fingerprint() != reported_fingerprint {
        return Err(RegistryWorkflowError::FingerprintMismatch);
    }
    Ok(ConfirmedDeviceFingerprint {
        certificate_object_hash: reported_fingerprint,
    })
}

/// Plant die Aktivierung eines bestaetigten Geraeteantrags als Aenderung 0.
///
/// Antrag und Bestaetigung muessen dasselbe Zertifikat meinen; sonst deckte
/// eine Bestaetigung ein anderes Objekt als das, das aktiviert wird.
///
/// # Errors
///
/// `EA-WORKFLOW-FINGERPRINT-MISMATCH`, wenn Bestaetigung und Antrag
/// auseinanderlaufen; `EA-OPERATOR-REGISTRY-WINDOW` aus der Ereignisfabrik.
pub fn plan_device_approval(
    events: &RegistryEventFactory<'_>,
    window: RegistryWindow,
    pending: &PendingDeviceRegistration,
    confirmation: ConfirmedDeviceFingerprint,
) -> Result<RegistryEventFieldsV1, RegistryWorkflowError> {
    if confirmation.certificate_object_hash != pending.certificate_object_hash {
        return Err(RegistryWorkflowError::FingerprintMismatch);
    }
    events.plan(
        window,
        &RegistryActionV1::DeviceApprove {
            certificate_object_hash: pending.certificate_object_hash,
        },
    )
}
