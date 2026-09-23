//! Die minimale native Root-Zeremonie der Bundle-Familie (v1.1-Profil §1.3
//! U4, §5; Scheibe f): eine `webBundleRelease` oder ein `webBundleRevocation`,
//! wurzelsigniert auf dem Autoritätswirt und ins `trust/`-Verzeichnis des
//! Archivs gelegt.
//!
//! # Ablauf
//!
//! 1. Autoritätswirt, `OrganizationAdmin`, Zweck `AdminRootCeremony`.
//! 2. Core aus dem Anker: Organisation, `root-key-thumbprint`, `issued-at` aus
//!    der frischen Wanduhr; `effective-from` standardmäßig die Kopfversion und
//!    NIE darunter — eine Rückdatierung öffnete die historische Escrow-Sperre
//!    für ältere Publikationsfreigaben rückwirkend.
//! 3. Frische Reauthentifizierung `AdminRootCeremony` am Kontexthash
//!    `trust_digest` der Nutzlast.
//! 4. Root signiert über `NativeSigningSlot::Root` unter dem Zertifikatshash
//!    des Ankers — genau das, was `verify_web_bundle_trust_signature` erwartet.
//! 5. Selbstprüfung über [`ea_trust::verify_web_bundle_family_admission`] —
//!    dieselbe Regel, mit der der Server annimmt.
//! 6. Kopf und Sitzung noch einmal nachgelesen, dann die Datei
//!    (inhaltsadressiert, ohne Überschreiben, idempotent).
//!
//! # Grenze (Ruling Q2)
//!
//! Die Zeremonie schreibt KEINE Auditzeile: die Freigabe ist wurzelsigniert
//! und append-only, und das Publikationsaudit (Aktion 13) trägt den Hash der
//! Freigabe, die die Sperre öffnete. Eine eigene Aktion 15 gibt es nicht.

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::Path,
};

use ea_crypto::{object_hash, trust_digest};
use ea_format::{
    OperatorRoleV1, TrustObjectV1, TrustPayloadV1, WebBundleReleaseCoreV1,
    WebBundleRevocationCoreV1, encode_trust,
};
use ea_operator::ReauthPurpose;
use ea_recovery::ReaderKeyEscrowError;
use ea_trust::{
    SelectedRegistryHead, TrustAnchorV1, TrustError, WebBundleAdmission,
    verify_web_bundle_family_admission,
};
use ea_types::{CertificateHash, Hash32, ObjectHash, RegistryVersion, UnixMillis};

use crate::{
    native_provider::NativeSigningSlot,
    operator_runtime::{OperatorRuntime, fresh_wall_clock},
    reader_key_escrow_publication::{TrustDigestSigner, trust_digest_signer},
};

/// Was die Zeremonie wurzelsignieren soll.
pub enum WebBundleRequest {
    /// Eine Freigabe des Bundles mit diesem Hash und dieser Fassung.
    Release {
        bundle_hash: Hash32,
        bundle_version: String,
        /// `None`: die Version des gewählten Kopfes.
        effective_from: Option<RegistryVersion>,
    },
    /// Der Widerruf einer Freigabe, die im Bestand liegt.
    Revocation {
        release_object_hash: ObjectHash,
        /// `None`: die Version des gewählten Kopfes.
        effective_from: Option<RegistryVersion>,
    },
}

/// Das geschriebene Objekt.
pub struct PublishedWebBundleObject {
    pub object_hash: ObjectHash,
    pub exact_bytes: Vec<u8>,
    /// Für eine Freigabe: ob die Fassung die Escrow-Familien trägt. Für einen
    /// Widerruf `None`.
    pub carries_reader_key_escrow: Option<bool>,
}

/// Alles, was die Zeremonie nach außen braucht. Öffentlich baubar nur hinter
/// `test-support`; der Produktivpfad ist allein [`publish_web_bundle_object`].
#[doc(hidden)]
pub struct WebBundleCeremonyContext<'a> {
    pub anchor: &'a TrustAnchorV1,
    pub head: &'a SelectedRegistryHead,
    /// Die exakten Trust-Objekte des Bestands.
    pub catalog: &'a [&'a [u8]],
    /// Frische Reauthentifizierung `AdminRootCeremony` an diesem Kontexthash.
    pub reauthenticate: &'a dyn Fn(Hash32) -> Result<(), ReaderKeyEscrowError>,
    pub root_sign: TrustDigestSigner<'a>,
    /// Kopf und Sitzung unverändert, unmittelbar vor dem Schreiben.
    pub session_current: &'a dyn Fn() -> Result<(), ReaderKeyEscrowError>,
    pub write: &'a dyn Fn(&[u8]) -> Result<(), ReaderKeyEscrowError>,
    pub now: UnixMillis,
}

const fn refused() -> ReaderKeyEscrowError {
    ReaderKeyEscrowError::Trust(TrustError::ActionMismatch)
}

fn ceremony(
    context: &WebBundleCeremonyContext<'_>,
    request: WebBundleRequest,
) -> Result<PublishedWebBundleObject, ReaderKeyEscrowError> {
    let head_version = context.head.registry_version();
    let effective = |requested: Option<RegistryVersion>| {
        let version = requested.unwrap_or(head_version);
        if version < head_version {
            return Err(refused());
        }
        Ok(version)
    };
    let anchor = context.anchor;
    let payload = match request {
        WebBundleRequest::Release {
            bundle_hash,
            bundle_version,
            effective_from,
        } => TrustPayloadV1::web_bundle_release(WebBundleReleaseCoreV1 {
            organization_id: anchor.organization_id(),
            bundle_hash,
            bundle_version,
            effective_from_registry_version: effective(effective_from)?,
            issued_at: context.now,
            root_key_thumbprint: anchor.root_key_thumbprint(),
        }),
        WebBundleRequest::Revocation {
            release_object_hash,
            effective_from,
        } => TrustPayloadV1::web_bundle_revocation(WebBundleRevocationCoreV1 {
            organization_id: anchor.organization_id(),
            release_object_hash,
            effective_from_registry_version: effective(effective_from)?,
            issued_at: context.now,
            root_key_thumbprint: anchor.root_key_thumbprint(),
        }),
    }
    .map_err(|_| refused())?;
    let digest = trust_digest(payload.exact_digest_input());
    (context.reauthenticate)(digest)?;
    let signature = (context.root_sign)(
        CertificateHash::from(anchor.root_certificate_object_hash()),
        digest,
    )?;
    let exact_bytes = encode_trust(
        &TrustObjectV1::new(payload, vec![signature]).map_err(|_| ReaderKeyEscrowError::Crypto)?,
    )
    .map_err(|_| ReaderKeyEscrowError::Crypto)?
    .into_vec();
    let admission = verify_web_bundle_family_admission(anchor, context.catalog, &exact_bytes)
        .map_err(|_| refused())?;
    let carries_reader_key_escrow = match admission {
        WebBundleAdmission::Release {
            carries_reader_key_escrow,
            ..
        } => Some(carries_reader_key_escrow),
        WebBundleAdmission::Revocation { .. } => None,
    };
    (context.session_current)()?;
    (context.write)(&exact_bytes)?;
    Ok(PublishedWebBundleObject {
        object_hash: object_hash(&exact_bytes),
        exact_bytes,
        carries_reader_key_escrow,
    })
}

/// Fixture-Eingang: dieselbe Zeremonie gegen einen gegebenen Kontext. Nur
/// hinter `test-support`.
///
/// # Errors
///
/// Wie [`publish_web_bundle_object`] nach der Rollenprüfung.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn publish_web_bundle_object_in_context(
    context: &WebBundleCeremonyContext<'_>,
    request: WebBundleRequest,
) -> Result<PublishedWebBundleObject, ReaderKeyEscrowError> {
    ceremony(context, request)
}

/// Legt exakte Trust-Bytes inhaltsadressiert unter `trust/` des Archivs ab:
/// ohne Überschreiben, idempotent für dieselben Bytes, dauerhaft (Datei und
/// Verzeichnis synchronisiert).
///
/// # Errors
///
/// `Output` für jeden Dateifehler und für abweichende Bytes unter demselben
/// Namen.
pub(crate) fn distribute_trust_object(
    archive_directory: &Path,
    exact_bytes: &[u8],
) -> Result<(), ReaderKeyEscrowError> {
    let io = |_| ReaderKeyEscrowError::Output;
    let directory = archive_directory.join(ea_archive::TRUST_DIR_V1);
    fs::create_dir_all(&directory).map_err(io)?;
    let name = format!("{}.etb", hex::encode(object_hash(exact_bytes).as_bytes()));
    let target = directory.join(&name);
    if let Ok(existing) = fs::read(&target) {
        return if existing == exact_bytes {
            Ok(())
        } else {
            Err(ReaderKeyEscrowError::Output)
        };
    }
    let partial = directory.join(format!(".{name}.partial"));
    let _ = fs::remove_file(&partial);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(io)?;
    file.write_all(exact_bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    drop(file);
    // Ein harter Link legt den Namen atomar und OHNE Überschreiben an.
    let linked = fs::hard_link(&partial, &target);
    let _ = fs::remove_file(&partial);
    match linked {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return if fs::read(&target).map_err(io)? == exact_bytes {
                Ok(())
            } else {
                Err(ReaderKeyEscrowError::Output)
            };
        }
        Err(_) => return Err(ReaderKeyEscrowError::Output),
    }
    fs::File::open(&directory)
        .and_then(|handle| handle.sync_all())
        .map_err(io)
}

/// Die Zeremonie in der Laufzeit des Autoritätswirts.
///
/// # Errors
///
/// `Operator` für einen Wirt ohne Autorität, eine andere Rolle oder einen
/// anderen Zweck, eine gescheiterte Reauthentifizierung und einen bewegten
/// Kopf; `Trust(ActionMismatch)` für eine Rückdatierung, einen Widerruf ohne
/// Freigabe im Bestand und jeden Befund der Selbstprüfung; `Crypto`, `Output`.
pub fn publish_web_bundle_object(
    runtime: &OperatorRuntime,
    request: WebBundleRequest,
) -> Result<PublishedWebBundleObject, ReaderKeyEscrowError> {
    let config = runtime.config();
    if !config.authority
        || config.role != OperatorRoleV1::OrganizationAdmin
        || config.purpose != ReauthPurpose::AdminRootCeremony
    {
        return Err(ReaderKeyEscrowError::Operator);
    }
    let now = || fresh_wall_clock().map_err(|_| ReaderKeyEscrowError::Operator);
    let session = std::cell::RefCell::new(None);
    let reauthenticate = |context_hash: Hash32| {
        let verified = runtime
            .reauthenticate_for_context(ReauthPurpose::AdminRootCeremony, context_hash)
            .map_err(|_| ReaderKeyEscrowError::Operator)?;
        if verified.proof().context_hash() != Some(context_hash) {
            return Err(ReaderKeyEscrowError::Operator);
        }
        *session.borrow_mut() = Some(verified);
        Ok(())
    };
    let root_sign = trust_digest_signer(runtime, NativeSigningSlot::Root);
    let session_current = || {
        runtime
            .ensure_same_action_authority()
            .map_err(|_| ReaderKeyEscrowError::Operator)?;
        let at = now()?;
        match session.borrow().as_ref() {
            Some(verified)
                if verified
                    .proof()
                    .is_valid_at(ReauthPurpose::AdminRootCeremony, at) =>
            {
                Ok(())
            }
            _ => Err(ReaderKeyEscrowError::Operator),
        }
    };
    let archive_directory = config.archive_directory.clone();
    let write = |bytes: &[u8]| distribute_trust_object(&archive_directory, bytes);
    let catalog: Vec<&[u8]> = runtime
        .inventory()
        .trust()
        .iter()
        .map(|object| object.exact_bytes().as_bytes())
        .collect();
    ceremony(
        &WebBundleCeremonyContext {
            anchor: runtime.anchor(),
            head: runtime.head(),
            catalog: &catalog,
            reauthenticate: &reauthenticate,
            root_sign: &root_sign,
            session_current: &session_current,
            write: &write,
            now: now()?,
        },
        request,
    )
}

#[cfg(test)]
mod tests {
    use super::distribute_trust_object;

    fn temp_archive(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "ea-web-bundle-distribute-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn entries(directory: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Inhaltsadressiert unter `trust/`, idempotent, ohne Überbleibsel.
    #[test]
    fn an_object_lands_once_under_its_hash_and_a_replay_is_idempotent() {
        let archive = temp_archive("once");
        let bytes = b"exact trust bytes".to_vec();
        distribute_trust_object(&archive, &bytes).unwrap();
        distribute_trust_object(&archive, &bytes).unwrap();
        let name = format!(
            "{}.etb",
            hex::encode(ea_crypto::object_hash(&bytes).as_bytes())
        );
        let trust = archive.join(ea_archive::TRUST_DIR_V1);
        assert_eq!(entries(&trust), std::slice::from_ref(&name));
        assert_eq!(std::fs::read(trust.join(name)).unwrap(), bytes);
        std::fs::remove_dir_all(archive).unwrap();
    }

    /// Andere Bytes unter demselben Namen werden nie überschrieben.
    #[test]
    fn different_bytes_under_the_same_name_are_refused() {
        let archive = temp_archive("clash");
        let bytes = b"exact trust bytes".to_vec();
        let trust = archive.join(ea_archive::TRUST_DIR_V1);
        std::fs::create_dir_all(&trust).unwrap();
        let name = format!(
            "{}.etb",
            hex::encode(ea_crypto::object_hash(&bytes).as_bytes())
        );
        std::fs::write(trust.join(&name), b"something else").unwrap();
        assert!(distribute_trust_object(&archive, &bytes).is_err());
        assert_eq!(std::fs::read(trust.join(name)).unwrap(), b"something else");
        std::fs::remove_dir_all(archive).unwrap();
    }
}
