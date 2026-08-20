//! Ein deterministischer In-Prozess-Provider fuer Tests.
//!
//! Nur unter dem Feature `test-support` uebersetzt, das NIE ein Default-Feature
//! ist: dieser Provider haelt Schluesselmaterial im Prozessspeicher und gibt es
//! heraus, und genau das darf ein Produktionsbau nicht enthalten.
//!
//! Er erreicht ausschliesslich [`KeyProtectionProfileV1::OsWrapped`] und
//! behauptet nie mehr. Ein Provider, der Hardware verspricht und Software
//! liefert, waere der stille Rueckfall, den `design.md`:1489 verbietet.

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
};

use ea_crypto::{CanonicalPublicCoseKey, ContentType, ProtectedHeader, SecretBytes, SecretVec};
use ea_format::KeyProtectionProfileV1;
use ea_types::{CertificateHash, Hash32};
use ed25519_dalek::{Signer, SigningKey};

use crate::{
    contract::{CoseSign1Bytes, KeyError, KeyHandle, KeyProvider, KeystoreProvider, SecretPurpose},
    profile::{WriterKeyProfile, require_stage_two_protection_profile},
};

/// Das einzige Schutzprofil, das ein In-Prozess-Provider erreichen kann.
const REACHED_PROTECTION_PROFILE: KeyProtectionProfileV1 = KeyProtectionProfileV1::OsWrapped;

/// Die Zwecke, die durch [`KeyProvider::sign`] signieren.
const SIGNING_PURPOSES: &[SecretPurpose] = &[
    SecretPurpose::WriterSigningKey,
    SecretPurpose::OperatorInstanceKey,
];

/// Der Inhalt des Speichers unter EINEM Schloss.
///
/// Eintraege und Epochen gehoeren zusammen, und die Regel gilt in BEIDE
/// Richtungen: jeder Vorgang, der beide beruehrt, laeuft unter EINEM Nehmen des
/// Schlosses. Das sind genau zwei — `delete`, das einen Eintrag entfernt und im
/// selben Zug die Epoche seines Zwecks hebt, und
/// [`Store::insert_fresh_material`], das die Epoche liest und das daraus
/// gebildete Material ablegt.
///
/// Zwei getrennte Nehmen liessen dazwischen jeweils ein Fenster: beim Loeschen
/// eines, in dem der Eintrag fort und die Epoche noch die alte ist, und beim
/// Erzeugen das spiegelbildliche, in dem eine gelesene Epoche schon veraltet
/// ist, wenn das Material abgelegt wird. Das zweite Fenster stellte ein
/// geloeschtes Geheimnis wieder her.
#[derive(Default)]
struct Store {
    entries: HashMap<KeyHandle, [u8; 32]>,
    epochs: HashMap<SecretPurpose, u32>,
}

impl Store {
    /// Liest die Epoche des Zwecks und legt das daraus gebildete Material ab —
    /// EIN Vorgang unter EINEM Schloss.
    ///
    /// Dass beides hier zusammenliegt, ist der Zweck der Methode und nicht ihre
    /// Bequemlichkeit. Faende das Nachschlagen unter einem Schloss statt und
    /// das Ablegen unter einem zweiten, koennte dazwischen ein `delete` die
    /// Epoche heben; das Ablegen schriebe dann das Material der ALTEN Epoche
    /// zurueck, und das geloeschte Geheimnis waere wiederhergestellt — genau
    /// der Mangel, gegen den die Epoche eingefuehrt wurde, nur durch eine
    /// engere Tuer.
    ///
    /// Die Methode haengt am Speicher und kennt weder den Provider noch das
    /// Schloss. Ein zweites Nehmen ist darin nicht ausdrueckbar, nicht nur
    /// unerwuenscht.
    fn insert_fresh_material(
        &mut self,
        seed: &[u8; 32],
        handle: KeyHandle,
        purpose: SecretPurpose,
    ) {
        let epoch = self.epochs.get(&purpose).copied().unwrap_or(0);
        self.entries.insert(handle, derive(seed, purpose, epoch));
    }
}

pub struct InMemoryKeyProvider {
    account_instance: Hash32,
    seed: [u8; 32],
    store: Mutex<Store>,
}

impl InMemoryKeyProvider {
    /// Ein Provider, der aus `seed` reproduzierbar dieselben Schluessel bildet.
    ///
    /// Der Startwert ist zugleich die Kontoinstanz: zwei Provider mit
    /// demselben Startwert sind dasselbe Geraet mit demselben Konto, und ein
    /// Griff des einen adressiert denselben Eintrag beim anderen.
    #[must_use]
    pub fn new_for_test(seed: [u8; 32]) -> Self {
        Self {
            account_instance: Hash32::try_from(seed.as_slice())
                .expect("a 32-byte seed is a 32-byte hash"),
            seed,
            store: Mutex::new(Store::default()),
        }
    }

    /// Der OEFFENTLICHE Ed25519-Signaturschluessel eines Zwecks — NUR fuer
    /// Fixtures.
    ///
    /// Sie existiert, weil eine Harness sonst kein Geraetezertifikat bauen
    /// kann, das zu DIESEM Provider passt: [`KeyProvider::sign`] liefert
    /// COSE-Bytes, deren Protected Header nur den Abdruck traegt, und die
    /// Registry-Fixture der Stufe 1 baut Zertifikate umgekehrt aus dem
    /// oeffentlichen Schluessel. Ohne diesen Zugriff bliebe der Weg, die
    /// private Ableitung dieses Moduls in der Fixture NACHZUBAUEN — ein Test,
    /// der an einem Implementierungsdetail haengt statt an der Schnittstelle.
    ///
    /// SIE GIBT NICHTS PRIVATES HERAUS. Der oeffentliche Teil eines
    /// Signaturschluessels ist genau das, was jede Signatur ohnehin
    /// veroeffentlicht; das private Material verlaesst den Provider hier nicht.
    /// Sie liegt trotzdem hinter `test-support`, weil ein nativer Provider
    /// diesen Zugriff nicht anbieten kann und ein Produktionspfad ihn deshalb
    /// nicht benutzen darf.
    ///
    /// # Errors
    ///
    /// [`KeyError::NotFound`], wenn fuer `purpose` noch nichts erzeugt wurde,
    /// sonst [`KeyError::PurposeMismatch`] fuer einen Zweck ohne
    /// Signaturschluessel.
    #[cfg(any(test, feature = "test-support"))]
    pub fn signing_public_key_for_test(
        &self,
        purpose: SecretPurpose,
    ) -> Result<[u8; 32], KeyError> {
        if !SIGNING_PURPOSES.contains(&purpose) {
            return Err(KeyError::PurposeMismatch);
        }
        let handle = self.handle(purpose);
        let material = self.material(&handle)?;
        Ok(SigningKey::from_bytes(&material).verifying_key().to_bytes())
    }

    fn store(&self) -> MutexGuard<'_, Store> {
        self.store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn handle(&self, purpose: SecretPurpose) -> KeyHandle {
        KeyHandle::new(KeystoreProvider::InMemory, self.account_instance, purpose)
    }

    fn material(&self, handle: &KeyHandle) -> Result<[u8; 32], KeyError> {
        self.store()
            .entries
            .get(handle)
            .copied()
            .ok_or(KeyError::NotFound)
    }
}

impl KeyProvider for InMemoryKeyProvider {
    fn generate(
        &self,
        purpose: SecretPurpose,
        protection: KeyProtectionProfileV1,
    ) -> Result<KeyHandle, KeyError> {
        WriterKeyProfile::validate_local(&[purpose])?;
        require_stage_two_protection_profile(protection)?;
        if protection != REACHED_PROTECTION_PROFILE {
            return Err(KeyError::UnreachableProtectionProfile);
        }
        let handle = self.handle(purpose);
        self.store()
            .insert_fresh_material(&self.seed, handle, purpose);
        Ok(handle)
    }

    fn sign(
        &self,
        handle: &KeyHandle,
        content_type: ContentType,
        certificate_hash: CertificateHash,
        payload: &[u8],
    ) -> Result<CoseSign1Bytes, KeyError> {
        handle.require_purpose(SIGNING_PURPOSES)?;
        let signing_key = SigningKey::from_bytes(&self.material(handle)?);
        let public = CanonicalPublicCoseKey::ed25519(signing_key.verifying_key().to_bytes())
            .map_err(KeyError::Crypto)?;
        let protected =
            ProtectedHeader::normal(content_type, public.thumbprint(), certificate_hash);
        let signature = signing_key.sign(&protected.sig_structure_bytes(payload));
        CoseSign1Bytes::compose(&protected, payload, &signature.to_bytes())
    }

    fn wrap_secret(
        &self,
        purpose: SecretPurpose,
        secret: SecretBytes<32>,
    ) -> Result<KeyHandle, KeyError> {
        let handle = self.handle(purpose);
        handle.require_purpose(&[SecretPurpose::DraftDek])?;
        self.store()
            .entries
            .insert(handle, secret.with_exposed(|bytes| *bytes));
        Ok(handle)
    }

    fn unwrap_secret(&self, handle: &KeyHandle) -> Result<SecretBytes<32>, KeyError> {
        handle.require_purpose(&[SecretPurpose::DraftDek])?;
        self.material(handle).map(SecretBytes::new)
    }

    fn unwrap_database_key(&self, handle: &KeyHandle) -> Result<SecretVec, KeyError> {
        handle.require_purpose(&[SecretPurpose::LocalDatabaseKey])?;
        self.material(handle)
            .map(|material| SecretVec::new(material.to_vec()))
    }

    fn delete(&self, handle: &KeyHandle) -> Result<(), KeyError> {
        // Der Eintrag geht fort UND die Epoche seines Zwecks steigt. Die
        // Adresse selbst bleibt bestehen: sie ist Dienst und Konto und wird
        // nicht verbraucht, sonst zerfiele das Ersetzen-an-Ort-und-Stelle, das
        // dieser Provider bewusst traegt.
        //
        // Bedingungslos, auch wenn nichts zu entfernen war: eine Epoche, die
        // nur bei einem Treffer steigt, liesse sich mit einem Loeschen ins
        // Leere umgehen.
        let mut store = self.store();
        store.entries.remove(handle);
        let epoch = store.epochs.entry(handle.purpose()).or_default();
        *epoch = epoch.wrapping_add(1);
        Ok(())
    }

    fn contains(&self, handle: &KeyHandle) -> Result<bool, KeyError> {
        Ok(self.store().entries.contains_key(handle))
    }

    fn reached_protection_profile(
        &self,
        handle: &KeyHandle,
    ) -> Result<KeyProtectionProfileV1, KeyError> {
        self.material(handle).map(|_| REACHED_PROTECTION_PROFILE)
    }
}

/// Deterministisches Testmaterial, AUSDRUECKLICH OHNE Sicherheitsanspruch.
///
/// Der Startwert wird mit einer Zweckmarke und der EPOCHE des Zwecks
/// ueberlagert. Die Zweckmarke trennt die vier Zwecke; die Epoche trennt
/// das, was VOR einem `delete` galt, von dem, was danach entsteht.
///
/// Ohne die Epoche waere `derive` eine reine Funktion aus Startwert und
/// Zweck, und ein geloeschtes Geheimnis liesse sich durch ein erneutes
/// [`KeyProvider::generate`] byteweise wiederherstellen — ueber die
/// oeffentliche Flaeche, ohne einen einzigen Blick ins Innere. Der Nachweis
/// „kein entschluesselbarer `draftDEK` bleibt zurueck", den spaetere Tasks
/// gegen genau diesen Provider fuehren, waere dann wertlos.
///
/// Das genuegt fuer einen reproduzierbaren Testlauf und fuer nichts sonst;
/// `test-support` ist nie ein Default-Feature, also verlaesst dieses
/// Material keinen Testlauf.
fn derive(seed: &[u8; 32], purpose: SecretPurpose, epoch: u32) -> [u8; 32] {
    let tag = match purpose {
        SecretPurpose::WriterSigningKey => 1u8,
        SecretPurpose::OperatorInstanceKey => 2,
        SecretPurpose::DraftDek => 3,
        SecretPurpose::LocalDatabaseKey => 4,
    };
    let epoch_bytes = epoch.to_be_bytes();
    let mut material = *seed;
    for (index, byte) in material.iter_mut().enumerate() {
        // Der Index bleibt unter 32, die Umwandlung kann nicht scheitern.
        let mixer = u8::try_from(index).unwrap_or(u8::MAX) | 1;
        *byte ^= tag.wrapping_mul(mixer).wrapping_add(epoch_bytes[index % 4]);
    }
    material
}
