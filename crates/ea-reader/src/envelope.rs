//! Die PRF-Envelopes des Browser-Tresors und der EINE Ort seiner
//! Schluesselableitung.
//!
//! # Warum die PRF-Ausgabe nicht selbst verschluesselt
//!
//! `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §6.2
//! schreibt `KEK_i = HKDF(PRF_i(festes App-Salt), info = "ea-reader-vault-v1")`
//! vor und verbietet ausdruecklich, die PRF-Ausgabe direkt als
//! Verschluesselungsschluessel zu nehmen. Der Grund ist betrieblich und nicht
//! aesthetisch: waere die PRF-Ausgabe der Schluessel, gaebe es je Authenticator
//! einen eigenen Tresor, und das Loeschen EINES Passkeys machte die Daten
//! dauerhaft unerreichbar. Mit der Umschliessung traegt der Tresor genau EINEN
//! Tresorschluessel und je Authenticator ein Envelope darueber; ein geloeschter
//! Passkey kostet einen Entsperrweg und nie den Inhalt. Die zweite Haelfte —
//! ein entfernter Entsperrweg kostet den Inhalt nicht — misst
//! `the_prf_output_never_wraps_the_vault_and_each_authenticator_opens_it_alone`.
//! Die erste misst DERSELBE Zeuge, aber ueber den direkten Vergleich von
//! [`derive_kek_v1`] gegen `Hkdf::<Sha256>::expand(VAULT_KEK_INFO_V1, ..)` und
//! ausdruecklich NICHT ueber die Kanarienschleife im Chiffrat: die ist eine
//! Anwesenheitsprobe und bliebe gruen, wenn die rohe PRF-Ausgabe selbst der
//! Wrapping-Schluessel waere — ein AEAD-Chiffrat traegt seinen Schluessel nie
//! im Klartext.
//!
//! # Beide AAD-Bindungen sind bezeugt
//!
//! Ein Envelope haengt an seiner `credentialId`, ein Speicherblob an seiner
//! Adresse; beides ist eine AEAD-Bindung und keine verglichene Zeichenkette.
//! Ohne Zeugen waere die Aussage geschenkt, denn ein weggelassener Zusatz
//! entschluesselt weiterhin fehlerfrei — er bindet nur nichts mehr. Deshalb
//! misst `a_relabelled_envelope_refuses_under_its_own_kek` (in diesem Modul,
//! weil [`VaultEnvelopeV1::from_parts`] `pub(crate)` ist) das Umhaengen eines
//! Envelopes auf eine fremde `credentialId`, und
//! `a_blob_moved_to_a_foreign_address_refuses` in
//! `crates/ea-reader/tests/cache_canaries.rs` das Vertauschen zweier Blobs.
//!
//! # Sieben abgeleitete Schluessel, EIN Ort
//!
//! Aus dem Tresorschluessel entstehen der Cacheschluessel, der Schluessel des
//! Eintragszustands, der des Trust-Standes, der des bestaetigten Sync-Cursors,
//! der Indexschluessel und — seit der Aufgabe „Sitzungssperre, Zeroize,
//! authenticator-bestätigter Einzelexport und signiertes lokales Audit" — der
//! des signierten Auditprotokolls; aus der PRF-Ausgabe entsteht der
//! Wrapping-Schluessel. Alle sieben gehen durch [`derive_key`], und die sieben
//! Info-Zeichenketten stehen nebeneinander in diesem Modul. Waeren sie verteilt,
//! haette eine Schluesselrotation sieben Orte statt einem, und zwei Kontexte
//! koennten unbemerkt gleich werden — was zwei getrennte Speicher zu einem
//! machte.
//!
//! # Die Info-Kontexte von Cache und Zustandsspeicher verlassen das Modul NICHT
//!
//! [`VAULT_CACHE_INFO_V1`](self) und `VAULT_STATE_INFO_V1` sind modulprivat:
//! `crates/ea-reader/src/cache.rs` und `crates/ea-reader/src/entry_state.rs`
//! bekommen ihre Schluessel ueber [`derive_cache_key_v1`] beziehungsweise
//! [`derive_entry_state_key_v1`] und leiten nichts selbst ab. Der Indexkontext
//! ist die Ausnahme und OEFFENTLICH — nicht, damit jemand ihn benutzt, sondern
//! weil er der Ableitungsvertrag ist, den `web-reader-design.md` §6.2 benennt;
//! den fertigen Indexschluessel gibt allein `UnlockedVault::index_key` heraus.

use ea_crypto::{AEAD_NONCE_SIZE, AEAD_OVERHEAD, CEK_SIZE, SecretBytes, SecretVec, aead_open};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::vault::ReaderVaultError;

/// Der Info-String aus `web-reader-design.md` §6.2, zeichengleich.
///
/// OEFFENTLICH, weil die Aufgabe „Browser-Enrollment: zwei Pflicht-Authenticators
/// und das nicht überspringbare Fingerprint-Gate" den Ableitungsvertrag benennen
/// koennen muss, ohne ihn ein zweites Mal zu schreiben.
pub const VAULT_KEK_INFO_V1: &[u8] = b"ea-reader-vault-v1";

/// Der Ableitungskontext des Objektcaches.
const VAULT_CACHE_INFO_V1: &[u8] = b"ea-reader-cache-v1";

/// Der Ableitungskontext des Eintragszustandsspeichers.
const VAULT_STATE_INFO_V1: &[u8] = b"ea-reader-entry-state-v1";

/// Der Ableitungskontext des Trust-Standspeichers.
///
/// Modulprivat wie Cache und Zustandsspeicher: `crates/ea-reader/src/trust_state.rs`
/// bekommt seinen Schluessel ueber [`derive_trust_state_key_v1`] und leitet
/// nichts selbst ab.
const VAULT_TRUST_STATE_INFO_V1: &[u8] = b"ea-reader-trust-state-v1";

/// Der Ableitungskontext des bestaetigten Sync-Cursors.
///
/// Modulprivat wie Cache und Zustandsspeicher: `crates/ea-reader/src/cursor.rs`
/// bekommt seinen Schluessel ueber [`derive_sync_cursor_key_v1`] und leitet
/// nichts selbst ab. Er steht HIER und nicht dort, weil dieses Modul der EINE
/// Ort jeder Ableitung ist — ein sechster Kontext neben den fuenf und nicht ein
/// sechster ORT.
const VAULT_SYNC_CURSOR_INFO_V1: &[u8] = b"ea-reader-sync-cursor-v1";

/// Der Ableitungskontext des signierten lokalen Auditprotokolls.
///
/// Modulprivat wie Cache und Zustandsspeicher: `crates/ea-reader/src/audit.rs`
/// bekommt seinen Schluessel ueber [`derive_audit_log_key_v1`] und leitet
/// nichts selbst ab. Ein SIEBTER Kontext neben den sechs und nicht ein siebter
/// Ort: das Protokoll traegt je Zeile Entry-Hash, Zielart und die pseudonyme
/// Bedienerbindung, und was OPFS erreicht, ist auch hier Chiffrat.
const VAULT_AUDIT_LOG_INFO_V1: &[u8] = b"ea-reader-audit-log-v1";

/// Der Ableitungskontext des Indexblobs. Er entsteht HIER, damit alle sieben
/// abgeleiteten Schluessel EINEN Ort haben.
///
/// OEFFENTLICH, anders als die Kontexte von Cache und Zustandsspeicher: die
/// Aufgabe „Verschlüsselter invertierter Index in OPFS, Suche,
/// Schemakompatibilität und die GEMESSENE 50.000-Paket-Schwelle" liegt in einer
/// EIGENEN Crate und kann `derive_key` nicht rufen — sie bekommt den fertigen
/// Schluessel ueber `UnlockedVault::index_key` und leitet nichts selbst ab. Die
/// Konstante bleibt trotzdem sichtbar, weil sie der Ableitungsvertrag ist, den
/// ADR 0005 und `web-reader-design.md` §6.2 benennen.
pub const VAULT_INDEX_INFO_V1: &[u8] = b"ea-reader-index-v1";

/// Die AEAD-Domaene der Envelopes.
///
/// Sie steht als Praefix vor der `credentialId` im zusaetzlichen
/// authentifizierten Datum. Die Bindung ist die Aussage: ein Envelope laesst
/// sich nicht auf einen fremden Authenticator umhaengen, weil der Vergleich
/// nicht auf einem Feld beruht, das ein Angreifer mitschreiben kann, sondern
/// auf dem Poly1305-Tag.
const VAULT_ENVELOPE_AAD_V1: &[u8] = b"EINSATZARCHIV-READER-VAULT-ENVELOPE-v1";

/// Die AEAD-Domaene der Tresor- und Speicherblobs.
///
/// `pub(crate)` und nicht modulprivat, weil `crates/ea-reader/src/vault.rs` den
/// Tresorkoerper und `cache.rs`/`entry_state.rs` ihre Blobs damit binden. Die
/// Domaene liegt trotzdem HIER, neben den Info-Kontexten: eine zweite
/// Domaenenkonstante an einer zweiten Stelle waere genau der stille Bruch, den
/// dieses Modul verhindert.
pub(crate) const VAULT_BLOB_AAD_V1: &[u8] = b"EINSATZARCHIV-READER-VAULT-BLOB-v1";

/// Die Groesse eines umschlossenen Tresorschluessels in Byte.
///
/// Sie wird aus [`CEK_SIZE`] und [`AEAD_OVERHEAD`] gerechnet und ausdruecklich
/// NICHT ueber `HPKE_WRAPPED_CEK_SIZE` ausgedrueckt: dass beide heute 48 sind,
/// ist eine Zahlengleichheit ohne Bedeutungsgleichheit. Hier wird mit AEAD
/// umschlossen und nicht mit HPKE.
const WRAPPED_VAULT_KEY_SIZE: usize = CEK_SIZE + AEAD_OVERHEAD;

/// Die AUSGABE der WebAuthn-PRF-Erweiterung eines Authenticators.
///
/// Die Zeremonie selbst gehoert der Aufgabe „Browser-Enrollment: zwei
/// Pflicht-Authenticators und das nicht überspringbare Fingerprint-Gate"; hier
/// tritt ausschliesslich ihr Ergebnis ein. Der Typ traegt kein `Clone` und kein
/// `Debug`, weil [`SecretBytes`] beides bewusst nicht hat.
pub struct AuthenticatorPrfV1 {
    credential_id: Vec<u8>,
    prf_output: SecretBytes<32>,
}

impl AuthenticatorPrfV1 {
    /// Ein Authenticator aus seiner `credentialId` und seiner PRF-Ausgabe.
    ///
    /// Beide BESITZEND: die `credentialId` wird in das Envelope kopiert, und
    /// die PRF-Ausgabe steht unter `ZeroizeOnDrop`, sobald sie hier liegt.
    #[must_use]
    pub const fn new(credential_id: Vec<u8>, prf_output: SecretBytes<32>) -> Self {
        Self {
            credential_id,
            prf_output,
        }
    }

    /// Die `credentialId` dieses Authenticators.
    ///
    /// Kein Geheimnis: sie steht im Klartext im Envelope und unterscheidet die
    /// Entsperrwege.
    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }
}

/// Ein Entsperrweg: der Tresorschluessel, umschlossen unter genau EINEM `KEK_i`.
#[derive(Clone)]
pub struct VaultEnvelopeV1 {
    credential_id: Vec<u8>,
    nonce: [u8; AEAD_NONCE_SIZE],
    wrapped_vault_key: [u8; WRAPPED_VAULT_KEY_SIZE],
}

impl VaultEnvelopeV1 {
    /// Umschliesst den Tresorschluessel unter `KEK_i`.
    ///
    /// Die `credentialId` steht im Plan-Text dieser Aufgabe als „gebundener
    /// Zusatz" und ist deshalb ein ARGUMENT und kein Nachtrag: ohne sie
    /// entstuende das zusaetzliche authentifizierte Datum nicht, und das
    /// Envelope waere auf einen fremden Authenticator umhaengbar.
    ///
    /// # Errors
    /// `EA-CRYPTO-SIZE-LIMIT`, wenn die AEAD-Laengenpruefung von `ea-crypto`
    /// den Klartext abweist — fuer 32 Byte unerreichbar, aber nicht
    /// wegdiskutiert.
    pub fn wrap(
        kek: &SecretBytes<CEK_SIZE>,
        vault_key: &SecretBytes<CEK_SIZE>,
        nonce: &[u8; AEAD_NONCE_SIZE],
        credential_id: Vec<u8>,
    ) -> Result<Self, ReaderVaultError> {
        let plaintext = vault_key.with_exposed(|bytes| SecretVec::new(bytes.to_vec()));
        let ciphertext = ea_crypto::aead_seal(
            kek,
            &SecretBytes::new(*nonce),
            plaintext,
            &envelope_aad(&credential_id),
        )?;
        let wrapped_vault_key: [u8; WRAPPED_VAULT_KEY_SIZE] = ciphertext
            .try_into()
            .map_err(|_| ReaderVaultError::Contents)?;
        Ok(Self {
            credential_id,
            nonce: *nonce,
            wrapped_vault_key,
        })
    }

    /// Ein Envelope aus seinen drei gespeicherten Bestandteilen.
    ///
    /// Der Weg zurueck aus `SealedVaultV1::from_deterministic_cbor` und sonst
    /// nichts: `pub(crate)`, damit ausserhalb dieser Crate niemand ein Envelope
    /// zusammensetzt, das keine AEAD-Umschliessung hinter sich hat.
    pub(crate) fn from_parts(
        credential_id: Vec<u8>,
        nonce: [u8; AEAD_NONCE_SIZE],
        wrapped_vault_key: &[u8],
    ) -> Result<Self, ReaderVaultError> {
        let wrapped_vault_key: [u8; WRAPPED_VAULT_KEY_SIZE] = wrapped_vault_key
            .try_into()
            .map_err(|_| ReaderVaultError::Contents)?;
        Ok(Self {
            credential_id,
            nonce,
            wrapped_vault_key,
        })
    }

    /// # Errors
    /// `EA-CRYPTO-AEAD-OPEN`, wenn `kek` nicht der ist, der umschlossen hat.
    pub fn unwrap(
        &self,
        kek: &SecretBytes<CEK_SIZE>,
    ) -> Result<SecretBytes<CEK_SIZE>, ReaderVaultError> {
        let opened = aead_open(
            kek,
            &SecretBytes::new(self.nonce),
            &self.wrapped_vault_key,
            &envelope_aad(&self.credential_id),
        )?;
        let mut vault_key = [0_u8; CEK_SIZE];
        let sized = opened.with_exposed(|bytes| {
            if bytes.len() == CEK_SIZE {
                vault_key.copy_from_slice(bytes);
                true
            } else {
                false
            }
        });
        if !sized {
            vault_key.zeroize();
            return Err(ReaderVaultError::Contents);
        }
        let secret = SecretBytes::new(vault_key);
        vault_key.zeroize();
        Ok(secret)
    }

    /// Die `credentialId`, an die dieses Envelope gebunden ist.
    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// Der Nonce dieses Envelopes. Er liegt im KLARTEXT und muss es auch.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; AEAD_NONCE_SIZE] {
        &self.nonce
    }

    /// Der umschlossene Tresorschluessel — Chiffrat samt Poly1305-Tag.
    ///
    /// Der Kanarienzeuge liest GENAU DIESE Bytes und sucht die rohe PRF-Ausgabe
    /// darin. Das ist eine ANWESENHEITSPROBE und nicht der Beleg von §6.2 —
    /// den fuehrt derselbe Zeuge ueber den direkten Vergleich von
    /// [`derive_kek_v1`] gegen die HKDF-Rechnung. Der Zugang bleibt trotzdem
    /// noetig: ohne ihn liesse sich nicht einmal pruefen, ob ein Schluessel
    /// versehentlich unverschluesselt neben seinem Chiffrat landet.
    #[must_use]
    pub fn wrapped_vault_key(&self) -> &[u8] {
        &self.wrapped_vault_key
    }

    /// Kippt das unterste Bit des ersten umschlossenen Bytes.
    ///
    /// Hinter `test-support` und in keinem Release. Sie ist der einzige Weg,
    /// `a_flipped_envelope_byte_and_a_substituted_anchor_both_refuse` eine
    /// ECHTE AEAD-Weigerung zeigen zu lassen statt einer nachgestellten.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn flip_one_wrapped_key_byte_for_test(&mut self) {
        self.wrapped_vault_key[0] ^= 0x01;
    }
}

/// Das zusaetzliche authentifizierte Datum eines Speicherblobs.
///
/// Die ADRESSE geht mit ein — `cache/<hex>` beziehungsweise
/// `entry-state/<hex>`. Damit ist ein Blob nicht auf eine fremde Adresse
/// umhaengbar: wer zwei Blobs vertauscht, bekommt `EA-CRYPTO-AEAD-OPEN` und
/// nicht stillschweigend den falschen Inhalt. Der Tresorkoerper selbst hat
/// keine Adresse und bekommt deshalb die leere.
pub(crate) fn blob_aad(address: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(VAULT_BLOB_AAD_V1.len() + address.len());
    aad.extend_from_slice(VAULT_BLOB_AAD_V1);
    aad.extend_from_slice(address);
    aad
}

/// Das zusaetzliche authentifizierte Datum eines Envelopes.
fn envelope_aad(credential_id: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(VAULT_ENVELOPE_AAD_V1.len() + credential_id.len());
    aad.extend_from_slice(VAULT_ENVELOPE_AAD_V1);
    aad.extend_from_slice(credential_id);
    aad
}

/// Der EINE oeffentliche Ableitungsweg der PRF-Ausgabe zum Wrapping-Schluessel.
///
/// Die Aufgabe „Browser-Enrollment: zwei Pflicht-Authenticators und das nicht
/// überspringbare Fingerprint-Gate" ruft genau diese Funktion; sie schreibt
/// weder HKDF noch den Info-String ein zweites Mal.
///
/// # Errors
/// `EA-READER-VAULT-KEK-DERIVATION`, wenn HKDF die verlangte Ausgabelaenge
/// abweist.
pub fn derive_kek_v1(prf: &AuthenticatorPrfV1) -> Result<SecretBytes<CEK_SIZE>, ReaderVaultError> {
    derive_key(&prf.prf_output, VAULT_KEK_INFO_V1)
}

/// Der Cacheschluessel `HKDF-SHA-256(vault_key, info = VAULT_CACHE_INFO_V1)`.
pub(crate) fn derive_cache_key_v1(
    vault_key: &SecretBytes<CEK_SIZE>,
) -> Result<SecretBytes<CEK_SIZE>, ReaderVaultError> {
    derive_key(vault_key, VAULT_CACHE_INFO_V1)
}

/// Der Schluessel des Zustandsspeichers.
pub(crate) fn derive_entry_state_key_v1(
    vault_key: &SecretBytes<CEK_SIZE>,
) -> Result<SecretBytes<CEK_SIZE>, ReaderVaultError> {
    derive_key(vault_key, VAULT_STATE_INFO_V1)
}

/// Der Schluessel des Trust-Standspeichers.
pub(crate) fn derive_trust_state_key_v1(
    vault_key: &SecretBytes<CEK_SIZE>,
) -> Result<SecretBytes<CEK_SIZE>, ReaderVaultError> {
    derive_key(vault_key, VAULT_TRUST_STATE_INFO_V1)
}

/// Der Schluessel des bestaetigten Sync-Cursors.
pub(crate) fn derive_sync_cursor_key_v1(
    vault_key: &SecretBytes<CEK_SIZE>,
) -> Result<SecretBytes<CEK_SIZE>, ReaderVaultError> {
    derive_key(vault_key, VAULT_SYNC_CURSOR_INFO_V1)
}

/// Der Schluessel des signierten lokalen Auditprotokolls.
pub(crate) fn derive_audit_log_key_v1(
    vault_key: &SecretBytes<CEK_SIZE>,
) -> Result<SecretBytes<CEK_SIZE>, ReaderVaultError> {
    derive_key(vault_key, VAULT_AUDIT_LOG_INFO_V1)
}

/// Der Indexschluessel.
pub(crate) fn derive_index_key_v1(
    vault_key: &SecretBytes<CEK_SIZE>,
) -> Result<SecretBytes<CEK_SIZE>, ReaderVaultError> {
    derive_key(vault_key, VAULT_INDEX_INFO_V1)
}

/// HKDF-SHA-256 ueber ein Geheimnis, ohne Salz und mit festem Kontext.
///
/// Ohne Salz, weil das Eingabeschluesselmaterial in beiden Faellen bereits
/// gleichverteilte 32 Byte sind — eine PRF-Ausgabe oder ein gezogener
/// Tresorschluessel — und ein zweites, mitzuspeicherndes Geheimnis dem Tresor
/// nur einen weiteren Verlustpunkt gaebe. Die Trennung leistet der
/// Info-Kontext, und der ist je Zweck ein anderer.
///
/// Das Stackarray wird nach der Uebernahme durch [`SecretBytes`] ausdruecklich
/// geloescht: `SecretBytes` steht unter `ZeroizeOnDrop`, aber fuer die Kopie,
/// aus der es gebaut wurde, kann es nichts tun.
fn derive_key(
    ikm: &SecretBytes<32>,
    info: &[u8],
) -> Result<SecretBytes<CEK_SIZE>, ReaderVaultError> {
    let mut derived = [0_u8; CEK_SIZE];
    let expanded =
        ikm.with_exposed(|bytes| Hkdf::<Sha256>::new(None, bytes).expand(info, &mut derived));
    if expanded.is_err() {
        derived.zeroize();
        return Err(ReaderVaultError::KekDerivation);
    }
    let key = SecretBytes::new(derived);
    derived.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::{VaultEnvelopeV1, derive_key};
    use ea_crypto::{AEAD_NONCE_SIZE, CEK_SIZE, SecretBytes};

    /// Ein Envelope laesst sich NICHT auf eine fremde `credentialId` umhaengen.
    ///
    /// Der Zeuge liegt in der Crate und nicht in `tests/`, weil
    /// [`VaultEnvelopeV1::from_parts`] `pub(crate)` ist — und das soll es
    /// bleiben: ausserhalb dieser Crate soll niemand ein Envelope
    /// zusammensetzen, das keine AEAD-Umschliessung hinter sich hat. Die
    /// Alternative waere eine weitere `*_for_test`-Methode hinter
    /// `test-support` gewesen; sie kostete mehr Oberflaeche als dieser Test.
    ///
    /// Gemessen wird mit DEMSELBEN `kek`: faellt die `credentialId` aus
    /// [`super::envelope_aad`], geht das umetikettierte Envelope auf, und die
    /// Bindung, die der Modulkopf als Existenzgrund ausschreibt, waere leer.
    #[test]
    fn a_relabelled_envelope_refuses_under_its_own_kek() {
        let kek = derive_key(&SecretBytes::new([0xa1_u8; 32]), super::VAULT_KEK_INFO_V1).unwrap();
        let vault_key = SecretBytes::new([0x5c_u8; CEK_SIZE]);
        let nonce = [0x07_u8; AEAD_NONCE_SIZE];

        let envelope =
            VaultEnvelopeV1::wrap(&kek, &vault_key, &nonce, b"passkey-eins".to_vec()).unwrap();
        assert!(envelope.unwrap(&kek).is_ok());

        let relabelled = VaultEnvelopeV1::from_parts(
            b"passkey-zwei".to_vec(),
            nonce,
            envelope.wrapped_vault_key(),
        )
        .unwrap();
        // Kein `unwrap_err()`: der Erfolgsfall traegt `SecretBytes`, und das
        // hat bewusst kein `Debug` — ein Tresorschluessel soll sich nicht
        // beilaeufig in eine Testmeldung schreiben.
        match relabelled.unwrap(&kek) {
            Ok(_) => panic!("ein umetikettiertes Envelope DARF NICHT aufgehen"),
            Err(error) => assert_eq!(error.code(), "EA-CRYPTO-AEAD-OPEN"),
        }
    }
}
