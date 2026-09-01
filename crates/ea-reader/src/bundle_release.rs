//! Die Aktivierungsregel des Web-Bundles nach `web-reader-design.md` §4.2.
//!
//! # Die Regel in einem Satz
//!
//! Der Service Worker DARF eine Kandidatenfassung nur aktivieren, wenn ihr Hash
//! gegen eine gepinnte, wurzelsignierte `webBundleRelease` aufgeht; jeder
//! andere Ausgang laesst die zuletzt gueltige Fassung aktiv. Es gibt deshalb
//! keinen Rueckgabewert, der „aktivieren, aber mit Warnung" bedeutet.
//!
//! # Uebergehen und Abweisen sind NICHT dasselbe
//!
//! Ein Objekt eines anderen Subtyps gehoert einem anderen Pruefweg und wird
//! still uebergangen. Ein Objekt DIESER Familie, das seine Wurzelsignatur
//! nicht belegt, ist der Angriff, gegen den §4.1 gebaut ist: es wird
//! ABGEWIESEN und darf nicht als abwesend gelten. Ein kompromittierter
//! Sync-Server, der eine fremd signierte Freigabe unterschiebt, muss als
//! [`BundleRejectionCodeV1::WrongRoot`] sichtbar werden und nicht als blosse
//! Hashabweichung.
//!
//! # Was hier NICHT entschieden wird
//!
//! Die WURZELROTATION. [`TrustAnchorV1`] nennt ueber
//! `root_certificate_object_hash` das INITIALE Wurzelzertifikat, und eine
//! Freigabe, die eine rotierte Wurzel unterschrieben hat, geht dagegen nicht
//! auf. Solange keine Rotation stattgefunden hat — der Stand dieser Stufe —
//! ist das Verhalten korrekt und fail-closed: eine solche Freigabe faellt mit
//! `WrongRoot`, die zuletzt gueltige Fassung bleibt aktiv, also verliert
//! niemand Zugriff. Die Aufloesung gehoert dorthin, wo die Rotationszeremonie
//! gebaut wird.

use ea_crypto::{object_hash, verify_web_bundle_trust_signature};
use ea_format::{DecodedTrustPayloadV1, ParsedArchiveObject, TrustSubtypeV1, decode_exact_object};
use ea_trust::TrustAnchorV1;
use ea_types::{CertificateHash, Hash32, ObjectHash, RegistryVersion, UnixMillis};

/// Warum eine Kandidatenfassung nicht aktiviert wurde.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundleRejectionCodeV1 {
    /// Der Trust-Bestand nennt gar keine wirksame Freigabe.
    NoPinnedRelease,
    /// Die Freigabe belegt keine tragende Wurzelsignatur.
    Unsigned,
    /// Die Signatur steht unter einer FREMDEN Wurzel.
    WrongRoot,
    /// Die Freigabe gehoert einer fremden Organisation.
    WrongOrganization,
    /// Ein wirksamer Widerruf hat die Freigabe entzogen.
    Revoked,
    /// Die Freigabe wird erst ab einem spaeteren Registry-Stand wirksam.
    NotYetEffective,
    /// Der Hash des Kandidaten geht gegen keine aktive Freigabe auf.
    HashMismatch,
}

/// Die Entscheidung ueber genau eine Kandidatenfassung.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundleActivationDecisionV1 {
    /// Aktivieren — der Hash geht gegen die gepinnte Freigabe auf.
    Activate {
        /// Die Fassung, unter der der Cache gefuehrt wird.
        bundle_version: String,
    },
    /// Nicht aktivieren; die zuletzt gueltige Fassung bleibt aktiv.
    KeepActive {
        /// Der Grund, in der Sprache von §4.2.
        code: BundleRejectionCodeV1,
    },
}

/// Ein Objekt, das sich als wurzelsignierte Freigabe AUSGIBT und die Pruefung
/// nicht besteht, ist ein Angriff und kein Rauschen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReaderBundleError {
    code: BundleRejectionCodeV1,
}

impl ReaderBundleError {
    #[must_use]
    pub const fn code(&self) -> BundleRejectionCodeV1 {
        self.code
    }
}

impl core::fmt::Display for ReaderBundleError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self.code {
            BundleRejectionCodeV1::NoPinnedRelease => "no pinned web bundle release",
            BundleRejectionCodeV1::Unsigned => "web bundle release without a bearing signature",
            BundleRejectionCodeV1::WrongRoot => "web bundle release under a foreign root",
            BundleRejectionCodeV1::WrongOrganization => {
                "web bundle release of a foreign organization"
            }
            BundleRejectionCodeV1::Revoked => "revoked web bundle release",
            BundleRejectionCodeV1::NotYetEffective => "web bundle release not yet effective",
            BundleRejectionCodeV1::HashMismatch => "web bundle candidate hash mismatch",
        })
    }
}

impl std::error::Error for ReaderBundleError {}

/// Eine wurzelgepruefte Freigabe samt ihrem Stand im gegebenen Registry-Stand.
struct PinnedRelease {
    bundle_hash: Hash32,
    bundle_version: String,
    effective_from_registry_version: RegistryVersion,
    issued_at: UnixMillis,
    object_hash: ObjectHash,
    effective: bool,
    revoked: bool,
}

/// Der gepinnte Bundle-Stand eines Geraets.
pub struct ReaderBundlePin {
    releases: Vec<PinnedRelease>,
    active: Option<usize>,
}

impl ReaderBundlePin {
    /// Baut den Pin aus den exakten Bytes des lokalen Trust-Bestandes.
    ///
    /// Fremde Subtypen werden uebergangen. Jede Freigabe und jeder Widerruf
    /// dieser Familie MUSS seine Wurzelsignatur gegen `anchor` belegen und die
    /// Organisation des Ankers tragen; sonst ist der ganze Aufruf ein Fehler.
    ///
    /// # Errors
    ///
    /// [`ReaderBundleError`] mit dem Code, der den ersten Verstoss benennt.
    /// Ein Objekt, das gar nicht dekodiert, gilt als [`BundleRejectionCodeV1::Unsigned`]:
    /// es legt keine pruefbare Wurzelsignatur vor, und es zu uebergehen hiesse,
    /// einer untergeschobenen Fassung eine Formabweichung als Versteck zu
    /// lassen. Der Preis ist benannt und nicht geglaettet: ein verstuemmeltes
    /// Objekt einer FREMDEN Familie landet damit ebenfalls hier, statt
    /// uebergangen zu werden.
    pub fn from_trust_objects(
        anchor: &TrustAnchorV1,
        exact_trust_objects: &[&[u8]],
        at_registry_version: RegistryVersion,
    ) -> Result<Self, ReaderBundleError> {
        let expected_certificate_hash =
            CertificateHash::from(anchor.root_certificate_object_hash());
        let mut releases: Vec<PinnedRelease> = Vec::new();
        let mut revoked_object_hashes: Vec<ObjectHash> = Vec::new();

        for bytes in exact_trust_objects {
            let Ok(ParsedArchiveObject::Trust(parsed)) = decode_exact_object(bytes) else {
                // Undekodierbar: keine pruefbare Wurzelsignatur. Fail-closed.
                return Err(ReaderBundleError {
                    code: BundleRejectionCodeV1::Unsigned,
                });
            };
            let object = parsed.value();
            if !matches!(
                object.subtype(),
                TrustSubtypeV1::WebBundleRelease | TrustSubtypeV1::WebBundleRevocation
            ) {
                // Fremder Subtyp, fremder Pruefweg.
                continue;
            }

            let [signature] = object.signatures() else {
                // Die Kardinalitaet steht seit Stufe 3 in `validate_signature_count`
                // und wird hier nicht ein zweites Mal erfunden — aber bezeugt.
                return Err(ReaderBundleError {
                    code: BundleRejectionCodeV1::Unsigned,
                });
            };
            verify_web_bundle_trust_signature(
                signature,
                anchor.root_public_cose_key(),
                expected_certificate_hash,
                object.exact_digest_input(),
            )
            .map_err(|error| ReaderBundleError {
                code: match error {
                    // Ein fremder Schluesselabdruck oder Zertifikatshash ist der
                    // Tausch, gegen den §4.1 gebaut ist.
                    ea_crypto::CryptoError::SignerMismatch => BundleRejectionCodeV1::WrongRoot,
                    _ => BundleRejectionCodeV1::Unsigned,
                },
            })?;

            let payload = object.decoded_payload().map_err(|_| ReaderBundleError {
                code: BundleRejectionCodeV1::Unsigned,
            })?;
            match payload {
                DecodedTrustPayloadV1::WebBundleRelease(core) => {
                    if core.organization_id != anchor.organization_id() {
                        return Err(ReaderBundleError {
                            code: BundleRejectionCodeV1::WrongOrganization,
                        });
                    }
                    releases.push(PinnedRelease {
                        bundle_hash: core.bundle_hash,
                        bundle_version: core.bundle_version,
                        effective: core.effective_from_registry_version <= at_registry_version,
                        effective_from_registry_version: core.effective_from_registry_version,
                        issued_at: core.issued_at,
                        object_hash: object_hash(bytes),
                        revoked: false,
                    });
                }
                DecodedTrustPayloadV1::WebBundleRevocation(core) => {
                    if core.organization_id != anchor.organization_id() {
                        return Err(ReaderBundleError {
                            code: BundleRejectionCodeV1::WrongOrganization,
                        });
                    }
                    // Ein Widerruf wirkt erst ab seinem EIGENEN Registry-Stand.
                    if core.effective_from_registry_version <= at_registry_version {
                        revoked_object_hashes.push(core.release_object_hash);
                    }
                }
                _ => unreachable!("der Subtyp ist auf die zwei Faelle der Familie eingeschraenkt"),
            }
        }

        for release in &mut releases {
            release.revoked = revoked_object_hashes.contains(&release.object_hash);
        }

        Ok(Self {
            active: select_active(&releases),
            releases,
        })
    }

    /// Der Hash der aktiven Freigabe, falls eine gepinnt ist.
    #[must_use]
    pub fn active_bundle_hash(&self) -> Option<Hash32> {
        self.active.map(|index| self.releases[index].bundle_hash)
    }

    /// Die Entscheidung ueber genau diese Kandidatenfassung.
    #[must_use]
    pub fn evaluate(&self, candidate_bundle_hash: Hash32) -> BundleActivationDecisionV1 {
        if let Some(active) = self.active.map(|index| &self.releases[index])
            && active.bundle_hash == candidate_bundle_hash
        {
            return BundleActivationDecisionV1::Activate {
                bundle_version: active.bundle_version.clone(),
            };
        }

        let named = self
            .releases
            .iter()
            .find(|release| release.bundle_hash == candidate_bundle_hash);
        let code = match named {
            Some(release) if release.revoked => BundleRejectionCodeV1::Revoked,
            Some(release) if !release.effective => BundleRejectionCodeV1::NotYetEffective,
            Some(_) => BundleRejectionCodeV1::HashMismatch,
            None if self.active.is_none() => BundleRejectionCodeV1::NoPinnedRelease,
            None => BundleRejectionCodeV1::HashMismatch,
        };
        BundleActivationDecisionV1::KeepActive { code }
    }
}

/// Aktiv ist die wirksame, nicht widerrufene Freigabe mit dem hoechsten
/// Wirksamkeitsstand.
///
/// Bei Gleichstand entscheidet das spaetere `issued_at`; bei erneutem
/// Gleichstand KEINE — zwei gleichzeitig wirksame Freigaben desselben Standes
/// waeren eine Aussage der Wurzel, die niemand aufloesen darf.
fn select_active(releases: &[PinnedRelease]) -> Option<usize> {
    let mut best: Option<usize> = None;
    let mut ambiguous = false;

    for (index, release) in releases.iter().enumerate() {
        if !release.effective || release.revoked {
            continue;
        }
        match best {
            None => {
                best = Some(index);
                ambiguous = false;
            }
            Some(current) => {
                let incumbent = &releases[current];
                let key = (release.effective_from_registry_version, release.issued_at);
                let incumbent_key = (
                    incumbent.effective_from_registry_version,
                    incumbent.issued_at,
                );
                if key > incumbent_key {
                    best = Some(index);
                    ambiguous = false;
                } else if key == incumbent_key {
                    ambiguous = true;
                }
            }
        }
    }

    if ambiguous { None } else { best }
}
