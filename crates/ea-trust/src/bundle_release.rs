//! Die Aktivierungsregel des Web-Bundles nach `web-reader-design.md` §4.2.
//!
//! # Warum sie im Trust-Kern liegt
//!
//! Dieselbe Regel entscheidet zwei Dinge: im Reader, ob der Service Worker
//! eine Kandidatenfassung aktiviert, und im Server wie in der nativen
//! Zeremonie, ob die Cutover-Vorbedingung des v1.1-Profils (§5) gilt — eine
//! aktive `webBundleRelease` eines v1.1-fähigen Bundles. Es gibt genau EINE
//! Umsetzung (Ruling U1); `ea-reader` exportiert sie unverändert weiter.
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
use ea_types::{CertificateHash, Hash32, ObjectHash, RegistryVersion, UnixMillis};

use crate::TrustAnchorV1;

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

/// Die kleinste `bundle-version`, die die drei Reader-Key-Escrow-Familien
/// trägt (v1.1-Profil §5, U4: „v1.1-fähig" heißt nicht kleiner als die
/// gepinnte Mindestversion).
///
/// Der Wert liegt bewusst ÜBER jeder heute ausgelieferten Fassung (der
/// eingefrorene Vektor trägt `2026.3.1`): keine bestehende Freigabe öffnet die
/// Sperre. Die Ordnung steht in [`bundle_version_carries_reader_key_escrow`].
pub const MIN_ESCROW_BUNDLE_VERSION: &str = "2026.4.0";

/// Ob eine `bundle-version` die drei Escrow-Familien trägt.
///
/// Die Fassung ist eine Folge punktgetrennter Dezimalkomponenten; verglichen
/// wird komponentenweise numerisch, fehlende Komponenten zählen als null
/// (`2026.4` = `2026.4.0`). Alles, was sich so nicht zerlegen lässt — eine
/// leere Komponente, ein Nicht-Ziffernzeichen, ein Vorzeichen, ein Überlauf
/// —, gilt als NICHT fähig: die Sperre bleibt im Zweifel zu.
#[must_use]
pub fn bundle_version_carries_reader_key_escrow(bundle_version: &str) -> bool {
    let (Some(candidate), Some(minimum)) = (
        dotted_decimal(bundle_version),
        dotted_decimal(MIN_ESCROW_BUNDLE_VERSION),
    ) else {
        return false;
    };
    let width = candidate.len().max(minimum.len());
    let component = |parts: &[u64], index: usize| parts.get(index).copied().unwrap_or(0);
    for index in 0..width {
        let (have, need) = (component(&candidate, index), component(&minimum, index));
        if have != need {
            return have > need;
        }
    }
    true
}

fn dotted_decimal(version: &str) -> Option<Vec<u64>> {
    version
        .split('.')
        .map(|part| {
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            part.parse::<u64>().ok()
        })
        .collect()
}

/// Warum die Cutover-Vorbedingung nicht gilt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EscrowCutoverError {
    /// Ein Objekt der Bundle-Familie besteht seine Wurzelprüfung nicht — ein
    /// Angriff, keine Abwesenheit (siehe [`ReaderBundlePin::from_trust_objects`]).
    Bundle(BundleRejectionCodeV1),
    /// Zur Registry-Version der Publikation gilt keine aktive Freigabe.
    NoActiveRelease,
    /// Die aktive Freigabe nennt eine Fassung unter
    /// [`MIN_ESCROW_BUNDLE_VERSION`] oder eine, die sich nicht ordnen lässt.
    ReleaseNotCapable,
}

impl core::fmt::Display for EscrowCutoverError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bundle(code) => {
                core::fmt::Display::fmt(&ReaderBundleError { code: *code }, formatter)
            }
            Self::NoActiveRelease => formatter.write_str("no active web bundle release"),
            Self::ReleaseNotCapable => formatter
                .write_str("the active web bundle release does not carry the reader key escrow"),
        }
    }
}

impl std::error::Error for EscrowCutoverError {}

impl ReaderBundlePin {
    /// Objekthash und Fassung der aktiven Freigabe, falls eine gepinnt ist.
    #[must_use]
    pub fn active_release(&self) -> Option<(ObjectHash, &str)> {
        self.active.map(|index| {
            let release = &self.releases[index];
            (release.object_hash, release.bundle_version.as_str())
        })
    }
}

/// Die Freigabe, die die Cutover-Vorbedingung des Reader-Key-Escrows erfüllt
/// (v1.1-Profil §5, Entscheidung 9).
///
/// Vor der Annahme einer Publikation MUSS eine aktive, wurzelsignierte
/// `webBundleRelease` eines v1.1-fähigen Bundles gelten, deren
/// `effective-from-registry-version` nicht größer ist als
/// `at_registry_version` — die Registry-Version der Publikation, also die der
/// Publikationsfreigabe. „Aktiv" ist genau die Freigabe, die auch der Reader
/// pinnt ([`ReaderBundlePin`]); eine jüngere Freigabe einer älteren Fassung
/// schließt die Sperre deshalb wieder.
///
/// Der Rückgabewert ist der Objekthash dieser Freigabe: die native Zeremonie
/// schreibt ihn als `bundle-release-object-hash` in ihr Audit (§8), der
/// Server nimmt nur an, wenn es ihn gibt. Server und Zeremonie rufen dieselbe
/// Funktion — es gibt keinen Serverschalter, der sie übergeht (§9).
///
/// # Errors
///
/// [`EscrowCutoverError::Bundle`] für eine Freigabe oder einen Widerruf, der
/// seine Wurzelsignatur nicht belegt oder einer fremden Organisation gehört;
/// [`EscrowCutoverError::NoActiveRelease`] ohne aktive Freigabe;
/// [`EscrowCutoverError::ReleaseNotCapable`] für eine aktive Freigabe einer
/// nicht v1.1-fähigen Fassung.
pub fn reader_key_escrow_cutover_release(
    anchor: &TrustAnchorV1,
    exact_trust_objects: &[&[u8]],
    at_registry_version: RegistryVersion,
) -> Result<ObjectHash, EscrowCutoverError> {
    let pin = ReaderBundlePin::from_trust_objects(anchor, exact_trust_objects, at_registry_version)
        .map_err(|error| EscrowCutoverError::Bundle(error.code()))?;
    let (object_hash, bundle_version) = pin
        .active_release()
        .ok_or(EscrowCutoverError::NoActiveRelease)?;
    if !bundle_version_carries_reader_key_escrow(bundle_version) {
        return Err(EscrowCutoverError::ReleaseNotCapable);
    }
    Ok(object_hash)
}

/// Was die Annahme eines Objekts der Bundle-Familie ergab.
#[derive(Clone, Copy)]
pub enum WebBundleAdmission {
    /// Eine wurzelsignierte Freigabe dieser Organisation.
    Release {
        object_hash: ObjectHash,
        /// Ob die Fassung die drei Escrow-Familien trägt
        /// ([`bundle_version_carries_reader_key_escrow`]). Eine ältere
        /// Fassung ist ein legitimer Rückzug und wird ebenso angenommen.
        carries_reader_key_escrow: bool,
    },
    /// Ein wurzelsignierter Widerruf einer Freigabe, die im Katalog liegt.
    Revocation {
        object_hash: ObjectHash,
        release_object_hash: ObjectHash,
    },
}

/// Warum ein Objekt der Bundle-Familie nicht angenommen wird.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebBundleAdmissionError {
    /// Das Objekt ist weder `webBundleRelease` noch `webBundleRevocation`.
    NotBundleFamily,
    /// Die Familie trägt nicht — derselbe Code wie beim Reader-Pin.
    Bundle(BundleRejectionCodeV1),
    /// Der Widerruf nennt keine Freigabe des Katalogs. Ein hängender Widerruf
    /// würde später eine Freigabe entziehen, die es bei seiner Annahme nicht
    /// gab; die Reihenfolge ist deshalb Freigabe vor Widerruf.
    UnknownRelease,
}

impl core::fmt::Display for WebBundleAdmissionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotBundleFamily => formatter.write_str("not a web bundle family object"),
            Self::Bundle(code) => {
                core::fmt::Display::fmt(&ReaderBundleError { code: *code }, formatter)
            }
            Self::UnknownRelease => {
                formatter.write_str("web bundle revocation of a release outside the catalog")
            }
        }
    }
}

impl std::error::Error for WebBundleAdmissionError {}

/// Der eigene Einstieg der Bundle-Familie (v1.1-Profil §1.3 U4): nimmt eine
/// `webBundleRelease` oder einen `webBundleRevocation` in einen Katalog auf.
///
/// Die Regel ist die des Reader-Pins ([`ReaderBundlePin::from_trust_objects`])
/// über den Katalog samt Kandidat — Wurzelsignatur gegen den Anker,
/// Organisation, und die ganze Familie fail-closed. Dazu:
///
/// - `root-key-thumbprint` im Core ist der Abdruck der Ankerwurzel;
/// - ein Widerruf nennt eine `webBundleRelease`, die schon im Katalog liegt.
///
/// Die Annahme hängt an keinem Registry-Stand: ob eine Freigabe wirkt und
/// die Escrow-Sperre öffnet, entscheidet [`reader_key_escrow_cutover_release`]
/// zu dessen Stand. Eine Fähigkeitsprüfung gibt es hier deshalb nicht.
///
/// `exact_trust_objects` darf den Kandidaten schon enthalten; er zählt genau
/// einmal.
///
/// # Errors
///
/// [`WebBundleAdmissionError::NotBundleFamily`] für einen fremden Subtyp;
/// [`WebBundleAdmissionError::Bundle`] für jeden Befund der Familienregel (ein
/// undekodierbarer Kandidat gilt wie beim Pin als `Unsigned`);
/// [`WebBundleAdmissionError::UnknownRelease`] für einen Widerruf ohne seine
/// Freigabe im Katalog.
pub fn verify_web_bundle_family_admission(
    anchor: &TrustAnchorV1,
    exact_trust_objects: &[&[u8]],
    candidate: &[u8],
) -> Result<WebBundleAdmission, WebBundleAdmissionError> {
    let unsigned = WebBundleAdmissionError::Bundle(BundleRejectionCodeV1::Unsigned);
    let Ok(ParsedArchiveObject::Trust(parsed)) = decode_exact_object(candidate) else {
        return Err(unsigned);
    };
    if !matches!(
        parsed.value().subtype(),
        TrustSubtypeV1::WebBundleRelease | TrustSubtypeV1::WebBundleRevocation
    ) {
        return Err(WebBundleAdmissionError::NotBundleFamily);
    }
    let candidate_hash = object_hash(candidate);
    let mut objects: Vec<&[u8]> = exact_trust_objects
        .iter()
        .copied()
        .filter(|bytes| object_hash(bytes) != candidate_hash)
        .collect();
    let catalog_len = objects.len();
    objects.push(candidate);
    ReaderBundlePin::from_trust_objects(anchor, &objects, RegistryVersion::new(0))
        .map_err(|error| WebBundleAdmissionError::Bundle(error.code()))?;
    let wrong_root = WebBundleAdmissionError::Bundle(BundleRejectionCodeV1::WrongRoot);
    match parsed.value().decoded_payload().map_err(|_| unsigned)? {
        DecodedTrustPayloadV1::WebBundleRelease(core) => {
            if core.root_key_thumbprint != anchor.root_key_thumbprint() {
                return Err(wrong_root);
            }
            Ok(WebBundleAdmission::Release {
                object_hash: candidate_hash,
                carries_reader_key_escrow: bundle_version_carries_reader_key_escrow(
                    &core.bundle_version,
                ),
            })
        }
        DecodedTrustPayloadV1::WebBundleRevocation(core) => {
            if core.root_key_thumbprint != anchor.root_key_thumbprint() {
                return Err(wrong_root);
            }
            let names_a_release = objects[..catalog_len].iter().any(|bytes| {
                object_hash(bytes) == core.release_object_hash
                    && matches!(
                        decode_exact_object(bytes),
                        Ok(ParsedArchiveObject::Trust(release))
                            if release.value().subtype() == TrustSubtypeV1::WebBundleRelease
                    )
            });
            if !names_a_release {
                return Err(WebBundleAdmissionError::UnknownRelease);
            }
            Ok(WebBundleAdmission::Revocation {
                object_hash: candidate_hash,
                release_object_hash: core.release_object_hash,
            })
        }
        _ => Err(WebBundleAdmissionError::NotBundleFamily),
    }
}
