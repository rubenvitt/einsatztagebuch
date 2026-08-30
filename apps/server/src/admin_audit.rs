//! Das privilegierte Administrationsaudit und die Faehigkeitsgrenze der
//! Serververwaltung.
//!
//! # Was hier protokolliert wird — und was ausdruecklich nicht
//!
//! Die Tabelle `technical_admin_audit` (`migrations/0001_initial.sql`:343-350)
//! protokolliert VERWALTUNGSHANDLUNGEN am Server, nicht Einsaetze. Dieses
//! Modul gibt ihr die typisierte Flaeche: [`AdminAuditRecordV1`] traegt einen
//! pseudonymen Handelnden, ein pseudonymes Geraet, einen geschlossenen
//! Handlungscode, ein geschlossenes technisches Ergebnis, die Zeit und
//! HOECHSTENS einen Objekthash. Ein Freitextfeld gibt es nicht, und es gibt
//! auch keinen Konstruktor, der eines annehmen koennte: ein solcher waere
//! genau der Kanal, ueber den ein fachlicher Wert doch noch in die Datenbank
//! kaeme. Dieselbe Entscheidung steht schon ueber `security_events`
//! (`migrations/0001_initial.sql`:328-338).
//!
//! Die acht Handlungen aus [`AdminActionCodeV1`] sind die, die
//! `design.md` Abschnitt 23, Kriterium 45 („Sync-Server-Administration")
//! benennt: privilegierte Anmeldung, Konfigurationsaenderung,
//! Sicherung, Rueckspielung, Aenderung des Object Lock, Rotation des
//! Serverschluessels, Aktualisierung und die Behandlung eines Security Events.
//!
//! # Die Faehigkeitsgrenze
//!
//! [`ServerAdminConfig::schema_capabilities`] beschreibt die Faehigkeitsmenge
//! der ADMINISTRATIONSKONFIGURATION — nicht die des Quittungsschluessels. Die
//! Gleichheit auf genau [`CertificateCapability::ServerReceipt`] sagt: der
//! Serveradministrator kann keine Autoritaet darueber hinaus konfigurieren.
//!
//! Die drei Verbote — nicht entschluesseln, nicht als Writer signieren, nicht
//! als Registry autorisieren — stehen als ABWESENHEIT jeder Grant- und
//! Signaturfaehigkeit da und NICHT als eigene Varianten:
//! [`CertificateCapability`] ist auf sieben Varianten geschlossen, und eine
//! parallele Aufzaehlung in `apps/server` oder `crates/ea-sync-server` ist
//! ausgeschlossen. Die Zweckbindung des technischen Cursors laeuft ueber eine
//! additive Domaenenzeichenkette und nicht ueber eine achte Variante, deshalb
//! steht diese Zusage ohne Vorbehalt.

use ea_crypto::CertificateCapability;
use ea_types::{Id16, ObjectHash, OrganizationId, UnixMillis};

/// Die Konfiguration der Serververwaltung.
///
/// Ein Nullgroessentyp mit Absicht: die Stufe 3 konfiguriert an der
/// Verwaltung keinen einzigen Wert, der eine Autoritaet verliehe. Was der Typ
/// traegt, ist die Zusage selbst — [`Self::schema_capabilities`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServerAdminConfig;

impl ServerAdminConfig {
    /// Die Faehigkeiten, die diese Konfiguration ueberhaupt ausdruecken kann.
    ///
    /// GENAU eine: [`CertificateCapability::ServerReceipt`]. Der Server stellt
    /// Quittungen aus; er erteilt keine Grants, genehmigt keine historischen
    /// Grants, bestaetigt keine Vernichtung und beglaubigt keine Loeschung.
    #[must_use]
    pub fn schema_capabilities() -> Vec<CertificateCapability> {
        vec![CertificateCapability::ServerReceipt]
    }
}

/// Die acht privilegierten Handlungen, die das Audit kennt.
///
/// Acht und nicht sieben, weil Sicherung und Rueckspielung getrennt stehen:
/// eine gemeinsame Variante liesse offen, welche der beiden geschehen ist,
/// und genau diese Unterscheidung traegt der Stufe-3-Restore-Nachweis.
///
/// Geschlossen und ohne `Other`-Arm: eine Handlung, die hier nicht steht, wird
/// nicht protokolliert, sondern existiert nicht. Die Wire-Literale sind
/// `SCREAMING-KEBAB` wie die uebrigen Codes dieses Arbeitsbereichs und werden
/// nie umbenannt — sie stehen in ausgelieferten Auditzeilen.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AdminActionCodeV1 {
    /// Anmeldung an der privilegierten Verwaltungsflaeche.
    PrivilegedLogin,
    /// Aenderung an der Serverkonfiguration.
    ConfigurationChange,
    /// Anlegen einer Sicherung von Datenbank und Bucket.
    BackupCreate,
    /// Rueckspielung einer Sicherung.
    BackupRestore,
    /// Aenderung der Object-Lock-Einstellung des Buckets.
    ObjectLockChange,
    /// Rotation des Root-signierten Ed25519-Serverschluessels.
    ServerKeyRotation,
    /// Aktualisierung der Serversoftware oder ihres Basisimages.
    SoftwareUpdate,
    /// Behandlung eines Security Events durch die Verwaltung.
    SecurityEventHandling,
}

impl AdminActionCodeV1 {
    /// Jede Variante, in Deklarationsreihenfolge.
    ///
    /// Sie steht hier, damit ein Test die Menge gegen eine UNABHAENGIGE Liste
    /// halten kann, statt sie aus sich selbst abzuleiten.
    pub const ALL: [Self; 8] = [
        Self::PrivilegedLogin,
        Self::ConfigurationChange,
        Self::BackupCreate,
        Self::BackupRestore,
        Self::ObjectLockChange,
        Self::ServerKeyRotation,
        Self::SoftwareUpdate,
        Self::SecurityEventHandling,
    ];

    /// Das Wire-Literal dieses Handlungscodes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrivilegedLogin => "EA-ADMIN-PRIVILEGED-LOGIN",
            Self::ConfigurationChange => "EA-ADMIN-CONFIGURATION-CHANGE",
            Self::BackupCreate => "EA-ADMIN-BACKUP-CREATE",
            Self::BackupRestore => "EA-ADMIN-BACKUP-RESTORE",
            Self::ObjectLockChange => "EA-ADMIN-OBJECT-LOCK-CHANGE",
            Self::ServerKeyRotation => "EA-ADMIN-SERVER-KEY-ROTATION",
            Self::SoftwareUpdate => "EA-ADMIN-SOFTWARE-UPDATE",
            Self::SecurityEventHandling => "EA-ADMIN-SECURITY-EVENT-HANDLING",
        }
    }
}

/// Das technische Ergebnis einer privilegierten Handlung.
///
/// Drei Auspraegungen und keine vierte: gelungen, fail-closed abgewiesen,
/// technisch gescheitert. Ein Grund als Freitext gehoert NICHT dazu.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AdminActionOutcomeV1 {
    /// Die Handlung ist durchgefuehrt.
    Succeeded,
    /// Die Handlung wurde fail-closed abgewiesen.
    Refused,
    /// Die Handlung ist technisch gescheitert.
    Failed,
}

impl AdminActionOutcomeV1 {
    /// Das Wire-Literal dieses Ergebnisses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Refused => "refused",
            Self::Failed => "failed",
        }
    }
}

/// Eine Zeile des privilegierten Administrationsaudits.
///
/// Die Felder sind privat und werden ausschliesslich ueber
/// [`AdminAuditRecordV1::new`] gesetzt. Damit gibt es keinen Weg, einen
/// fachlichen Wert in eine Auditzeile zu legen: jedes Feld ist entweder eine
/// pseudonyme 16-Byte-Kennung, ein geschlossener Code, eine Zeit oder ein
/// Objekthash.
///
/// KEIN `Debug`: `Id16`, `OrganizationId` und `ObjectHash` fuehren bewusst
/// keines, damit eine Kennung nicht ueber eine beilaeufige Debug-Ausgabe in
/// einen Bytestrom geraet. Ein abgeleitetes `Debug` hier verlangte es von
/// ihnen und hoebe genau diese Entscheidung auf.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AdminAuditRecordV1 {
    organization: OrganizationId,
    actor: Id16,
    device: Id16,
    action: AdminActionCodeV1,
    outcome: AdminActionOutcomeV1,
    object: Option<ObjectHash>,
    recorded_at: UnixMillis,
}

impl AdminAuditRecordV1 {
    /// Baut eine Auditzeile.
    ///
    /// `actor` und `device` sind PSEUDONYME: sie identifizieren einen Bediener
    /// und ein Geraet innerhalb der Organisation und tragen keinen Namen.
    /// `object` traegt hoechstens einen Objekthash — nie einen Objektinhalt.
    #[must_use]
    pub const fn new(
        organization: OrganizationId,
        actor: Id16,
        device: Id16,
        action: AdminActionCodeV1,
        outcome: AdminActionOutcomeV1,
        object: Option<ObjectHash>,
        recorded_at: UnixMillis,
    ) -> Self {
        Self {
            organization,
            actor,
            device,
            action,
            outcome,
            object,
            recorded_at,
        }
    }

    /// Die Organisation, unter der die Zeile gebucht wird.
    #[must_use]
    pub const fn organization(&self) -> OrganizationId {
        self.organization
    }

    /// Die pseudonyme Kennung des Handelnden — Spalte `operator_subject_id`.
    #[must_use]
    pub const fn actor(&self) -> Id16 {
        self.actor
    }

    /// Der Handlungscode — Spalte `action_code`.
    #[must_use]
    pub const fn action(&self) -> AdminActionCodeV1 {
        self.action
    }

    /// Der Zeitpunkt — Spalte `recorded_at_millis`.
    #[must_use]
    pub const fn recorded_at(&self) -> UnixMillis {
        self.recorded_at
    }

    /// Die technische Kennung der Zeile — Spalte `subject_key`.
    ///
    /// Sie setzt sich aus dem Geraetepseudonym, dem Ergebnis und dem
    /// Objekthash zusammen, jeweils hexadezimal beziehungsweise als
    /// geschlossenes Literal, getrennt durch `/`. Ein fehlender Objekthash
    /// steht als `-`; ein leeres Feld waere von einem verlorenen Feld nicht zu
    /// unterscheiden.
    ///
    /// Die Zusammensetzung ist noetig, weil `technical_admin_audit` genau eine
    /// technische Spalte fuehrt und diese Stufe GENAU EINE Migration
    /// ausliefert (`apps/server/tests/migrations.rs::the_single_migration_creates_every_planned_table`);
    /// die Fortschreibung des Schemas gegen eine bereits ausgelieferte
    /// Installation ist Gegenstand der Stufe 7.
    #[must_use]
    pub fn subject_key(&self) -> String {
        let object = self
            .object
            .map_or_else(|| "-".to_owned(), |hash| hex::encode(hash.as_bytes()));
        format!(
            "{}/{}/{object}",
            hex::encode(self.device.as_bytes()),
            self.outcome.as_str()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{AdminActionCodeV1, AdminActionOutcomeV1, AdminAuditRecordV1, ServerAdminConfig};
    use ea_crypto::CertificateCapability;
    use ea_types::{Id16, ObjectHash, OrganizationId, UnixMillis};

    /// Die Zusage der Rollentrennung, ausgeschrieben.
    ///
    /// Die Gleichheit ist der Kern; die zweite Zusicherung nennt jede
    /// verbotene Faehigkeit EINZELN, damit eine spaetere Erweiterung der
    /// Menge nicht still durchginge, sondern hier mit dem Namen der
    /// hinzugekommenen Faehigkeit rot wuerde.
    #[test]
    fn server_admin_configuration_has_no_content_or_grant_authority() {
        let caps = ServerAdminConfig::schema_capabilities();
        assert_eq!(caps, vec![CertificateCapability::ServerReceipt]);
        assert!(!caps.iter().any(|c| matches!(
            c,
            CertificateCapability::InitialGrant
                | CertificateCapability::HistoricalGrant
                | CertificateCapability::OrganizationAdminApprove
                | CertificateCapability::HistoricalGrantApprove
                | CertificateCapability::DestructionApprove
                | CertificateCapability::DeletionAttest
        )));
    }

    /// Die acht Handlungscodes tragen acht verschiedene Wire-Literale, und
    /// jedes traegt das Praefix `EA-ADMIN-`.
    ///
    /// Ohne die Verschiedenheit koennten zwei Handlungen dieselbe Auditzeile
    /// erzeugen, und die Zeile sagte nicht mehr, was geschehen ist.
    #[test]
    fn every_admin_action_code_carries_its_own_prefixed_literal() {
        let literals: std::collections::BTreeSet<&str> = AdminActionCodeV1::ALL
            .iter()
            .map(|action| action.as_str())
            .collect();
        assert_eq!(literals.len(), AdminActionCodeV1::ALL.len());
        for action in AdminActionCodeV1::ALL {
            assert!(
                action.as_str().starts_with("EA-ADMIN-"),
                "{action:?} traegt kein Administrationspraefix: {}",
                action.as_str()
            );
        }
    }

    /// Die technische Kennung traegt AUSSCHLIESSLICH Hexziffern, die drei
    /// geschlossenen Ergebnisliterale, `/` und `-`.
    ///
    /// Das ist die ausfuehrbare Fassung der Zusage „nur Objekthashes": ein
    /// fachliches Zeichen kaeme durch dieses Alphabet nicht hindurch.
    #[test]
    fn the_subject_key_carries_only_technical_characters() {
        let organization =
            OrganizationId::from(Id16::try_from(&[0x11_u8; 16][..]).expect("sechzehn Byte"));
        let actor = Id16::try_from(&[0x22_u8; 16][..]).expect("sechzehn Byte");
        let device = Id16::try_from(&[0x33_u8; 16][..]).expect("sechzehn Byte");
        let object = ObjectHash::try_from(&[0x44_u8; 32][..]).expect("zweiunddreissig Byte");

        for (outcome, expected) in [
            (AdminActionOutcomeV1::Succeeded, "succeeded"),
            (AdminActionOutcomeV1::Refused, "refused"),
            (AdminActionOutcomeV1::Failed, "failed"),
        ] {
            for object in [Some(object), None] {
                let record = AdminAuditRecordV1::new(
                    organization,
                    actor,
                    device,
                    AdminActionCodeV1::ServerKeyRotation,
                    outcome,
                    object,
                    UnixMillis::new(1_700_000_000_000),
                );
                let key = record.subject_key();
                assert!(
                    key.contains(expected),
                    "die Kennung MUSS ihr Ergebnis nennen: {key}"
                );
                assert!(
                    key.chars().all(|c| c.is_ascii_hexdigit()
                        || c.is_ascii_lowercase()
                        || matches!(c, '/' | '-')),
                    "die Kennung traegt ein Zeichen ausserhalb des technischen Alphabets: {key}"
                );
                assert!(record.actor() == actor);
                assert!(record.organization() == organization);
                assert_eq!(record.action(), AdminActionCodeV1::ServerKeyRotation);
            }
        }
    }
}
