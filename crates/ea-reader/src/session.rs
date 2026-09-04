//! Die Reader-Sitzung: Sperre bei Untaetigkeit, verkuerzte Frist im
//! Hintergrundtab, Zeroize beim Sperren und die Authenticator-Bestaetigung.
//!
//! `docs/superpowers/specs/2026-08-15-einsatzarchiv-web-reader-design.md` §6.5
//! haelt fest, dass der X25519-Schluessel waehrend einer entsperrten Sitzung
//! im WASM-Speicher liegt, und nennt vier verpflichtende Gegenmassnahmen:
//! `zeroize` beim Sperren, Sperrung nach fuenf Minuten Untaetigkeit, eine
//! VERKUERZTE Frist beim Wechsel des Tabs in den Hintergrund und eine erneute
//! Authenticator-Bestaetigung nach jeder Sperrung. §11.2 fuehrt daneben den
//! OS-Lock-Ausloeser des Desktops als dokumentierte SOLL-Abweichung: der
//! Browser hat kein Ereignis dafuer, und [`ReaderSession`] TRAEGT deshalb
//! keines — nicht als Luecke, sondern als die Abweichung, die die
//! Spezifikation ausschreibt.
//!
//! # Die Sperrentscheidung faellt beim Zugriff und haengt an KEINEM Timer
//!
//! Hintergrundtabs werden in Chromium und Firefox auf etwa ein Timerereignis
//! je Sekunde gedrosselt und auf Mobilgeraeten beim Wechsel der Anwendung
//! ganz angehalten; ein `setTimeout`, das die Sperre ausloest, sperrt dort
//! nie. Deshalb rechnet [`ReaderSession::state_at`] die verstrichene Zeit bei
//! JEDEM Zugriff nach, und [`ReaderSession::vault`] sperrt, BEVOR es etwas
//! herausgibt. Ein Timer im Wirt darf zusaetzlich sperren — er beschleunigt
//! das Zeroize —, aber die Zusage steht hier.
//!
//! # Die Zeit kommt als Parameter herein und haelt eine monotone Untergrenze
//!
//! Dieselbe Regel wie ueberall im Kern: kein `SystemTime::now()`. Weil der
//! Aufrufer im Browser sitzt, haelt die Sitzung den hoechsten je gesehenen
//! Zeitwert als Untergrenze; ein `now` darunter verlaengert nichts. Eine
//! vorwaerts luegende Uhr sperrt frueher und ist deshalb kein Angriff.
//!
//! # Was die Sitzung offen haelt, und was NICHT
//!
//! Offen gehalten werden AUSSCHLIESSLICH [`VerifiedDecryptedRecord`]-Werte,
//! deren Nutzlast in `ea_crypto::SecretVec` liegt. Die Sitzung haelt weder
//! `ea_schema::ValidatedPayload` noch `ea_schema::DerivedView` in einem Feld
//! und gibt keines von beiden heraus — das ist die SCHRANKE, mit der die
//! Aufgabe „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter
//! und der Anchor, den nur der Vault liefert" ihre weitergereichte Restfrage
//! hier beantwortet bekommt. Beide Typen existieren nur innerhalb eines
//! einzigen `decrypt_verified`-Aufrufs beziehungsweise innerhalb von
//! `VerifiedDecryptedRecord::with_payload`.
//!
//! ```compile_fail
//! # use ea_reader::ReaderSession;
//! # fn hold(session: &ReaderSession) -> &ea_schema::ValidatedPayload {
//! session.validated_payload()
//! # }
//! ```
//!
//! # Der Nachweis ist nicht kopierbar
//!
//! [`ReaderAuthenticatorConfirmation`] ist weder `Clone` noch `Copy`, und der
//! Grund ist derselbe, den `ea_operator::OperatorSessionProof` traegt: ein
//! kopierbarer Nachweis machte den VERBRAUCH wirkungslos. [`ReaderSession::unlock`],
//! [`ReaderSession::reopen`] und `ReaderExportService::export_one` nehmen ihn
//! per Wert, und danach ist er fort.
//!
//! ```compile_fail
//! # use ea_reader::ReaderAuthenticatorConfirmation;
//! fn require_clone<T: Clone>() {}
//! require_clone::<ReaderAuthenticatorConfirmation>();
//! ```

use core::fmt;

use ea_types::{EntryHash, Hash32, UnixMillis};
use sha2::{Digest, Sha256};

use crate::decrypt::VerifiedDecryptedRecord;
use crate::envelope::AuthenticatorPrfV1;
use crate::vault::{ReaderVaultError, SealedVaultV1, UnlockedVault};

/// Der Vorgabewert der Untaetigkeitsfrist: fuenf Minuten.
///
/// Zeichengleich zu `ea_operator::MAX_INACTIVITY_MS`, aber HIER deklariert,
/// weil jene Crate wasm32-ausgenommen ist und keine Bibliothekskante des
/// Readers werden darf. `crates/ea-reader/tests/session_lock.rs` misst die
/// Gleichheit gegen das Original ueber eine ENTWICKLUNGSkante.
pub const READER_INACTIVITY_MS_V1: i64 = 5 * 60 * 1_000;

/// Die verkuerzte Frist des Hintergrundtabs nach `web-reader-design.md` §6.5.
///
/// §6.5 fordert die Frist als „verkuerzt", ohne eine Zahl zu nennen. Dreissig
/// Sekunden liegen eine Groessenordnung unter dem Fuenfminutenvorgabewert und
/// deutlich ueber der Drosselungsschwelle von etwa einer Sekunde, unterhalb
/// derer eine Frist im Hintergrundtab nicht mehr beobachtbar waere.
pub const READER_BACKGROUND_INACTIVITY_MS_V1: i64 = 30 * 1_000;

/// Wie lange eine Authenticator-Bestaetigung nach ihrer Ausstellung gilt.
///
/// Eine Minute: lang genug fuer die Zielwahl, die zwischen Zeremonie und
/// Export liegt, kurz genug, dass eine liegengebliebene Bestaetigung keine
/// zweite Handlung traegt. Eine Bestaetigung wird ausserdem VERBRAUCHT; die
/// Frist begrenzt nur, wie lange eine unverbrauchte liegen darf.
pub const READER_CONFIRMATION_VALIDITY_MS_V1: i64 = 60 * 1_000;

/// Die Sichtbarkeit des Tabs, wie der Wirt sie meldet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TabVisibility {
    /// Der Tab ist im Vordergrund.
    Visible,
    /// Der Tab ist im Hintergrund; die verkuerzte Frist laeuft.
    Hidden,
}

/// Der Zustand der Sitzung zu einem Zeitpunkt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReaderSessionState {
    /// Der Tresor ist zugaenglich.
    Unlocked,
    /// Der Tresor ist fort; es braucht eine frische Bestaetigung.
    Locked,
}

impl ReaderSessionState {
    /// Der Wortlaut, den die Bruecke nach JavaScript reicht.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unlocked => "unlocked",
            Self::Locked => "locked",
        }
    }
}

/// Der Zweck einer Authenticator-Bestaetigung — GESCHLOSSEN und zweiwertig.
///
/// Gebaut wie `ea_operator::ReauthPurpose`, aber hier deklariert, weil jene
/// Crate wasm32-ausgenommen ist. Eine Bestaetigung fuer einen Zweck
/// autorisiert den anderen nie: die fuer den Export entsperrt keine Sitzung,
/// die fuer das Entsperren exportiert nichts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReaderConfirmationPurpose {
    /// Entsperren oder Wiedereroeffnen der Sitzung.
    Unlock,
    /// Ein Einzelexport nach `web-reader-design.md` §8.2.
    SingleExport,
}

impl ReaderConfirmationPurpose {
    /// Der stabile Wortlaut des Zwecks.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unlock => "unlock",
            Self::SingleExport => "single-export",
        }
    }
}

/// Der Fehlschlag einer Sitzungshandlung.
#[derive(Clone, Eq, PartialEq)]
pub enum ReaderSessionError {
    /// Die Bestaetigung traegt einen anderen Zweck als die Handlung.
    ConfirmationPurpose,
    /// Die Bestaetigung ist abgelaufen oder liegt in der Zukunft.
    ConfirmationStale,
    /// Die Sitzung ist gesperrt.
    Locked,
    /// Ein Fehlschlag des Tresors beim Nachweis des Authenticators.
    Vault(ReaderVaultError),
}

impl ReaderSessionError {
    /// Stabiler Fehlercode. Zeugen assertieren gegen ihn, nie gegen
    /// Formatierung.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ConfirmationPurpose => "EA-READER-SESSION-CONFIRMATION-PURPOSE",
            Self::ConfirmationStale => "EA-READER-SESSION-CONFIRMATION-STALE",
            Self::Locked => "EA-READER-SESSION-LOCKED",
            Self::Vault(error) => error.code(),
        }
    }
}

impl From<ReaderVaultError> for ReaderSessionError {
    fn from(error: ReaderVaultError) -> Self {
        Self::Vault(error)
    }
}

impl fmt::Display for ReaderSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for ReaderSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ReaderSessionError {}

/// Der Nachweis einer FRISCHEN Authenticator-Bestaetigung.
///
/// Er entsteht AUSSCHLIESSLICH in [`ReaderAuthenticatorConfirmation::prove`],
/// und dort nur, wenn die vorgelegte PRF-Ausgabe das Envelope dieses
/// Authenticators im versiegelten Tresor tatsaechlich oeffnet. Das ist der
/// geprueft-Assertion-Pfad des Enrollments: eine PRF-Ausgabe ist nur nach
/// einer WebAuthn-Zeremonie mit Nutzerverifikation zu haben, und ob sie zu
/// diesem Tresor gehoert, entscheidet die AEAD-Umschliessung und nicht der
/// Aufrufer. Weder `Clone` noch `Copy`: siehe Modulkopf.
///
/// Das Feld `credential_id_hash` ist die PSEUDONYME Bedienerbindung des
/// Browsers: SHA-256 ueber die `credentialId` des bestaetigenden
/// Authenticators. Sie tritt im Audit an die Stelle der OS-Kontobindung des
/// Desktops und nennt weder die Kennung selbst noch einen Klarnamen.
pub struct ReaderAuthenticatorConfirmation {
    purpose: ReaderConfirmationPurpose,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
    credential_id_hash: Hash32,
}

impl ReaderAuthenticatorConfirmation {
    /// Belegt einen Authenticator gegen den versiegelten Tresor und stellt die
    /// Bestaetigung fuer GENAU EINEN Zweck aus.
    ///
    /// Der Tresor wird dabei NICHT geoeffnet: `SealedVaultV1::prove_authenticator`
    /// packt den umschlossenen Tresorschluessel aus und laesst ihn sofort
    /// fallen. Ein zweiter [`UnlockedVault`] entsteht nicht.
    ///
    /// # Errors
    /// `EA-READER-VAULT-NO-ENVELOPE`, wenn kein Envelope diese `credentialId`
    /// traegt; `EA-CRYPTO-AEAD-OPEN`, wenn die PRF-Ausgabe nicht passt;
    /// `EA-READER-SESSION-CONFIRMATION-STALE`, wenn die Gueltigkeitsfrist
    /// ueber `now` nicht darstellbar ist.
    pub fn prove(
        sealed: &SealedVaultV1,
        authenticator: &AuthenticatorPrfV1,
        purpose: ReaderConfirmationPurpose,
        now: UnixMillis,
    ) -> Result<Self, ReaderSessionError> {
        sealed.prove_authenticator(authenticator)?;
        let expires_at = now
            .get()
            .checked_add(READER_CONFIRMATION_VALIDITY_MS_V1)
            .map(UnixMillis::new)
            .ok_or(ReaderSessionError::ConfirmationStale)?;
        let digest: [u8; 32] = Sha256::digest(authenticator.credential_id()).into();
        Ok(Self {
            purpose,
            issued_at: now,
            expires_at,
            credential_id_hash: Hash32::try_from(digest.as_slice())
                .expect("SHA-256 liefert 32 Byte"),
        })
    }

    /// Der Zweck, fuer den die Bestaetigung ausgestellt wurde.
    #[must_use]
    pub const fn purpose(&self) -> ReaderConfirmationPurpose {
        self.purpose
    }

    /// Der Ausstellungszeitpunkt.
    #[must_use]
    pub const fn issued_at(&self) -> UnixMillis {
        self.issued_at
    }

    /// Das Ende der Gueltigkeit.
    #[must_use]
    pub const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }

    /// Die pseudonyme Bedienerbindung: SHA-256 der `credentialId`.
    #[must_use]
    pub const fn credential_id_hash(&self) -> Hash32 {
        self.credential_id_hash
    }

    /// Ob die Bestaetigung DIESEN Zweck zu DIESEM Zeitpunkt traegt.
    ///
    /// Drei Bedingungen, alle drei noetig: der Zweck passt, `now` liegt nicht
    /// vor der Ausstellung und nicht hinter dem Ablauf. Eine Uhr, die hinter
    /// die Ausstellung zurueckfaellt, macht die Bestaetigung ungueltig statt
    /// juenger.
    #[must_use]
    pub fn is_fresh_for(&self, purpose: ReaderConfirmationPurpose, now: UnixMillis) -> bool {
        self.purpose == purpose && now >= self.issued_at && now <= self.expires_at
    }

    /// Der gemeinsame Pruefpfad von Sitzung und Export: Zweck VOR Frische, weil
    /// „falscher Zweck" und „abgelaufen" verschiedene Aussagen sind und ein
    /// Aufrufer beide unterscheiden koennen muss.
    pub(crate) fn check(
        &self,
        purpose: ReaderConfirmationPurpose,
        now: UnixMillis,
    ) -> Result<(), ReaderSessionError> {
        if self.purpose != purpose {
            return Err(ReaderSessionError::ConfirmationPurpose);
        }
        if now < self.issued_at || now > self.expires_at {
            return Err(ReaderSessionError::ConfirmationStale);
        }
        Ok(())
    }
}

impl fmt::Debug for ReaderAuthenticatorConfirmation {
    /// Zweck und Fristen — nicht die Bindung.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReaderAuthenticatorConfirmation")
            .field("purpose", &self.purpose)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Die entsperrte oder gesperrte Sitzung des Readers.
///
/// Kein `Clone` und kein abgeleitetes `Debug`: die Sitzung haelt den
/// [`UnlockedVault`] und die offenen Datensaetze.
pub struct ReaderSession {
    vault: Option<UnlockedVault>,
    open_records: Vec<VerifiedDecryptedRecord>,
    last_activity_at: UnixMillis,
    hidden_since: Option<UnixMillis>,
    monotonic_floor: UnixMillis,
    operator_binding_hash: Hash32,
}

impl ReaderSession {
    /// Eroeffnet eine Sitzung ueber einen entsperrten Tresor und eine FRISCHE
    /// Bestaetigung mit dem Zweck [`ReaderConfirmationPurpose::Unlock`].
    ///
    /// Der Tresor kommt BESITZEND herein: die Sitzung ist von jetzt an der
    /// einzige Halter, und [`ReaderSession::lock`] ist die einzige Stelle, an
    /// der er faellt.
    ///
    /// # Errors
    /// `EA-READER-SESSION-CONFIRMATION-PURPOSE` fuer eine Bestaetigung mit
    /// anderem Zweck, `EA-READER-SESSION-CONFIRMATION-STALE` fuer eine
    /// abgelaufene. In beiden Faellen faellt der hereingereichte Tresor sofort.
    pub fn unlock(
        vault: UnlockedVault,
        confirmation: ReaderAuthenticatorConfirmation,
        now: UnixMillis,
    ) -> Result<Self, ReaderSessionError> {
        confirmation.check(ReaderConfirmationPurpose::Unlock, now)?;
        Ok(Self {
            vault: Some(vault),
            open_records: Vec::new(),
            last_activity_at: now,
            hidden_since: None,
            monotonic_floor: now,
            operator_binding_hash: confirmation.credential_id_hash,
        })
    }

    /// Eroeffnet eine gesperrte Sitzung neu — mit einem FRISCH entsperrten
    /// Tresor und einer FRISCHEN Bestaetigung.
    ///
    /// Die Sperre hat den alten Tresor fallen lassen; wiederkommen kann er nur
    /// ueber den Authenticator, und genau deshalb ist ein neuer
    /// [`UnlockedVault`] Parameter und keine Erinnerung der Sitzung. Die
    /// Bindung wechselt mit: es gilt die `credentialId` der Bestaetigung, die
    /// diese Eroeffnung getragen hat.
    ///
    /// # Errors
    /// Wie [`ReaderSession::unlock`]; ausserdem faellt auf eine bereits
    /// entsperrte Sitzung nichts — sie bleibt, wie sie ist, und der
    /// hereingereichte Tresor faellt.
    pub fn reopen(
        &mut self,
        vault: UnlockedVault,
        confirmation: ReaderAuthenticatorConfirmation,
        now: UnixMillis,
    ) -> Result<(), ReaderSessionError> {
        let now = self.observe(now);
        confirmation.check(ReaderConfirmationPurpose::Unlock, now)?;
        if self.state_at(now) == ReaderSessionState::Unlocked {
            return Ok(());
        }
        self.vault = Some(vault);
        self.last_activity_at = now;
        self.hidden_since = None;
        self.operator_binding_hash = confirmation.credential_id_hash;
        Ok(())
    }

    /// Meldet eine Eingabe. Sie verlaengert NUR eine Sitzung, die zu `now`
    /// noch offen ist: eine faellige Sperre faellt zuerst.
    pub fn note_activity(&mut self, now: UnixMillis) {
        let now = self.observe(now);
        if self.state_at(now) == ReaderSessionState::Unlocked {
            self.last_activity_at = now;
        }
    }

    /// Meldet die Sichtbarkeit des Tabs.
    ///
    /// Der Wechsel in den Hintergrund startet die verkuerzte Frist AB JETZT
    /// und nicht ab der letzten Eingabe. Der Wechsel zurueck beendet sie, ist
    /// aber KEINE Eingabe: die Fuenfminutenfrist laeuft weiter ab der letzten
    /// echten Aktivitaet. Eine faellige Sperre faellt zuerst.
    pub fn note_visibility(&mut self, visibility: TabVisibility, now: UnixMillis) {
        let now = self.observe(now);
        if self.state_at(now) == ReaderSessionState::Locked {
            return;
        }
        self.hidden_since = match visibility {
            TabVisibility::Hidden => Some(self.hidden_since.unwrap_or(now)),
            TabVisibility::Visible => None,
        };
    }

    /// Der Zustand zu `now` — und die EINZIGE Stelle, an der eine Frist
    /// entscheidet.
    ///
    /// Zwei Fristen, jede fuer sich hinreichend: die Untaetigkeit seit der
    /// letzten Eingabe und, im Hintergrund, die verkuerzte Frist seit dem
    /// Wechsel. Ist eine erreicht, sperrt der Aufruf SELBST; der Aufrufer
    /// bekommt den Zustand nach der Sperre.
    pub fn state_at(&mut self, now: UnixMillis) -> ReaderSessionState {
        let now = self.observe(now);
        if self.vault.is_none() {
            return ReaderSessionState::Locked;
        }
        let idle = now.get().saturating_sub(self.last_activity_at.get());
        let hidden = self
            .hidden_since
            .map(|since| now.get().saturating_sub(since.get()));
        let due = idle >= READER_INACTIVITY_MS_V1
            || hidden.is_some_and(|hidden| hidden >= READER_BACKGROUND_INACTIVITY_MS_V1);
        if due {
            self.lock();
            return ReaderSessionState::Locked;
        }
        ReaderSessionState::Unlocked
    }

    /// Der Tresor — nur, wenn die Sitzung zu `now` offen ist.
    ///
    /// Jeder Zugriff rechnet die Frist nach und sperrt, bevor er etwas
    /// herausgibt. Der Zugriff selbst ist KEINE Eingabe: ein Skript, das den
    /// Tresor im Takt liest, haelt die Sitzung nicht offen.
    pub fn vault(&mut self, now: UnixMillis) -> Option<&UnlockedVault> {
        match self.state_at(now) {
            ReaderSessionState::Unlocked => self.vault.as_ref(),
            ReaderSessionState::Locked => None,
        }
    }

    /// Nimmt einen entschluesselten Datensatz in die Sitzung auf.
    ///
    /// Er faellt mit der Sperre. Die Sitzung haelt NICHTS, was aus ihm
    /// abgeleitet ist — keinen `ValidatedPayload`, keine `DerivedView`.
    pub fn open_record(&mut self, record: VerifiedDecryptedRecord) {
        self.open_records.push(record);
    }

    /// Die offenen Datensaetze, AUSGELIEHEN.
    #[must_use]
    pub fn open_records(&self) -> &[VerifiedDecryptedRecord] {
        &self.open_records
    }

    /// Nimmt GENAU EINEN offenen Datensatz aus der Sitzung heraus — den Weg,
    /// auf dem ein Einzelexport seinen Datensatz bekommt.
    ///
    /// Es gibt keine Methode, die alle nimmt.
    pub fn take_open_record(&mut self, entry_hash: EntryHash) -> Option<VerifiedDecryptedRecord> {
        let index = self
            .open_records
            .iter()
            .position(|record| record.entry_hash() == entry_hash)?;
        Some(self.open_records.swap_remove(index))
    }

    /// Sperrt: der Tresor faellt, die offenen Datensaetze fallen.
    ///
    /// Die EINZIGE Stelle, an der Schluesselmaterial verschwindet, und sie tut
    /// es ueber `SecretBytes`/`SecretVec`, die `ZeroizeOnDrop` bereits tragen;
    /// der Reader baut keinen eigenen Loeschpfad. Was BLEIBT, ist benannt und
    /// nicht weggeredet: Klartext, der innerhalb eines `with_payload`-Aufrufs
    /// in einem gewoehnlichen `Vec<u8>` lag, ist mit dessen Freigabe nicht
    /// genullt, und WASM-Linearspeicher wird dem Wirt nie zurueckgegeben.
    /// Diese Zeile steht als SOLL-Abweichung im Stufe-4-Gate und benennt die
    /// Zeroize-Faehigkeit von `ea-schema` als Haertungskandidaten der Stufe 7.
    pub fn lock(&mut self) {
        self.vault = None;
        self.open_records.clear();
        self.hidden_since = None;
    }

    /// Die pseudonyme Bedienerbindung der Bestaetigung, die diese Sitzung
    /// eroeffnet hat.
    #[must_use]
    pub const fn operator_binding_hash(&self) -> Hash32 {
        self.operator_binding_hash
    }

    /// Hebt `now` auf die monotone Untergrenze und schreibt sie fort.
    fn observe(&mut self, now: UnixMillis) -> UnixMillis {
        if now < self.monotonic_floor {
            return self.monotonic_floor;
        }
        self.monotonic_floor = now;
        now
    }
}

impl fmt::Debug for ReaderSession {
    /// Zustand und Fristen — keine Datensaetze, kein Tresor.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReaderSession")
            .field("locked", &self.vault.is_none())
            .field("open_record_count", &self.open_records.len())
            .field("last_activity_at", &self.last_activity_at)
            .field("hidden_since", &self.hidden_since)
            .field("monotonic_floor", &self.monotonic_floor)
            .finish_non_exhaustive()
    }
}
