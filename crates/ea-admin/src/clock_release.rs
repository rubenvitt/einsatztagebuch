//! Die Uhrfreigabe: Ausstellung, Verbrauch und Bedienfuehrung.
//!
//! # Diese Fassade baut den Freigabekern NICHT nach
//!
//! Der Kern steht vollstaendig in `ea-trust`: [`ea_trust::verify_clock_release`]
//! ist der einzige Erzeuger von [`ea_trust::VerifiedClockRelease`], und
//! [`ea_trust::select_registry_head`] verbraucht den Nachweis PER WERT und
//! committet Nonce-Sperre, Kopf und Zeit-Floor atomar. Dieses Modul fuegt der
//! Vertrauensschicht keine Regel hinzu; es fuellt die drei Luecken, die der
//! Kern offen laesst:
//!
//! 1. **Den Erzeuger der exakten Auditbytes.** Der Kontext
//!    [`ea_format::ClockReleaseContextV1`] prueft ausdruecklich nichts; Fenster
//!    und Zeitgleichheit misst `encode_local_audit_core` an der
//!    Signaturgrenze. Die Zeile wird ueber
//!    [`ea_audit::LocalAuditService::record_signed`] gebucht, und ihre
//!    `exact_bytes()` sind der Eingang von `verify_clock_release`.
//! 2. **Den Aufnahmepunkt fuer [`ReauthPurpose::ClockSkewRelease`].**
//! 3. **Die Bedienfuehrung, wenn keine unabhaengige Zeitreferenz vorliegt.**
//!
//! # Warum der Zweckgate hier liegt und nicht in `operator.rs`
//!
//! `OperatorBindingService::verify_session` ist selbst zweckneutral; die
//! Abweisung „alles ausser `AdminRootCeremony`" steht je Eintrittspunkt
//! (`operator.rs` in `revoke` und `provision`, ebenso `operator_host.rs` und
//! `operator_authority.rs`). Ein zusaetzlicher Zweck an EINEM dieser Gates
//! oeffnete ihn fuer die Bindungsaenderung UND fuer die Bereitstellung mit,
//! und beide haben mit einer Uhrfreigabe nichts zu tun. Deshalb ein EIGENER
//! Eintrittspunkt in diesem Modul, mit dem Muster aus
//! `crates/ea-writer/src/finalize.rs`: erst die Bindung, dann
//! `proof.is_valid_for(purpose, now)`, und bei Fehlschlag ausdruecklich die
//! Unterscheidung, ob der Nachweis EINEN ANDEREN Zweck deckt.
//!
//! # Zwei Zeitrahmen, keiner davon erfunden
//!
//! Die Frische des Bedienernachweises wird gegen die
//! `preexisting_effective_now()` des GEWAEHLTEN Kopfes gemessen — derselbe
//! Rahmen, in dem `BoundOperator::resolve` ihn ausgestellt hat. Die
//! Auditzeile dagegen spricht ueber die GESPERRTE Bewertung und traegt deren
//! `raw_now` als `effective_now`; der Aufrufer bindet den
//! [`ea_audit::LocalAuditService`] an genau diesen Wert. Ein falsch gebundener
//! Dienst faellt geschlossen aus: `verify_clock_release` vergleicht
//! `effective_now` byteweise gegen `max(floor, wall)` der Bewertung.
//!
//! # Keine zweite Uhr, keine zweite Gnadenfrist, kein zweiter Ablauf
//!
//! Dieses Modul rechnet an keiner Stelle mit Millisekunden. Die Bewertung
//! kommt aus [`ea_time::evaluate_preexisting_time`], das Freigabefenster
//! kommt als Paar `issued_at`/`expires_at` vom Aufrufer und wird
//! unveraendert in den signierten Kontext gelegt. `issued_at < expires_at`
//! erzwingt die Signaturgrenze, die EINSCHLIESSENDE Enthaltung
//! `issued_at <= raw_now <= expires_at` erzwingt `verify_clock_release`.
//!
//! # Keine Nonce in einer Meldung
//!
//! Der Kontext bindet eine Zufalls-Nonce, die
//! [`ea_audit::SignedLocalAuditService`] selbst zieht. Sie erreicht dieses
//! Modul nie als Wert, [`IssuedClockRelease`] formatiert sie nicht, und
//! [`ClockReleaseWorkflowError`] nennt ausschliesslich seinen stabilen Code.

use core::fmt;

use ea_audit::{AuditActorProof, AuditError, LocalAuditService, TypedLocalAuditEvent};
use ea_format::{
    ClockReleaseContextV1, ClockReleaseJustificationV1, IndependentTimeKindV1,
    IndependentTimeReferenceV1, LocalAuditActionV1, LocalAuditOutcomeV1,
};
use ea_operator::{OperatorSessionProof, ReauthPurpose};
use ea_time::{
    FutureSkew, IndependentTimeKind, TimeError, TrustedTimeState, evaluate_preexisting_time,
};
use ea_trust::{
    ClockReleaseError, RegistryCandidate, RegistryError, RegistrySelectionOutcome,
    SelectedRegistryHead, TrustError, TrustStateStore, VerifiedSignedTime, VerifiedTrust,
    prepare_local_time, select_registry_head, verify_clock_release, verify_registry_candidate,
};
use ea_types::{ChainSequence, EventId, ObjectHash, UnixMillis};

/// Ein Fehlschlag an der Grenze der Uhrfreigabe.
///
/// # Warum das Praefix `EA-SKEW-` heisst
///
/// `EA-ADMIN-` ist gesperrt: es ist der AKTIONSCODE-Namensraum der acht
/// Serverzeilen des technischen Verwaltungsaudits, und ein Fehlercode
/// derselben Familie benennte einen Abbruch statt einer vollzogenen Handlung
/// (Begruendung im Volltext in `crates/ea-admin/src/error.rs`).
///
/// `EA-CLOCK-RELEASE-` scheidet ebenfalls aus, und zwar aus dem Gegengrund:
/// `EA-TRUST-CLOCK-RELEASE-{MISMATCH,EXPIRED,REPLAY}` sind die Befunde des
/// KERNS. Eine zweite, kuerzere Familie mit demselben Wortstamm liesse einen
/// Leser nicht mehr entscheiden, welche Schicht gesprochen hat.
///
/// `EA-SKEW-` benennt stattdessen den Gegenstand dieser Scheibe — den
/// Uhrenversatz und seine Freigabe — und ist im ganzen Baum frei
/// (`grep -ro '"EA-[A-Z0-9]*-' crates apps` kennt diese Familie nicht).
///
/// Die durchgereichten Arme behalten den Code ihrer Herkunft. Insbesondere
/// bleibt die Wiedereinspielung einer Freigabe
/// [`TrustError::ClockReleaseReplay`] mit `EA-TRUST-CLOCK-RELEASE-REPLAY`: die
/// Zusage gehoert `ea-trust`, und ein zweiter Code fuer denselben Befund waere
/// eine zweite Wahrheit.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClockReleaseWorkflowError {
    /// Es liegt kein frischer Bedienernachweis vor.
    ReauthRequired,
    /// Der vorgelegte Nachweis deckt EINEN ANDEREN Zweck.
    ReauthPurposeMismatch,
    /// Der Nachweis gehoert zu einer ANDEREN Bedienerbindung.
    ///
    /// `OperatorSessionProof::is_valid_for` prueft die Bindung ausdruecklich
    /// nicht; dieser Arm ist die Stelle, an der dieses Modul sie prueft.
    ReauthBindingMismatch,
    /// Es gibt keine unabhaengige Zeitreferenz.
    ///
    /// Der Zustand, fuer den der Kern heute nur das nichtssagende
    /// [`ClockReleaseError::Mismatch`] liefert. Er ist ausdruecklich ein
    /// ANDERER Ausgang als „Freigabe abgewiesen": es wird gar keine Freigabe
    /// angeboten, weil ohne Referenz nichts da ist, wogegen sie messen
    /// koennte.
    IndependentTimeUnavailable,
    /// Die Uhr ist gar nicht gesperrt; eine Freigabe hat keinen Gegenstand.
    NotBlocked,
    /// Die Auditzeile ist nicht zustande gekommen — durchgereichter Code.
    Audit(AuditError),
    /// Die Zeitarithmetik hat abgelehnt — durchgereichter Code.
    Time(TimeError),
    /// Der Freigabekern hat abgelehnt — durchgereichter Code.
    Release(ClockReleaseError),
    /// Die Kopfauswahl hat abgelehnt — durchgereichter Code.
    Registry(RegistryError),
    /// Die Vertrauensschicht hat abgelehnt — durchgereichter Code.
    Trust(TrustError),
}

impl ClockReleaseWorkflowError {
    /// Stabiler Fehlercode.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ReauthRequired => "EA-SKEW-REAUTH-REQUIRED",
            Self::ReauthPurposeMismatch => "EA-SKEW-REAUTH-PURPOSE",
            Self::ReauthBindingMismatch => "EA-SKEW-REAUTH-BINDING",
            Self::IndependentTimeUnavailable => "EA-SKEW-INDEPENDENT-TIME-UNAVAILABLE",
            Self::NotBlocked => "EA-SKEW-NOT-BLOCKED",
            Self::Audit(error) => error.code(),
            Self::Time(error) => error.code(),
            Self::Release(error) => error.code(),
            Self::Registry(error) => error.code(),
            Self::Trust(error) => error.code(),
        }
    }
}

impl fmt::Display for ClockReleaseWorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl fmt::Debug for ClockReleaseWorkflowError {
    /// AUSSCHLIESSLICH der Code. Eine Fehlermeldung, die den Freigabekontext
    /// mitfuehrte, traege die Nonce in jede Protokolldatei.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ClockReleaseWorkflowError {}

impl From<AuditError> for ClockReleaseWorkflowError {
    fn from(error: AuditError) -> Self {
        Self::Audit(error)
    }
}

impl From<TimeError> for ClockReleaseWorkflowError {
    fn from(error: TimeError) -> Self {
        Self::Time(error)
    }
}

impl From<ClockReleaseError> for ClockReleaseWorkflowError {
    fn from(error: ClockReleaseError) -> Self {
        Self::Release(error)
    }
}

impl From<RegistryError> for ClockReleaseWorkflowError {
    fn from(error: RegistryError) -> Self {
        Self::Registry(error)
    }
}

impl From<TrustError> for ClockReleaseWorkflowError {
    fn from(error: TrustError) -> Self {
        Self::Trust(error)
    }
}

/// Was die Bedienfuehrung ueberhaupt anbieten darf.
///
/// Drei Ausgaenge, und sie folgen der Bewertung von `ea-time` statt einer
/// eigenen Auslegung: `FutureSkew::Blocked` ist ohne unabhaengige Referenz
/// strukturell unerreichbar (`crates/ea-time/src/evaluate.rs`), die Dreiteilung
/// ist damit exakt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockReleaseAvailability {
    /// Die Uhr ist gesperrt UND eine unabhaengige Referenz liegt vor.
    Offered,
    /// Es gibt keine unabhaengige Referenz — es wird GAR KEINE Freigabe
    /// angeboten.
    IndependentTimeUnavailable,
    /// Die Uhr ist nicht gesperrt.
    NotBlocked,
}

/// Der Gegenstand einer Freigabe.
///
/// `issued_at` und `expires_at` kommen vom Aufrufer und werden unveraendert in
/// den signierten Kontext gelegt: dieses Modul fuehrt keine eigene
/// Gnadenfrist. Ein Fenster mit `issued_at >= expires_at` weist bereits die
/// Signaturgrenze ab.
pub struct ClockReleaseRequest<'a> {
    /// Der Kandidat, dessen Auswahl die Freigabe tragen soll.
    pub candidate: &'a RegistryCandidate,
    /// Der persistierte Zeitzustand — Floor und unabhaengige Referenz.
    pub trusted_time: &'a TrustedTimeState,
    /// Die exakt beobachtete Wanduhr des Betriebssystems.
    pub observed_os_wall_clock: UnixMillis,
    /// Der geschlossene Begruendungscode `0..2`.
    pub justification: ClockReleaseJustificationV1,
    /// Der Beginn des Freigabefensters, EINSCHLIESSEND.
    pub issued_at: UnixMillis,
    /// Das Ende des Freigabefensters, EINSCHLIESSEND.
    pub expires_at: UnixMillis,
}

/// Die ausgestellte, signierte und gebuchte Freigabezeile.
///
/// Sie traegt nur ihre Kennung und ihre exakten Bytes. Einen Leser fuer den
/// Kontext gibt es nicht: die Nonce darf weder in eine Protokollzeile noch in
/// eine Bedienoberflaeche gelangen.
pub struct IssuedClockRelease {
    id: EventId,
    exact_bytes: Vec<u8>,
}

impl IssuedClockRelease {
    /// Die exakten `local-audit-event-v1`-Bytes.
    #[must_use]
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    /// Die Kennung der gebuchten Auditzeile.
    #[must_use]
    pub const fn id(&self) -> EventId {
        self.id
    }
}

impl fmt::Debug for IssuedClockRelease {
    /// Undurchsichtig wie [`ea_audit::SignedLocalAuditEvent`]: die Bytes
    /// tragen die Nonce, und eine Freigabezeile gehoert nicht in eine
    /// Protokollzeile.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IssuedClockRelease(<signed>)")
    }
}

/// Der Dienst, der eine Uhrfreigabe anbietet und ausstellt.
///
/// Er haelt den GEWAEHLTEN Kopf, weil aus ihm gleich drei Angaben kommen, die
/// sonst frei gesetzt werden koennten: die gebundene Wachrichtlinie
/// (Objekthash und `maxFutureClockSkewMs`), der Zeitrahmen, gegen den die
/// Frische des Bedienernachweises gemessen wird, und die Bindung, gegen die
/// [`ea_operator::BoundOperator`] ihn ausgestellt hat.
pub struct ClockReleaseService<'a> {
    guard_head: &'a SelectedRegistryHead,
    audit: &'a dyn LocalAuditService,
    admin_binding_object_hash: ObjectHash,
}

impl<'a> ClockReleaseService<'a> {
    /// Baut den Dienst gegen den gewaehlten Kopf und die Adminbindung, fuer
    /// die er handelt.
    #[must_use]
    pub const fn new(
        guard_head: &'a SelectedRegistryHead,
        audit: &'a dyn LocalAuditService,
        admin_binding_object_hash: ObjectHash,
    ) -> Self {
        Self {
            guard_head,
            audit,
            admin_binding_object_hash,
        }
    }

    /// Was die Bedienfuehrung fuer diesen Zeitzustand anbieten darf.
    ///
    /// Der `&TrustedTimeState` gehoert `ea-time` und ist damit ausserhalb
    /// dieser Kiste nicht ueberall nennbar. Ein Aufrufer ohne diese Kante —
    /// das Wiederherstellungswerkzeug, ausdruecklich — nimmt deshalb
    /// [`crate::operator_runtime::OperatorRuntime::clock_release_availability`],
    /// das den persistierten Zustand INNERHALB von `ea-admin` liest und nach
    /// aussen nur [`ClockReleaseAvailability`] gibt. Die Zuordnung von
    /// [`ea_time::FutureSkew`] auf die drei Ausgaenge steht genau hier und
    /// nirgends ein zweites Mal.
    ///
    /// # Errors
    ///
    /// [`ClockReleaseWorkflowError::Time`], wenn die Bewertung ueberlaeuft
    /// oder der uebergebene Zustand nicht monoton ist.
    pub fn availability(
        &self,
        trusted_time: &TrustedTimeState,
        observed_os_wall_clock: UnixMillis,
    ) -> Result<ClockReleaseAvailability, ClockReleaseWorkflowError> {
        let evaluation = evaluate_preexisting_time(
            observed_os_wall_clock,
            trusted_time,
            self.max_future_clock_skew_ms(),
        )?;
        Ok(match evaluation.future_skew() {
            FutureSkew::Blocked => ClockReleaseAvailability::Offered,
            FutureSkew::UnprovableWithoutIndependentReference => {
                ClockReleaseAvailability::IndependentTimeUnavailable
            }
            FutureSkew::WithinLimit => ClockReleaseAvailability::NotBlocked,
        })
    }

    /// Stellt genau eine Freigabe aus und bucht sie als signierte Auditzeile.
    ///
    /// # Errors
    ///
    /// [`ClockReleaseWorkflowError::ReauthBindingMismatch`],
    /// [`ClockReleaseWorkflowError::ReauthPurposeMismatch`] und
    /// [`ClockReleaseWorkflowError::ReauthRequired`] fuer einen Nachweis, der
    /// nicht frisch fuer [`ReauthPurpose::ClockSkewRelease`] und nicht fuer
    /// die gehaltene Bindung ausgestellt ist;
    /// [`ClockReleaseWorkflowError::IndependentTimeUnavailable`] und
    /// [`ClockReleaseWorkflowError::NotBlocked`], wenn der Zeitzustand gar
    /// keine Freigabe traegt; [`ClockReleaseWorkflowError::Release`] mit
    /// `EA-TRUST-TIME-SOURCE-UNSUPPORTED` fuer eine TSA-Referenz; sonst der
    /// durchgereichte Fehler der Auditgrenze.
    pub fn issue(
        &self,
        request: ClockReleaseRequest<'_>,
        proof: &OperatorSessionProof,
    ) -> Result<IssuedClockRelease, ClockReleaseWorkflowError> {
        self.require_fresh_release_proof(proof)?;

        let evaluation = evaluate_preexisting_time(
            request.observed_os_wall_clock,
            request.trusted_time,
            self.max_future_clock_skew_ms(),
        )?;
        match evaluation.future_skew() {
            FutureSkew::Blocked => {}
            FutureSkew::UnprovableWithoutIndependentReference => {
                return Err(ClockReleaseWorkflowError::IndependentTimeUnavailable);
            }
            FutureSkew::WithinLimit => return Err(ClockReleaseWorkflowError::NotBlocked),
        }

        // `Blocked` gibt es nur MIT Referenz; der Arm bleibt trotzdem
        // geschlossen, damit eine spaetere Aenderung von `ea-time` hier
        // auffliegt statt eine Freigabe ohne Referenz zu bauen.
        let reference = request
            .trusted_time
            .independent_reference()
            .ok_or(ClockReleaseWorkflowError::IndependentTimeUnavailable)?;
        let kind = match reference.kind() {
            IndependentTimeKind::Receipt => IndependentTimeKindV1::Receipt,
            IndependentTimeKind::Checkpoint => IndependentTimeKindV1::Checkpoint,
            // Der Kern weist eine TSA-Referenz mit
            // `EA-TRUST-TIME-SOURCE-UNSUPPORTED` ab. Diese Fassade baut sie
            // gar nicht erst — mit demselben Code, damit es fuer denselben
            // Befund keine zweite Wahrheit gibt.
            IndependentTimeKind::Tsa => {
                return Err(ClockReleaseWorkflowError::Release(
                    ClockReleaseError::Trust(TrustError::TimeSourceUnsupported),
                ));
            }
        };

        let context = ClockReleaseContextV1::new(
            request.trusted_time.floor(),
            request.observed_os_wall_clock,
            self.max_future_clock_skew_ms(),
            request.candidate.registry_version(),
            request.candidate.registry_head_hash(),
            self.guard_head.policy_object_hash(),
            IndependentTimeReferenceV1::new(
                kind,
                reference.object_hash(),
                reference.verified_time(),
            ),
            request.justification,
            request.issued_at,
            request.expires_at,
        );
        let signed = self.audit.record_signed(
            AuditActorProof::OperatorSession(proof),
            TypedLocalAuditEvent {
                action: LocalAuditActionV1::ClockSkewRelease(context),
                // NUR Ausgang 1 ergibt eine Freigabe; der Kern verlangt ihn
                // ausdruecklich (`require_signed_correlations`).
                outcome: LocalAuditOutcomeV1::Accepted,
            },
        )?;
        Ok(IssuedClockRelease {
            id: signed.id(),
            exact_bytes: signed.exact_bytes().to_vec(),
        })
    }

    /// Die gebundene Wachrichtlinie des gewaehlten Kopfes.
    fn max_future_clock_skew_ms(&self) -> u64 {
        self.guard_head.policy_fields().max_future_clock_skew_ms
    }

    /// Verlangt einen Nachweis der EIGENEN Bindung, FRISCH und fuer die
    /// Uhrfreigabe.
    ///
    /// Muster und Reihenfolge aus `crates/ea-writer/src/finalize.rs`: die
    /// Bindung kommt zuerst, weil ein Nachweis einer fremden Bindung auch dann
    /// keine Autorisierung ist, wenn er taufrisch ist.
    fn require_fresh_release_proof(
        &self,
        proof: &OperatorSessionProof,
    ) -> Result<(), ClockReleaseWorkflowError> {
        if proof.binding_object_hash() != self.admin_binding_object_hash {
            return Err(ClockReleaseWorkflowError::ReauthBindingMismatch);
        }
        let now = self.guard_head.preexisting_effective_now();
        if proof.is_valid_for(ReauthPurpose::ClockSkewRelease, now) {
            return Ok(());
        }
        let authorizes_another = ReauthPurpose::ALL
            .iter()
            .copied()
            .filter(|candidate| *candidate != ReauthPurpose::ClockSkewRelease)
            .any(|candidate| proof.is_valid_for(candidate, now));
        if authorizes_another {
            Err(ClockReleaseWorkflowError::ReauthPurposeMismatch)
        } else {
            Err(ClockReleaseWorkflowError::ReauthRequired)
        }
    }
}

/// Fuehrt den Dreischritt aus: Kandidat, lokale Zeit, Kopfauswahl unter einer
/// Freigabe.
///
/// Die Reihenfolge ist der ganze Punkt. Eine Fassade, die die Freigabe prueft
/// und den Rest abkuerzt, haette die Freigabe zu einem Generalschluessel
/// gemacht: `verify_registry_candidate` faellt VOR jeder Freigabe ueber eine
/// abgelaufene Administrationsautorisierung und ueber jeden Signaturfehler,
/// und `select_registry_head` faellt DANACH weiterhin ueber `notAfter`,
/// `notBefore` und das erschoepfte Sequenz-Lease. Die Freigabe hebt genau eine
/// Sache auf — die Sperre wegen Uhrenvorlaufs — und keine zweite.
///
/// Der Zeit-Floor wird dabei nie abgesenkt: `select_registry_head` bestaetigt
/// ihn am aktuellen Kopf und hebt ihn an einem Nachfolger ueber
/// `advance_registry_floor` nur an.
///
/// # Errors
///
/// Der durchgereichte Code der Stelle, an der der Dreischritt gescheitert
/// ist — insbesondere `EA-TRUST-CLOCK-RELEASE-REPLAY` fuer eine bereits
/// verbrauchte Freigabe.
pub fn apply_clock_release(
    store: &mut dyn TrustStateStore,
    trust: &VerifiedTrust,
    proposed_sequence: ChainSequence,
    observed_os_wall_clock: UnixMillis,
    sources: &[VerifiedSignedTime],
    exact_release_bytes: &[u8],
) -> Result<RegistrySelectionOutcome, ClockReleaseWorkflowError> {
    let candidate = verify_registry_candidate(trust, proposed_sequence)?;
    let mut local_time = prepare_local_time(store, &candidate, observed_os_wall_clock, sources)?;
    let release = verify_clock_release(&candidate, &mut local_time, exact_release_bytes)?;
    Ok(select_registry_head(candidate, local_time, Some(release))?)
}
