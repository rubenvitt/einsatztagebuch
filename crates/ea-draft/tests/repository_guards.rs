//! Die vier Waechter der Entwurfsablage, die keine Zusicherung trug.
//!
//! Sie stehen in EINER Datei, weil sie dieselbe Grenze bewachen: den Zugang zu
//! der EINEN Entwurfszeile. Die Sperre traegt Produktinvariante 1 („es
//! existiert genau ein aktiver Entwurf", `design.md`:426) — ohne sie sind zwei
//! Writer-Instanzen auf demselben Konto zwei Bearbeiter desselben Entwurfs.

mod support;

use ea_draft::DraftRepository as _;

use self::support::DraftHarness;

/// Die AUSSCHLIESSLICHE Entwurfssperre laesst genau einen Bewerber durch.
///
/// Die Sperre liegt auf einer BETRIEBSSYSTEMSPERRE ueber der Sperrdatei
/// (`crates/ea-draft/src/lock.rs`), nicht auf dem Dasein der Datei. Zwei
/// Bewerber sind hier zwei getrennte Dateigriffe im selben Prozess; `flock`
/// bzw. `LockFileEx` binden je Dateigriff und nicht je Prozess, also ist die
/// Ablehnung unten dieselbe, die eine zweite Writer-Instanz auf demselben
/// Konto bekaeme — der Fall, gegen den Invariante 1 steht. Ohne die Sperre
/// gelaenge das blosse Oeffnen beiden.
#[test]
fn the_exclusive_draft_lock_admits_exactly_one_holder() {
    let harness = DraftHarness::new();

    let held = harness.repo.acquire_draft_lock().unwrap();
    assert_eq!(
        harness.repo.acquire_draft_lock().unwrap_err().code(),
        "EA-DRAFT-LOCK-HELD"
    );

    // Und sie ist WIRKLICH ein Waechter und keine dauerhafte Blockade: sein
    // `Drop` gibt sie frei, sonst waere nach dem ersten Verwerfen kein Eingang
    // mehr passierbar.
    drop(held);
    let _next = harness.repo.acquire_draft_lock().unwrap();
}

/// Eine LIEGENGEBLIEBENE Sperrdatei ohne lebende Sperre blockiert nicht.
///
/// Der Fall ist ein harter Abbruch — `SIGKILL`, Stromausfall — mitten unter
/// der Entwurfssperre. Haengt die Sperre am DASEIN der Datei, ist der Entwurf
/// danach dauerhaft unerreichbar: der Neustartpfad
/// (`DiscardService::resume_after_restart`) nimmt selbst die Sperre und kaeme
/// nie an ihr vorbei, das Geraet waere ohne Handeingriff tot. Die
/// Betriebssystemsperre gibt der Kern beim Prozessende frei; die
/// zurueckgebliebene Datei ist danach ein leeres Gehaeuse.
#[test]
fn a_leftover_draft_lock_file_without_a_live_lock_is_reclaimed() {
    let harness = DraftHarness::new();
    harness.leave_a_stale_lock_file();

    let held = harness
        .repo
        .acquire_draft_lock()
        .expect("eine tote Sperrdatei darf die Entwurfssperre NICHT blockieren");

    // Und der Griff ist eine ECHTE Sperre und kein blosses Oeffnen: der
    // zweite Bewerber bekommt weiterhin den gepinnten Code.
    assert_eq!(
        harness.repo.acquire_draft_lock().unwrap_err().code(),
        "EA-DRAFT-LOCK-HELD"
    );
    drop(held);
    assert!(
        harness.repo.acquire_draft_lock().is_ok(),
        "nach dem `Drop` MUSS die Sperre wieder frei sein"
    );
}

/// Ein Griff auf einen Entwurf, den es nicht mehr gibt, bekommt KEINEN
/// Schluessel.
///
/// `draft_dek_handle` vergleicht die Kennung der gelesenen Zeile mit der des
/// uebergebenen Belegs (`crates/ea-draft/src/autosave.rs`:205). Ohne diesen
/// Vergleich gaebe die Ablage den `draftDEK` des AKTUELLEN Entwurfs an einen
/// Beleg heraus, der einen laengst ersetzten nennt — und der Aufrufer
/// entschluesselte damit fremden Inhalt oder loeschte den falschen Schluessel.
#[test]
fn a_stale_saved_draft_never_yields_the_current_draft_dek() {
    let harness = DraftHarness::new();
    let draft = harness.repo.load_or_create().unwrap();
    let stale = harness.repo.save(draft.with_notes("ALT")).unwrap();
    // Der Beleg ist gueltig, solange sein Entwurf steht.
    harness.repo.draft_dek_handle(&stale).unwrap();

    let blank = harness.repo.replace_with_blank().unwrap();

    assert_eq!(
        harness.repo.draft_dek_handle(&stale).unwrap_err().code(),
        "EA-DRAFT-NOT-FOUND"
    );
    // Der Beleg des NEUEN Entwurfs geht durch: sonst koennte die Ablehnung
    // oben von etwas anderem als dem Kennungsvergleich kommen.
    harness.repo.draft_dek_handle(&blank).unwrap();
}

/// Die SCHREIBENDEN Uebergangsarme lehnen NAMENTLICH ab, solange
/// `0002_discard.sql` nicht registriert ist — die lesenden melden Abwesenheit.
///
/// „Die Tabelle gibt es noch nicht" ist eine andere Aussage als „die Datenbank
/// ist beschaedigt", und nur die erste darf ein spaeterer Task aufloesen
/// (`crates/ea-draft/src/model.rs`:33-38). Ohne die POSITIVE Abfrage der
/// Registratur fiele hier ein roher SQL-Fehlschlag an — `EA-STORE-DATABASE` —
/// und der Unterschied waere fort. GEMESSEN: mit entferntem Waechter meldet
/// `commit_discard_intent` genau diesen Code.
///
/// Der dritte schreibende Arm, `remove_ciphertext_and_intent_create_blank`,
/// ist in diesem Zustand nicht erreichbar und steht deshalb hier nicht: sein
/// Argument ist ein `DiscardIntent`, und der entsteht ausschliesslich aus
/// `commit_discard_intent` oder `pending_discard` — der eine lehnt hier ab, der
/// andere meldet Abwesenheit. Ein Aufrufer kann ihn nicht herstellen.
#[test]
fn the_transition_arms_name_the_missing_migration_instead_of_failing_raw() {
    let harness = DraftHarness::new();
    let draft = harness.repo.load_or_create().unwrap();
    let saved = harness.repo.save(draft).unwrap();

    // Danach wird NICHT wieder geoeffnet: die Migrationskette laeuft bei jedem
    // Oeffnen und legte die Tabelle sofort wieder an.
    harness.unregister_discard_migration();

    assert_eq!(
        harness
            .repo
            .commit_discard_intent(&saved)
            .unwrap_err()
            .code(),
        "EA-DRAFT-TRANSITION-UNAVAILABLE"
    );
    assert_eq!(
        harness
            .repo
            .replace_prepared_finalization_marker(None)
            .unwrap_err()
            .code(),
        "EA-DRAFT-TRANSITION-UNAVAILABLE"
    );
    // Die LESENDEN Arme melden dagegen Abwesenheit und keinen Fehler: ohne die
    // Tabelle KANN es weder Absicht noch Marke geben, und das ist eine wahre
    // Aussage und kein Fehlschlag.
    assert!(harness.repo.pending_discard().unwrap().is_none());
    assert!(
        harness
            .repo
            .prepared_finalization_marker()
            .unwrap()
            .is_none()
    );
    // Und die Ablehnung hat nichts geschrieben: der Entwurf steht unveraendert
    // und ist weiter lesbar.
    assert_eq!(harness.active_draft_row_count(), 1);
    assert_eq!(
        harness.repo.load_or_create().unwrap().revision(),
        saved.revision()
    );
}

/// Eine entschluesselte Nutzlast, die keine Entwurfsgestalt hat, wird
/// ABGELEHNT und nicht zurechtgebogen.
///
/// Das Chiffrat ist gueltig — dieselbe Nonce, dieselben Zusatzdaten, derselbe
/// `draftDEK` —, also geht die AEAD auf und erst die Pruefung dahinter faellt.
/// Ein `from_utf8_lossy` an dieser Stelle gaebe dem Bediener einen Entwurf mit
/// Ersatzzeichen zurueck, und die naechste Autospeicherung schriebe diesen
/// verstuemmelten Text als seinen eigenen fest.
#[test]
fn a_payload_that_is_not_a_draft_is_refused_instead_of_repaired() {
    let harness = DraftHarness::new();
    let draft = harness.repo.load_or_create().unwrap();
    let saved = harness.repo.save(draft.with_notes("ORIGINAL")).unwrap();

    harness.overwrite_payload_with_non_utf8(&saved);

    assert_eq!(
        harness.repo.load_or_create().unwrap_err().code(),
        "EA-DRAFT-PAYLOAD"
    );
    // Und die Ablehnung ist keine Reparatur: die Zeile steht unveraendert, es
    // ist KEIN zweiter Entwurf entstanden, der die Invariante brechen wuerde.
    assert_eq!(harness.active_draft_row_count(), 1);
}

/// Ein Schluesselspeicher, der GENAU EINEN Zugriff auf ein eingepacktes
/// Geheimnis verweigert.
///
/// Er meldet [`ea_key_provider::KeyError::PurposeMismatch`] — ein
/// voruebergehender Fehler, der eine Aussage ueber JETZT ist: Geraet gesperrt,
/// TPM belegt. Verweigert wird ausschliesslich `unwrap_secret`, und der erste
/// solche Zugriff des Anlegens liegt INNERHALB der Datenbanktransaktion,
/// unmittelbar hinter dem `wrap_secret`, das den Eintrag schon geschrieben hat.
///
/// EINMALIG und nicht dauerhaft: erst das spaetere Durchlassen belegt, dass die
/// Fixture ausser diesem einen Zugriff nichts fehlt.
struct BrieflyLockedProvider {
    inner: std::sync::Arc<ea_key_provider::InMemoryKeyProvider>,
    refusals_left: std::sync::atomic::AtomicUsize,
}

impl ea_key_provider::KeyProvider for BrieflyLockedProvider {
    fn generate(
        &self,
        purpose: ea_key_provider::SecretPurpose,
        protection: ea_format::KeyProtectionProfileV1,
    ) -> Result<ea_key_provider::KeyHandle, ea_key_provider::KeyError> {
        self.inner.generate(purpose, protection)
    }

    fn sign(
        &self,
        handle: &ea_key_provider::KeyHandle,
        content_type: ea_crypto::ContentType,
        certificate_hash: ea_types::CertificateHash,
        payload: &[u8],
    ) -> Result<ea_key_provider::CoseSign1Bytes, ea_key_provider::KeyError> {
        self.inner
            .sign(handle, content_type, certificate_hash, payload)
    }

    fn wrap_secret(
        &self,
        purpose: ea_key_provider::SecretPurpose,
        secret: ea_crypto::SecretBytes<32>,
    ) -> Result<ea_key_provider::KeyHandle, ea_key_provider::KeyError> {
        self.inner.wrap_secret(purpose, secret)
    }

    fn unwrap_secret(
        &self,
        handle: &ea_key_provider::KeyHandle,
    ) -> Result<ea_crypto::SecretBytes<32>, ea_key_provider::KeyError> {
        use std::sync::atomic::Ordering;
        if self
            .refusals_left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok()
        {
            return Err(ea_key_provider::KeyError::PurposeMismatch);
        }
        self.inner.unwrap_secret(handle)
    }

    fn unwrap_database_key(
        &self,
        handle: &ea_key_provider::KeyHandle,
    ) -> Result<ea_crypto::SecretVec, ea_key_provider::KeyError> {
        self.inner.unwrap_database_key(handle)
    }

    fn delete(&self, handle: &ea_key_provider::KeyHandle) -> Result<(), ea_key_provider::KeyError> {
        self.inner.delete(handle)
    }

    fn contains(
        &self,
        handle: &ea_key_provider::KeyHandle,
    ) -> Result<bool, ea_key_provider::KeyError> {
        self.inner.contains(handle)
    }

    fn reached_protection_profile(
        &self,
        handle: &ea_key_provider::KeyHandle,
    ) -> Result<ea_format::KeyProtectionProfileV1, ea_key_provider::KeyError> {
        self.inner.reached_protection_profile(handle)
    }
}

/// Ein zurueckgerollter leerer Entwurf laesst KEINEN verwaisten
/// Schluesselspeichereintrag zurueck.
///
/// # Was hier gemessen wird
///
/// `replace_with_blank` IST Schritt 13 der Finalisierung
/// (`crates/ea-writer/src/finalize.rs`): Uebergangsplatz raeumen, alte
/// Entwurfszeile loeschen und den leeren Entwurf mit FRISCHEM `draftDEK` in
/// DERSELBEN Datenbanktransaktion anlegen. Der frische Schluessel entsteht
/// dabei im Schluesselspeicher — und der kennt keine Transaktion. Rollt die
/// Datenbank zurueck, bleibt sein Eintrag liegen: ein Geheimnis, auf das keine
/// Zeile mehr zeigt, an genau der Adresse, unter der die Ablage den naechsten
/// Entwurf sucht.
///
/// Gemessen wird ausdruecklich am SPEICHER (`contains`) und nicht daran, ob
/// sich ein Entwurf oeffnen laesst: die zweite Frage waere auch dann gruen,
/// wenn der Eintrag laege, denn die zurueckgerollte Zeile ist ohnehin die alte.
///
/// Der frische Eintrag ueberschreibt beim Anlegen, was an der Adresse lag —
/// sie ist (Speicher, Konto, `DraftDek`) und damit EIN Platz. Das Abraeumen
/// STELLT den vorigen Schluessel deshalb nicht wieder her; es sorgt dafuer,
/// dass kein LEBENDES Geheimnis ohne Zeile zurueckbleibt. Der Zeuge loescht den
/// alten Schluessel darum vorher, genau wie Schritt 9 es tut.
#[test]
fn a_rolled_back_blank_draft_leaves_no_orphaned_keystore_entry() {
    let harness = DraftHarness::new();
    let draft = harness.repo.load_or_create().unwrap();
    let saved = harness.repo.save(draft.with_notes("CANARY-DRAFT")).unwrap();
    let handle = harness.repo.draft_dek_handle(&saved).unwrap();

    // Schritt 9: der `draftDEK` ist fort. Ab hier ist jede Anwesenheit unter
    // dieser Adresse ein Eintrag, den Schritt 13 angelegt hat.
    ea_key_provider::KeyProvider::delete(harness.provider().as_ref(), &handle).unwrap();
    assert!(!ea_key_provider::KeyProvider::contains(harness.provider().as_ref(), &handle).unwrap());

    let locked = std::sync::Arc::new(BrieflyLockedProvider {
        inner: harness.provider(),
        refusals_left: std::sync::atomic::AtomicUsize::new(1),
    }) as std::sync::Arc<dyn ea_key_provider::KeyProvider>;
    let repo = harness.repo_with_provider(std::sync::Arc::clone(&locked));
    let refused = repo
        .replace_with_blank()
        .expect_err("der frische draftDEK laesst sich nicht auspacken");
    assert_eq!(refused.code(), "EA-KEY-PURPOSE-MISMATCH");

    // Die Datenbanktransaktion ist ZURUECKGEROLLT: die alte Zeile steht noch.
    assert_eq!(harness.active_draft_row_count(), 1);
    // Und der Schluesselspeicher traegt nichts, worauf sie zeigt.
    assert!(
        !ea_key_provider::KeyProvider::contains(harness.provider().as_ref(), &handle).unwrap(),
        "der fuer den leeren Entwurf angelegte draftDEK darf den Rollback nicht ueberleben"
    );

    // Die POSITIVKONTROLLE: ausser diesem einen Zugriff fehlt der Fixture
    // nichts — derselbe Aufruf traegt jetzt durch.
    let blank = repo
        .replace_with_blank()
        .expect("nach dem Entsperren muss Schritt 13 tragen");
    assert_eq!(blank.revision(), 0);
    assert_eq!(harness.active_draft_row_count(), 1);
}
