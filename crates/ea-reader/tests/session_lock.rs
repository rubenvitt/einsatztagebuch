//! Die Sitzungssperre nach `web-reader-design.md` §6.5: Zeroize beim Sperren,
//! fuenf Minuten Untaetigkeit, die verkuerzte Frist im Hintergrundtab, die
//! monotone Uhr und die erneute Authenticator-Bestaetigung nach jeder Sperre.
//!
//! Was hier NICHT bezeugt wird, steht ausdruecklich: dass ein `SecretBytes`
//! beim Fallen genullt wird, misst `crates/ea-crypto`; dieser Zeuge misst, dass
//! die Sitzung nach der Sperre keinen Weg mehr zu ihm hat und dass jeder
//! Zugriff die Frist selbst nachrechnet — ohne Timer.

#[path = "verify_fixtures/mod.rs"]
mod verify_fixtures;

use ea_reader::{
    READER_BACKGROUND_INACTIVITY_MS_V1, READER_CONFIRMATION_VALIDITY_MS_V1,
    READER_INACTIVITY_MS_V1, ReaderAuthenticatorConfirmation, ReaderConfirmationPurpose,
    ReaderSession, ReaderSessionState, TabVisibility, UnixMillis,
};

use verify_fixtures::fixtures;

/// Die Uhr des Laufs, relativ zur Kulissenuhr: `decrypt_verified` verlangt
/// EXAKT `fixtures::EFFECTIVE_NOW`, also rechnet die Sitzung ab dort.
fn t(offset_ms: i64) -> UnixMillis {
    UnixMillis::new(fixtures::EFFECTIVE_NOW.get() + offset_ms)
}

fn unlocked_at(now: UnixMillis) -> ReaderSession {
    ReaderSession::unlock(
        fixtures::unlocked_vault_with_pinned_anchor(),
        fixtures::confirmation(ReaderConfirmationPurpose::Unlock, now),
        now,
    )
    .expect("eine frische Entsperrbestaetigung eroeffnet die Sitzung")
}

/// Der Fuenfminutenvorgabewert ist KEINE zweite Zahl. `ea-operator` haelt ihn
/// als `MAX_INACTIVITY_MS`, ist aber wasm32-ausgenommen und darf keine
/// Bibliothekskante des Readers werden; deshalb steht er in `src/session.rs`
/// ein zweites Mal als Literal und wird HIER gegen das Original gemessen.
/// `ea-operator` ist dafuer eine DEV-Kante: die wasm32-Zeile faehrt ohne
/// `--all-targets`, und genau das haelt Dev-Dependencies aus dem wasm-Graphen.
#[test]
fn the_reader_inactivity_default_is_the_same_five_minutes_as_the_desktop() {
    assert_eq!(READER_INACTIVITY_MS_V1, ea_operator::MAX_INACTIVITY_MS);
    const {
        assert!(READER_BACKGROUND_INACTIVITY_MS_V1 < READER_INACTIVITY_MS_V1);
        assert!(READER_CONFIRMATION_VALIDITY_MS_V1 < READER_INACTIVITY_MS_V1);
    }
}

/// Sperren heisst zeroize. Der Zeuge misst nicht „is_locked", sondern dass der
/// Tresor nach der Sperre nicht mehr herausgegeben wird und die
/// entschluesselten Datensaetze fort sind.
#[test]
fn locking_zeroizes_the_key_material_and_drops_every_open_record() {
    let mut session = unlocked_at(t(0));
    session.open_record(fixtures::decrypted_genesis_record());
    assert_eq!(session.open_records().len(), 1);
    assert!(session.vault(t(1)).is_some());

    session.lock();

    assert!(session.vault(t(2)).is_none());
    assert!(session.open_records().is_empty());
    assert_eq!(session.state_at(t(2)), ReaderSessionState::Locked);
    // Eine Sperre ist ENDGUELTIG bis zur naechsten Bestaetigung: Eingabe und
    // Sichtbarkeit aendern daran nichts.
    session.note_activity(t(3));
    session.note_visibility(TabVisibility::Visible, t(4));
    assert_eq!(session.state_at(t(5)), ReaderSessionState::Locked);
}

/// Die Fuenfminutenfrist zaehlt ab der letzten EINGABE, und der Zugriff auf
/// den Tresor ist keine: ein Skript, das den Tresor im Takt liest, haelt die
/// Sitzung nicht offen.
#[test]
fn five_minutes_without_input_lock_even_while_the_vault_is_being_read() {
    let mut session = unlocked_at(t(0));
    assert!(session.vault(t(READER_INACTIVITY_MS_V1 - 1)).is_some());
    assert!(session.vault(t(READER_INACTIVITY_MS_V1)).is_none());

    let mut session = unlocked_at(t(0));
    session.note_activity(t(100_000));
    assert!(
        session
            .vault(t(100_000 + READER_INACTIVITY_MS_V1 - 1))
            .is_some()
    );
    assert!(
        session
            .vault(t(100_000 + READER_INACTIVITY_MS_V1))
            .is_none()
    );
}

/// Die verkuerzte Frist gilt AB dem Wechsel in den Hintergrund und nicht ab der
/// letzten Eingabe. Der zweite Teil ist der wichtigere: die Entscheidung faellt
/// beim naechsten Zugriff und haengt an keinem Timer — Hintergrundtabs werden
/// in allen Engines gedrosselt, auf Mobilgeraeten ganz angehalten, und ein
/// Sperrmechanismus, der auf ein `setTimeout` wartet, sperrt dort nie.
#[test]
fn a_backgrounded_tab_locks_on_the_shortened_deadline_without_any_timer() {
    let mut session = unlocked_at(t(0));
    session.note_visibility(TabVisibility::Hidden, t(1_000));
    let just_before = t(1_000 + READER_BACKGROUND_INACTIVITY_MS_V1 - 1);
    assert_eq!(session.state_at(just_before), ReaderSessionState::Unlocked);
    let just_after = t(1_000 + READER_BACKGROUND_INACTIVITY_MS_V1);
    assert_eq!(session.state_at(just_after), ReaderSessionState::Locked);
    assert!(session.vault(just_after).is_none());
    assert!(session.open_records().is_empty());
}

/// Ein zweites `Hidden` startet die Frist NICHT neu, und die Rueckkehr in den
/// Vordergrund vor der Frist beendet sie — ohne die lange Frist zu
/// verlaengern, denn ein Tabwechsel ist keine Eingabe.
#[test]
fn returning_to_the_foreground_ends_the_short_deadline_but_is_not_activity() {
    let mut session = unlocked_at(t(0));
    session.note_visibility(TabVisibility::Hidden, t(1_000));
    session.note_visibility(TabVisibility::Hidden, t(20_000));
    session.note_visibility(TabVisibility::Visible, t(25_000));
    assert_eq!(
        session.state_at(t(1_000 + READER_BACKGROUND_INACTIVITY_MS_V1)),
        ReaderSessionState::Unlocked
    );
    assert_eq!(
        session.state_at(t(READER_INACTIVITY_MS_V1 - 1)),
        ReaderSessionState::Unlocked
    );
    assert_eq!(
        session.state_at(t(READER_INACTIVITY_MS_V1)),
        ReaderSessionState::Locked
    );

    // Und die Gegenprobe: zweimal `Hidden` mit einer Luecke dazwischen, aber
    // ohne Rueckkehr — die Frist laeuft ab dem ERSTEN Wechsel.
    let mut session = unlocked_at(t(0));
    session.note_visibility(TabVisibility::Hidden, t(1_000));
    session.note_visibility(TabVisibility::Hidden, t(20_000));
    assert_eq!(
        session.state_at(t(1_000 + READER_BACKGROUND_INACTIVITY_MS_V1)),
        ReaderSessionState::Locked
    );
}

/// Eine Uhr, die zurueckspringt, verlaengert keine Sitzung. Die Zeit kommt als
/// Parameter herein, wie ueberall in diesem Kern, und deshalb MUSS die Sitzung
/// eine monotone Untergrenze halten.
#[test]
fn a_clock_that_jumps_backwards_never_extends_a_session() {
    let mut session = unlocked_at(t(0));
    assert_eq!(
        session.state_at(t(READER_INACTIVITY_MS_V1)),
        ReaderSessionState::Locked
    );
    assert_eq!(session.state_at(t(1)), ReaderSessionState::Locked);

    // Der subtilere Fall: die Uhr faellt VOR der Frist zurueck, und der
    // Rueckfall darf die Frist nicht nach hinten schieben.
    let mut session = unlocked_at(t(0));
    assert_eq!(session.state_at(t(200_000)), ReaderSessionState::Unlocked);
    assert_eq!(session.state_at(t(50_000)), ReaderSessionState::Unlocked);
    assert_eq!(
        session.state_at(t(READER_INACTIVITY_MS_V1 - 1)),
        ReaderSessionState::Unlocked
    );
    assert_eq!(
        session.state_at(t(READER_INACTIVITY_MS_V1)),
        ReaderSessionState::Locked
    );

    // Auch im Hintergrund: eine Uhr, die hinter den Wechsel zurueckfaellt,
    // verkuerzt nichts und verlaengert nichts.
    let mut session = unlocked_at(t(0));
    session.note_visibility(TabVisibility::Hidden, t(10_000));
    assert_eq!(session.state_at(t(5_000)), ReaderSessionState::Unlocked);
    assert_eq!(
        session.state_at(t(10_000 + READER_BACKGROUND_INACTIVITY_MS_V1)),
        ReaderSessionState::Locked
    );
}

/// Die Sitzung haelt KEIN Schema-Zwischenprodukt. `ea_schema::ValidatedPayload`
/// und `ea_schema::DerivedView` besitzen einen gewoehnlichen `Vec<u8>` und
/// ueberschreiben ihn beim Fallen nicht — die Restfrage, die der Task
/// „Verifikation vor Entschlüsselung, fehlender Grant, Modusparameter und der
/// Anchor, den nur der Vault liefert" hierher weitergibt. Die Antwort ist eine
/// SCHRANKE und keine Behauptung: was die Sitzung offen haelt, ist
/// ausschliesslich `VerifiedDecryptedRecord`, dessen Nutzlast in
/// `ea_crypto::SecretVec` liegt. Der `compile_fail`-Doctest dazu steht im
/// Modulkopf von `crates/ea-reader/src/session.rs`.
#[test]
fn the_session_holds_no_schema_payload_beyond_a_single_decryption() {
    let mut session = unlocked_at(t(0));
    session.open_record(fixtures::decrypted_genesis_record());
    let mut seen = 0;
    for record in session.open_records() {
        // Die EINE ausleihende Klartextflaeche. Es gibt keinen Zugriff, der die
        // Bytes oder die geparste Nutzlast HERAUSGIBT, also kann die Schleife
        // nichts halten.
        record.with_plaintext(|bytes| {
            assert!(!bytes.is_empty());
            seen += 1;
        });
    }
    assert_eq!(seen, 1, "ANTI-LEERLAUF: genau ein Datensatz war offen");
    session.lock();
    assert!(session.open_records().is_empty());
}

/// Nach jeder Sperrung eine FRISCHE Bestaetigung. Die alte gilt nicht wieder,
/// die Bestaetigung fuer den Export entsperrt keine Sitzung, und erst eine
/// frische Entsperrbestaetigung mit einem frisch entsperrten Tresor eroeffnet
/// sie neu.
#[test]
fn a_reused_or_wrongly_purposed_confirmation_does_not_reopen_a_locked_session() {
    let mut session = unlocked_at(t(0));
    session.lock();

    let export_purposed = fixtures::confirmation(ReaderConfirmationPurpose::SingleExport, t(3));
    let refused = session
        .reopen(
            fixtures::unlocked_vault_with_pinned_anchor(),
            export_purposed,
            t(3),
        )
        .expect_err("eine Exportbestaetigung eroeffnet keine Sitzung");
    assert_eq!(refused.code(), "EA-READER-SESSION-CONFIRMATION-PURPOSE");
    assert_eq!(session.state_at(t(4)), ReaderSessionState::Locked);

    // Die ALTE Bestaetigung: ausgestellt bei t(0), vorgelegt nach ihrer Frist.
    let stale = fixtures::confirmation(ReaderConfirmationPurpose::Unlock, t(0));
    let refused = session
        .reopen(
            fixtures::unlocked_vault_with_pinned_anchor(),
            stale,
            t(READER_CONFIRMATION_VALIDITY_MS_V1 + 1),
        )
        .expect_err("eine abgelaufene Bestaetigung eroeffnet keine Sitzung");
    assert_eq!(refused.code(), "EA-READER-SESSION-CONFIRMATION-STALE");

    // Eine Bestaetigung aus der ZUKUNFT ist ebenso wenig frisch.
    let now = t(READER_CONFIRMATION_VALIDITY_MS_V1 + 2);
    let future = fixtures::confirmation(
        ReaderConfirmationPurpose::Unlock,
        UnixMillis::new(now.get() + 1),
    );
    let refused = session
        .reopen(fixtures::unlocked_vault_with_pinned_anchor(), future, now)
        .expect_err("eine Bestaetigung aus der Zukunft eroeffnet keine Sitzung");
    assert_eq!(refused.code(), "EA-READER-SESSION-CONFIRMATION-STALE");

    let fresh = fixtures::confirmation(ReaderConfirmationPurpose::Unlock, now);
    session
        .reopen(fixtures::unlocked_vault_with_pinned_anchor(), fresh, now)
        .expect("eine frische Entsperrbestaetigung eroeffnet die Sitzung neu");
    assert_eq!(session.state_at(now), ReaderSessionState::Unlocked);
    assert!(session.vault(now).is_some());
    // Die Frist laeuft ab der Wiedereroeffnung, nicht ab der ersten Eroeffnung.
    assert!(
        session
            .vault(UnixMillis::new(now.get() + READER_INACTIVITY_MS_V1 - 1))
            .is_some()
    );
    assert!(
        session
            .vault(UnixMillis::new(now.get() + READER_INACTIVITY_MS_V1))
            .is_none()
    );
}

/// Auch die ERSTE Eroeffnung verlangt den richtigen Zweck.
#[test]
fn an_export_confirmation_opens_no_session_at_all() {
    let refused = ReaderSession::unlock(
        fixtures::unlocked_vault_with_pinned_anchor(),
        fixtures::confirmation(ReaderConfirmationPurpose::SingleExport, t(0)),
        t(0),
    )
    .expect_err("eine Exportbestaetigung eroeffnet keine Sitzung");
    assert_eq!(refused.code(), "EA-READER-SESSION-CONFIRMATION-PURPOSE");
}

/// Eine Bestaetigung, die der Authenticator nicht belegt hat, EXISTIERT nicht.
///
/// Der Abbruchpunkt „abgebrochene Authenticator-Bestaetigung" aus
/// `docs/traceability/stage-4-fault-points.json`: die Zeremonie liefert keine
/// oder eine fremde PRF-Ausgabe, und der Nachweis faellt an der
/// AEAD-Umschliessung des Envelopes — nicht an einer Pruefung, die der
/// Aufrufer haette weglassen koennen. Ohne Bestaetigung gibt es weder eine
/// Sitzung noch einen Export; beide nehmen den Typ per Wert.
#[test]
fn a_confirmation_that_the_authenticator_did_not_prove_never_exists() {
    let sealed = fixtures::sealed_vault_with_pinned_anchor();

    let foreign = ReaderAuthenticatorConfirmation::prove(
        &sealed,
        &fixtures::authenticator_with_a_foreign_prf_output(),
        ReaderConfirmationPurpose::SingleExport,
        t(0),
    )
    .expect_err("eine fremde PRF-Ausgabe belegt nichts");
    assert_eq!(foreign.code(), "EA-CRYPTO-AEAD-OPEN");

    let unknown = ReaderAuthenticatorConfirmation::prove(
        &sealed,
        &ea_reader::AuthenticatorPrfV1::new(
            b"ein-passkey-den-dieser-tresor-nicht-kennt".to_vec(),
            ea_crypto::SecretBytes::new([0xa1; 32]),
        ),
        ReaderConfirmationPurpose::Unlock,
        t(0),
    )
    .expect_err("eine unbekannte credentialId belegt nichts");
    assert_eq!(unknown.code(), "EA-READER-VAULT-NO-ENVELOPE");

    // Positivkontrolle: derselbe Weg mit dem echten Authenticator traegt, und
    // die Bindung ist SHA-256 der credentialId, nicht die credentialId selbst.
    let proven = ReaderAuthenticatorConfirmation::prove(
        &sealed,
        &fixtures::authenticator(),
        ReaderConfirmationPurpose::Unlock,
        t(0),
    )
    .expect("der eigene Authenticator belegt sich");
    assert_eq!(proven.purpose(), ReaderConfirmationPurpose::Unlock);
    assert_eq!(proven.issued_at(), t(0));
    assert_eq!(proven.expires_at(), t(READER_CONFIRMATION_VALIDITY_MS_V1));
    assert!(proven.credential_id_hash() == fixtures::credential_id_hash());
    assert!(proven.is_fresh_for(ReaderConfirmationPurpose::Unlock, t(0)));
    assert!(proven.is_fresh_for(
        ReaderConfirmationPurpose::Unlock,
        t(READER_CONFIRMATION_VALIDITY_MS_V1)
    ));
    assert!(!proven.is_fresh_for(
        ReaderConfirmationPurpose::Unlock,
        t(READER_CONFIRMATION_VALIDITY_MS_V1 + 1)
    ));
    assert!(!proven.is_fresh_for(ReaderConfirmationPurpose::SingleExport, t(0)));
    assert!(!proven.is_fresh_for(ReaderConfirmationPurpose::Unlock, t(-1)));
}

/// Die Sitzung traegt die Bindung der Bestaetigung, die sie eroeffnet hat, und
/// GENAU EIN Datensatz laesst sich herausnehmen — nie alle.
#[test]
fn the_session_carries_the_binding_and_hands_out_one_record_at_a_time() {
    let mut session = unlocked_at(t(0));
    assert!(session.operator_binding_hash() == fixtures::credential_id_hash());

    let record = fixtures::decrypted_genesis_record();
    let entry_hash = record.entry_hash();
    session.open_record(record);
    let foreign = ea_reader::EntryHash::try_from(&[0x99_u8; 32][..]).expect("32 Byte");
    assert!(session.take_open_record(foreign).is_none());
    assert_eq!(session.open_records().len(), 1);
    let taken = session
        .take_open_record(entry_hash)
        .expect("der offene Datensatz laesst sich herausnehmen");
    assert!(taken.entry_hash() == entry_hash);
    assert!(session.open_records().is_empty());
    assert!(session.take_open_record(entry_hash).is_none());
}

/// Der `Debug`-Abzug der Sitzung nennt Fristen und Zaehler — keinen Klartext,
/// keinen Tresor.
#[test]
fn the_session_debug_output_carries_no_plaintext() {
    let mut session = unlocked_at(t(0));
    session.open_record(fixtures::decrypted_genesis_record());
    let rendered = format!("{session:?}");
    assert!(rendered.starts_with("ReaderSession {"));
    assert!(rendered.contains("open_record_count: 1"));
    assert!(!ea_testkit::contains_canary(
        rendered.as_bytes(),
        b"ea.genesis"
    ));
    assert!(!ea_testkit::contains_canary(
        rendered.as_bytes(),
        b"plaintext"
    ));
    assert!(!ea_testkit::contains_canary(rendered.as_bytes(), b"vault:"));
}
