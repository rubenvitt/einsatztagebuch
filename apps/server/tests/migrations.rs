//! Die eine Migration der Stufe 3 gegen ein ECHTES PostgreSQL.
//!
//! Zwei Aussagen, und beide sind Sicherheitsaussagen:
//!
//! 1. Die fuenf Eindeutigkeitszwaenge aus `design.md` §13.4 existieren wirklich
//!    — nicht als Absicht in einer Datei, sondern als Constraint, an dem ein
//!    zweiter Schreibversuch zerbricht.
//! 2. Keine Spalte traegt einen fachlichen Wert. Der Kanarienvogel liest
//!    `information_schema.columns` und faellt ueber jede Spalte, deren Name ein
//!    verbotenes Wort ist.

mod common;

use ea_sync_server::CommitRepository;
use ea_trust::{RegistrySelectionOutcome, StateStoreError, TrustStateStore};
use ea_types::UnixMillis;
use einsatzarchiv_server::adapters::{
    postgres::PostgresRepository, trust_state::PostgresTrustStateStore,
};
use sqlx::{PgPool, Row};

/// Der technische Grunddatensatz, auf den jede Tabelle mit
/// Organisationsbezug verweist.
async fn insert_organization(pool: &PgPool, organization: &[u8; 16]) {
    sqlx::query(
        "INSERT INTO organizations (organization_id, root_key_thumbprint, created_at_millis) \
         VALUES ($1, $2, $3)",
    )
    .bind(&organization[..])
    .bind(&[7_u8; 32][..])
    .bind(1_700_000_000_000_i64)
    .execute(pool)
    .await
    .expect("the organization row is technical and must insert");
}

mod fixtures {
    /// Eine Entry-Zeile, ausschliesslich aus technischen Werten.
    pub struct Row {
        pub sequence: i64,
        pub entry_hash: [u8; 32],
        pub object_hash: [u8; 32],
        pub request_id: [u8; 16],
    }

    /// Die vier Unterscheidungsmerkmale als Buchstabenmarke, damit die
    /// Testfaelle so lesbar bleiben wie im Plan.
    #[must_use]
    pub fn row(sequence: i64, entry: &str, object: &str, request: &str) -> Row {
        Row {
            sequence,
            entry_hash: filled(entry),
            object_hash: filled(object),
            request_id: filled(request)[..16]
                .try_into()
                .expect("a 32 byte pattern carries 16 bytes"),
        }
    }

    fn filled(marker: &str) -> [u8; 32] {
        let bytes = marker.as_bytes();
        std::array::from_fn(|index| bytes[index % bytes.len()])
    }
}

const CHAIN_ID: [u8; 16] = [0x11; 16];
const ORGANIZATION_ID: [u8; 16] = [0x22; 16];
const DEVICE_ID: [u8; 16] = [0x33; 16];

/// Schreibt Entry UND Request-ID in EINER Transaktion.
///
/// Beide gehoeren zum selben Commit, also muessen sie gemeinsam scheitern:
/// eine Request-ID, die einen abgelehnten Entry ueberlebte, waere selbst ein
/// Befund.
async fn insert_entry(pool: &PgPool, row: fixtures::Row) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO entries (entry_hash, organization_id, chain_id, sequence_number, \
         entry_object_hash, initial_grant_plan_hash, receipt_object_hash, device_id, \
         accepted_at_server_millis, evidence_due_at_millis, registry_version, \
         registry_head_hash) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(&row.entry_hash[..])
    .bind(&ORGANIZATION_ID[..])
    .bind(&CHAIN_ID[..])
    .bind(row.sequence)
    .bind(&row.object_hash[..])
    .bind(&[1_u8; 32][..])
    .bind(&[2_u8; 32][..])
    .bind(&DEVICE_ID[..])
    .bind(1_700_000_000_000_i64)
    .bind(1_700_000_600_000_i64)
    .bind(1_i64)
    .bind(&[3_u8; 32][..])
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO request_ids (organization_id, request_id, seen_at_millis, \
         expires_at_millis) VALUES ($1, $2, $3, $4)",
    )
    .bind(&ORGANIZATION_ID[..])
    .bind(&row.request_id[..])
    .bind(1_700_000_000_000_i64)
    .bind(1_700_000_300_000_i64)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await
}

#[tokio::test]
async fn chain_sequence_entry_hash_object_hash_and_request_id_are_unique() {
    let database = common::fresh_database().await;
    insert_organization(database.pool(), &ORGANIZATION_ID).await;

    insert_entry(
        database.pool(),
        fixtures::row(1, "entry-a", "object-a", "request-a"),
    )
    .await
    .unwrap();

    for row in [
        // gleiche Kette, gleiche Sequenz
        fixtures::row(1, "entry-b", "object-b", "request-b"),
        // derselbe entryHash ein zweites Mal
        fixtures::row(2, "entry-a", "object-c", "request-c"),
        // derselbe .eip-objectHash ein zweites Mal
        fixtures::row(3, "entry-c", "object-a", "request-d"),
        // dieselbe Request-ID ein zweites Mal
        fixtures::row(4, "entry-d", "object-d", "request-a"),
    ] {
        assert!(
            insert_entry(database.pool(), row).await.is_err(),
            "each of the four uniqueness constraints of design.md §13.4 must reject its \
             duplicate"
        );
    }

    database.cleanup().await;
}

#[tokio::test]
async fn registry_version_is_unique_per_organization() {
    let database = common::fresh_database().await;
    insert_organization(database.pool(), &ORGANIZATION_ID).await;

    let insert = |head: [u8; 32]| {
        let pool = database.pool().clone();
        async move {
            sqlx::query(
                "INSERT INTO registry_events (organization_id, registry_version, \
                 registry_head_hash, effective_from_millis) VALUES ($1, $2, $3, $4)",
            )
            .bind(&ORGANIZATION_ID[..])
            .bind(9_i64)
            .bind(&head[..])
            .bind(1_700_000_000_000_i64)
            .execute(&pool)
            .await
        }
    };

    insert([0xaa; 32]).await.unwrap();
    assert!(
        insert([0xbb; 32]).await.is_err(),
        "the fifth uniqueness constraint of design.md §13.4 — the registry version — must reject \
         a second head for the same version"
    );

    database.cleanup().await;
}

/// Die zwei Weboberflaechentabellen tragen ihre eigenen Eindeutigkeiten.
#[tokio::test]
async fn web_surface_tables_carry_their_required_uniqueness() {
    let database = common::fresh_database().await;
    insert_organization(database.pool(), &ORGANIZATION_ID).await;

    let credential = [0x44_u8; 32];
    let register = |subject: [u8; 16]| {
        let pool = database.pool().clone();
        async move {
            sqlx::query(
                "INSERT INTO webauthn_credentials (organization_id, subject_id, credential_id, \
                 public_key, signature_counter, registered_at_millis) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(&ORGANIZATION_ID[..])
            .bind(&subject[..])
            .bind(&credential[..])
            .bind(&[0x55_u8; 32][..])
            .bind(0_i64)
            .bind(1_700_000_000_000_i64)
            .execute(&pool)
            .await
        }
    };
    register([0x66; 16]).await.unwrap();
    assert!(
        register([0x77; 16]).await.is_err(),
        "a credential ID must be unique per organization (web-reader-design.md §6.4.1)"
    );

    let store_blob = |organization: [u8; 16], ciphertext: &'static [u8]| {
        let pool = database.pool().clone();
        async move {
            sqlx::query(
                "INSERT INTO reader_vault_blobs (organization_id, subject_id, blob_hash, \
                 ciphertext, stored_at_millis) VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(&organization[..])
            .bind(&[0x66_u8; 16][..])
            .bind(&[0x88_u8; 32][..])
            .bind(ciphertext)
            .bind(1_700_000_000_000_i64)
            .execute(&pool)
            .await
        }
    };
    store_blob(ORGANIZATION_ID, b"opaque-a").await.unwrap();
    assert!(
        store_blob(ORGANIZATION_ID, b"opaque-b").await.is_err(),
        "a wrapped blob is keyed by organization, subjectId and blob hash"
    );

    // Dieselbe `subjectId` und derselbe Blobhash in einer ANDEREN Organisation
    // sind eine andere Zeile. Ohne die Organisation im Schluessel waere die
    // Herausgabe nicht organisationsgebunden, obwohl die Credentialaufloesung
    // es ist (`web-reader-design.md` §6.4.1).
    let foreign = [0x9f_u8; 16];
    insert_organization(database.pool(), &foreign).await;
    store_blob(foreign, b"opaque-c")
        .await
        .expect("a foreign organization holds its own row under the same subjectId");

    database.cleanup().await;
}

/// Die Woerter, die in KEINEM Spaltennamen dieses Schemas vorkommen duerfen.
///
/// Verglichen wird je Namenssegment zwischen den Unterstrichen und nicht als
/// Teilzeichenkette: `ciphertext` traegt kein `text`, und `sort_order` traegt
/// keinen `ort`. Die Liste deckt `design.md` §13.4 („Keine fachlichen Werte“)
/// samt der deutschen Schreibweise ab, weil ein spaeterer Autor eher
/// `stichwort` als `keyword` schreibt.
const FORBIDDEN_COLUMN_WORDS: &[&str] = &[
    "incident",
    "einsatz",
    "einsatznummer",
    "einsatzzeit",
    "alarm",
    "alarmzeit",
    "keyword",
    "stichwort",
    "location",
    "ort",
    "standort",
    "adresse",
    "address",
    "person",
    "patient",
    "vehicle",
    "fahrzeug",
    "note",
    "notes",
    "notiz",
    "name",
    "caller",
    "melder",
    "diagnose",
    "symptom",
    "verletzung",
    "time",
    "title",
    "titel",
    "description",
    "beschreibung",
    "comment",
    "kommentar",
];

fn forbidden_word_in(column: &str) -> Option<&'static str> {
    column.split('_').find_map(|segment| {
        FORBIDDEN_COLUMN_WORDS
            .iter()
            .copied()
            .find(|word| *word == segment)
    })
}

#[tokio::test]
async fn no_column_of_the_schema_carries_a_domain_value() {
    let database = common::fresh_database().await;

    // `_sqlx_migrations` gehoert dem Migrator und nicht diesem Schema: seine
    // Spalte `description` traegt den Namen der Migrationsdatei, keinen
    // Einsatzwert. Sie steht hier ausdruecklich ausgenommen, damit die
    // Ausnahme benannt ist statt das Wort aus der Verbotsliste zu streichen.
    let rows = sqlx::query(
        "SELECT table_name, column_name FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name <> '_sqlx_migrations' \
         ORDER BY table_name, column_name",
    )
    .fetch_all(database.pool())
    .await
    .expect("reading information_schema.columns must succeed");

    // Positivkontrolle: ein leeres Ergebnis waere ebenfalls frei von verbotenen
    // Woertern und bewiese nichts. Die Migration legt sechsundzwanzig Tabellen
    // an; deutlich weniger Spalten als hier gefordert hiesse, dass der
    // Kanarienvogel gar nicht hingesehen hat.
    assert!(
        rows.len() >= 100,
        "the canary must actually inspect the schema; it found only {} columns",
        rows.len()
    );

    for row in &rows {
        let table: String = row.get("table_name");
        let column: String = row.get("column_name");
        assert!(
            forbidden_word_in(&column).is_none(),
            "{table}.{column} carries the domain word {:?}; design.md §13.4 forbids every \
             fachlicher Wert in the server schema",
            forbidden_word_in(&column).unwrap_or_default()
        );
    }

    // Zweite Positivkontrolle: das Praedikat selbst muss zuschlagen koennen.
    assert_eq!(forbidden_word_in("einsatz_nummer"), Some("einsatz"));
    assert_eq!(forbidden_word_in("patient_id"), Some("patient"));
    assert_eq!(forbidden_word_in("ciphertext"), None);
    assert_eq!(forbidden_word_in("accepted_at_server_millis"), None);

    database.cleanup().await;
}

/// Die beiden `subject_key`-Spalten nehmen NUR ihre technische Form an.
///
/// Der Kommentar ueber `security_events` sagte immer schon „ausschliesslich
/// eine technische Kennung"; die Spalte war trotzdem freier `TEXT`, und der
/// Kanarienvogel `no_column_of_the_schema_carries_a_domain_value` sieht nur
/// SPALTENNAMEN, nie Werte. Die Zusage stand damit nirgends ausfuehrbar. Sie
/// steht jetzt als CHECK in der Migration, und dieser Fall misst BEIDE
/// Richtungen — sonst bewiese ein durchgelassener Wert nichts ueber einen
/// abgewiesenen.
#[tokio::test]
async fn the_subject_key_columns_admit_only_their_technical_shape() {
    let database = common::fresh_database().await;
    let organization = [0x71_u8; 16];
    insert_organization(database.pool(), &organization).await;

    let hex_hash = "a".repeat(64);
    let hex_device = "b".repeat(32);

    // Die beiden Formen, die der Server WIRKLICH schreibt.
    for accepted in [hex_hash.clone(), format!("eip/{hex_hash}")] {
        plant_security_event(database.pool(), &organization, &accepted)
            .await
            .unwrap_or_else(|error| {
                panic!("the shape the server writes must be admitted: {accepted} ({error})")
            });
    }
    // Und die Formen, die es nicht gibt: ein fachlicher Wert, ein unbekanntes
    // Typsegment, ein Grossbuchstabe, ein Anhang hinter der gueltigen Form.
    for refused in [
        "Einsatz 7, Melder Mueller".to_owned(),
        format!("xyz/{hex_hash}"),
        "A".repeat(64),
        format!("{hex_hash} und noch etwas"),
    ] {
        assert!(
            plant_security_event(database.pool(), &organization, &refused)
                .await
                .is_err(),
            "a free text must not reach security_events.subject_key: {refused}"
        );
    }

    // Dasselbe fuer das Administrationsaudit, dessen Form
    // `apps/server/src/admin_audit.rs::subject_key` zusammensetzt.
    for accepted in [
        format!("{hex_device}/succeeded/{hex_hash}"),
        format!("{hex_device}/refused/-"),
        format!("{hex_device}/failed/{hex_hash}"),
    ] {
        plant_admin_audit(database.pool(), &organization, &accepted)
            .await
            .unwrap_or_else(|error| {
                panic!("the shape admin_audit.rs builds must be admitted: {accepted} ({error})")
            });
    }
    for refused in [
        format!("{hex_device}/geloescht/{hex_hash}"),
        format!("{hex_device}/succeeded"),
        format!("{hex_hash}/succeeded/{hex_hash}"),
        "Bediener Mueller/succeeded/-".to_owned(),
    ] {
        assert!(
            plant_admin_audit(database.pool(), &organization, &refused)
                .await
                .is_err(),
            "a free text must not reach technical_admin_audit.subject_key: {refused}"
        );
    }

    database.cleanup().await;
}

async fn plant_security_event(
    pool: &PgPool,
    organization: &[u8; 16],
    subject_key: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO security_events (organization_id, event_code, subject_key, \
         observed_at_millis) VALUES ($1, 'sequence-fork', $2, 1)",
    )
    .bind(&organization[..])
    .bind(subject_key)
    .execute(pool)
    .await
    .map(|_| ())
}

async fn plant_admin_audit(
    pool: &PgPool,
    organization: &[u8; 16],
    subject_key: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO technical_admin_audit (organization_id, operator_subject_id, \
         action_code, subject_key, recorded_at_millis) VALUES ($1, $2, 'server-key-rotation', \
         $3, 1)",
    )
    .bind(&organization[..])
    .bind(&[0x72_u8; 16][..])
    .bind(subject_key)
    .execute(pool)
    .await
    .map(|_| ())
}

/// Alle sechsundzwanzig Tabellen der Stufe 3 sind da, samt den additiven
/// Migrationen fuer bestehende Installationen.
#[tokio::test]
async fn the_migrations_create_every_planned_table() {
    let database = common::fresh_database().await;

    let expected = [
        "chain_heads",
        "challenges",
        "checkpoints",
        "clock_release_replays",
        "destruction_attestations",
        "destruction_targets",
        "destruction_transitions",
        "destructions",
        "entries",
        "evidence_jobs",
        "grants",
        "object_index",
        "organizations",
        "pending_device_requests",
        "reader_acknowledgements",
        "reader_vault_blobs",
        "receipts",
        "registry_events",
        "replay_nonces",
        "request_ids",
        "role_intervals",
        "security_events",
        "technical_admin_audit",
        "trust_events",
        "trust_state",
        "webauthn_credentials",
    ];
    let rows = sqlx::query(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_type = 'BASE TABLE' AND table_name <> \
         '_sqlx_migrations' ORDER BY table_name",
    )
    .fetch_all(database.pool())
    .await
    .expect("reading information_schema.tables must succeed");
    let actual: Vec<String> = rows.iter().map(|row| row.get("table_name")).collect();
    assert_eq!(actual, expected);

    let applied: Vec<(i64,)> =
        sqlx::query_as("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(database.pool())
            .await
            .expect("the migration bookkeeping table must exist");
    assert_eq!(
        applied,
        vec![(1_i64,), (2_i64,)],
        "the original schema and the additive trust cache migration must both apply"
    );

    database.cleanup().await;
}

#[tokio::test]
async fn the_trust_cache_migration_upgrades_the_original_schema_without_replacing_it() {
    let original = std::env::temp_dir().join(format!("ea-original-{}", common::unique_suffix()));
    std::fs::create_dir(&original).expect("the original migration directory must be creatable");
    std::fs::copy(
        "migrations/0001_initial.sql",
        original.join("0001_initial.sql"),
    )
    .expect("the released migration must copy unchanged");
    let database = common::fresh_database_with_migrations(&original).await;
    std::fs::remove_dir_all(&original).expect("the disposable migration copy must be removable");
    insert_organization(database.pool(), &ORGANIZATION_ID).await;
    sqlx::query(
        "INSERT INTO trust_events (organization_id, event_id, object_hash, event_code, \
         received_at_millis) VALUES ($1, $2, $3, 'deviceCertificate', 17)",
    )
    .bind(&ORGANIZATION_ID[..])
    .bind(&[0x81_u8; 16][..])
    .bind(&[0x82_u8; 32][..])
    .execute(database.pool())
    .await
    .unwrap();

    sqlx_core::migrate::Migrator::new(std::path::Path::new("migrations"))
        .await
        .unwrap()
        .run(database.pool())
        .await
        .expect("upgrade must validate the original migration checksum and preserve its rows");
    let has_revision: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'organizations' \
         AND column_name = 'trust_catalog_revision')",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert!(
        has_revision,
        "upgrading an existing schema must install cache invalidation"
    );
    let first: i64 = sqlx::query_scalar("SELECT trust_catalog_revision FROM organizations")
        .fetch_one(database.pool())
        .await
        .unwrap();
    let received: i64 = sqlx::query_scalar("SELECT received_at_millis FROM trust_events")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(
        received, 17,
        "the pre-upgrade trust object must survive unchanged"
    );

    sqlx::query("UPDATE trust_events SET received_at_millis = 18")
        .execute(database.pool())
        .await
        .unwrap();
    let updated: i64 = sqlx::query_scalar("SELECT trust_catalog_revision FROM organizations")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert!(
        updated > first,
        "upgraded rows must participate in invalidation"
    );
    sqlx::query("DELETE FROM trust_events")
        .execute(database.pool())
        .await
        .unwrap();
    let deleted: i64 = sqlx::query_scalar("SELECT trust_catalog_revision FROM organizations")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert!(deleted > updated);
    sqlx::query("DELETE FROM organizations")
        .execute(database.pool())
        .await
        .unwrap();
    insert_organization(database.pool(), &ORGANIZATION_ID).await;
    let recreated: i64 = sqlx::query_scalar("SELECT trust_catalog_revision FROM organizations")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert!(
        recreated > deleted,
        "recreating an organization must not reuse a cache generation"
    );
    database.cleanup().await;
}

/// Die Constraintnamen, auf die `adapters/postgres.rs` seine Fehlerzuordnung
/// stuetzt.
///
/// `map_commit_error` unterscheidet ein verlorenes Rennen um den Kettenkopf von
/// einem Widerspruch in der Commit-Identitaet anhand des Constraintnamens, den
/// PostgreSQL selbst vergibt. Wuerde eine spaetere Migration einen dieser
/// Zwaenge umbenennen oder ausdruecklich benennen, fiele die Zuordnung still auf
/// den falschen Code zurueck — dieser Test haelt die Namen fest.
#[tokio::test]
async fn the_head_race_constraints_carry_the_names_the_adapter_maps() {
    let database = common::fresh_database().await;

    let rows = sqlx::query(
        "SELECT conname FROM pg_constraint \
         WHERE conrelid IN ('entries'::regclass, 'chain_heads'::regclass, \
         'checkpoints'::regclass) AND contype IN ('u', 'p') ORDER BY conname",
    )
    .fetch_all(database.pool())
    .await
    .expect("reading pg_constraint must succeed");
    let names: Vec<String> = rows.iter().map(|row| row.get("conname")).collect();
    // Der Checkpoint-Zwang steht MIT in der Liste: `map_commit_error` bildet
    // genau diesen Namen auf `EA-DB-CHECKPOINT-PREDECESSOR` ab. Waere er
    // laenger als die 63 Zeichen, die PostgreSQL fuer einen Bezeichner
    // zulaesst, wuerde er stillschweigend gekuerzt — und die Zuordnung fiele
    // auf „Widerspruch in der Commit-Identitaet" zurueck.
    assert_eq!(
        names,
        vec![
            "chain_heads_pkey",
            "checkpoints_organization_id_chain_id_covered_sequence_key",
            "checkpoints_pkey",
            "checkpoints_technical_index_key",
            "entries_chain_id_sequence_number_key",
            "entries_entry_object_hash_key",
            "entries_pkey",
        ]
    );

    database.cleanup().await;
}

// ---------------------------------------------------------------------------
// Der persistente `ea_trust::TrustStateStore`
// ---------------------------------------------------------------------------

mod trust_state {
    use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

    use ea_crypto::object_hash;
    use ea_trust::{
        RegistrySelectionOutcome, TrustObjectSource, TrustSourceError, TrustStateKey,
        load_trust_state, prepare_local_time, select_registry_head, verify_registry_candidate,
        verify_trust,
    };
    use ea_types::{ChainSequence, DeviceId, Id16, ObjectHash, UnixMillis};
    use einsatzarchiv_server::adapters::trust_state::PostgresTrustStateStore;

    /// Der eingefrorene Positivfall der Trust-Vektoren.
    ///
    /// Er wird GELESEN, nicht nachgebaut: die Bytes liegen unter
    /// `vectors/trust/v1/registry/accepted-bootstrap-and-first-head/` und sind
    /// dieselben, gegen die `tests/ea-system-tests` seine Pipeline faehrt. Ein
    /// zweiter, handgebauter Vertrauensbestand in diesem Paket waere eine
    /// zweite Quelle fuer dieselbe Aussage.
    const FIXTURE: &str = "vectors/trust/v1/registry/accepted-bootstrap-and-first-head";

    pub fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    pub struct Catalog(BTreeMap<ObjectHash, Arc<[u8]>>);

    impl TrustObjectSource for Catalog {
        fn visit_trust_object_hashes(
            &self,
            visitor: &mut dyn FnMut(ObjectHash) -> Result<(), TrustSourceError>,
        ) -> Result<(), TrustSourceError> {
            for hash in self.0.keys().copied() {
                visitor(hash)?;
            }
            Ok(())
        }

        fn read_exact_trust_object(
            &self,
            object_hash: ObjectHash,
        ) -> Result<Option<Arc<[u8]>>, TrustSourceError> {
            Ok(self.0.get(&object_hash).map(Arc::clone))
        }
    }

    /// Ankerbytes und Objektkatalog des Fixture-Falls.
    pub fn fixture() -> (Vec<u8>, Catalog) {
        let directory = workspace_root().join(FIXTURE);
        let anchor = std::fs::read(directory.join("anchor.bin")).expect("the anchor vector");
        let mut catalog = BTreeMap::new();
        for slot in [
            "root-certificate",
            "admin-certificate-a",
            "admin-certificate-b",
            "admin-binding-a",
            "admin-binding-b",
            "policy",
            "policy-authorization",
            "head-event",
            "head-authorization",
        ] {
            let bytes = std::fs::read(directory.join(format!("{slot}.bin")))
                .unwrap_or_else(|error| panic!("the {slot} vector must be readable: {error}"));
            catalog.insert(object_hash(&bytes), Arc::<[u8]>::from(bytes));
        }
        (anchor, Catalog(catalog))
    }

    pub fn state_key(anchor_bytes: &[u8]) -> TrustStateKey {
        let anchor = ea_trust::decode_trust_anchor(anchor_bytes).expect("the anchor must decode");
        TrustStateKey {
            organization_id: anchor.organization_id(),
            device_id: DeviceId::from(Id16::try_from(&[0xf0_u8; 16][..]).expect("sixteen bytes")),
        }
    }

    /// Ein voller Durchlauf `load` → `verify_trust` → Kandidat →
    /// `prepare_local_time` → `select_registry_head` ueber DIESEN Speicher.
    ///
    /// `prepare_local_time` und `select_registry_head` sind der einzige
    /// oeffentliche Weg in die schreibende Haelfte des Vertrags; genau deshalb
    /// laeuft der Zeuge hier entlang und nicht an einem selbstgebauten Commit.
    pub fn run_selection(
        store: &mut PostgresTrustStateStore,
        anchor_bytes: &[u8],
        catalog: &Catalog,
        clock: UnixMillis,
        interlude: impl FnOnce(),
    ) -> Result<RegistrySelectionOutcome, String> {
        let anchor = ea_trust::decode_trust_anchor(anchor_bytes).expect("the anchor must decode");
        let key = state_key(anchor_bytes);
        let snapshot = load_trust_state(store, key).map_err(|error| error.code().to_owned())?;
        let trust =
            verify_trust(&anchor, catalog, snapshot).map_err(|error| error.code().to_owned())?;
        let candidate = verify_registry_candidate(&trust, ChainSequence::new(1))
            .map_err(|error| error.code().to_owned())?;
        let local_time = prepare_local_time(store, &candidate, clock, &[])
            .map_err(|error| error.code().to_owned())?;
        // Zwischen dem Lesen der erwarteten Revision und dem Commit: hier setzt
        // der Zeuge fuer das verlorene Rennen seinen konkurrierenden Schreiber.
        interlude();
        select_registry_head(candidate, local_time, None).map_err(|error| error.code().to_owned())
    }
}

/// Die Uhr des eingefrorenen Fixture-Falls.
///
/// GEMESSEN, nicht geraten: bei 800 waehlt `select_registry_head` den Kopf
/// (`Selected`). Frueher liegt der Kopf noch in der Zukunft
/// (`EA-TRUST-PENDING-FUTURE`), spaeter zieht die Auswahl erst den Policy-Kopf
/// nach (`Advanced`).
const FIXTURE_CLOCK_MILLIS: i64 = 800;

/// Nebenlaeufigkeitsaussage, erste Haelfte: der Commit laeuft unter GENAU der
/// Revision, die der Aufrufer gelesen hat, und hebt sie um eins.
///
/// Gefahren wird der einzige oeffentliche Weg in die schreibende Haelfte des
/// Vertrags — `prepare_local_time` und `select_registry_head` —, nicht ein
/// selbstgebauter Commit: die Commit-Typen von `ea-trust` haben
/// `pub(crate)`-Konstruktoren, und ein Zeuge, der sie umginge, pruefte eine
/// andere Kante als die, die der Server benutzt.
#[tokio::test(flavor = "multi_thread")]
async fn the_trust_state_store_commits_under_the_revision_it_read() {
    let database = common::fresh_database().await;
    let (anchor, catalog) = trust_state::fixture();
    let key = trust_state::state_key(&anchor);
    let clock = UnixMillis::new(FIXTURE_CLOCK_MILLIS);
    let mut store = PostgresTrustStateStore::new(database.pool().clone(), clock);

    // Der leere Stand ist kein Fehler, sondern Revision null ohne gepinnten
    // Kopf — genau wie beim lesenden Modell `EphemeralTrustStateStore`.
    let empty = store.load(key).expect("the empty state must load");
    assert_eq!(empty.revision(), 0);
    assert!(empty.pinned_head().is_none());
    assert_eq!(empty.trusted_time().floor(), clock);

    let outcome = trust_state::run_selection(&mut store, &anchor, &catalog, clock, || {})
        .expect("the frozen positive fixture must select its head");
    assert!(matches!(outcome, RegistrySelectionOutcome::Selected(_)));

    // Fortgeschrieben um GENAU EINS, mit gepinntem Kopf.
    let committed = store.load(key).expect("the committed state must load");
    assert_eq!(committed.revision(), 1);
    let pin = committed
        .pinned_head()
        .expect("the selection must pin its head");
    assert!(pin.registry_version().get() >= 1);

    // Und die Zeile steht wirklich in der Datenbank, nicht nur im Speicher.
    let row: (i64, i64) = sqlx::query_as(
        "SELECT revision, trusted_floor_millis FROM trust_state \
         WHERE organization_id = $1 AND device_id = $2",
    )
    .bind(&key.organization_id.as_bytes()[..])
    .bind(&key.device_id.as_bytes()[..])
    .fetch_one(database.pool())
    .await
    .expect("the trust state row must exist");
    assert_eq!(row.0, 1);

    // Ein zweiter Durchlauf liest die Revision eins und schreibt zwei fort —
    // die erwartete Revision ist immer die zuletzt gelesene.
    let outcome = trust_state::run_selection(&mut store, &anchor, &catalog, clock, || {})
        .expect("a second pass must still select");
    assert!(matches!(outcome, RegistrySelectionOutcome::Selected(_)));
    assert_eq!(store.load(key).expect("state").revision(), 2);

    database.cleanup().await;
}

/// Nebenlaeufigkeitsaussage, zweite Haelfte: ein VERLORENES RENNEN wird mit
/// `EA-TRUST-STATE-CONFLICT` beantwortet, und der Adapter wiederholt NICHT.
///
/// Der konkurrierende Schreiber setzt zwischen dem Lesen der erwarteten
/// Revision und dem Commit eine eigene Zeile — genau das Fenster, in dem ein
/// zweiter Server denselben Stand fortschreiben wuerde.
#[tokio::test(flavor = "multi_thread")]
async fn a_lost_race_answers_with_the_documented_conflict_and_does_not_retry() {
    let database = common::fresh_database().await;
    let (anchor, catalog) = trust_state::fixture();
    let key = trust_state::state_key(&anchor);
    let clock = UnixMillis::new(FIXTURE_CLOCK_MILLIS);
    let mut store = PostgresTrustStateStore::new(database.pool().clone(), clock);

    let competitor = database.pool().clone();
    let outcome = trust_state::run_selection(&mut store, &anchor, &catalog, clock, || {
        // Der konkurrierende Commit. Er laeuft ueber eine eigene Verbindung und
        // hebt die Revision auf eins, waehrend der laufende Durchlauf noch mit
        // der gelesenen Null rechnet.
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                sqlx::query(
                    "INSERT INTO trust_state (organization_id, device_id, revision, \
                     trusted_floor_millis) VALUES ($1, $2, 1, $3)",
                )
                .bind(&key.organization_id.as_bytes()[..])
                .bind(&key.device_id.as_bytes()[..])
                .bind(FIXTURE_CLOCK_MILLIS)
                .execute(&competitor)
                .await
                .expect("the competing commit must land");
            });
        });
    });
    let Err(error) = outcome else {
        panic!("a lost race must not be answered with a silent success");
    };
    assert_eq!(error, "EA-TRUST-STATE-CONFLICT");

    // KEIN interner Retry: der Stand traegt unveraendert die Revision des
    // Gewinners, nicht die des Verlierers.
    let row: (i64,) = sqlx::query_as(
        "SELECT revision FROM trust_state WHERE organization_id = $1 AND device_id = $2",
    )
    .bind(&key.organization_id.as_bytes()[..])
    .bind(&key.device_id.as_bytes()[..])
    .fetch_one(database.pool())
    .await
    .expect("the winner's row must exist");
    assert_eq!(
        row.0, 1,
        "the adapter must not retry; the loser re-reads and decides again"
    );

    database.cleanup().await;
}

/// Die Laufzeitform, beide Zweige.
///
/// Der Adapter brueckt einen SYNCHRONEN Vertrag in asynchrone Anweisungen und
/// braucht dafuer die Mehrfaden-Laufzeit. Auf jeder anderen antwortet er
/// fail-closed statt mit Panik — eine Panik risse den Faden mit, statt einen
/// Befund zu liefern. Die Mehrfaden-Haelfte belegen die beiden Zeugen darueber;
/// hier steht die andere.
#[tokio::test]
async fn the_trust_state_store_fails_closed_on_a_current_thread_runtime() {
    let database = common::fresh_database().await;
    let (anchor, _catalog) = trust_state::fixture();
    let key = trust_state::state_key(&anchor);
    let mut store = PostgresTrustStateStore::new(
        database.pool().clone(),
        UnixMillis::new(FIXTURE_CLOCK_MILLIS),
    );

    let Err(error) = store.load(key) else {
        panic!("a current thread runtime cannot carry this adapter");
    };
    assert_eq!(error.code(), "EA-TRUST-STATE-UNAVAILABLE");
    assert_eq!(error, StateStoreError::Unavailable);

    database.cleanup().await;
}

// ---------------------------------------------------------------------------
// `CommitRepository::commit_locked_head` gegen die echte Datenbank
// ---------------------------------------------------------------------------

mod commit {
    use ea_format::ObjectTypeV1;
    use ea_sync_server::{CheckpointCommitV1, CommitDbCommand, CommitIdentityV1, IndexedObjectV1};
    use ea_types::{
        ChainId, ChainSequence, DeviceId, EntryHash, Hash32, Id16, ObjectHash, OrganizationId,
        RegistryVersion, UnixMillis,
    };

    pub fn hash32(marker: u8) -> Hash32 {
        Hash32::try_from(&[marker; 32][..]).expect("thirty two bytes")
    }

    pub fn object(marker: u8) -> ObjectHash {
        ObjectHash::from(hash32(marker))
    }

    pub fn entry(marker: u8) -> EntryHash {
        EntryHash::from(hash32(marker))
    }

    pub fn id16(marker: u8) -> Id16 {
        Id16::try_from(&[marker; 16][..]).expect("sixteen bytes")
    }

    /// Ein vollstaendiger Commit-Auftrag aus rein technischen Werten.
    ///
    /// `indexed_objects` traegt Entry, initiale Grants UND Receipt: der
    /// Objektindex entsteht in derselben Transaktion, und die
    /// Fremdschluessel von `grants` und `receipts` zeigen darauf.
    pub struct Builder {
        pub organization: OrganizationId,
        pub chain: ChainId,
        pub sequence: u64,
        pub previous: Option<EntryHash>,
        pub entry_hash: EntryHash,
        pub entry_object: ObjectHash,
        pub grant_plan: Hash32,
        pub grants: Vec<ObjectHash>,
        pub receipt: ObjectHash,
        pub checkpoint: ObjectHash,
        /// Der Anker, auf dem der Checkpoint dieses Commits aufsetzt.
        pub previous_checkpoint: Option<ObjectHash>,
        pub accepted_at: i64,
    }

    impl Builder {
        pub fn new(organization: OrganizationId, chain: ChainId, sequence: u64) -> Self {
            Self {
                organization,
                chain,
                sequence,
                previous: None,
                entry_hash: entry(0x10),
                entry_object: object(0x20),
                grant_plan: hash32(0x30),
                grants: vec![object(0x40), object(0x41)],
                receipt: object(0x50),
                checkpoint: object(0x51),
                previous_checkpoint: None,
                accepted_at: 1_700_000_000_000,
            }
        }

        pub fn build(&self) -> CommitDbCommand {
            let mut indexed = vec![
                IndexedObjectV1 {
                    kind: ObjectTypeV1::Entry,
                    object_hash: self.entry_object,
                    size_bytes: 512,
                },
                IndexedObjectV1 {
                    kind: ObjectTypeV1::Receipt,
                    object_hash: self.receipt,
                    size_bytes: 256,
                },
                IndexedObjectV1 {
                    kind: ObjectTypeV1::Evidence,
                    object_hash: self.checkpoint,
                    size_bytes: 256,
                },
            ];
            indexed.extend(self.grants.iter().map(|hash| IndexedObjectV1 {
                kind: ObjectTypeV1::Grant,
                object_hash: *hash,
                size_bytes: 641,
            }));
            let mut grants = self.grants.clone();
            grants.sort_unstable();
            CommitDbCommand {
                organization_id: self.organization,
                chain_id: self.chain,
                device_id: DeviceId::from(id16(0x60)),
                sequence: ChainSequence::new(self.sequence),
                previous_entry_hash: self.previous,
                identity: CommitIdentityV1 {
                    entry_hash: self.entry_hash,
                    entry_object_hash: self.entry_object,
                    initial_grant_plan_hash: self.grant_plan,
                    initial_grant_object_hashes: grants.clone(),
                },
                grant_recipients: grants
                    .iter()
                    .enumerate()
                    .map(|(index, hash)| ea_sync_server::GrantRecipientV1 {
                        object_hash: *hash,
                        recipient_key_thumbprint: ea_types::KeyThumbprint::try_from(
                            &[0xb0_u8.wrapping_add(
                                u8::try_from(index).expect("a fixture has few grants"),
                            ); 32][..],
                        )
                        .expect("thirty two bytes"),
                    })
                    .collect(),
                receipt_object_hash: self.receipt,
                accepted_at_server: UnixMillis::new(self.accepted_at),
                evidence_due_at: Some(UnixMillis::new(self.accepted_at + 600_000)),
                registry_version: RegistryVersion::new(1),
                registry_head_hash: object(0x70),
                indexed_objects: indexed,
                checkpoint: CheckpointCommitV1 {
                    object_hash: self.checkpoint,
                    covered_sequence: ChainSequence::new(self.sequence),
                    issued_at_server: UnixMillis::new(self.accepted_at),
                    previous_evidence_hash: self.previous_checkpoint,
                },
            }
        }
    }
}

const COMMIT_ORGANIZATION: [u8; 16] = [0x2a; 16];
const COMMIT_CHAIN: [u8; 16] = [0x2b; 16];

async fn commit_fixture(pool: &PgPool) -> (ea_types::OrganizationId, ea_types::ChainId) {
    insert_organization(pool, &COMMIT_ORGANIZATION).await;
    (
        ea_types::OrganizationId::from(
            ea_types::Id16::try_from(&COMMIT_ORGANIZATION[..]).expect("sixteen bytes"),
        ),
        ea_types::ChainId::from(
            ea_types::Id16::try_from(&COMMIT_CHAIN[..]).expect("sixteen bytes"),
        ),
    )
}

/// Der glueckliche Pfad: Entry, Grants, Receipt, Objektindex und der neue
/// Kettenkopf werden GEMEINSAM sichtbar (`design.md` §13.3, Schritt 8).
#[tokio::test]
async fn a_commit_makes_entry_grants_receipt_and_head_visible_together() {
    let database = common::fresh_database().await;
    let (organization, chain) = commit_fixture(database.pool()).await;
    let repository = PostgresRepository::new(database.pool().clone());

    let command = commit::Builder::new(organization, chain, 0).build();
    let state = repository
        .commit_locked_head(command)
        .await
        .expect("the first commit of a chain must land");
    assert!(state.newly_committed);
    assert_eq!(state.sequence.get(), 0);

    let counts: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM entries), (SELECT count(*) FROM grants), \
         (SELECT count(*) FROM receipts), (SELECT count(*) FROM checkpoints), \
         (SELECT count(*) FROM object_index), (SELECT count(*) FROM chain_heads)",
    )
    .fetch_one(database.pool())
    .await
    .expect("counting must succeed");
    // Der Objektindex traegt fuenf Zeilen: Entry, zwei Grants, Quittung UND
    // den Standard-Checkpoint. Der Anker wird mit demselben Commit sichtbar
    // (`design.md` §15.2).
    assert_eq!(counts, (1, 2, 1, 1, 5, 1));

    let head: (i64, Vec<u8>) =
        sqlx::query_as("SELECT head_sequence, head_entry_hash FROM chain_heads")
            .fetch_one(database.pool())
            .await
            .expect("the head must exist");
    assert_eq!(head.0, 0);
    assert_eq!(head.1, commit::entry(0x10).as_bytes());

    database.cleanup().await;
}

/// Eine Annahmezeit UNTER der des Vorgaengers wird unter der Sperre
/// abgewiesen.
///
/// `design.md`:929: „`accepted-at-server` … darf je Kette nicht unter der des
/// vorherigen Receipts liegen." Sequenz und Vorgaengerhash fangen das NICHT —
/// der Nachzuegler sitzt korrekt hinter dem Kopf. Er hat dessen Annahmezeit
/// nur gelesen, BEVOR ein anderer Commit sie vorgezogen hat, und ohne diese
/// Pruefung wuerde er eine rueckwaerts laufende Zeit SIGNIERT sichtbar
/// schalten. Danach waere sie unheilbar.
#[tokio::test]
async fn an_accepted_time_below_the_head_is_a_head_conflict() {
    let database = common::fresh_database().await;
    let (organization, chain) = commit_fixture(database.pool()).await;
    let repository = PostgresRepository::new(database.pool().clone());

    let mut first = commit::Builder::new(organization, chain, 0);
    first.accepted_at = 1_700_000_010_000;
    repository
        .commit_locked_head(first.build())
        .await
        .expect("the first commit must land");

    // Korrekte Sequenz, korrekter Vorgaenger — nur die Zeit laeuft zurueck.
    let mut successor = commit::Builder::new(organization, chain, 1);
    successor.entry_hash = commit::entry(0x1a);
    successor.entry_object = commit::object(0x2a);
    successor.receipt = commit::object(0x5a);
    successor.checkpoint = commit::object(0x5b);
    successor.previous_checkpoint = Some(commit::object(0x51));
    successor.grants = vec![commit::object(0x4a)];
    successor.previous = Some(commit::entry(0x10));
    successor.accepted_at = 1_700_000_009_999;
    let error = repository
        .commit_locked_head(successor.build())
        .await
        .expect_err("a receipt time below the head must be refused");
    assert_eq!(error.code(), "EA-DB-HEAD-CONFLICT");

    // Genau die Kopfzeit ist zulaessig — die Zusage ist „nicht darunter",
    // nicht „streng darueber".
    successor.accepted_at = 1_700_000_010_000;
    repository
        .commit_locked_head(successor.build())
        .await
        .expect("an accepted time equal to the head must land");

    let times: Vec<i64> = sqlx::query_scalar(
        "SELECT accepted_at_server_millis FROM entries ORDER BY sequence_number",
    )
    .fetch_all(database.pool())
    .await
    .expect("reading the accepted times must succeed");
    assert_eq!(times, vec![1_700_000_010_000, 1_700_000_010_000]);

    database.cleanup().await;
}

/// Dieselbe Commit-Identitaet ein zweites Mal ist ein IDEMPOTENTER REPLAY und
/// liefert denselben gespeicherten Receipt — kein zweiter Eintrag, kein
/// fortgeschriebener Kopf.
#[tokio::test]
async fn the_same_commit_identity_replays_idempotently() {
    let database = common::fresh_database().await;
    let (organization, chain) = commit_fixture(database.pool()).await;
    let repository = PostgresRepository::new(database.pool().clone());

    let builder = commit::Builder::new(organization, chain, 0);
    let first = repository
        .commit_locked_head(builder.build())
        .await
        .expect("the first commit must land");
    let replay = repository
        .commit_locked_head(builder.build())
        .await
        .expect("the identical commit must replay instead of failing");

    assert!(first.newly_committed);
    assert!(!replay.newly_committed, "a replay stores nothing new");
    assert!(replay.receipt_object_hash == first.receipt_object_hash);
    assert_eq!(replay.accepted_at_server, first.accepted_at_server);

    let entries: (i64,) = sqlx::query_as("SELECT count(*) FROM entries")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(entries.0, 1);
    let head: (i64,) = sqlx::query_as("SELECT head_sequence FROM chain_heads")
        .fetch_one(database.pool())
        .await
        .unwrap();
    assert_eq!(head.0, 0);

    database.cleanup().await;
}

/// Derselbe `entryHash` mit ANDERER Identitaet ist kein Replay, sondern ein
/// Widerspruch — und wird nicht automatisch repariert.
#[tokio::test]
async fn the_same_entry_hash_with_a_different_identity_is_a_conflict() {
    let database = common::fresh_database().await;
    let (organization, chain) = commit_fixture(database.pool()).await;
    let repository = PostgresRepository::new(database.pool().clone());

    let builder = commit::Builder::new(organization, chain, 0);
    repository
        .commit_locked_head(builder.build())
        .await
        .unwrap();

    for mutate in [
        // andere .eip-Bytes
        Box::new(|b: &mut commit::Builder| b.entry_object = commit::object(0x21))
            as Box<dyn FnOnce(&mut commit::Builder)>,
        // anderer Grant-Plan
        Box::new(|b: &mut commit::Builder| b.grant_plan = commit::hash32(0x31)),
        // andere initiale Grants
        Box::new(|b: &mut commit::Builder| b.grants = vec![commit::object(0x42)]),
    ] {
        let mut divergent = commit::Builder::new(organization, chain, 0);
        mutate(&mut divergent);
        let error = repository
            .commit_locked_head(divergent.build())
            .await
            .expect_err("a divergent identity under the same entryHash must be refused");
        assert_eq!(error.code(), "EA-DB-COMMIT-IDENTITY-CONFLICT");
    }

    database.cleanup().await;
}

/// Falsche Sequenz oder falscher Vorgaenger: der Kopf entscheidet, und zwar mit
/// `EA-DB-HEAD-CONFLICT`.
#[tokio::test]
async fn a_wrong_sequence_or_predecessor_is_a_head_conflict() {
    let database = common::fresh_database().await;
    let (organization, chain) = commit_fixture(database.pool()).await;
    let repository = PostgresRepository::new(database.pool().clone());

    // Eine Kette beginnt bei null; Sequenz eins ohne Vorgaenger passt nicht.
    let mut ahead = commit::Builder::new(organization, chain, 1);
    ahead.entry_hash = commit::entry(0x11);
    let error = repository
        .commit_locked_head(ahead.build())
        .await
        .expect_err("a chain must start at sequence zero");
    assert_eq!(error.code(), "EA-DB-HEAD-CONFLICT");

    repository
        .commit_locked_head(commit::Builder::new(organization, chain, 0).build())
        .await
        .unwrap();

    // Richtige Sequenz, FALSCHER Vorgaenger.
    let mut wrong_predecessor = commit::Builder::new(organization, chain, 1);
    wrong_predecessor.entry_hash = commit::entry(0x12);
    wrong_predecessor.entry_object = commit::object(0x22);
    wrong_predecessor.receipt = commit::object(0x52);
    wrong_predecessor.grants = vec![commit::object(0x43)];
    wrong_predecessor.previous = Some(commit::entry(0xee));
    let error = repository
        .commit_locked_head(wrong_predecessor.build())
        .await
        .expect_err("a wrong predecessor must be refused");
    assert_eq!(error.code(), "EA-DB-HEAD-CONFLICT");

    // Dieselbe Sequenz mit einem ANDEREN entryHash — das verlorene Rennen um
    // den Kopf, nicht ein Identitaetswiderspruch.
    let mut fork = commit::Builder::new(organization, chain, 0);
    fork.entry_hash = commit::entry(0x13);
    fork.entry_object = commit::object(0x23);
    fork.receipt = commit::object(0x53);
    fork.grants = vec![commit::object(0x44)];
    let error = repository
        .commit_locked_head(fork.build())
        .await
        .expect_err("a second entry at the same sequence must be refused");
    assert_eq!(error.code(), "EA-DB-HEAD-CONFLICT");

    database.cleanup().await;
}

/// Ein Fehlschlag MITTEN im Commit laesst nichts zurueck.
///
/// Der Auftrag traegt einen `.eip`-Objekthash, den bereits ein anderer Entry
/// fuehrt: der Objektindex ist dann schon geschrieben, und erst die
/// `entries`-Zeile bricht. Danach darf von diesem Auftrag NICHTS sichtbar sein
/// — weder die neuen Indexzeilen noch ein fortgeschriebener Kopf.
#[tokio::test]
async fn a_failed_commit_rolls_back_everything_it_had_written() {
    let database = common::fresh_database().await;
    let (organization, chain) = commit_fixture(database.pool()).await;
    let repository = PostgresRepository::new(database.pool().clone());

    repository
        .commit_locked_head(commit::Builder::new(organization, chain, 0).build())
        .await
        .unwrap();
    let before: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM object_index), (SELECT count(*) FROM entries), \
         (SELECT head_sequence FROM chain_heads)",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();

    // Sequenz eins, korrekter Vorgaenger — aber der `.eip`-Objekthash gehoert
    // schon dem Entry der Sequenz null.
    let mut colliding = commit::Builder::new(organization, chain, 1);
    colliding.entry_hash = commit::entry(0x14);
    colliding.previous = Some(commit::entry(0x10));
    colliding.receipt = commit::object(0x54);
    colliding.checkpoint = commit::object(0x55);
    colliding.previous_checkpoint = Some(commit::object(0x51));
    colliding.grants = vec![commit::object(0x45)];
    let error = repository
        .commit_locked_head(colliding.build())
        .await
        .expect_err("a duplicate .eip object hash must be refused");
    assert_eq!(error.code(), "EA-DB-COMMIT-IDENTITY-CONFLICT");

    let after: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM object_index), (SELECT count(*) FROM entries), \
         (SELECT head_sequence FROM chain_heads)",
    )
    .fetch_one(database.pool())
    .await
    .unwrap();
    assert_eq!(
        after, before,
        "the failed commit must leave no object index row, no entry and no advanced head"
    );

    database.cleanup().await;
}

/// Die Request-ID-Sperre aus §13.1: genau einmal.
#[tokio::test]
async fn a_request_id_is_accepted_exactly_once() {
    let database = common::fresh_database().await;
    let (organization, _chain) = commit_fixture(database.pool()).await;
    let repository = PostgresRepository::new(database.pool().clone());
    let request_id = [0x9a_u8; 16];

    repository
        .consume_request_id(
            organization,
            &request_id,
            UnixMillis::new(1_700_000_000_000),
            UnixMillis::new(1_700_000_300_000),
        )
        .await
        .expect("the first use must be accepted");
    let error = repository
        .consume_request_id(
            organization,
            &request_id,
            UnixMillis::new(1_700_000_000_001),
            UnixMillis::new(1_700_000_300_001),
        )
        .await
        .expect_err("the second use must be refused");
    assert_eq!(error.code(), "EA-DB-REQUEST-ID-REPLAY");

    database.cleanup().await;
}
