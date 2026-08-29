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

    let store_blob = |ciphertext: &'static [u8]| {
        let pool = database.pool().clone();
        async move {
            sqlx::query(
                "INSERT INTO reader_vault_blobs (subject_id, blob_hash, ciphertext, \
                 stored_at_millis) VALUES ($1, $2, $3, $4)",
            )
            .bind(&[0x66_u8; 16][..])
            .bind(&[0x88_u8; 32][..])
            .bind(ciphertext)
            .bind(1_700_000_000_000_i64)
            .execute(&pool)
            .await
        }
    };
    store_blob(b"opaque-a").await.unwrap();
    assert!(
        store_blob(b"opaque-b").await.is_err(),
        "a wrapped blob is keyed exclusively by subjectId and blob hash"
    );

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
    // Woertern und bewiese nichts. Die Migration legt einundzwanzig Tabellen
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

/// Alle einundzwanzig Tabellen der Stufe 3 sind da, und es ist bei EINER
/// Migration geblieben.
#[tokio::test]
async fn the_single_migration_creates_every_planned_table() {
    let database = common::fresh_database().await;

    let expected = [
        "chain_heads",
        "checkpoints",
        "clock_release_replays",
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
        vec![(1_i64,)],
        "Stage 3 delivers EXACTLY one migration; evolution against a delivered installation is \
         the subject of Stage 7"
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
         WHERE conrelid IN ('entries'::regclass, 'chain_heads'::regclass) \
         AND contype IN ('u', 'p') ORDER BY conname",
    )
    .fetch_all(database.pool())
    .await
    .expect("reading pg_constraint must succeed");
    let names: Vec<String> = rows.iter().map(|row| row.get("conname")).collect();
    assert_eq!(
        names,
        vec![
            "chain_heads_pkey",
            "entries_chain_id_sequence_number_key",
            "entries_entry_object_hash_key",
            "entries_pkey",
        ]
    );

    database.cleanup().await;
}
