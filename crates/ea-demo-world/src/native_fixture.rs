//! Der FIXTURE-HELFER zur Demowelt: das native JSON-Protokoll von
//! `ea-native-operator`, beantwortet mit den festen, öffentlich bekannten
//! Schlüsseln der gesäten Welt.
//!
//! Das ist KEINE native Sicherheitskette. Es gibt keinen Schlüsselbund, keinen
//! TPM, keine Anwesenheitsprüfung und keine Sperrbeobachtung: jede Signatur
//! entsteht aus einer Quelltextkonstante, jede Anwesenheit wird bestätigt,
//! ohne dass jemand gefragt wurde. Der Helfer existiert, damit die Oberfläche
//! gegen die Demowelt anklickbar ist — nicht, um irgendetwas zu schützen.
//!
//! # Woher die Zahlen kommen
//!
//! Ausschließlich aus [`crate::world`] und derselben Fixture-Kette, aus der
//! die Welt gesät wird. Jede Antwort, die eine Bindung der Registry treffen
//! muss — Konto, Instanzschlüssel, Signierschlüssel, Datenbankschlüssel —,
//! liest dieselbe Konstante oder dieselbe Ableitung wie die Saat. Die Form des
//! Protokolls folgt dem Fixture-Helfer der CLI-Tests
//! (`apps/cli/tests/operator.rs`, `native_cli_helper`), und wie dort meldet
//! `root-signing` immer `{"ok":false}`: eine Demowelt signiert keine Root.
//!
//! # Welche Station
//!
//! `NativeOperatorProvider` startet den Helfer mit `env_clear()` und ohne ein
//! einziges Argument. Der einzige Kanal, der übrig bleibt, ist der Ort der
//! Datei selbst: der Fixture-Wirt legt den Helfer IN das Stationsverzeichnis,
//! und der Helfer liest die Rolle aus der `operator.json` daneben.

use std::{
    fs,
    io::{BufRead, Read as _, Write},
    path::{Path, PathBuf},
};

use ea_crypto::{SecretBytes, SecretVec};
use ea_format::KeyProtectionProfileV1;
use ea_key_provider::{InMemoryKeyProvider, KeyProvider as _, SecretPurpose};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};

use crate::support::verify_support::archive_support::trust_support;
use crate::world::{
    DEMO_ADMIN_DATABASE_SEED, DEMO_ADMIN_INSTANCE_SECRET, DEMO_WRITER_DATABASE_SEED,
    DEMO_WRITER_INSTANCE_SECRET, demo_account_inputs,
};

/// Der Name, unter dem `NativeOperatorProvider` einen Helfer erwartet und
/// unter dem allein dieser Helfer antwortet.
pub const HELPER_FILE_NAME: &str = if cfg!(windows) {
    "ea-native-operator.exe"
} else {
    "ea-native-operator"
};

/// Das Verzeichnis neben dem Helfer, in dem er zwischen zwei Aufrufen den
/// versiegelten Entwurfsschlüssel ablegt. Jeder Aufruf ist ein eigener
/// Prozess; ohne diese Ablage gäbe es nach dem Speichern keinen Entwurf mehr.
pub const STATE_DIRECTORY: &str = "fixture-native-state";

/// Der feste Umschlagschlüssel des Entwurfsschlüssels. Derselbe Wert wie im
/// Fixture-Helfer der CLI-Tests; er behauptet keinen Schutz durch das
/// Betriebssystem.
const DRAFT_WRAPPING_KEY: [u8; 32] = [0x93; 32];
const DRAFT_WRAPPING_AAD: &[u8] = b"native-draft-fixture-v1";

/// Welche der zwei gesäten Stationen dieser Helfer bedient.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixtureStation {
    Writer,
    Admin,
}

impl FixtureStation {
    /// Liest die Rolle aus `<verzeichnis>/operator.json`, wie die Saat sie
    /// schreibt. Jede andere Rolle ist keine Station der Demowelt.
    ///
    /// # Errors
    ///
    /// Wenn die Datei fehlt, kein JSON ist oder eine andere Rolle trägt.
    pub fn from_station_directory(directory: &Path) -> Result<Self, String> {
        let path = directory.join("operator.json");
        let bytes = fs::read(&path)
            .map_err(|error| format!("{} ist nicht lesbar: {error}", path.display()))?;
        let config: Value = serde_json::from_slice(&bytes)
            .map_err(|_| format!("{} ist kein JSON", path.display()))?;
        match config.get("role").and_then(Value::as_str) {
            Some("writer") => Ok(Self::Writer),
            Some("organization-admin") => Ok(Self::Admin),
            other => Err(format!(
                "{} trägt die Rolle {other:?}; die Demowelt kennt nur writer und \
                 organization-admin",
                path.display()
            )),
        }
    }

    fn admin(self) -> bool {
        self == Self::Admin
    }

    /// Die Installationskennung dieses Helfers. Sie bleibt über jeden
    /// Einzelaufruf und über den Beobachterprozess gleich.
    #[must_use]
    pub fn installation_id(self) -> String {
        match self {
            Self::Writer => "c1",
            Self::Admin => "c2",
        }
        .repeat(32)
    }

    /// Die `account`-Antwort: das feste Fixture-Konto aus
    /// [`demo_account_inputs`], Feld für Feld in der Form, die
    /// `NativeOperatorProvider::account` liest.
    #[must_use]
    pub fn account_response(self) -> Value {
        match demo_account_inputs(self.admin()) {
            ea_operator::OsAccountInputs::MacOs {
                guid_values,
                unique_id_values,
                actual_uid,
            } => json!({
                "platform": "macos",
                "guid_values": guid_values,
                "unique_id_values": unique_id_values,
                "uid": actual_uid,
                "locked": false,
            }),
            ea_operator::OsAccountInputs::Windows {
                sid,
                identifier_authority,
                subauthorities,
            } => json!({
                "platform": "windows",
                "sid": hex::encode(sid),
                "identifier_authority": hex::encode(identifier_authority),
                "subauthorities": subauthorities,
                "locked": false,
            }),
            ea_operator::OsAccountInputs::Linux {
                machine_id_file,
                uid,
            } => json!({
                "platform": "linux",
                "machine_id_bytes": hex::encode(machine_id_file),
                "uid": uid,
                "locked": false,
            }),
        }
    }

    /// Der Ed25519-Schlüssel eines Signierplatzes, oder `None`, wenn diese
    /// Station den Platz nicht führt. `root-signing` führt keine Station.
    fn signing_secret(self, slot: &str) -> Option<[u8; 32]> {
        match (self, slot) {
            (Self::Writer, "operator-instance") => Some(DEMO_WRITER_INSTANCE_SECRET),
            (Self::Admin, "operator-instance") => Some(DEMO_ADMIN_INSTANCE_SECRET),
            // Das Writer-Gerätezertifikat der Saat entsteht mit dem
            // Vorgabeschlüssel der Fixture-Kette.
            (Self::Writer, "writer-signing") => Some(trust_support::device_signing_secret()),
            // Die Adminstation führt das Zertifikat des ZWEITEN Bootstrap-
            // Admins (`second_bootstrap_admin_hash` in `world.rs`).
            (Self::Admin, "admin-signing") => Some(trust_support::second_admin_signing_secret()),
            _ => None,
        }
    }

    fn database_seed(self) -> [u8; 32] {
        match self {
            Self::Writer => DEMO_WRITER_DATABASE_SEED,
            Self::Admin => DEMO_ADMIN_DATABASE_SEED,
        }
    }
}

/// Beantwortet genau eine Einzelanfrage (alles außer `watch-session`).
///
/// Die Antwort trägt immer `installation_id`; `ok` ist `true`, wenn die
/// Anfrage nicht ausdrücklich abgelehnt wird.
///
/// # Errors
///
/// Wenn die versiegelte Entwurfsablage unter `state` nicht les- oder
/// schreibbar ist.
pub fn respond(station: FixtureStation, state: &Path, request: &Value) -> Result<Value, String> {
    let op = request.get("op").and_then(Value::as_str).unwrap_or("");
    let slot = request.get("slot").and_then(Value::as_str).unwrap_or("");
    let writer = station == FixtureStation::Writer;
    let mut response = match (op, slot) {
        ("account", _) => station.account_response(),
        ("public-key", _) => match station.signing_secret(slot) {
            Some(secret) => json!({
                "public_key": hex::encode(SigningKey::from_bytes(&secret).verifying_key().to_bytes()),
            }),
            None => json!({"ok": false}),
        },
        ("sign", _) => match (
            station.signing_secret(slot),
            request
                .get("data")
                .and_then(Value::as_str)
                .and_then(|data| hex::decode(data).ok()),
        ) {
            (Some(secret), Some(data)) => json!({
                "signature": hex::encode(SigningKey::from_bytes(&secret).sign(&data).to_bytes()),
            }),
            _ => json!({"ok": false}),
        },
        ("unwrap-secret", "database-key") => database_key(station)?,
        ("contains", "draft-key") if writer => {
            json!({"contains": sealed_draft_path(state).exists()})
        }
        ("contains", _) => json!({"contains": true}),
        ("wrap-secret", "draft-key") if writer => wrap_draft_key(state, request)?,
        ("unwrap-secret", "draft-key") if writer => unwrap_draft_key(state)?,
        ("delete", "draft-key") if writer => {
            let sealed = sealed_draft_path(state);
            if sealed.exists() {
                fs::remove_file(&sealed).map_err(|error| {
                    format!("{} ließ sich nicht löschen: {error}", sealed.display())
                })?;
            }
            json!({})
        }
        // `initialize`, `generate`, `root-signing`, `private-console-line`,
        // `backup-signing-seed` und alles Unbekannte: abgelehnt. Eine gesäte
        // Welt wird nicht neu bereitgestellt.
        _ => json!({"ok": false}),
    };
    if response.get("ok").is_none() {
        response["ok"] = json!(true);
    }
    response["installation_id"] = json!(station.installation_id());
    Ok(response)
}

fn database_key(station: FixtureStation) -> Result<Value, String> {
    // Dieselbe Ableitung wie `write_station_database` in `world.rs`.
    let provider = InMemoryKeyProvider::new_for_test(station.database_seed());
    let key = provider
        .generate(
            SecretPurpose::LocalDatabaseKey,
            KeyProtectionProfileV1::OsWrapped,
        )
        .map_err(|error| format!("Datenbankschlüssel: {}", error.code()))?;
    let secret = provider
        .unwrap_database_key(&key)
        .map_err(|error| format!("Datenbankschlüssel: {}", error.code()))?;
    Ok(secret.with_exposed(|bytes| json!({"secret": hex::encode(bytes)})))
}

fn sealed_draft_path(state: &Path) -> PathBuf {
    state.join("draft-key.sealed")
}

fn wrap_draft_key(state: &Path, request: &Value) -> Result<Value, String> {
    let Some(secret) = request
        .get("data")
        .and_then(Value::as_str)
        .and_then(|data| hex::decode(data).ok())
        .filter(|secret| secret.len() == 32)
    else {
        return Ok(json!({"ok": false}));
    };
    fs::create_dir_all(state)
        .map_err(|error| format!("{} ließ sich nicht anlegen: {error}", state.display()))?;
    // Ein Zähler statt Zufall: jeder Umschlag bekommt eine eigene Nonce, und
    // der Helfer braucht dafür keine zweite Quelle.
    let counter_path = state.join("draft-key.counter");
    let counter = fs::read_to_string(&counter_path)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(0)
        + 1;
    fs::write(&counter_path, counter.to_string())
        .map_err(|error| format!("{} ist nicht schreibbar: {error}", counter_path.display()))?;
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    let ciphertext = ea_crypto::aead_seal(
        &SecretBytes::new(DRAFT_WRAPPING_KEY),
        &SecretBytes::new(nonce),
        SecretVec::new(secret),
        DRAFT_WRAPPING_AAD,
    )
    .map_err(|_| "der Entwurfsschlüssel ließ sich nicht versiegeln".to_owned())?;
    let mut sealed = nonce.to_vec();
    sealed.extend(ciphertext);
    let path = sealed_draft_path(state);
    fs::write(&path, sealed)
        .map_err(|error| format!("{} ist nicht schreibbar: {error}", path.display()))?;
    Ok(json!({}))
}

fn unwrap_draft_key(state: &Path) -> Result<Value, String> {
    let Ok(sealed) = fs::read(sealed_draft_path(state)) else {
        return Ok(json!({"ok": false}));
    };
    if sealed.len() < 12 {
        return Ok(json!({"ok": false}));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sealed[..12]);
    match ea_crypto::aead_open(
        &SecretBytes::new(DRAFT_WRAPPING_KEY),
        &SecretBytes::new(nonce),
        &sealed[12..],
        DRAFT_WRAPPING_AAD,
    ) {
        Ok(secret) => Ok(secret.with_exposed(|bytes| json!({"secret": hex::encode(bytes)}))),
        Err(_) => Ok(json!({"ok": false})),
    }
}

/// Ein Rahmen des Protokolls: kompaktes JSON, Zeilenende, sofort geleert.
fn emit(output: &mut impl Write, value: &Value) -> Result<(), String> {
    let mut frame = serde_json::to_vec(value).map_err(|_| "Antwort nicht kodierbar".to_owned())?;
    frame.push(b'\n');
    output
        .write_all(&frame)
        .and_then(|()| output.flush())
        .map_err(|error| format!("Antwort nicht schreibbar: {error}"))
}

/// Liest eine Zeile von höchstens 1024 Bytes. `None` heißt: Eingabe zu Ende
/// oder unlesbar — der Beobachter endet dann.
fn read_bounded_line(input: &mut impl BufRead) -> Option<String> {
    let mut bytes = Vec::new();
    let read = input
        .by_ref()
        .take(1025)
        .read_until(b'\n', &mut bytes)
        .ok()?;
    if read == 0 || bytes.len() > 1024 {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// Führt einen Helferaufruf vollständig aus: liest die Anfrage, beantwortet
/// sie und — für `watch-session` — bedient danach Challenge um Challenge, bis
/// der Wirt die Eingabe schließt.
///
/// Anders als der Testhelfer endet der Beobachter NICHT nach einer festen
/// Frist: dies ist eine Anwendung, die jemand bedient. Die Lebensdauer der
/// Sitzung begrenzt weiter der Wirt selbst (`SessionWatch`, 300 s ohne
/// verifizierte Anwesenheit).
///
/// # Errors
///
/// Wenn die Anfrage kein JSON ist, die Antwort nicht geschrieben werden kann
/// oder die Entwurfsablage scheitert.
pub fn serve(
    station: FixtureStation,
    station_directory: &Path,
    mut input: impl BufRead,
    mut output: impl Write,
) -> Result<(), String> {
    let first = read_bounded_line(&mut input).ok_or("keine Anfrage auf stdin")?;
    let request: Value =
        serde_json::from_str(first.trim_end()).map_err(|_| "die Anfrage ist kein JSON")?;
    let installation = station.installation_id();
    if request.get("op").and_then(Value::as_str) != Some("watch-session") {
        let response = respond(station, &station_directory.join(STATE_DIRECTORY), &request)?;
        return emit(&mut output, &response);
    }
    if request.get("installation_id").and_then(Value::as_str) != Some(installation.as_str()) {
        return emit(&mut output, &json!({"ok": false}));
    }
    emit(
        &mut output,
        &json!({"ok": true, "installation_id": installation, "ready": true}),
    )?;
    while let Some(line) = read_bounded_line(&mut input) {
        let Some(challenge) = line
            .strip_prefix("{\"challenge\":\"")
            .and_then(|rest| rest.strip_suffix("\"}\n"))
        else {
            return Ok(());
        };
        if challenge.len() != 64
            || !challenge
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Ok(());
        }
        emit(
            &mut output,
            &json!({"ok": true, "installation_id": installation, "challenge": challenge}),
        )?;
    }
    Ok(())
}

/// Der ganze Helferprozess: prüft den eigenen Dateinamen, findet die Station
/// neben sich und bedient stdin/stdout.
///
/// Der Helfer antwortet NUR unter dem Namen [`HELPER_FILE_NAME`] und nur in
/// einem Verzeichnis, das eine Station der Demowelt ist. Unter seinem
/// Baunamen gestartet, verweigert er — er ist dann nicht an seinem Platz.
///
/// # Errors
///
/// Mit einer lesbaren Begründung, die der Aufrufer auf stderr schreibt.
pub fn run_helper_process() -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("der eigene Pfad ist nicht bestimmbar: {error}"))?;
    let name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if !name.eq_ignore_ascii_case(HELPER_FILE_NAME) {
        return Err(format!(
            "FIXTURE-Helfer: antwortet nur als {HELPER_FILE_NAME} in einem \
             Stationsverzeichnis der Demowelt, nicht als {name}. Der Fixture-Wirt \
             ea-desktop-fixture legt ihn dort selbst ab."
        ));
    }
    let directory = executable
        .parent()
        .ok_or("der Helfer liegt in keinem Verzeichnis")?;
    let station = FixtureStation::from_station_directory(directory)?;
    let stdin = std::io::stdin();
    serve(station, directory, stdin.lock(), std::io::stdout().lock())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn station_directory(tag: &str, role: &str) -> crate::support::TempDir {
        let directory = crate::support::temp_dir(tag);
        fs::write(
            directory.path().join("operator.json"),
            serde_json::to_vec(&json!({"role": role})).unwrap(),
        )
        .unwrap();
        directory
    }

    #[test]
    fn the_station_is_read_from_the_neighbouring_operator_config() {
        let writer = station_directory("native-fixture-writer", "writer");
        let admin = station_directory("native-fixture-admin", "organization-admin");
        let reader = station_directory("native-fixture-reader", "reader");
        assert_eq!(
            FixtureStation::from_station_directory(writer.path()),
            Ok(FixtureStation::Writer)
        );
        assert_eq!(
            FixtureStation::from_station_directory(admin.path()),
            Ok(FixtureStation::Admin)
        );
        assert!(FixtureStation::from_station_directory(reader.path()).is_err());
    }

    #[test]
    fn root_signing_and_provisioning_are_always_refused() {
        let state = crate::support::temp_dir("native-fixture-refusal");
        for station in [FixtureStation::Writer, FixtureStation::Admin] {
            for request in [
                json!({"op": "public-key", "slot": "root-signing"}),
                json!({"op": "sign", "slot": "root-signing", "data": "00"}),
                json!({"op": "initialize"}),
                json!({"op": "generate", "slot": "operator-instance"}),
            ] {
                let response = respond(station, state.path(), &request).unwrap();
                assert_eq!(response["ok"], json!(false), "{station:?} {request}");
            }
        }
        // Der Writer führt keinen Adminplatz, die Adminstation keinen Writerplatz.
        let admin_slot = json!({"op": "public-key", "slot": "admin-signing"});
        let writer_slot = json!({"op": "public-key", "slot": "writer-signing"});
        assert_eq!(
            respond(FixtureStation::Writer, state.path(), &admin_slot).unwrap()["ok"],
            json!(false)
        );
        assert_eq!(
            respond(FixtureStation::Admin, state.path(), &writer_slot).unwrap()["ok"],
            json!(false)
        );
    }

    #[test]
    fn the_watcher_answers_readiness_and_every_fresh_challenge_until_eof() {
        let directory = station_directory("native-fixture-watch", "writer");
        let id = FixtureStation::Writer.installation_id();
        let challenge = "ab".repeat(32);
        let input = format!(
            "{}\n{{\"challenge\":\"{challenge}\"}}\n{{\"challenge\":\"{challenge}\"}}\n",
            json!({"op": "watch-session", "installation_id": id})
        );
        let mut output = Vec::new();
        serve(
            FixtureStation::Writer,
            directory.path(),
            input.as_bytes(),
            &mut output,
        )
        .unwrap();
        let lines: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            lines,
            vec![
                json!({"ok": true, "installation_id": id, "ready": true}),
                json!({"ok": true, "installation_id": id, "challenge": challenge}),
                json!({"ok": true, "installation_id": id, "challenge": challenge}),
            ]
        );
    }

    #[test]
    fn a_wrapped_draft_key_survives_between_two_helper_processes() {
        let state = crate::support::temp_dir("native-fixture-draft");
        let secret = hex::encode([0x5a; 32]);
        let station = FixtureStation::Writer;
        let contains = json!({"op": "contains", "slot": "draft-key"});
        assert_eq!(
            respond(station, state.path(), &contains).unwrap()["contains"],
            json!(false)
        );
        let wrapped = respond(
            station,
            state.path(),
            &json!({"op": "wrap-secret", "slot": "draft-key", "data": secret}),
        )
        .unwrap();
        assert_eq!(wrapped["ok"], json!(true));
        let unwrapped = respond(
            station,
            state.path(),
            &json!({"op": "unwrap-secret", "slot": "draft-key"}),
        )
        .unwrap();
        assert_eq!(unwrapped["secret"], json!(secret));
        respond(
            station,
            state.path(),
            &json!({"op": "delete", "slot": "draft-key"}),
        )
        .unwrap();
        assert_eq!(
            respond(station, state.path(), &contains).unwrap()["contains"],
            json!(false)
        );
    }
}
