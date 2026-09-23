//! Der native Gegenpart des Browserzeugen `apps/web/tests/e2e/reader-key-escrow.spec.ts`
//! (Scheibe e, DRK-460).
//!
//! Der Browser erzeugt und importiert DATEIEN (Ruling U3); dieser Peer stellt
//! die Gegenseite aus den echten Bausteinen: die Registry-Linie der
//! Escrow-Zeugen (`crates/ea-trust/tests/escrow_support`), die Prüfung des
//! Registrierungsantrags aus der Admin-Inbox (`ea_admin`), den Trust-Kern und
//! den ECHTEN Öffnungsdienst `ea_recovery::ReaderKeyEscrowOpeningService`
//! (Scheibe c, C5). Er ist ein Testwerkzeug und kein Produktpfad: Freigabe,
//! Wurzel- und Approver-Signaturen kommen aus den Testkit-Bauern.
//!
//! Unterbefehle (Ausgabe JSON auf stdout, Fehler auf stderr mit Exit 1):
//!
//! - `anchor` — Anker, Organisation und Subject der Linie als Hex.
//! - `certify <antrag> <trustdir>` — prüft den Antrag wie die Admin-Inbox und
//!   aktiviert ein Reader-Zertifikat aus SEINEN Schlüsseln; schreibt alle
//!   Trust-Objekte nach `<trustdir>`.
//! - `certify-foreign <antrag> <trustdir>` — dasselbe mit fremdem KEM.
//! - `check-package <paket> <antrag>` — öffnet das Paket mit dem
//!   Recovery-Geheimnis, verlangt den KEM des Antrags und führt Freigabe,
//!   Intent, Wurzelsignatur und `verify_reader_key_escrows` durch.
//! - `line-with-escrow <trustdir> <statedir>` — eine Linie mit
//!   veröffentlichtem Escrow eines bekannten KEM.
//! - `open <transport> <statedir> <umschlag>` — zwei Approver autorisieren,
//!   der Öffnungsdienst versiegelt an den Transport-Schlüssel.
//! - `open-foreign <statedir> <umschlag>` — ein Umschlag an einen ANDEREN
//!   Transport-Schlüssel.
#[path = "../../../crates/ea-trust/tests/escrow_support/mod.rs"]
mod escrow_support;
#[path = "../../../crates/ea-verify/src/state.rs"]
#[allow(dead_code)]
mod state;
#[path = "../../../crates/ea-trust/tests/support/mod.rs"]
mod support;

use std::{env, fs, path::Path, process::ExitCode};

use ea_crypto::{
    CanonicalPublicCoseKey, HpkeRecipientPrivateKey, HpkeSealed, SecretBytes, hpke_aad, hpke_info,
    hpke_open, object_hash,
};
use ea_format::{
    DecodedTrustPayloadV1, ReaderKeyEscrowHpkeContextV1, ReaderKeyEscrowTransportRequestV1,
    TrustPayloadV1, decode_reader_key_escrow_package, decode_reader_key_escrow_transport_request,
    encode_reader_key_escrow_envelope,
};
use ea_recovery::{
    ConsumptionReceipt, EscrowOpeningLedger, ReaderKeyEscrowError, ReaderKeyEscrowOpeningService,
};
use ea_testkit::reader_key_escrow_fixture::signed_reader_key_escrow;
use ea_trust::{
    AuthorizedEscrowTransportKey, ReaderKeyEscrowHead, TrustObjectSource,
    VerifiedReaderKeyEscrowRecoveryAuthorization, verify_intended_reader_key_escrow,
    verify_reader_key_escrow_approval, verify_reader_key_escrow_recovery_authorization,
    verify_reader_key_escrows, verify_signed_reader_key_escrow,
};
use ea_types::{SubjectId, UnixMillis};
use escrow_support::{
    Basis, EscrowLine, EscrowLineOptions, READER_KEM_SEED, RECOVERY_KEM_SEED, approval_core,
    escrow_core, escrow_line, millis, recovery_core, root, select, signed_approval,
    signed_recovery, subject, tip_sequence, x25519_key, x25519_public,
};
use support::{ActionSpec, HeadOptions};

type PeerResult = Result<String, String>;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["anchor"] => anchor(),
        ["certify", request, trust] => certify(request, trust, false),
        ["certify-foreign", request, trust] => certify(request, trust, true),
        ["check-package", package, request] => check_package(package, request),
        ["line-with-escrow", trust, state] => line_with_escrow(trust, state),
        ["open", transport, state, out] => open(transport, state, out),
        ["open-foreign", state, out] => open_foreign(state, out),
        _ => Err(format!("unbekannter Aufruf: {args:?}")),
    };
    match result {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn reader_subject() -> SubjectId {
    subject(0xc1)
}

fn failed(what: &str) -> impl Fn(ea_trust::TrustError) -> String + '_ {
    move |error| format!("{what}: {}", error.code())
}

/// Alle Trust-Objekte der Linie als `<objecthash>.etb` — der Inhalt eines
/// Datei-Modus-Ordners.
fn write_trust(escrow: &EscrowLine, directory: &str) -> Result<usize, String> {
    fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    let source = escrow.line.source();
    let mut hashes = Vec::new();
    source
        .visit_trust_object_hashes(&mut |hash| {
            hashes.push(hash);
            Ok(())
        })
        .map_err(|_| "Trust-Quelle".to_owned())?;
    for hash in &hashes {
        let bytes = source
            .read_exact_trust_object(*hash)
            .map_err(|_| "Trust-Objekt".to_owned())?
            .ok_or("Trust-Objekt fehlt")?;
        fs::write(
            Path::new(directory).join(format!("{}.etb", hex::encode(hash.as_bytes()))),
            &bytes,
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(hashes.len())
}

fn anchor() -> PeerResult {
    let escrow = escrow_line(EscrowLineOptions::default());
    Ok(serde_json::json!({
        "organizationId": hex::encode(support::organization().as_bytes()),
        "subjectId": hex::encode(reader_subject().as_bytes()),
        "pinnedAnchor": hex::encode(escrow.line.exact_anchor_bytes()),
    })
    .to_string())
}

/// Der Antrag, geprüft wie in der Admin-Inbox — der Querzeuge zu E0.
fn verified_request(
    path: &str,
) -> Result<(CanonicalPublicCoseKey, CanonicalPublicCoseKey), String> {
    let exact = fs::read(path).map_err(|error| error.to_string())?;
    let verified = ea_admin::administration_runtime::inbox::verify_registration(
        &exact,
        support::organization(),
    )
    .map_err(|_| "der Registrierungsantrag besteht die Inbox-Prüfung nicht".to_owned())?;
    let core = verified.core();
    if core.requested_role != 1 {
        return Err("der Antrag verlangt keine Reader-Rolle".to_owned());
    }
    let kem = core
        .kem_public_cose_key
        .clone()
        .ok_or("der Antrag trägt keinen KEM")?;
    Ok((core.signing_public_cose_key.clone(), kem))
}

/// Die Linie der Escrow-Zeugen plus ein Reader-Zertifikat aus den
/// Antragsschlüsseln. Deterministisch: derselbe Antrag ergibt dieselben Bytes.
fn certified_line(signing: CanonicalPublicCoseKey, kem: CanonicalPublicCoseKey) -> EscrowLine {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    escrow.line.push(
        ActionSpec::Device {
            kind: ea_format::CertificateKindV1::Reader,
            marker: 0x83,
            effective_from: None,
        },
        HeadOptions {
            signing_public_key_override: Some(signing),
            kem_public_key_override: Some(kem),
            ..HeadOptions::default()
        },
    );
    escrow
}

fn certify(request: &str, trust: &str, foreign: bool) -> PeerResult {
    let (signing, kem) = verified_request(request)?;
    let kem = if foreign { x25519_key([0x0d; 32]) } else { kem };
    let fingerprint = kem.thumbprint();
    let escrow = certified_line(signing, kem);
    let files = write_trust(&escrow, trust)?;
    Ok(serde_json::json!({
        "files": files,
        "readerKemFingerprint": hex::encode(fingerprint.as_bytes()),
    })
    .to_string())
}

fn check_package(package: &str, request: &str) -> PeerResult {
    let (signing, kem) = verified_request(request)?;
    let mut escrow = certified_line(signing, kem.clone());
    let exact = fs::read(package).map_err(|error| error.to_string())?;
    let decoded = decode_reader_key_escrow_package(&exact)
        .map_err(|error| format!("Paket: {}", error.code()))?;
    let core = decoded.core().clone();

    // Das Chiffrat öffnet mit dem Recovery-Geheimnis zum KEM DES ANTRAGS.
    let context = ReaderKeyEscrowHpkeContextV1::from_escrow_core(&core).encode();
    let secret = hpke_open(
        &HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(RECOVERY_KEM_SEED))
            .map_err(|error| error.code().to_owned())?,
        &HpkeSealed::from_parts(core.encapsulated_key, core.encrypted_reader_kem_key)
            .map_err(|error| error.code().to_owned())?,
        &hpke_info(&context),
        &hpke_aad(&context),
    )
    .map_err(|error| format!("Öffnen: {}", error.code()))?;
    let derived = secret
        .with_exposed(|bytes| HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(*bytes)))
        .map_err(|error| error.code().to_owned())?
        .public_key();
    if CanonicalPublicCoseKey::x25519(*derived.as_bytes()).ok() != Some(kem) {
        return Err("der versiegelte KEM ist nicht der des Antrags".to_owned());
    }

    // Freigabe, Intent, Wurzelsignatur — die native Kette über GENAU diesen Core.
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let issued = core.issued_at.get() as u64;
    let mut fields = approval_core(
        &escrow.line,
        Basis::of_selected(&head),
        (issued - 1_000, issued + 1_000),
        0xe8,
    );
    fields.escrow_core_hash = ea_crypto::reader_key_escrow_core_hash(decoded.exact_core());
    fields.reader_certificate_object_hash = core.reader_certificate_object_hash;
    fields.reader_subject_id = core.reader_subject_id;
    let approval_bytes = signed_approval(&escrow.line, &fields);
    let approval =
        verify_reader_key_escrow_approval(&trust, &head, &approval_bytes, core.issued_at)
            .map_err(failed("Freigabe"))?;
    let payload = TrustPayloadV1::reader_key_escrow(core.clone(), approval.object_hash())
        .map_err(|error| error.code().to_owned())?;
    let DecodedTrustPayloadV1::ReaderKeyEscrow(intended) = payload
        .decoded_payload()
        .map_err(|error| error.code().to_owned())?
    else {
        return Err("keine Escrow-Nutzlast".to_owned());
    };
    let intent = verify_intended_reader_key_escrow(&trust, &head, &approval, &intended)
        .map_err(failed("Intent"))?;
    let escrow_bytes = signed_reader_key_escrow(&core, approval.object_hash(), &root(&escrow.line));
    verify_signed_reader_key_escrow(&intent, &escrow_bytes).map_err(failed("Wurzel"))?;
    escrow.line.add_object(approval_bytes);
    escrow.line.add_object(escrow_bytes.clone());
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let set = verify_reader_key_escrows(&trust, ReaderKeyEscrowHead::Selected(&head))
        .map_err(failed("Bestand"))?;
    let valid = set
        .valid_for_reader_certificate(core.reader_certificate_object_hash)
        .is_some_and(|verified| verified.object_hash() == object_hash(&escrow_bytes));
    if !valid {
        return Err("das veröffentlichte Escrow ist nicht gültig".to_owned());
    }
    Ok(serde_json::json!({
        "ok": true,
        "escrowCoreHash": hex::encode(fields.escrow_core_hash.as_bytes()),
    })
    .to_string())
}

const APPROVAL_FILE: &str = "escrow-approval.bin";
const ESCROW_FILE: &str = "escrow.bin";

fn line_with_escrow(trust: &str, state: &str) -> PeerResult {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    let core = escrow_core(
        &escrow,
        &escrow.reader,
        READER_KEM_SEED,
        reader_subject(),
        1_200,
    );
    let tip = *escrow.line.heads().last().ok_or("keine Köpfe")?;
    let approval = approval_core(
        &escrow.line,
        Basis::of(&tip, tip.effective_from.get()),
        (1_000, 1_300),
        0xe4,
    );
    // Die Kapselung im Core ist zufällig: die EXAKTEN Bytes werden
    // festgehalten, damit `open` dasselbe Escrow sieht wie der Browser.
    let (approval_bytes, escrow_bytes) = escrow_support::escrow_bytes(&escrow, &core, &approval);
    escrow.line.add_object(approval_bytes.clone());
    escrow.line.add_object(escrow_bytes.clone());
    fs::create_dir_all(state).map_err(|error| error.to_string())?;
    fs::write(Path::new(state).join(APPROVAL_FILE), &approval_bytes)
        .map_err(|error| error.to_string())?;
    fs::write(Path::new(state).join(ESCROW_FILE), &escrow_bytes)
        .map_err(|error| error.to_string())?;
    write_trust(&escrow, trust)?;
    Ok(serde_json::json!({
        "organizationId": hex::encode(support::organization().as_bytes()),
        "subjectId": hex::encode(reader_subject().as_bytes()),
        "pinnedAnchor": hex::encode(escrow.line.exact_anchor_bytes()),
        "expectedKemFingerprint": hex::encode(x25519_key(READER_KEM_SEED).thumbprint().as_bytes()),
        "escrowObjectHash": hex::encode(object_hash(&escrow_bytes).as_bytes()),
    })
    .to_string())
}

/// Die Linie mit dem festgehaltenen Escrow.
fn reloaded(state: &str) -> Result<EscrowLine, String> {
    let mut escrow = escrow_line(EscrowLineOptions::default());
    for file in [APPROVAL_FILE, ESCROW_FILE] {
        escrow
            .line
            .add_object(fs::read(Path::new(state).join(file)).map_err(|error| error.to_string())?);
    }
    Ok(escrow)
}

/// Der Ledger des Peers: verbraucht im Speicher. Das dauerhafte SQLCipher-
/// Ledger ist Sache der nativen Administration (Scheibe c).
struct MemoryLedger;

impl EscrowOpeningLedger for MemoryLedger {
    fn consume(
        &self,
        authorization: &VerifiedReaderKeyEscrowRecoveryAuthorization,
        transport: &AuthorizedEscrowTransportKey,
    ) -> Result<ConsumptionReceipt, ReaderKeyEscrowError> {
        Ok(ConsumptionReceipt::new(
            authorization,
            transport,
            UnixMillis::new(1_100),
        ))
    }

    fn store_result(
        &self,
        _receipt: &ConsumptionReceipt,
        _envelope: &ea_format::ReaderKeyEscrowEnvelopeV1,
    ) -> Result<(), ReaderKeyEscrowError> {
        Ok(())
    }

    fn book_failure(&self, _receipt: &ConsumptionReceipt) {}
}

fn open_for(
    escrow: &EscrowLine,
    request: &ReaderKeyEscrowTransportRequestV1,
    out: &str,
) -> PeerResult {
    let (trust, head) = select(&escrow.line, tip_sequence(&escrow.line));
    let set = verify_reader_key_escrows(&trust, ReaderKeyEscrowHead::Selected(&head))
        .map_err(failed("Bestand"))?;
    let verified = set
        .get(request.escrow_object_hash)
        .ok_or("das Escrow der Transportanfrage fehlt")?;
    let mut core = recovery_core(
        request.escrow_object_hash,
        verified.core(),
        Basis::of_selected(&head),
        (1_000, 1_300),
        0xe9,
    );
    core.target_transport_key_thumbprint =
        CanonicalPublicCoseKey::x25519(request.target_transport_public_key)
            .map_err(|error| error.code().to_owned())?
            .thumbprint();
    let bytes = signed_recovery(&core, &escrow.approvers);
    let authorization =
        verify_reader_key_escrow_recovery_authorization(&trust, &head, &bytes, millis(1_100))
            .map_err(failed("Autorisierung"))?;
    let transport = authorization
        .require_target_transport_key(request.target_transport_public_key)
        .map_err(failed("Transport"))?;
    let kem = HpkeRecipientPrivateKey::from_bytes(SecretBytes::new(RECOVERY_KEM_SEED))
        .map_err(|error| error.code().to_owned())?;
    let session = || Ok(());
    let envelope = ReaderKeyEscrowOpeningService::new(&kem, &MemoryLedger, &session)
        .open(&authorization, &transport)
        .map_err(|error| format!("Öffnung: {}", error.code()))?;
    let exact =
        encode_reader_key_escrow_envelope(&envelope).map_err(|error| error.code().to_owned())?;
    fs::write(out, &exact).map_err(|error| error.to_string())?;
    Ok(serde_json::json!({
        "authorizationObjectHash": hex::encode(authorization.object_hash().as_bytes()),
    })
    .to_string())
}

fn open(transport: &str, state: &str, out: &str) -> PeerResult {
    let escrow = reloaded(state)?;
    let exact = fs::read(transport).map_err(|error| error.to_string())?;
    let request = decode_reader_key_escrow_transport_request(&exact)
        .map_err(|error| format!("Transportanfrage: {}", error.code()))?;
    open_for(&escrow, &request, out)
}

fn open_foreign(state: &str, out: &str) -> PeerResult {
    let escrow = reloaded(state)?;
    let escrow_bytes =
        fs::read(Path::new(state).join(ESCROW_FILE)).map_err(|error| error.to_string())?;
    let request = ReaderKeyEscrowTransportRequestV1 {
        organization_id: support::organization(),
        escrow_object_hash: object_hash(&escrow_bytes),
        target_transport_public_key: x25519_public([0x0e; 32]),
    };
    open_for(&escrow, &request, out)
}
