//! Actual configured Desktop „Vernichtung fortsetzen" in state4 (Ruling G2,
//! DRK-319 S2) over TLS/PG/S3: one `destruction_resume_core` call re-contacts
//! the restarted registered server (which executes only now), chains the native
//! 4→1 retry and continues to 1→3. The Reader confirmation is a certified
//! synthetic original imported before state4 (no actual OPFS here).
use super::super::retry::{
    assert_server_completed_once, incomplete_with_unexecuted_server, local_counts, server_count,
    server_transitions,
};
use super::*;

fn view(
    value: Result<
        ea_desktop::commands::destruction::DestructionAdministrationWire,
        ea_desktop::commands::CommandError,
    >,
) -> serde_json::Value {
    serde_json::to_value(value.unwrap()).unwrap()
}

#[test]
fn native_desktop_resume_in_state4_chains_the_retry_and_completes_against_the_restarted_server() {
    let began = std::time::Instant::now();
    let f = NativeDestructionFixture::with_reader_opfs();
    let mut o = incomplete_with_unexecuted_server(&f, true);
    let id = hex(o.id.as_bytes());
    let job = hex(o.job.as_bytes());

    // A host without any server transport never idles silently in state4 and
    // appends nothing for this server-bound job.
    let before = local_counts(&f);
    let local = super::super::super::super::desktop::desktop(&f);
    local.login().unwrap();
    let state = local.desktop_state();
    let failed = view(destruction_read_core(&state, Some(&id)));
    assert_eq!(failed["process"]["state"], "incompleteUnreachableReplica");
    let refused = destruction_resume_core(&state, &id)
        .err()
        .expect("no silent no-op in state4 without a server transport");
    eprintln!("desktop retry: NoServer host refusal {}", refused.code);
    assert_eq!(refused.code, "EA-DESTRUCTION-TARGET");
    assert_eq!(local_counts(&f), before);
    assert_eq!(
        view(destruction_read_core(&state, Some(&id)))["process"],
        failed["process"]
    );
    drop(state);
    drop(local);

    // Same registered server at the identical address, database and bucket.
    o.server.restart_listener(&o.services);
    assert_eq!(server_count(&o.services, &o.server, "destruction_jobs"), 0);
    let host = configured_host(&f, &o.server);
    let state = host.desktop_state();
    let done = view(destruction_resume_core(&state, &id));
    eprintln!("desktop retry: one Resume call {:?}", began.elapsed());
    assert_eq!(done["process"]["state"], "completeManagedScope");
    assert_eq!(done["process"]["destructionId"], id);
    assert_eq!(done["process"]["preflight"]["jobHash"], job);
    assert_eq!(
        done["process"]["replicas"].as_array().unwrap().len(),
        failed["process"]["replicas"].as_array().unwrap().len()
    );
    assert!(
        done["process"]["replicas"]
            .as_array()
            .unwrap()
            .iter()
            .all(|replica| replica["resultCode"] == 0 && replica["attestationHash"].is_string()),
        "every original duty is confirmed"
    );
    assert_eq!(
        server_count(&o.services, &o.server, "destruction_jobs"),
        1,
        "the server received the job and executed within this Resume"
    );
    assert_server_completed_once(&o, &f);
    let completed = local_counts(&f);
    let stored = server_transitions(&o.services, &o.server);
    drop(state);
    drop(host);

    // A new host reconstructs the exact durable view; synchronizing adds nothing.
    let reopened = configured_host(&f, &o.server);
    let state = reopened.desktop_state();
    assert_eq!(
        view(destruction_read_core(&state, Some(&id)))["process"],
        done["process"]
    );
    assert_eq!(
        view(destruction_synchronize_core(&state, &id, &job))["process"],
        done["process"]
    );
    assert_eq!(local_counts(&f), completed);
    assert_eq!(server_transitions(&o.services, &o.server), stored);
}
