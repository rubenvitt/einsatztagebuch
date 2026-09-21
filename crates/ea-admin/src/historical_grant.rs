//! Native composition of historical re-grant issuance.
use crate::operator_runtime::{OperatorRuntime, fresh_wall_clock};
use ea_archive::ArchiveInventory;
use ea_format::{CertificateKindV1, GrantKindV1, GrantPurposeV1, OperatorRoleV1};
use ea_operator::ReauthPurpose;
use ea_recovery::{
    GrantOperatorContext, GrantRegistrySource, HistoricalGrantError as Error,
    HistoricalGrantService, HistoricalGrantSigner, ResolvedGrantInputsV1, VerifiedRecoveryEntry,
};
use ea_trust::{
    RegistrySelectionOutcome, SelectedRegistryHead, TrustStateKey, load_trust_state,
    prepare_local_time, select_registry_head, verify_checkpoint_time, verify_grant_authorization,
    verify_receipt_time, verify_registry_candidate, verify_trust,
};
use ea_types::UnixMillis;
use std::{cell::Cell, path::Path, time::Instant};

/// The native runtime and recovery input resolver must describe the same frozen objects.
pub fn issue_historical_grants(
    runtime: &OperatorRuntime,
    inputs: &ResolvedGrantInputsV1,
) -> Result<IssuedHistoricalGrants, Error> {
    if runtime.config().role != OperatorRoleV1::OrganizationAdmin
        || runtime.config().purpose != ReauthPurpose::HistoricalRegrant
    {
        return Err(Error::Operator);
    }
    let inventory = ArchiveInventory::build(inputs.source()).map_err(|_| Error::Archive)?;
    macro_rules! same {
        ($field:ident) => {
            if inventory
                .$field()
                .iter()
                .map(|p| p.object_hash())
                .collect::<std::collections::BTreeSet<_>>()
                != runtime
                    .inventory()
                    .$field()
                    .iter()
                    .map(|p| p.object_hash())
                    .collect::<std::collections::BTreeSet<_>>()
            {
                return Err(Error::Archive);
            }
        };
    }
    same!(entries);
    same!(trust);
    same!(grants);
    same!(receipts);
    same!(evidence);
    same!(destroyed);
    let registry = NativeGrantRegistry {
        runtime,
        started: Instant::now(),
        floor: Cell::new(runtime.head().preexisting_effective_now().value()),
    };
    let head = registry.current_head()?;
    let authorization = verify_grant_authorization(&inputs.authorization_bytes, &head)
        .map_err(Error::Authorization)?;
    let authority_thumbprint =
        HistoricalGrantSigner::key_thumbprint(inputs.authority()).map_err(|_| Error::Issuer)?;
    let issuer = head
        .active_certificates()
        .find(|(_, f)| {
            f.certificate_kind == CertificateKindV1::HistoricalGrantAuthority
                && f.signing_key_thumbprint == Some(authority_thumbprint)
        })
        .map(|(h, _)| h)
        .ok_or(Error::Issuer)?;
    // Fully verify every explicit target before asking the OS for presence.
    let mut entries = Vec::new();
    for entry_hash in &authorization.fields().entry_hashes {
        let original = inventory
            .grants()
            .iter()
            .find(|p| {
                let f = p.value().grant_body().fields();
                f.entry_hash == *entry_hash
                    && f.kind == GrantKindV1::Initial
                    && f.purpose == GrantPurposeV1::Recovery
            })
            .ok_or(Error::Original)?;
        entries.push(VerifiedRecoveryEntry::verify(
            inputs.source(),
            runtime.anchor(),
            *entry_hash,
            original.object_hash(),
            head.preexisting_effective_now().value(),
        )?);
    }
    let session = runtime.reauthenticate().map_err(|_| Error::Operator)?;
    let audit = runtime.audit_service();
    let mut grants = Vec::new();
    for entry in &entries {
        grants.push(HistoricalGrantService::create(
            entry,
            &authorization,
            inputs.recovery_key(),
            inputs.authority(),
            issuer,
            &inputs.recipient_certificate_bytes,
            &registry,
            GrantOperatorContext {
                device_certificate: runtime.config().device_certificate_hash,
                proof: session.proof(),
                account: runtime.native().as_ref(),
            },
            &audit,
        )?);
    }
    registry.current_head().and_then(|h| {
        verify_grant_authorization(authorization.exact_bytes(), &h).map_err(Error::Authorization)
    })?;
    Ok(IssuedHistoricalGrants {
        grants,
        authorization,
        session,
    })
}

/// Keeps native presence alive until atomic output publication.
pub struct IssuedHistoricalGrants {
    grants: Vec<ea_format::ExactObjectBytes>,
    authorization: ea_trust::VerifiedGrantAuthorization,
    session: crate::VerifiedOperatorSession,
}
impl IssuedHistoricalGrants {
    pub fn publish(
        mut self,
        runtime: &OperatorRuntime,
        directory: &Path,
    ) -> Result<Vec<ea_types::ObjectHash>, Error> {
        let registry = NativeGrantRegistry {
            runtime,
            started: Instant::now(),
            floor: Cell::new(runtime.head().preexisting_effective_now().value()),
        };
        let ea_format::ParsedArchiveObject::Trust(parsed) =
            ea_format::decode_exact_object(self.authorization.exact_bytes())
                .map_err(|_| Error::Context)?
        else {
            return Err(Error::Context);
        };
        let exact_authorization =
            ea_format::encode_trust(parsed.value()).map_err(|_| Error::Context)?;
        self.grants.insert(0, exact_authorization);
        let mut hashes = publish_historical_grants(directory, &self.grants, || {
            let head = registry.current_head()?;
            verify_grant_authorization(self.authorization.exact_bytes(), &head)
                .map_err(Error::Authorization)?;
            ea_operator::verify_current_session(
                &head,
                runtime.config().device_certificate_hash,
                OperatorRoleV1::OrganizationAdmin,
                self.session.proof(),
                ReauthPurpose::HistoricalRegrant,
                runtime.native().as_ref(),
            )
            .map_err(|_| Error::Operator)
        })?;
        hashes.remove(0);
        Ok(hashes)
    }
}

struct NativeGrantRegistry<'a> {
    runtime: &'a OperatorRuntime,
    started: Instant,
    floor: Cell<UnixMillis>,
}
impl GrantRegistrySource for NativeGrantRegistry<'_> {
    fn current_head(&self) -> Result<SelectedRegistryHead, Error> {
        let run = self.runtime;
        run.ensure_current().map_err(|_| Error::Context)?;
        let elapsed =
            i64::try_from(self.started.elapsed().as_millis()).map_err(|_| Error::Context)?;
        let now = fresh_wall_clock()
            .map_err(|_| Error::Context)?
            .max(UnixMillis::new(
                run.head()
                    .preexisting_effective_now()
                    .value()
                    .get()
                    .saturating_add(elapsed),
            ))
            .max(self.floor.get());
        self.floor.set(now);
        let mut store = run.trust_store().clone();
        let device_id = run
            .head()
            .active_certificate_fields(run.config().device_certificate_hash)
            .ok_or(Error::Operator)?
            .device_id;
        let key = TrustStateKey {
            organization_id: run.anchor().organization_id(),
            device_id,
        };
        for _ in 0..=run.inventory().trust().len() {
            let trust = verify_trust(
                run.anchor(),
                run.inventory(),
                load_trust_state(&mut store, key).map_err(|_| Error::Context)?,
            )
            .map_err(|_| Error::Context)?;
            let pin = trust.pinned_head().copied();
            let candidate = verify_registry_candidate(&trust, run.next_sequence())
                .map_err(|_| Error::Context)?;
            let mut sources = Vec::new();
            if let Some(authority) = candidate.preexisting_authority() {
                for receipt in run.inventory().receipts() {
                    if let Ok(s) = verify_receipt_time(authority, receipt) {
                        sources.push(s);
                    }
                }
                for evidence in run.inventory().evidence() {
                    if let Ok(s) = verify_checkpoint_time(authority, evidence) {
                        sources.push(s);
                    }
                }
            }
            let time = prepare_local_time(&mut store, &candidate, now, &sources)
                .map_err(|_| Error::Context)?;
            match select_registry_head(candidate, time, None).map_err(|_| Error::Context)? {
                RegistrySelectionOutcome::Selected(head)
                    if pin.is_some_and(|p| {
                        p.registry_version() == head.registry_version()
                            && p.registry_head_hash() == head.registry_head_hash()
                    }) =>
                {
                    return Ok(head);
                }
                RegistrySelectionOutcome::Selected(_) | RegistrySelectionOutcome::Advanced(_) => {}
                RegistrySelectionOutcome::PendingFuture(_) => return Err(Error::Context),
            }
        }
        Err(Error::Context)
    }
}

/// Publish only already audited bytes. The final name appears atomically after
/// the complete file is synced. Replaying identical bytes is idempotent.
fn publish_historical_grants(
    directory: &Path,
    grants: &[ea_format::ExactObjectBytes],
    check: impl Fn() -> Result<(), Error>,
) -> Result<Vec<ea_types::ObjectHash>, Error> {
    check()?;
    let publish = || -> Result<Vec<ea_types::ObjectHash>, Error> {
        use std::{
            fs::{self, OpenOptions},
            io::{ErrorKind, Write},
        };
        if !directory.exists() {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(directory)?;
            // Ein Verzeichnis lässt sich nur auf Unix als Datei öffnen und
            // flushen; wie im übrigen Archiv bleibt der dauerhafte
            // Verzeichniseintrag anderswo eine Zusage des Wirtsystems.
            #[cfg(unix)]
            if let Some(parent) = directory.parent() {
                fs::File::open(parent)?.sync_all()?;
            }
        }
        if fs::symlink_metadata(directory)?.file_type().is_symlink() {
            return Err(Error::Output);
        }
        let mut hashes = Vec::new();
        for grant in grants {
            let hash = ea_crypto::object_hash(grant.as_bytes());
            let extension = match ea_format::decode_exact_object(grant.as_bytes())
                .map_err(|_| Error::Context)?
            {
                ea_format::ParsedArchiveObject::Trust(_) => "etb",
                ea_format::ParsedArchiveObject::Grant(_) => "eag",
                _ => return Err(Error::Context),
            };
            let path = directory.join(format!("{}.{extension}", hex::encode(hash.as_bytes())));
            let mut random = [0; 16];
            getrandom::fill(&mut random).map_err(std::io::Error::other)?;
            let temporary = directory.join(format!(".grant-{}.tmp", hex::encode(random)));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let result = (|| -> Result<(), Error> {
                let mut file = options.open(&temporary)?;
                file.write_all(grant.as_bytes())?;
                file.sync_all()?;
                check()?;
                match fs::hard_link(&temporary, &path) {
                    Ok(()) => {}
                    Err(e)
                        if e.kind() == ErrorKind::AlreadyExists
                            && !fs::symlink_metadata(&path)?.file_type().is_symlink()
                            && fs::read(&path)? == grant.as_bytes() => {}
                    Err(e) => return Err(e.into()),
                }
                #[cfg(unix)]
                fs::File::open(directory)?.sync_all()?;
                Ok(())
            })();
            let cleanup = fs::remove_file(&temporary);
            result?;
            cleanup?;
            #[cfg(unix)]
            fs::File::open(directory)?.sync_all()?;
            hashes.push(hash);
        }
        Ok(hashes)
    };
    publish()
}
