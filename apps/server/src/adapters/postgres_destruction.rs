//! Transactional immutable destruction history and server jobs.
use ea_sync_server::managed_destruction::DestructionEventCommand;
use ea_sync_server::{AppendOutcome, RepositoryError, ServerClock};
use sqlx::{PgPool, Row};

pub(super) async fn record_event(
    pool: &PgPool,
    c: DestructionEventCommand,
    clock: &dyn ServerClock,
) -> Result<AppendOutcome, RepositoryError> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    lock_authority(
        &mut tx,
        c.organization_id,
        c.chain_id,
        &c.expected_chain_head,
        &c.authority_fence,
    )
    .await?;
    let id = c.event.fields().destruction_id;
    let row=sqlx::query("SELECT authorization_object_hash FROM destructions WHERE organization_id=$1 AND destruction_id=$2 FOR UPDATE")
        .bind(c.organization_id.as_bytes().as_slice()).bind(id.as_bytes().as_slice())
        .fetch_optional(&mut *tx).await.map_err(unavailable)?.ok_or(RepositoryError::HeadConflict)?;
    if row.get::<Vec<u8>, _>("authorization_object_hash") != c.authorization_hash.as_bytes() {
        return Ok(AppendOutcome::Conflict);
    }
    let hashes:Vec<Vec<u8>>=sqlx::query_scalar("SELECT object_hash FROM destruction_transitions WHERE organization_id=$1 AND destruction_id=$2 ORDER BY technical_index")
        .bind(c.organization_id.as_bytes().as_slice()).bind(id.as_bytes().as_slice())
        .fetch_all(&mut *tx).await.map_err(unavailable)?;
    let expected: Vec<&[u8]> = c
        .expected_history
        .iter()
        .map(|h| h.as_bytes().as_slice())
        .collect();
    if hashes.iter().map(Vec::as_slice).collect::<Vec<_>>() != expected {
        return Ok(AppendOutcome::Conflict);
    }

    let claims:Vec<Vec<u8>>=sqlx::query_scalar("SELECT object_hash FROM destruction_attestations WHERE organization_id=$1 AND destruction_id=$2 ORDER BY technical_index")
        .bind(c.organization_id.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).fetch_all(&mut *tx).await.map_err(unavailable)?;
    if claims.iter().map(Vec::as_slice).collect::<Vec<_>>()
        != c.expected_attestations
            .iter()
            .map(|h| h.as_bytes().as_slice())
            .collect::<Vec<_>>()
    {
        return Ok(AppendOutcome::Conflict);
    }
    if c.event.fields().to_state == 3
        && !server_removal_measured(&mut tx, c.organization_id, id, c.event.fields().executed_at)
            .await?
    {
        return Ok(AppendOutcome::Conflict);
    }
    let now = clock.now();
    if now < c.authority_fence.selected_at || now > c.authority_fence.not_after {
        return Err(RepositoryError::HeadConflict);
    }
    sqlx::query("INSERT INTO object_index(object_hash,organization_id,object_type_code,size_bytes,stored_at_millis) VALUES($1,$2,5,$3,$4) ON CONFLICT DO NOTHING")
        .bind(c.event.object_hash().as_bytes().as_slice()).bind(c.organization_id.as_bytes().as_slice())
        .bind(i64::try_from(c.indexed.size_bytes).map_err(|_|RepositoryError::Unavailable)?).bind(now.get())
        .execute(&mut *tx).await.map_err(unavailable)?;
    sqlx::query("INSERT INTO destruction_event_cores(object_hash,organization_id,destruction_id,event_id,exact_bytes) VALUES($1,$2,$3,$4,$5)")
        .bind(c.event.object_hash().as_bytes().as_slice()).bind(c.organization_id.as_bytes().as_slice()).bind(id.as_bytes().as_slice())
        .bind(c.event.fields().event_id.as_bytes().as_slice()).bind(c.event.exact_bytes())
        .execute(&mut *tx).await.map_err(unavailable)?;
    sqlx::query("INSERT INTO destruction_transitions(object_hash,organization_id,destruction_id,to_state_code,recorded_at_millis) VALUES($1,$2,$3,$4,$5)")
        .bind(c.event.object_hash().as_bytes().as_slice()).bind(c.organization_id.as_bytes().as_slice()).bind(id.as_bytes().as_slice())
        .bind(i16::from(c.event.fields().to_state)).bind(now.get()).execute(&mut *tx).await.map_err(unavailable)?;
    sqlx::query(
        "UPDATE destructions SET state_code=$3 WHERE organization_id=$1 AND destruction_id=$2",
    )
    .bind(c.organization_id.as_bytes().as_slice())
    .bind(id.as_bytes().as_slice())
    .bind(i16::from(c.event.fields().to_state))
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    if clock.now() > c.authority_fence.not_after {
        return Err(RepositoryError::HeadConflict);
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(AppendOutcome::Recorded)
}
fn unavailable(_: sqlx::Error) -> RepositoryError {
    RepositoryError::Unavailable
}

async fn lock_authority(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org: ea_types::OrganizationId,
    chain: ea_types::ChainId,
    expected: &ea_sync_server::ChainHeadStateV1,
    fence: &ea_sync_server::RegistryAdmissionFenceV1,
) -> Result<(), RepositoryError> {
    // Same catalog → chain → process lock order as reservation and Commit.
    let row=sqlx::query("SELECT trust_catalog_revision,trust_anchor_bytes FROM organizations WHERE organization_id=$1 FOR NO KEY UPDATE")
        .bind(org.as_bytes().as_slice()).fetch_optional(&mut **tx).await.map_err(unavailable)?
        .ok_or(RepositoryError::HeadConflict)?;
    if row.get::<i64, _>("trust_catalog_revision") != fence.catalog_revision
        || row
            .get::<Option<Vec<u8>>, _>("trust_anchor_bytes")
            .as_deref()
            != Some(fence.exact_anchor_bytes.as_slice())
    {
        return Err(RepositoryError::HeadConflict);
    }
    let row=sqlx::query("SELECT head_sequence,head_entry_hash,head_accepted_at_server_millis FROM chain_heads WHERE organization_id=$1 AND chain_id=$2 FOR UPDATE")
        .bind(org.as_bytes().as_slice()).bind(chain.as_bytes().as_slice())
        .fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or(RepositoryError::HeadConflict)?;
    if u64::try_from(row.get::<i64, _>("head_sequence")) != Ok(expected.sequence.get())
        || row.get::<Vec<u8>, _>("head_entry_hash") != expected.entry_hash.as_bytes()
        || row.get::<i64, _>("head_accepted_at_server_millis") != expected.accepted_at_server.get()
    {
        return Err(RepositoryError::HeadConflict);
    }
    Ok(())
}

pub(super) async fn read_job(
    pool: &PgPool,
    org: ea_types::OrganizationId,
    id: ea_types::DestructionId,
) -> Result<Option<ea_sync_server::managed_destruction::StoredDestructionJob>, RepositoryError> {
    let bytes: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT exact_upload FROM destruction_jobs WHERE organization_id=$1 AND destruction_id=$2",
    )
    .bind(org.as_bytes().as_slice())
    .bind(id.as_bytes().as_slice())
    .fetch_optional(pool)
    .await
    .map_err(unavailable)?;
    Ok(bytes.map(
        |exact_upload| ea_sync_server::managed_destruction::StoredDestructionJob { exact_upload },
    ))
}
pub(super) async fn target_objects(
    pool: &PgPool,
    org: ea_types::OrganizationId,
    id: ea_types::DestructionId,
    targets: &[(ea_types::EntryHash, u64, ea_types::ObjectHash)],
) -> Result<Vec<ea_sync_server::IndexedObjectV1>, RepositoryError> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
    let values = read_targets(&mut tx, org, id, targets).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(values)
}
async fn read_targets(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org: ea_types::OrganizationId,
    id: ea_types::DestructionId,
    targets: &[(ea_types::EntryHash, u64, ea_types::ObjectHash)],
) -> Result<Vec<ea_sync_server::IndexedObjectV1>, RepositoryError> {
    use ea_format::ObjectTypeV1;
    use ea_types::{EntryHash, ObjectHash};
    let rows=sqlx::query("SELECT t.entry_hash,t.chain_sequence,e.entry_object_hash,i.size_bytes,i.object_type_code FROM destruction_targets t LEFT JOIN entries e ON e.organization_id=t.organization_id AND e.entry_hash=t.entry_hash AND e.sequence_number=t.chain_sequence LEFT JOIN object_index i ON i.object_hash=e.entry_object_hash AND i.organization_id=t.organization_id WHERE t.organization_id=$1 AND t.destruction_id=$2 ORDER BY t.entry_hash")
        .bind(org.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).fetch_all(&mut **tx).await.map_err(unavailable)?;
    if rows.len() != targets.len() {
        return Err(RepositoryError::HeadConflict);
    }
    let mut result = Vec::new();
    for (row, (entry, sequence, original)) in rows.into_iter().zip(targets) {
        if EntryHash::try_from(row.get::<Vec<u8>, _>("entry_hash").as_slice()).ok() != Some(*entry)
            || u64::try_from(row.get::<i64, _>("chain_sequence")) != Ok(*sequence)
            || row
                .get::<Option<Vec<u8>>, _>("entry_object_hash")
                .as_deref()
                != Some(original.as_bytes().as_slice())
            || row.get::<Option<i16>, _>("object_type_code") != Some(1)
        {
            return Err(RepositoryError::HeadConflict);
        }
        result.push(ea_sync_server::IndexedObjectV1 {
            kind: ObjectTypeV1::Entry,
            object_hash: *original,
            size_bytes: u64::try_from(
                row.get::<Option<i64>, _>("size_bytes")
                    .ok_or(RepositoryError::HeadConflict)?,
            )
            .map_err(|_| RepositoryError::HeadConflict)?,
        });
    }
    let grants=sqlx::query("SELECT g.object_hash,i.size_bytes,i.object_type_code FROM destruction_targets t JOIN grants g ON g.organization_id=t.organization_id AND g.entry_hash=t.entry_hash LEFT JOIN object_index i ON i.object_hash=g.object_hash AND i.organization_id=t.organization_id WHERE t.organization_id=$1 AND t.destruction_id=$2 ORDER BY g.object_hash")
        .bind(org.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).fetch_all(&mut **tx).await.map_err(unavailable)?;
    for row in grants {
        if row.get::<Option<i16>, _>("object_type_code") != Some(2) {
            return Err(RepositoryError::HeadConflict);
        }
        result.push(ea_sync_server::IndexedObjectV1 {
            kind: ObjectTypeV1::Grant,
            object_hash: ObjectHash::try_from(row.get::<Vec<u8>, _>("object_hash").as_slice())
                .map_err(|_| RepositoryError::HeadConflict)?,
            size_bytes: u64::try_from(
                row.get::<Option<i64>, _>("size_bytes")
                    .ok_or(RepositoryError::HeadConflict)?,
            )
            .map_err(|_| RepositoryError::HeadConflict)?,
        });
    }
    result.sort_by_key(|o| o.object_hash);
    if result.len() > 10_000 {
        return Err(RepositoryError::HeadConflict);
    }
    Ok(result)
}
pub(super) async fn record_job(
    pool: &PgPool,
    c: ea_sync_server::managed_destruction::DestructionJobCommand,
    clock: &dyn ServerClock,
) -> Result<AppendOutcome, RepositoryError> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    lock_authority(
        &mut tx,
        c.organization_id,
        c.chain_id,
        &c.expected_chain_head,
        &c.authority_fence,
    )
    .await?;
    let auth = c.preflight.authorization();
    let id = auth.fields().destruction_id;
    let row=sqlx::query("SELECT authorization_object_hash FROM destructions WHERE organization_id=$1 AND destruction_id=$2 FOR UPDATE")
        .bind(c.organization_id.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).fetch_optional(&mut *tx).await.map_err(unavailable)?.ok_or(RepositoryError::HeadConflict)?;
    if row.get::<Vec<u8>, _>("authorization_object_hash") != auth.object_hash().as_bytes() {
        return Ok(AppendOutcome::Conflict);
    }
    let saved: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT exact_upload FROM destruction_jobs WHERE organization_id=$1 AND destruction_id=$2",
    )
    .bind(c.organization_id.as_bytes().as_slice())
    .bind(id.as_bytes().as_slice())
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    if let Some(saved) = saved {
        return Ok(if saved == c.preflight.exact_upload() {
            AppendOutcome::AlreadyRecorded
        } else {
            AppendOutcome::Conflict
        });
    }
    let targets = c
        .preflight
        .targets()
        .iter()
        .map(|t| (t.entry_hash(), t.sequence().get(), t.original_object_hash()))
        .collect::<Vec<_>>();
    let actual = read_targets(&mut tx, c.organization_id, id, &targets).await?;
    if actual.len() != c.objects.len() || actual.iter().zip(&c.objects).any(|(a, b)| a != &b.object)
    {
        return Ok(AppendOutcome::Conflict);
    }
    let now = clock.now();
    if now < c.authority_fence.selected_at || now > c.authority_fence.not_after {
        return Err(RepositoryError::HeadConflict);
    }
    sqlx::query("INSERT INTO destruction_jobs(organization_id,destruction_id,job_hash,authorization_hash,exact_upload,admitted_at_millis,catalog_revision,principal_certificate) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(c.organization_id.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).bind(c.preflight.job_hash().as_bytes().as_slice())
        .bind(auth.object_hash().as_bytes().as_slice()).bind(c.preflight.exact_upload()).bind(now.get()).bind(c.authority_fence.catalog_revision).bind(c.principal_certificate.as_bytes().as_slice())
        .execute(&mut *tx).await.map_err(unavailable)?;
    for object in c.objects {
        sqlx::query("INSERT INTO destruction_job_objects(organization_id,destruction_id,object_hash,object_type_code,size_bytes) VALUES($1,$2,$3,$4,$5)")
            .bind(c.organization_id.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).bind(object.object.object_hash.as_bytes().as_slice())
            .bind(i16::try_from(object.object.kind.code()).map_err(|_|RepositoryError::Unavailable)?).bind(object.object.size_bytes as i64)
            .execute(&mut *tx).await.map_err(unavailable)?;
        for version in object.versions {
            sqlx::query("INSERT INTO destruction_job_versions(organization_id,destruction_id,object_hash,version_id,delete_marker,retained_until_millis,legal_hold,storage_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
                .bind(c.organization_id.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).bind(object.object.object_hash.as_bytes().as_slice())
                .bind(version.version_id).bind(version.delete_marker).bind(version.retained_until.map(|t|t.get())).bind(version.legal_hold).bind(version.storage_key)
                .execute(&mut *tx).await.map_err(unavailable)?;
        }
    }
    if clock.now() > c.authority_fence.not_after {
        return Err(RepositoryError::HeadConflict);
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(AppendOutcome::Recorded)
}

pub(super) async fn begin_execution(
    pool: &PgPool,
    c: ea_sync_server::managed_destruction::ServerExecutionCommand,
) -> Result<Box<dyn ea_sync_server::managed_destruction::ServerExecutionGuard>, RepositoryError> {
    use ea_sync_server::managed_destruction::{FrozenDestructionObject, StoredObjectVersion};
    let mut tx = pool.begin().await.map_err(unavailable)?;
    lock_authority(
        &mut tx,
        c.organization_id,
        c.chain_id,
        &c.expected_chain_head,
        &c.authority_fence,
    )
    .await?;
    let row=sqlx::query("SELECT state_code FROM destructions WHERE organization_id=$1 AND destruction_id=$2 FOR UPDATE")
        .bind(c.organization_id.as_bytes().as_slice()).bind(c.destruction_id.as_bytes().as_slice()).fetch_optional(&mut *tx)
        .await.map_err(unavailable)?.ok_or(RepositoryError::HeadConflict)?;
    if !matches!(row.get::<i16, _>("state_code"), 1 | 2 | 4) {
        return Err(RepositoryError::HeadConflict);
    }
    let latest:Option<Vec<u8>>=sqlx::query_scalar("SELECT object_hash FROM destruction_transitions WHERE organization_id=$1 AND destruction_id=$2 ORDER BY technical_index DESC LIMIT 1")
        .bind(c.organization_id.as_bytes().as_slice()).bind(c.destruction_id.as_bytes().as_slice()).fetch_optional(&mut *tx).await.map_err(unavailable)?;
    if latest.as_deref() != Some(c.event_hash.as_bytes().as_slice()) {
        return Err(RepositoryError::HeadConflict);
    }
    let exact:Option<Vec<u8>>=sqlx::query_scalar("SELECT exact_upload FROM destruction_jobs WHERE organization_id=$1 AND destruction_id=$2 AND job_hash=$3")
        .bind(c.organization_id.as_bytes().as_slice()).bind(c.destruction_id.as_bytes().as_slice()).bind(c.job_hash.as_bytes().as_slice())
        .fetch_optional(&mut *tx).await.map_err(unavailable)?;
    if exact.as_deref() != Some(c.exact_job.as_slice()) {
        return Err(RepositoryError::HeadConflict);
    }
    let actual = read_targets(&mut tx, c.organization_id, c.destruction_id, &c.targets).await?;
    let rows=sqlx::query("SELECT object_hash,object_type_code,size_bytes FROM destruction_job_objects WHERE organization_id=$1 AND destruction_id=$2 ORDER BY object_hash")
        .bind(c.organization_id.as_bytes().as_slice()).bind(c.destruction_id.as_bytes().as_slice()).fetch_all(&mut *tx).await.map_err(unavailable)?;
    let mut objects = Vec::new();
    for row in rows {
        let hash = ea_types::ObjectHash::try_from(row.get::<Vec<u8>, _>("object_hash").as_slice())
            .map_err(|_| RepositoryError::Unavailable)?;
        let kind = match row.get::<i16, _>("object_type_code") {
            1 => ea_format::ObjectTypeV1::Entry,
            2 => ea_format::ObjectTypeV1::Grant,
            _ => return Err(RepositoryError::Unavailable),
        };
        let object = ea_sync_server::IndexedObjectV1 {
            object_hash: hash,
            kind,
            size_bytes: row.get::<i64, _>("size_bytes") as u64,
        };
        let rows=sqlx::query("SELECT storage_key,version_id,delete_marker,retained_until_millis,legal_hold FROM destruction_job_versions WHERE organization_id=$1 AND destruction_id=$2 AND object_hash=$3 ORDER BY storage_key,version_id")
            .bind(c.organization_id.as_bytes().as_slice()).bind(c.destruction_id.as_bytes().as_slice()).bind(hash.as_bytes().as_slice())
            .fetch_all(&mut *tx).await.map_err(unavailable)?;
        let versions = rows
            .into_iter()
            .map(|r| StoredObjectVersion {
                storage_key: r.get("storage_key"),
                version_id: r.get("version_id"),
                delete_marker: r.get("delete_marker"),
                retained_until: r
                    .get::<Option<i64>, _>("retained_until_millis")
                    .map(ea_types::UnixMillis::new),
                legal_hold: r.get("legal_hold"),
            })
            .collect();
        objects.push(FrozenDestructionObject { object, versions });
    }
    if actual.len() != objects.len() || actual.iter().zip(&objects).any(|(a, b)| a != &b.object) {
        return Err(RepositoryError::HeadConflict);
    }
    Ok(Box::new(PgExecution {
        tx,
        command: c,
        objects,
    }))
}
struct PgExecution {
    tx: sqlx::Transaction<'static, sqlx::Postgres>,
    command: ea_sync_server::managed_destruction::ServerExecutionCommand,
    objects: Vec<ea_sync_server::managed_destruction::FrozenDestructionObject>,
}
#[async_trait::async_trait]
impl ea_sync_server::managed_destruction::ServerExecutionGuard for PgExecution {
    fn objects(&self) -> &[ea_sync_server::managed_destruction::FrozenDestructionObject] {
        &self.objects
    }
    async fn finish(
        self: Box<Self>,
        measurement: ea_sync_server::managed_destruction::ServerRemovalMeasurement,
        clock: &dyn ServerClock,
    ) -> Result<(), RepositoryError> {
        let Self {
            mut tx,
            command: c,
            objects,
        } = *self;
        let now = clock.now();
        if now < c.authority_fence.selected_at
            || now > c.authority_fence.not_after
            || measurement.measured_at > now
        {
            return Err(RepositoryError::HeadConflict);
        }
        let att = &measurement.attestation;
        let expected = objects
            .iter()
            .map(|o| o.object.object_hash)
            .collect::<Vec<_>>();
        if (att.fields().result == 0 && att.fields().removed_object_hashes != expected)
            || att
                .fields()
                .removed_object_hashes
                .iter()
                .any(|hash| !expected.contains(hash))
            || att.certificate_hash() != c.component_certificate
            || att.fields().destruction_id != c.destruction_id
        {
            return Err(RepositoryError::HeadConflict);
        }
        for object in measurement.stubs {
            sqlx::query("INSERT INTO object_index(object_hash,organization_id,object_type_code,size_bytes,stored_at_millis) VALUES($1,$2,6,$3,$4) ON CONFLICT DO NOTHING")
                .bind(object.object_hash.as_bytes().as_slice()).bind(c.organization_id.as_bytes().as_slice()).bind(object.size_bytes as i64).bind(now.get())
                .execute(&mut *tx).await.map_err(unavailable)?;
            sqlx::query("INSERT INTO destruction_job_stubs(organization_id,destruction_id,object_hash) VALUES($1,$2,$3) ON CONFLICT DO NOTHING")
                .bind(c.organization_id.as_bytes().as_slice()).bind(c.destruction_id.as_bytes().as_slice()).bind(object.object_hash.as_bytes().as_slice())
                .execute(&mut *tx).await.map_err(unavailable)?;
        }
        sqlx::query("INSERT INTO object_index(object_hash,organization_id,object_type_code,size_bytes,stored_at_millis) VALUES($1,$2,5,$3,$4) ON CONFLICT DO NOTHING")
            .bind(att.object_hash().as_bytes().as_slice()).bind(c.organization_id.as_bytes().as_slice()).bind(att.exact_bytes().len() as i64).bind(now.get())
            .execute(&mut *tx).await.map_err(unavailable)?;
        sqlx::query("INSERT INTO destruction_attestations(object_hash,organization_id,destruction_id,recorded_at_millis) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
            .bind(att.object_hash().as_bytes().as_slice()).bind(c.organization_id.as_bytes().as_slice()).bind(c.destruction_id.as_bytes().as_slice()).bind(now.get())
            .execute(&mut *tx).await.map_err(unavailable)?;
        for hash in &att.fields().removed_object_hashes {
            sqlx::query("INSERT INTO destruction_removed_objects(organization_id,destruction_id,object_hash,attestation_hash) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
                .bind(c.organization_id.as_bytes().as_slice()).bind(c.destruction_id.as_bytes().as_slice())
                .bind(hash.as_bytes().as_slice()).bind(att.object_hash().as_bytes().as_slice())
                .execute(&mut *tx).await.map_err(unavailable)?;
        }
        sqlx::query("INSERT INTO destruction_server_measurements(organization_id,destruction_id,job_hash,event_hash,component_certificate,attestation_hash,exact_attestation,measured_at_millis,catalog_revision,result_code,controller_certificate) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING")
            .bind(c.organization_id.as_bytes().as_slice()).bind(c.destruction_id.as_bytes().as_slice()).bind(c.job_hash.as_bytes().as_slice())
            .bind(c.event_hash.as_bytes().as_slice()).bind(c.component_certificate.as_bytes().as_slice()).bind(att.object_hash().as_bytes().as_slice())
            .bind(att.exact_bytes()).bind(measurement.measured_at.get()).bind(c.authority_fence.catalog_revision).bind(i16::from(att.fields().result)).bind(c.controller_certificate.as_bytes().as_slice()).execute(&mut *tx).await.map_err(unavailable)?;
        if clock.now() > c.authority_fence.not_after {
            return Err(RepositoryError::HeadConflict);
        }
        tx.commit().await.map_err(unavailable)
    }
}

pub(super) async fn begin_object_write(
    pool: &PgPool,
    org: ea_types::OrganizationId,
    entry: ea_types::EntryHash,
) -> Result<Box<dyn ea_sync_server::managed_destruction::ObjectWriteGuard>, RepositoryError> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    let exists: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT organization_id FROM organizations WHERE organization_id=$1 FOR SHARE",
    )
    .bind(org.as_bytes().as_slice())
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    if exists.is_none() {
        return Err(RepositoryError::HeadConflict);
    }
    let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM destruction_targets WHERE organization_id=$1 AND entry_hash=$2)")
        .bind(org.as_bytes().as_slice()).bind(entry.as_bytes().as_slice()).fetch_one(&mut *tx).await.map_err(unavailable)?;
    if blocked {
        return Err(RepositoryError::HeadConflict);
    }
    Ok(Box::new(PgObjectWrite { _tx: tx }))
}
struct PgObjectWrite {
    _tx: sqlx::Transaction<'static, sqlx::Postgres>,
}
impl ea_sync_server::managed_destruction::ObjectWriteGuard for PgObjectWrite {}

pub(super) async fn record_attestation(
    pool: &PgPool,
    c: ea_sync_server::managed_destruction::DestructionAttestationCommand,
    clock: &dyn ServerClock,
) -> Result<AppendOutcome, RepositoryError> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    lock_authority(
        &mut tx,
        c.organization_id,
        c.chain_id,
        &c.expected_chain_head,
        &c.authority_fence,
    )
    .await?;
    let id = c.destruction_id;
    let job:Option<Vec<u8>>=sqlx::query_scalar("SELECT j.job_hash FROM destructions d JOIN destruction_jobs j USING(organization_id,destruction_id) WHERE d.organization_id=$1 AND d.destruction_id=$2 FOR UPDATE OF d")
        .bind(c.organization_id.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).fetch_optional(&mut *tx).await.map_err(unavailable)?;
    if job.as_deref() != Some(c.job_hash.as_bytes().as_slice()) {
        return Ok(AppendOutcome::Conflict);
    }
    let events:Vec<Vec<u8>>=sqlx::query_scalar("SELECT object_hash FROM destruction_transitions WHERE organization_id=$1 AND destruction_id=$2 ORDER BY object_hash")
        .bind(c.organization_id.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).fetch_all(&mut *tx).await.map_err(unavailable)?;
    let attestations:Vec<Vec<u8>>=sqlx::query_scalar("SELECT object_hash FROM destruction_attestations WHERE organization_id=$1 AND destruction_id=$2 ORDER BY object_hash")
        .bind(c.organization_id.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).fetch_all(&mut *tx).await.map_err(unavailable)?;
    let equal = |actual: &Vec<Vec<u8>>, expected: &Vec<ea_types::ObjectHash>| {
        actual
            .iter()
            .map(|v| v.as_slice())
            .collect::<std::collections::BTreeSet<_>>()
            == expected
                .iter()
                .map(|v| v.as_bytes().as_slice())
                .collect::<std::collections::BTreeSet<_>>()
    };
    if !equal(&events, &c.expected_events) || !equal(&attestations, &c.expected_attestations) {
        return Ok(AppendOutcome::Conflict);
    }
    let now = clock.now();
    if now < c.authority_fence.selected_at || now > c.authority_fence.not_after {
        return Err(RepositoryError::HeadConflict);
    }
    let att = &c.attestation;
    sqlx::query("INSERT INTO object_index(object_hash,organization_id,object_type_code,size_bytes,stored_at_millis) VALUES($1,$2,5,$3,$4) ON CONFLICT DO NOTHING")
        .bind(att.object_hash().as_bytes().as_slice()).bind(c.organization_id.as_bytes().as_slice()).bind(att.exact_bytes().len() as i64).bind(now.get())
        .execute(&mut *tx).await.map_err(unavailable)?;
    sqlx::query("INSERT INTO destruction_attestations(object_hash,organization_id,destruction_id,recorded_at_millis) VALUES($1,$2,$3,$4)")
        .bind(att.object_hash().as_bytes().as_slice()).bind(c.organization_id.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).bind(now.get())
        .execute(&mut *tx).await.map_err(unavailable)?;
    sqlx::query("INSERT INTO destruction_attestation_intake(object_hash,job_hash,principal_certificate,signer_certificate,exact_bytes,catalog_revision,admitted_at_millis) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(att.object_hash().as_bytes().as_slice()).bind(c.job_hash.as_bytes().as_slice()).bind(c.principal.as_bytes().as_slice())
        .bind(att.certificate_hash().as_bytes().as_slice()).bind(att.exact_bytes()).bind(c.authority_fence.catalog_revision).bind(now.get())
        .execute(&mut *tx).await.map_err(unavailable)?;
    if clock.now() > c.authority_fence.not_after {
        return Err(RepositoryError::HeadConflict);
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(AppendOutcome::Recorded)
}

pub(super) async fn server_removal_measured(
    connection: &mut sqlx::PgConnection,
    org: ea_types::OrganizationId,
    id: ea_types::DestructionId,
    at: ea_types::UnixMillis,
) -> Result<bool, RepositoryError> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM destruction_server_measurements m JOIN destruction_jobs j USING(organization_id,destruction_id)
        WHERE m.organization_id=$1 AND m.destruction_id=$2 AND m.job_hash=j.job_hash AND m.result_code=0 AND m.measured_at_millis<=$3
        AND NOT EXISTS(SELECT 1 FROM destruction_job_objects o WHERE o.organization_id=m.organization_id AND o.destruction_id=m.destruction_id
            AND NOT EXISTS(SELECT 1 FROM destruction_removed_objects r WHERE r.organization_id=o.organization_id AND r.destruction_id=o.destruction_id AND r.object_hash=o.object_hash)))")
        .bind(org.as_bytes().as_slice()).bind(id.as_bytes().as_slice()).bind(at.get()).fetch_one(connection).await.map_err(unavailable)
}
