//! Der content-addressed Object Store hinter einem S3-kompatiblen Dienst.
//!
//! Die drei Schritte von `design.md` §13.3 stehen hier so, wie sie dort stehen:
//! Schritt 1 stromt groessenbegrenzt in einen TEMPORAEREN Schluessel und hasht
//! dabei, Schritt 3 uebernimmt content-addressed per Put-if-absent, und
//! „gleiche Keys mit anderen Bytes sind ein Security Event“ ist keine Notiz,
//! sondern der Zweig, den [`S3ObjectStore::put_if_absent`] nimmt.
//!
//! ## Warum verglichen und nicht nur nachgesehen wird
//!
//! Ein blosses „liegt schon da“ machte aus dem Angriff einen idempotenten
//! Wiederholungsfall — genau den Befund, den §13.3 als Security Event fordert,
//! haette dann niemand gesehen. Der Adapter vergleicht deshalb die BYTES: erst
//! die Laenge (billig), bei Gleichstand die neu gerechneten Hashwerte. Erst
//! wenn die uebereinstimmen, ist es ein Replay.
//!
//! ## Was NICHT in den Object Store geht
//!
//! Schluessel sind `<type>/<hex objectHash>` und sonst nichts. Metadaten tragen
//! Inhaltstyp und Groesse, niemals ein fachliches Feld. Der Wrapped-Blob eines
//! Readers liegt ausdruecklich NICHT in diesem Namensraum, sondern in
//! `reader_vault_blobs` (`web-reader-design.md` §6.4).

use std::sync::Arc;

use async_trait::async_trait;
use aws_sdk_s3::{Client, primitives::ByteStream, types::CompletedPart};
use ea_crypto::StreamingObjectHasher;
use ea_format::ObjectTypeV1;
use ea_sync_server::{
    ObjectStore, ObjectTypeDirectory, SecurityEventKindV1, SecurityEventSink, SecurityEventV1,
    ServerClock, StagedObject, StoreError, StoredObject, object_key, object_type_segment,
};
use ea_types::{ObjectHash, OrganizationId};

/// Der Namensraum der temporaeren Schluessel.
///
/// Er liegt BEWUSST neben `<type>/…` und nie darin: ein halb hochgeladenes
/// Objekt darf unter keinen Umstaenden wie ein archiviertes aussehen.
const STAGING_PREFIX: &str = "staging";

/// Die Teilgroesse des mehrteiligen Uploads.
///
/// Fuenf MiB ist die kleinste Teilgroesse, die S3 fuer alle Teile ausser dem
/// letzten zulaesst, und damit die schaerfste Speicherdecke, die dieser Weg
/// hergibt: die Spitzenlast ist `min(Koerper, 5 MiB)`, ganz gleich wie gross der
/// Koerper ist.
///
/// Fuer ein zulaessiges Archivobjekt heisst das in der Praxis: EIN Teil.
/// `ea_format::MAX_ARCHIVE_OBJECT_BYTES_V1` sind vier MiB, also liegt die
/// Spitzenlast dort beim Koerper selbst — gedeckelt durch die Formatgrenze und
/// zusaetzlich durch das `limit`-Argument. Die mehrteilige Strecke haelt die
/// Deckelung fuer jeden kuenftigen Aufrufer, der eine groessere Grenze setzt.
const STAGING_PART_BYTES: usize = 5 * 1024 * 1024;

/// Die Metadatenschluessel. Beides technisch: Inhaltstyp und Groesse.
const METADATA_OBJECT_TYPE: &str = "object-type";
const METADATA_OBJECT_SIZE: &str = "object-size";

/// Der Medientyp der rohen Objektbytes.
const OBJECT_MEDIA_TYPE: &str = ea_sync_protocol::OBJECT_MEDIA_TYPE_V1;

pub struct S3ObjectStore {
    client: Client,
    bucket: String,
    organization_id: OrganizationId,
    security_events: Arc<dyn SecurityEventSink>,
    object_types: Arc<dyn ObjectTypeDirectory>,
    clock: Arc<dyn ServerClock>,
}

impl S3ObjectStore {
    /// Der Security-Event-Empfaenger ist ein PFLICHTBESTANDTEIL und kein
    /// Zusatz: ohne ihn koennte der Adapter den Befund aus §13.3 Schritt 3 zwar
    /// erkennen, aber nicht aufzeichnen — und ein nicht aufgezeichneter Befund
    /// ist keiner.
    #[must_use]
    pub fn new(
        client: Client,
        bucket: String,
        organization_id: OrganizationId,
        security_events: Arc<dyn SecurityEventSink>,
        object_types: Arc<dyn ObjectTypeDirectory>,
        clock: Arc<dyn ServerClock>,
    ) -> Self {
        Self {
            client,
            bucket,
            organization_id,
            security_events,
            object_types,
            clock,
        }
    }

    /// Bricht einen angefangenen mehrteiligen Upload ab.
    ///
    /// Fehler werden hier BEWUSST verschluckt: der Aufrufer bekommt den
    /// urspruenglichen Befund, und ein liegen gebliebener Teil-Upload ist ein
    /// Betriebsthema, kein zweiter Fehlercode.
    async fn abort_staging(&self, key: &str, upload_id: &str) {
        let _ = self
            .client
            .abort_multipart_upload()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await;
    }

    /// Laedt die Bytes unter `key` und rechnet ihren Objekthash neu.
    async fn stored_hash(&self, key: &str) -> Result<ObjectHash, StoreError> {
        let mut body = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|_| StoreError::Unavailable)?
            .body;
        let mut hasher = StreamingObjectHasher::new();
        while let Some(chunk) = body.next().await {
            hasher.update(&chunk.map_err(|_| StoreError::Unavailable)?);
        }
        Ok(hasher.finish())
    }

    async fn record_hash_conflict(&self, key: &str) {
        // Der Befund selbst darf an einer nicht erreichbaren Datenbank nicht
        // verloren gehen, aber er darf den Fehlercode auch nicht verdraengen:
        // der Aufrufer sieht in jedem Fall EA-STORE-HASH-CONFLICT.
        let _ = self
            .security_events
            .record(SecurityEventV1 {
                organization_id: self.organization_id,
                kind: SecurityEventKindV1::ObjectHashConflict,
                subject: key.to_owned(),
                observed_at: self.clock.now(),
            })
            .await;
    }
}

#[async_trait]
impl ObjectStore for S3ObjectStore {
    async fn stage_stream(
        &self,
        kind: ObjectTypeV1,
        mut body: ByteStream,
        limit: u64,
    ) -> Result<StagedObject, StoreError> {
        let staging_key = format!(
            "{STAGING_PREFIX}/{}/{}",
            object_type_segment(kind),
            hex::encode(staging_nonce())
        );
        let upload = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(&staging_key)
            .content_type(OBJECT_MEDIA_TYPE)
            .send()
            .await
            .map_err(|_| StoreError::Unavailable)?;
        let upload_id = upload
            .upload_id()
            .ok_or(StoreError::Unavailable)?
            .to_owned();

        match self
            .stream_into_parts(kind, &mut body, limit, &staging_key, &upload_id)
            .await
        {
            Ok(staged) => Ok(staged),
            Err(error) => {
                self.abort_staging(&staging_key, &upload_id).await;
                Err(error)
            }
        }
    }

    async fn put_if_absent(&self, staged: StagedObject) -> Result<StoredObject, StoreError> {
        let target = staged.object_key();
        let existing = self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&target)
            .send()
            .await;

        let outcome = match existing {
            Ok(head) => {
                // DIE BYTES ENTSCHEIDEN, die Laenge ist nur ein Schnellpfad.
                //
                // Siehe [`length_proves_conflict`]: eine fehlende
                // `content-length` ist KEIN Konflikt, sondern ein Grund, die
                // Bytes zu holen.
                if length_proves_conflict(
                    head.content_length()
                        .and_then(|length| u64::try_from(length).ok()),
                    staged.size_bytes(),
                ) || self.stored_hash(&target).await? != staged.object_hash()
                {
                    self.record_hash_conflict(&target).await;
                    let _ = self
                        .client
                        .delete_object()
                        .bucket(&self.bucket)
                        .key(staged.staging_key())
                        .send()
                        .await;
                    return Err(StoreError::HashConflict);
                }
                StoredObject::new(
                    staged.kind(),
                    staged.object_hash(),
                    staged.size_bytes(),
                    false,
                )
            }
            Err(error) if is_not_found(&error) => {
                self.client
                    .copy_object()
                    .bucket(&self.bucket)
                    .key(&target)
                    .copy_source(format!("{}/{}", self.bucket, staged.staging_key()))
                    .content_type(OBJECT_MEDIA_TYPE)
                    .metadata(METADATA_OBJECT_TYPE, object_type_segment(staged.kind()))
                    .metadata(METADATA_OBJECT_SIZE, staged.size_bytes().to_string())
                    .metadata_directive(aws_sdk_s3::types::MetadataDirective::Replace)
                    .send()
                    .await
                    .map_err(|_| StoreError::Unavailable)?;
                StoredObject::new(
                    staged.kind(),
                    staged.object_hash(),
                    staged.size_bytes(),
                    true,
                )
            }
            Err(_) => return Err(StoreError::Unavailable),
        };

        let _ = self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(staged.staging_key())
            .send()
            .await;
        Ok(outcome)
    }

    async fn get_exact(&self, hash: ObjectHash) -> Result<ByteStream, StoreError> {
        let kind = self
            .object_types
            .object_type_of(hash)
            .await
            .map_err(|_| StoreError::Unavailable)?
            .ok_or(StoreError::NotFound)?;
        let response = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(object_key(kind, hash))
            .send()
            .await
            .map_err(|error| {
                if is_not_found(&error) {
                    StoreError::NotFound
                } else {
                    StoreError::Unavailable
                }
            })?;
        Ok(response.body)
    }
}

impl S3ObjectStore {
    /// Der eigentliche Strom: hashen, Decke durchsetzen, teilweise hochladen.
    ///
    /// Es liegt zu keinem Zeitpunkt mehr als EIN Teil im Speicher, also nie der
    /// volle Koerper. Die Decke wirkt, BEVOR ein Byte gepuffert wird, und der
    /// Strom wird danach nicht weitergelesen — genau das ist die
    /// „groessenbegrenzte“ Zusage von `design.md` §13.3, Schritt 1.
    async fn stream_into_parts(
        &self,
        kind: ObjectTypeV1,
        body: &mut ByteStream,
        limit: u64,
        staging_key: &str,
        upload_id: &str,
    ) -> Result<StagedObject, StoreError> {
        let prefix = exact_object_prefix(kind);
        let mut hasher = StreamingObjectHasher::new();
        let mut buffer: Vec<u8> = Vec::with_capacity(STAGING_PART_BYTES);
        let mut parts: Vec<CompletedPart> = Vec::new();
        let mut head: Vec<u8> = Vec::with_capacity(prefix.len());
        let mut total: u64 = 0;

        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|_| StoreError::Unavailable)?;
            total = total.saturating_add(chunk.len() as u64);
            if total > limit {
                return Err(StoreError::LimitExceeded);
            }
            hasher.update(&chunk);

            // Das Praefix wird geprueft, sobald die ersten neun Bytes da sind —
            // vor dem ersten Teil-Upload und lange vor dem Ende des Stroms.
            if head.len() < prefix.len() {
                let missing = prefix.len() - head.len();
                head.extend_from_slice(&chunk[..missing.min(chunk.len())]);
                if head.len() == prefix.len() && head != prefix {
                    return Err(StoreError::ObjectTypeMismatch);
                }
            }

            buffer.extend_from_slice(&chunk);
            while buffer.len() >= STAGING_PART_BYTES {
                let rest = buffer.split_off(STAGING_PART_BYTES);
                let part = std::mem::replace(&mut buffer, rest);
                self.upload_part(staging_key, upload_id, &mut parts, part)
                    .await?;
            }
        }

        // Ein Koerper, der kuerzer als das Praefix ist, kann kein Archivobjekt
        // dieser Art sein.
        if head.len() < prefix.len() {
            return Err(StoreError::ObjectTypeMismatch);
        }
        // Der letzte Teil darf beliebig klein sein; ein einziger leerer Teil
        // waere nur noetig, wenn gar nichts hochgeladen wurde — und das kann
        // nach der Praefixpruefung nicht mehr eintreten.
        if !buffer.is_empty() {
            self.upload_part(
                staging_key,
                upload_id,
                &mut parts,
                std::mem::take(&mut buffer),
            )
            .await?;
        }

        let completed = aws_sdk_s3::types::CompletedMultipartUpload::builder()
            .set_parts(Some(parts))
            .build();
        self.client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(staging_key)
            .upload_id(upload_id)
            .multipart_upload(completed)
            .send()
            .await
            .map_err(|_| StoreError::Unavailable)?;

        Ok(StagedObject::new(
            kind,
            hasher.finish(),
            total,
            staging_key.to_owned(),
        ))
    }

    async fn upload_part(
        &self,
        key: &str,
        upload_id: &str,
        parts: &mut Vec<CompletedPart>,
        payload: Vec<u8>,
    ) -> Result<(), StoreError> {
        let number = i32::try_from(parts.len() + 1).map_err(|_| StoreError::LimitExceeded)?;
        let uploaded = self
            .client
            .upload_part()
            .bucket(&self.bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(number)
            .body(ByteStream::from(payload))
            .send()
            .await
            .map_err(|_| StoreError::Unavailable)?;
        parts.push(
            CompletedPart::builder()
                .part_number(number)
                .set_e_tag(uploaded.e_tag().map(str::to_owned))
                .build(),
        );
        Ok(())
    }
}

/// Das Exact-Object-Praefix der Art — die ersten neun Bytes jedes
/// Archivobjekts.
const fn exact_object_prefix(kind: ObjectTypeV1) -> &'static [u8] {
    match kind {
        ObjectTypeV1::Entry => &ea_format::EIP_PREFIX_V1,
        ObjectTypeV1::Grant => &ea_format::EAG_PREFIX_V1,
        ObjectTypeV1::Receipt => &ea_format::ESR_PREFIX_V1,
        ObjectTypeV1::Evidence => &ea_format::ECP_PREFIX_V1,
        ObjectTypeV1::Trust => &ea_format::ETB_PREFIX_V1,
        ObjectTypeV1::Destroyed => &ea_format::EDS_PREFIX_V1,
    }
}

/// Die Zufallsmarke eines temporaeren Schluessels.
///
/// Sie muss NUR eindeutig sein, nicht unvorhersagbar: der Schluessel liegt in
/// einem Namensraum, den kein Klient liest.
fn staging_nonce() -> [u8; 16] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let counter = STAGING_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut nonce = [0_u8; 16];
    nonce[..8].copy_from_slice(&(nanos as u64).to_be_bytes());
    nonce[8..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

static STAGING_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Erkennt „gibt es nicht“ unabhaengig davon, ob der Dienst `NoSuchKey` oder
/// nur ein nacktes 404 sendet — `HeadObject` traegt keinen Fehlerkoerper.
fn is_not_found<E, R>(error: &aws_sdk_s3::error::SdkError<E, R>) -> bool
where
    E: std::error::Error + aws_sdk_s3::error::ProvideErrorMetadata,
{
    use aws_sdk_s3::error::SdkError;
    match error {
        SdkError::ServiceError(service) => {
            matches!(service.err().code(), Some("NoSuchKey" | "NotFound" | "404"))
        }
        _ => false,
    }
}

/// Entscheidet allein anhand der LAENGEN, ob ein Konflikt schon feststeht.
///
/// Der Schnellpfad des Put-if-absent, und er taugt nur in EINE Richtung: zwei
/// vollstaendige Objekte verschiedener Laenge koennen nicht dieselben Bytes
/// sein, also erspart eine bekannte, abweichende Laenge den vollen Abruf. Alles
/// andere faellt auf den neu gerechneten Objekthash durch.
///
/// `None` heisst „der Dienst hat keine `content-length` geliefert“ — `HeadObject`
/// muss das nicht. Das ist AUSDRUECKLICH kein Konflikt. Die fruehere Fassung
/// fragte `!same_length || …` und machte daraus eines: ein Security Event ueber
/// Bytes, die nie jemand verglichen hat.
const fn length_proves_conflict(stored_length: Option<u64>, staged_length: u64) -> bool {
    match stored_length {
        Some(length) => length != staged_length,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::length_proves_conflict;

    /// Die drei Antworten des Schnellpfads, einzeln.
    ///
    /// Der mittlere Fall ist der sicherheitsrelevante: eine unbekannte Laenge
    /// darf niemals fuer sich allein einen Konflikt begruenden, sonst zeichnet
    /// der Server ein Security Event ueber Bytes auf, die er nicht angesehen
    /// hat. Das Gegenstueck — gleiche Laenge, andere Bytes — laeuft in
    /// `apps/server/tests/object_store.rs` gegen den echten Dienst.
    #[test]
    fn only_a_known_differing_length_settles_the_conflict() {
        assert!(length_proves_conflict(Some(8), 9));
        assert!(!length_proves_conflict(Some(9), 9));
        assert!(
            !length_proves_conflict(None, 9),
            "an unknown content-length must fall through to the byte comparison, never become a \
             Security Event of its own"
        );
    }
}
