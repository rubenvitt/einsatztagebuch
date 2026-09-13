use crate::{
    DestructionError as Error, DestructionState, VerifiedDestructionAuthorization,
    VerifiedDestructionEvent,
};
use ea_types::{DestructionId, EventId, ObjectHash, UnixMillis};
use std::collections::BTreeMap;

/// Pure signed-history reduction. Applying a claim performs no deletion and
/// grants no execution capability; request durability lives in the service.
pub struct DestructionStateMachine {
    destruction: DestructionId,
    authorization: ObjectHash,
    state: Option<DestructionState>,
    last: Option<ObjectHash>,
    last_time: Option<UnixMillis>,
    ids: BTreeMap<EventId, (ObjectHash, Vec<u8>)>,
    hashes: BTreeMap<ObjectHash, Vec<u8>>,
}
#[derive(Debug, Eq, PartialEq)]
pub enum ApplyOutcome {
    Advanced,
    Replay,
}
impl DestructionStateMachine {
    pub fn new(auth: &VerifiedDestructionAuthorization) -> Self {
        Self {
            destruction: auth.fields().destruction_id,
            authorization: auth.object_hash(),
            state: None,
            last: None,
            last_time: None,
            ids: BTreeMap::new(),
            hashes: BTreeMap::new(),
        }
    }
    pub const fn state(&self) -> Option<DestructionState> {
        self.state
    }
    pub const fn last_event_hash(&self) -> Option<ObjectHash> {
        self.last
    }
    pub fn apply(&mut self, event: &VerifiedDestructionEvent) -> Result<ApplyOutcome, Error> {
        let fields = &event.fields;
        if fields.destruction_id != self.destruction
            || fields.destruction_authorization_object_hash != self.authorization
        {
            return Err(Error::SecurityConflict);
        }
        if let Some((hash, bytes)) = self.ids.get(&fields.event_id) {
            return if *hash == event.hash && bytes == &event.exact {
                Ok(ApplyOutcome::Replay)
            } else {
                Err(Error::SecurityConflict)
            };
        }
        if self.hashes.contains_key(&event.hash) {
            return Err(Error::SecurityConflict);
        }
        if fields.previous_event_object_hash != self.last
            || fields.from_state != self.state.map(DestructionState::code)
            || !transition_allowed(fields.from_state, fields.to_state)
            || self.last_time.is_some_and(|last| fields.executed_at < last)
        {
            return Err(Error::SecurityConflict);
        }
        self.ids
            .insert(fields.event_id, (event.hash, event.exact.clone()));
        self.hashes.insert(event.hash, event.exact.clone());
        self.state = DestructionState::from_code(fields.to_state);
        self.last = Some(event.hash);
        self.last_time = Some(fields.executed_at);
        Ok(ApplyOutcome::Advanced)
    }
}
pub fn transition_allowed(from: Option<u8>, to: u8) -> bool {
    match (from, DestructionState::from_code(to)) {
        (None, Some(DestructionState::Requested)) => true,
        (Some(from), Some(to)) => {
            DestructionState::from_code(from).is_some_and(|from| from.may_advance_to(to))
        }
        _ => false,
    }
}
