-- Durable per-installation trust pins and authorization replay state.
-- SQLCipher covers this file together with the profile and audit journal.
CREATE TABLE operator_trust_state (
    organization_id BLOB NOT NULL CHECK(length(organization_id)=16),
    device_id BLOB NOT NULL CHECK(length(device_id)=16),
    chain_id BLOB NOT NULL CHECK(length(chain_id)=16),
    trust_anchor_hash BLOB NOT NULL CHECK(length(trust_anchor_hash)=32),
    revision BLOB NOT NULL CHECK(length(revision)=8),
    floor_ms INTEGER NOT NULL,
    independent_kind INTEGER CHECK(independent_kind IN (0,1,2)),
    independent_hash BLOB CHECK(length(independent_hash)=32),
    independent_time_ms INTEGER,
    pin_version BLOB CHECK(length(pin_version)=8),
    pin_hash BLOB CHECK(length(pin_hash)=32),
    PRIMARY KEY(organization_id,device_id),
    CHECK((independent_kind IS NULL AND independent_hash IS NULL AND independent_time_ms IS NULL)
       OR (independent_kind IS NOT NULL AND independent_hash IS NOT NULL AND independent_time_ms IS NOT NULL AND independent_time_ms<=floor_ms)),
    CHECK((pin_version IS NULL AND pin_hash IS NULL) OR (pin_version IS NOT NULL AND pin_hash IS NOT NULL))
) STRICT;

CREATE TABLE operator_admin_replay (
    organization_id BLOB NOT NULL CHECK(length(organization_id)=16),
    dimension INTEGER NOT NULL CHECK(dimension IN (0,1)),
    replay_value BLOB NOT NULL,
    PRIMARY KEY(organization_id,dimension,replay_value),
    CHECK((dimension=0 AND length(replay_value)=16) OR (dimension=1 AND length(replay_value)=32))
) STRICT;

CREATE TABLE operator_clock_release_replay (
    organization_id BLOB NOT NULL CHECK(length(organization_id)=16),
    device_id BLOB NOT NULL CHECK(length(device_id)=16),
    nonce BLOB NOT NULL CHECK(length(nonce)=32),
    PRIMARY KEY(organization_id,device_id,nonce)
) STRICT;
