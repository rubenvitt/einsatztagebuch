-- Exact request + signed local audit are committed in one SQLCipher transaction.
-- A server reservation is not this authoritative audited state event.
CREATE TABLE destruction_request (
    organization_id BLOB NOT NULL CHECK(length(organization_id)=16),
    destruction_id BLOB NOT NULL CHECK(length(destruction_id)=16),
    event_id BLOB NOT NULL UNIQUE CHECK(length(event_id)=16),
    event_hash BLOB NOT NULL UNIQUE CHECK(length(event_hash)=32),
    exact_authorization BLOB NOT NULL,
    exact_event BLOB NOT NULL,
    audit_event_id BLOB NOT NULL UNIQUE REFERENCES local_audit_event(event_id),
    PRIMARY KEY (organization_id, destruction_id)
);
CREATE TRIGGER destruction_request_no_update BEFORE UPDATE ON destruction_request
BEGIN SELECT RAISE(ABORT, 'destruction requests are append-only'); END;
CREATE TRIGGER destruction_request_no_delete BEFORE DELETE ON destruction_request
BEGIN SELECT RAISE(ABORT, 'destruction requests are append-only'); END;
