-- Operational custody is monotone and never confers a cryptographic role.
-- An immutable snapshot cannot silently lose a revoked/offline custodian.
CREATE TABLE managed_custody (
    organization_id BLOB NOT NULL CHECK(length(organization_id)=16),
    record_hash BLOB NOT NULL CHECK(length(record_hash)=32),
    exact_bytes BLOB NOT NULL,
    PRIMARY KEY(organization_id,record_hash)
);
CREATE TABLE destruction_inventory (
    organization_id BLOB NOT NULL CHECK(length(organization_id)=16),
    destruction_id BLOB NOT NULL CHECK(length(destruction_id)=16),
    authorization_hash BLOB NOT NULL CHECK(length(authorization_hash)=32),
    exact_bytes BLOB NOT NULL,
    PRIMARY KEY(organization_id,destruction_id),
    FOREIGN KEY(organization_id,destruction_id)
        REFERENCES destruction_request(organization_id,destruction_id)
);
CREATE TRIGGER managed_custody_no_update BEFORE UPDATE ON managed_custody
BEGIN SELECT RAISE(ABORT,'managed custody is append-only'); END;
CREATE TRIGGER managed_custody_no_delete BEFORE DELETE ON managed_custody
BEGIN SELECT RAISE(ABORT,'managed custody is append-only'); END;
CREATE TRIGGER destruction_inventory_no_update BEFORE UPDATE ON destruction_inventory
BEGIN SELECT RAISE(ABORT,'destruction inventory is immutable'); END;
CREATE TRIGGER destruction_inventory_no_delete BEFORE DELETE ON destruction_inventory
BEGIN SELECT RAISE(ABORT,'destruction inventory is immutable'); END;
