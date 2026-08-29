-- Die EINE Migration der Stufe 3.
--
-- `design.md` §13.4 zaehlt auf, was PostgreSQL mindestens enthaelt, und nennt
-- die eindeutigen Constraints, die MINDESTENS gelten: `chainId` + `sequence`,
-- `entryHash`, `objectHash`, Registry-Version und Request-ID. Alle fuenf
-- entstehen HIER und werden nicht spaeter nachgezogen. Migrationsfortschritt
-- gegen eine bereits ausgelieferte Installation — Reihenfolge,
-- Rueckwaertsvertraeglichkeit, Nachweis gegen einen bestehenden Bestand — ist
-- ausdruecklich Gegenstand der Stufe 7 und entsteht nicht ad hoc hier.
--
-- KEINE SPALTE DIESER DATEI TRAEGT EINEN FACHLICHEN WERT. Es gibt keine
-- Einsatznummer, keine Einsatzzeit, kein Stichwort, keinen Ort, keine Person,
-- kein Fahrzeug, keinen Patienten und keine Notiz — der Server bleibt blind,
-- und `apps/server/tests/migrations.rs` prueft genau das gegen
-- `information_schema.columns`. Zeiten sind ausschliesslich SERVERSEITIGE
-- technische Zeitpunkte in Millisekunden seit der Unix-Epoche und heissen
-- deshalb einheitlich `*_millis`.
--
-- Bytes stehen als `bytea` mit exakter Laengenpruefung: eine 16-Byte-Kennung
-- und ein 32-Byte-Hash sind Formate, keine Meinungen, und eine Pruefung an der
-- Tabelle faengt sie auch dann, wenn ein spaeterer Aufrufer sie vergisst.

CREATE TABLE organizations (
    organization_id BYTEA PRIMARY KEY CHECK (octet_length(organization_id) = 16),
    root_key_thumbprint BYTEA NOT NULL CHECK (octet_length(root_key_thumbprint) = 32),
    -- Die exakten Bytes des Trust Anchors dieser Organisation. Sie sind der
    -- EINZIGE Einstieg, an dem `ea_trust::verify_trust` serverseitig ueberhaupt
    -- ansetzen kann: ohne Anker gibt es keine Wurzel, gegen die eine
    -- Zertifikatskette prueft, und der Server muesste Rollen aus Zeilen raten.
    -- Genau das verbietet `design.md` §12. Nullable, weil eine Organisation
    -- technisch angelegt sein kann, bevor ihr Anker vorliegt; ohne Anker
    -- antwortet die Autoritaetsaufloesung fail-closed mit „unbekannt“.
    trust_anchor_bytes BYTEA,
    created_at_millis BIGINT NOT NULL
);

-- Ausgestellte Challenges (`design.md` §13.1). Die Tabelle wird EINMAL
-- geschrieben — von `POST /v1/auth/challenges` — und von der
-- Geraeteregistrierung, der WebAuthn-Credential-Registrierung und dem
-- Vault-Blob-Abruf gelesen. Gespeichert wird ausschliesslich der DIGEST der
-- Nonce und ihr Zustand: der Server braucht die Nonce nie im Klartext zurueck,
-- er muss nur wiedererkennen, dass er sie ausgegeben hat und dass sie noch
-- offen ist. Ein Auslesen dieser Tabelle gibt deshalb keine gueltige Nonce her.
--
-- Sie und nicht `replay_nonces` fuehrt die Einmaligkeit der Challenge-Nonce:
-- der Verbrauch allein reichte nicht, weil auch die AUSGABE gelesen werden
-- muss — vom signierten Registrierungs- und Credentialpfad ebenso wie vom
-- UNSIGNIERTEN Vault-Blob-Abruf, der gar keinen RFC-9421-Speicher anfasst.
CREATE TABLE challenges (
    organization_id BYTEA NOT NULL REFERENCES organizations (organization_id),
    nonce_digest BYTEA NOT NULL CHECK (octet_length(nonce_digest) = 32),
    challenge_state TEXT NOT NULL CHECK (challenge_state IN ('issued', 'spent')),
    issued_at_millis BIGINT NOT NULL,
    expires_at_millis BIGINT NOT NULL,
    spent_at_millis BIGINT,
    PRIMARY KEY (organization_id, nonce_digest),
    CHECK ((challenge_state = 'spent') = (spent_at_millis IS NOT NULL))
);

-- Die Ratenbegrenzung zaehlt je Organisation ueber ein Zeitfenster. Ohne
-- diesen Index waere das ein Scan ueber alle je ausgegebenen Challenges.
CREATE INDEX challenges_rate_window ON challenges (organization_id, issued_at_millis);

-- Beantragte, noch nicht freigegebene Geraete (`design.md` §13.1, Proof of
-- Possession). Der beantragte Schluessel ist hier abgelegt, verleiht aber
-- keine Autoritaet: die kommt ausschliesslich aus Root-signierten
-- Trust-Objekten.
CREATE TABLE pending_device_requests (
    organization_id BYTEA NOT NULL REFERENCES organizations (organization_id),
    device_id BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    requested_key_thumbprint BYTEA NOT NULL CHECK (octet_length(requested_key_thumbprint) = 32),
    request_object_hash BYTEA NOT NULL CHECK (octet_length(request_object_hash) = 32),
    request_state TEXT NOT NULL,
    received_at_millis BIGINT NOT NULL,
    PRIMARY KEY (organization_id, device_id)
);

-- Die `.etb`-Kette einer Organisation.
CREATE TABLE trust_events (
    organization_id BYTEA NOT NULL REFERENCES organizations (organization_id),
    event_id BYTEA NOT NULL CHECK (octet_length(event_id) = 16),
    object_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(object_hash) = 32),
    event_code TEXT NOT NULL,
    received_at_millis BIGINT NOT NULL,
    PRIMARY KEY (organization_id, event_id)
);

-- Die Registrierungskoepfe. Der Primaerschluessel IST der geforderte
-- Eindeutigkeitszwang ueber die Registry-Version.
CREATE TABLE registry_events (
    organization_id BYTEA NOT NULL REFERENCES organizations (organization_id),
    registry_version BIGINT NOT NULL CHECK (registry_version >= 0),
    registry_head_hash BYTEA NOT NULL CHECK (octet_length(registry_head_hash) = 32),
    effective_from_millis BIGINT NOT NULL,
    PRIMARY KEY (organization_id, registry_version)
);

-- Rollenintervalle je Zertifikat und Capability, in SEQUENZEN gemessen: die
-- Lease einer Rolle ist eine Kettenposition, keine Wanduhrzeit.
CREATE TABLE role_intervals (
    organization_id BYTEA NOT NULL REFERENCES organizations (organization_id),
    certificate_hash BYTEA NOT NULL CHECK (octet_length(certificate_hash) = 32),
    capability_code TEXT NOT NULL,
    from_sequence BIGINT NOT NULL CHECK (from_sequence >= 0),
    until_sequence BIGINT CHECK (until_sequence >= from_sequence),
    registry_version BIGINT NOT NULL CHECK (registry_version >= 0),
    PRIMARY KEY (organization_id, certificate_hash, capability_code, from_sequence)
);

-- Der gesperrte Kettenkopf (`design.md` §13.3, Schritt 4). `revision` traegt
-- das optimistische Compare-and-Set der Commit-Transaktion.
CREATE TABLE chain_heads (
    organization_id BYTEA NOT NULL REFERENCES organizations (organization_id),
    chain_id BYTEA NOT NULL CHECK (octet_length(chain_id) = 16),
    head_sequence BIGINT NOT NULL CHECK (head_sequence >= 0),
    head_entry_hash BYTEA NOT NULL CHECK (octet_length(head_entry_hash) = 32),
    head_accepted_at_server_millis BIGINT NOT NULL,
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
    PRIMARY KEY (organization_id, chain_id)
);

-- Die Entries. Drei der fuenf geforderten Eindeutigkeiten stehen hier:
-- `entryHash` als Primaerschluessel, `chainId` + `sequence` und der
-- `.eip`-`objectHash`.
CREATE TABLE entries (
    entry_hash BYTEA PRIMARY KEY CHECK (octet_length(entry_hash) = 32),
    organization_id BYTEA NOT NULL REFERENCES organizations (organization_id),
    chain_id BYTEA NOT NULL CHECK (octet_length(chain_id) = 16),
    sequence_number BIGINT NOT NULL CHECK (sequence_number >= 0),
    previous_entry_hash BYTEA CHECK (octet_length(previous_entry_hash) = 32),
    entry_object_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(entry_object_hash) = 32),
    initial_grant_plan_hash BYTEA NOT NULL CHECK (octet_length(initial_grant_plan_hash) = 32),
    receipt_object_hash BYTEA NOT NULL CHECK (octet_length(receipt_object_hash) = 32),
    device_id BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    accepted_at_server_millis BIGINT NOT NULL,
    evidence_due_at_millis BIGINT NOT NULL,
    registry_version BIGINT NOT NULL CHECK (registry_version >= 0),
    registry_head_hash BYTEA NOT NULL CHECK (octet_length(registry_head_hash) = 32),
    UNIQUE (chain_id, sequence_number)
);

-- Der technische Objektindex. Der Primaerschluessel IST der geforderte
-- Eindeutigkeitszwang ueber den `objectHash`, und er ist zugleich die Quelle,
-- aus der der Object Store die Objektart zu einem Hash aufloest.
CREATE TABLE object_index (
    object_hash BYTEA PRIMARY KEY CHECK (octet_length(object_hash) = 32),
    organization_id BYTEA NOT NULL REFERENCES organizations (organization_id),
    object_type_code SMALLINT NOT NULL CHECK (object_type_code BETWEEN 1 AND 6),
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    stored_at_millis BIGINT NOT NULL
);

-- Freigaben. Der Empfaenger steht als Schluesselabdruck da, nicht als Person.
CREATE TABLE grants (
    object_hash BYTEA PRIMARY KEY REFERENCES object_index (object_hash),
    organization_id BYTEA NOT NULL REFERENCES organizations (organization_id),
    entry_hash BYTEA NOT NULL REFERENCES entries (entry_hash),
    recipient_key_thumbprint BYTEA NOT NULL CHECK (octet_length(recipient_key_thumbprint) = 32),
    grant_kind_code TEXT NOT NULL,
    expires_at_millis BIGINT
);

-- Serverquittungen. Ein Entry traegt genau eine.
CREATE TABLE receipts (
    object_hash BYTEA PRIMARY KEY REFERENCES object_index (object_hash),
    organization_id BYTEA NOT NULL REFERENCES organizations (organization_id),
    entry_hash BYTEA NOT NULL UNIQUE REFERENCES entries (entry_hash),
    accepted_at_server_millis BIGINT NOT NULL,
    evidence_due_at_millis BIGINT NOT NULL
);

-- Checkpoints. `technical_index` ist die Blaetterposition, auf die sich der
-- `lastTechnicalIndex` eines technischen Cursors bezieht — eine reine
-- Zaehlgroesse ohne fachliche Bedeutung.
CREATE TABLE checkpoints (
    object_hash BYTEA PRIMARY KEY REFERENCES object_index (object_hash),
    organization_id BYTEA NOT NULL REFERENCES organizations (organization_id),
    chain_id BYTEA NOT NULL CHECK (octet_length(chain_id) = 16),
    covered_sequence BIGINT NOT NULL CHECK (covered_sequence >= 0),
    issued_at_millis BIGINT NOT NULL,
    technical_index BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE
);

-- Evidence-Auftraege. `due_at_millis` ist die `evidence-due-at` des Receipts.
CREATE TABLE evidence_jobs (
    organization_id BYTEA NOT NULL REFERENCES organizations (organization_id),
    entry_hash BYTEA NOT NULL REFERENCES entries (entry_hash),
    due_at_millis BIGINT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    job_state TEXT NOT NULL,
    last_attempt_at_millis BIGINT,
    PRIMARY KEY (organization_id, entry_hash)
);

-- Reader-Acknowledgements. Der Leser steht als pseudonyme `subjectId` da.
CREATE TABLE reader_acknowledgements (
    organization_id BYTEA NOT NULL REFERENCES organizations (organization_id),
    subject_id BYTEA NOT NULL CHECK (octet_length(subject_id) = 16),
    entry_hash BYTEA NOT NULL REFERENCES entries (entry_hash),
    ack_object_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(ack_object_hash) = 32),
    acknowledged_at_millis BIGINT NOT NULL,
    PRIMARY KEY (organization_id, subject_id, entry_hash)
);

-- RESERVIERT. Die Einmaligkeit der Challenge-Nonce fuehrt seit dem
-- Auth-Task die Tabelle `challenges`: sie kennt neben dem Verbrauch auch die
-- AUSGABE, und die liest der unsignierte Vault-Blob-Abruf ebenfalls. Diese
-- Tabelle bleibt fuer Einmalwerte, die nicht aus einer Challenge stammen; sie
-- wird derzeit von keinem Pfad beschrieben. Sie steht hier statt in einer
-- spaeteren Migration, weil die Stufe 3 GENAU EINE Migration liefert.
CREATE TABLE replay_nonces (
    organization_id BYTEA NOT NULL REFERENCES organizations (organization_id),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 32),
    consumed_at_millis BIGINT NOT NULL,
    expires_at_millis BIGINT NOT NULL,
    PRIMARY KEY (organization_id, nonce)
);

-- Request-IDs. Der Primaerschluessel IST der fuenfte geforderte
-- Eindeutigkeitszwang; eine Request-ID wird genau einmal angenommen.
CREATE TABLE request_ids (
    organization_id BYTEA NOT NULL REFERENCES organizations (organization_id),
    request_id BYTEA NOT NULL CHECK (octet_length(request_id) = 16),
    seen_at_millis BIGINT NOT NULL,
    expires_at_millis BIGINT NOT NULL,
    PRIMARY KEY (organization_id, request_id)
);

-- Security Events, append-only. `subject_key` traegt AUSSCHLIESSLICH eine
-- technische Kennung — einen Objektschluessel, einen Hex-Hash oder eine
-- Sequenz. Eine freie Beschreibung gibt es bewusst nicht: sie waere der Kanal,
-- ueber den ein fachlicher Wert doch noch in die Datenbank kaeme.
CREATE TABLE security_events (
    security_event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id BYTEA NOT NULL CHECK (octet_length(organization_id) = 16),
    event_code TEXT NOT NULL,
    subject_key TEXT NOT NULL,
    observed_at_millis BIGINT NOT NULL
);

-- Technisches Administrationsaudit. Es protokolliert Verwaltungshandlungen am
-- Server, nicht Einsaetze; der Handelnde steht als pseudonyme
-- Operator-Kennung da.
CREATE TABLE technical_admin_audit (
    admin_audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id BYTEA NOT NULL REFERENCES organizations (organization_id),
    operator_subject_id BYTEA NOT NULL CHECK (octet_length(operator_subject_id) = 16),
    action_code TEXT NOT NULL,
    subject_key TEXT NOT NULL,
    recorded_at_millis BIGINT NOT NULL
);

-- WebAuthn-Credentials der Leser (`web-reader-design.md` §6.4.1). Die
-- Registrierung verleiht dem Server KEINE Autoritaet; sie entscheidet allein,
-- wem er ein Chiffrat aushaendigt, das ohne Authenticator wertlos ist. Die
-- geforderte Eindeutigkeit ist (`organizationId`, `credentialId`).
CREATE TABLE webauthn_credentials (
    organization_id BYTEA NOT NULL REFERENCES organizations (organization_id),
    subject_id BYTEA NOT NULL CHECK (octet_length(subject_id) = 16),
    credential_id BYTEA NOT NULL CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
    public_key BYTEA NOT NULL,
    signature_counter BIGINT NOT NULL DEFAULT 0 CHECK (signature_counter >= 0),
    registered_at_millis BIGINT NOT NULL,
    PRIMARY KEY (organization_id, subject_id, credential_id),
    UNIQUE (organization_id, credential_id)
);

-- Wrapped-Reader-Vault-Blobs (`web-reader-design.md` §6.4). Ein opakes
-- Chiffrat, ausschliesslich ueber `subjectId` und Blobhash geschluesselt. Es
-- liegt AUSDRUECKLICH NICHT im Object Store unter `<type>/<hex objectHash>`:
-- dieser Namensraum ist dem Archivobjekt vorbehalten. Der Server kennt weder
-- Vault-Key noch PRF-Ausgaben.
CREATE TABLE reader_vault_blobs (
    subject_id BYTEA NOT NULL CHECK (octet_length(subject_id) = 16),
    blob_hash BYTEA NOT NULL CHECK (octet_length(blob_hash) = 32),
    ciphertext BYTEA NOT NULL,
    stored_at_millis BIGINT NOT NULL,
    PRIMARY KEY (subject_id, blob_hash)
);

-- Der persistente `ea_trust::TrustStateStore` des Servers. `revision` traegt
-- das Compare-and-Set: ein Commit gewinnt genau dann, wenn er die Revision
-- nennt, die er gelesen hat. Der Zeitboden ist streng monoton — ein
-- rueckwaerts laufender Boden waere genau der Angriff, gegen den `ea-time` ihn
-- ueberhaupt fuehrt.
CREATE TABLE trust_state (
    organization_id BYTEA NOT NULL CHECK (octet_length(organization_id) = 16),
    device_id BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    revision BIGINT NOT NULL CHECK (revision >= 0),
    trusted_floor_millis BIGINT NOT NULL,
    independent_kind_code SMALLINT CHECK (independent_kind_code BETWEEN 0 AND 2),
    independent_object_hash BYTEA CHECK (octet_length(independent_object_hash) = 32),
    independent_verified_at_millis BIGINT,
    pinned_registry_version BIGINT CHECK (pinned_registry_version >= 0),
    pinned_registry_head_hash BYTEA CHECK (octet_length(pinned_registry_head_hash) = 32),
    PRIMARY KEY (organization_id, device_id),
    CHECK ((independent_kind_code IS NULL) = (independent_object_hash IS NULL)),
    CHECK ((independent_kind_code IS NULL) = (independent_verified_at_millis IS NULL)),
    CHECK ((pinned_registry_version IS NULL) = (pinned_registry_head_hash IS NULL))
);

-- Die laufuebergreifende Wiedereinspielsperre der Uhrfreigabe. Der
-- Primaerschluessel IST die Sperre: ein zweites Einspielen desselben
-- Nachweises verletzt ihn.
CREATE TABLE clock_release_replays (
    organization_id BYTEA NOT NULL CHECK (octet_length(organization_id) = 16),
    target_device_id BYTEA NOT NULL CHECK (octet_length(target_device_id) = 16),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 32),
    consumed_at_millis BIGINT NOT NULL,
    PRIMARY KEY (organization_id, target_device_id, nonce)
);
