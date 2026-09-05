-- Rein technischer Cache-Stand, keine Autoritaet. Die exakten signierten
-- Trust-Objekte bleiben die einzige Quelle fuer Zertifikate und Capabilities.
-- Ein globales Sequenz-Token vermeidet wiederverwendete Staende auch dann,
-- wenn eine Organisation unter derselben Kennung geloescht und neu angelegt
-- wird. Die Originalmigration bleibt fuer bestehende Installationen exakt.
CREATE SEQUENCE trust_catalog_revision_seq;

ALTER TABLE organizations
    ADD COLUMN trust_catalog_revision BIGINT NOT NULL
    DEFAULT nextval('trust_catalog_revision_seq');

-- Der Trigger laeuft IN der Indextransaktion. Jede Serverinstanz sieht die
-- neuen Objekte und ihr neues Token gemeinsam; Rollbacks publizieren weder
-- Objekte noch einen neuen Cache-Stand. Auch Reparaturen am Katalog nehmen
-- denselben Weg, ohne dass eine Prozessbenachrichtigung verloren gehen kann.
CREATE FUNCTION invalidate_trust_authority_cache() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE organizations SET trust_catalog_revision = nextval('trust_catalog_revision_seq')
        WHERE organization_id = NEW.organization_id;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE organizations SET trust_catalog_revision = nextval('trust_catalog_revision_seq')
        WHERE organization_id = OLD.organization_id;
    ELSE
        UPDATE organizations SET trust_catalog_revision = nextval('trust_catalog_revision_seq')
        WHERE organization_id IN (OLD.organization_id, NEW.organization_id);
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER trust_authority_cache_changed
AFTER INSERT OR UPDATE OR DELETE ON trust_events
FOR EACH ROW EXECUTE FUNCTION invalidate_trust_authority_cache();

CREATE FUNCTION invalidate_truncated_trust_authority_cache() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE organizations SET trust_catalog_revision = nextval('trust_catalog_revision_seq');
    RETURN NULL;
END;
$$;

CREATE TRIGGER trust_authority_cache_truncated
AFTER TRUNCATE ON trust_events
FOR EACH STATEMENT EXECUTE FUNCTION invalidate_truncated_trust_authority_cache();
