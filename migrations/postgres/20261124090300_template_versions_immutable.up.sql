-- A template version is immutable once stored (published), and one a
-- message used is never deleted: the messages are reconstructed from it as
-- evidence of what was sent (ADR 0001 §3.14 class (a)). Only is_active may
-- change. Removing the whole tenant (organizations cascade) still removes
-- its templates and messages together.
CREATE OR REPLACE FUNCTION template_versions_immutable() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF EXISTS (SELECT 1 FROM templates WHERE id = OLD.template_id)
           AND EXISTS (SELECT 1 FROM messages WHERE template_version_id = OLD.id) THEN
            RAISE EXCEPTION 'template version % was used by a message and is kept', OLD.id
                USING ERRCODE = 'restrict_violation';
        END IF;
        RETURN OLD;
    END IF;
    IF (to_jsonb(NEW) - 'is_active') IS DISTINCT FROM (to_jsonb(OLD) - 'is_active') THEN
        RAISE EXCEPTION 'template version % is immutable; publish a new version instead', OLD.id
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER template_versions_immutable BEFORE UPDATE OR DELETE ON template_versions
    FOR EACH ROW EXECUTE FUNCTION template_versions_immutable();

-- A template whose versions a message used is never hard-deleted (the
-- product soft-deletes); only its tenant's removal takes it.
CREATE OR REPLACE FUNCTION templates_keep_used() RETURNS trigger AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM organizations WHERE id = OLD.org_id)
       AND EXISTS (SELECT 1 FROM messages m JOIN template_versions v ON v.id = m.template_version_id
                   WHERE v.template_id = OLD.id) THEN
        RAISE EXCEPTION 'template % has versions messages used and is kept', OLD.id
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER templates_keep_used BEFORE DELETE ON templates
    FOR EACH ROW EXECUTE FUNCTION templates_keep_used();
