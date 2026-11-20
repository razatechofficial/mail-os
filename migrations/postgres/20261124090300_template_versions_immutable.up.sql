-- A template version is immutable once stored (published): the messages
-- that used it are reconstructed from it as evidence of what was sent, so
-- only its is_active flag may change.
CREATE OR REPLACE FUNCTION template_versions_immutable() RETURNS trigger AS $$
BEGIN
    IF (to_jsonb(NEW) - 'is_active') IS DISTINCT FROM (to_jsonb(OLD) - 'is_active') THEN
        RAISE EXCEPTION 'template version % is immutable; publish a new version instead', OLD.id
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER template_versions_immutable BEFORE UPDATE ON template_versions
    FOR EACH ROW EXECUTE FUNCTION template_versions_immutable();
