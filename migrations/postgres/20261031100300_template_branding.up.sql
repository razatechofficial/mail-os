-- An organization's template branding: the designer's defaults. Absent
-- until an administrator saves one; reads fill the defaults.
CREATE TABLE IF NOT EXISTS template_branding (
    org_id                   VARCHAR(36) PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    company_name             TEXT        NOT NULL DEFAULT '',
    logo_url                 TEXT        NOT NULL DEFAULT '',
    logo_alt                 TEXT        NOT NULL DEFAULT '',
    primary_color            VARCHAR(7)  NOT NULL,
    background_color         VARCHAR(7)  NOT NULL,
    content_background_color VARCHAR(7)  NOT NULL,
    text_color               VARCHAR(7)  NOT NULL,
    link_color               VARCHAR(7)  NOT NULL,
    font_family              TEXT        NOT NULL,
    company_address          TEXT        NOT NULL DEFAULT '',
    footer_text              TEXT        NOT NULL DEFAULT '',
    updated_by               TEXT,
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);
