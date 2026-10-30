CREATE TABLE contact_list_members (
    contact_list_id VARCHAR(36) NOT NULL REFERENCES contact_lists(id) ON DELETE CASCADE,
    contact_id VARCHAR(36) NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (contact_list_id, contact_id)
);
CREATE INDEX idx_contact_list_members_contact_id ON contact_list_members(contact_id);
