ALTER TABLE alerts ADD COLUMN organization_id TEXT REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE alerts ADD COLUMN status TEXT NOT NULL DEFAULT 'open'
    CHECK (status IN ('open', 'acknowledged', 'resolved'));
ALTER TABLE alerts ADD COLUMN acknowledged_by TEXT REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE alerts ADD COLUMN acknowledged_at TEXT;
ALTER TABLE alerts ADD COLUMN resolved_by TEXT REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE alerts ADD COLUMN resolved_at TEXT;
ALTER TABLE alerts ADD COLUMN rule_key TEXT;
ALTER TABLE alerts ADD COLUMN details TEXT NOT NULL DEFAULT '{}';

UPDATE alerts
SET organization_id = (
    SELECT websites.organization_id
    FROM websites
    WHERE websites.id = alerts.website_id
)
WHERE organization_id IS NULL;

CREATE INDEX idx_alerts_organization_status_created
    ON alerts (organization_id, status, created_at DESC);

CREATE INDEX idx_alerts_website_created
    ON alerts (website_id, created_at DESC);

CREATE INDEX idx_alerts_rule_key_created
    ON alerts (rule_key, created_at DESC);
