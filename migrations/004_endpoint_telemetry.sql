
CREATE TABLE endpoint_hosts (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    os_type TEXT NOT NULL
        CHECK (os_type IN ('windows', 'linux')),
    agent_version TEXT NOT NULL DEFAULT '',
    credential_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled')),
    last_heartbeat TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (organization_id, hostname, os_type),
    FOREIGN KEY (organization_id)
        REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE INDEX idx_endpoint_hosts_org_status
    ON endpoint_hosts (organization_id, status);

CREATE TABLE endpoint_events (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    event_uid TEXT NOT NULL,
    event_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL
        CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    risk_score INTEGER NOT NULL
        CHECK (risk_score BETWEEN 0 AND 100),
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    source_ip TEXT,
    account_name TEXT,
    details TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (host_id)
        REFERENCES endpoint_hosts(id) ON DELETE CASCADE,
    UNIQUE (host_id, event_uid)
);

CREATE INDEX idx_endpoint_events_host_time
    ON endpoint_events (host_id, occurred_at DESC);

CREATE INDEX idx_endpoint_events_type_severity
    ON endpoint_events (event_type, severity, occurred_at DESC);
