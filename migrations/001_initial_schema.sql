CREATE TABLE organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    created_at TEXT NOT NULL
);

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled')),
    created_at TEXT NOT NULL
);

CREATE TABLE organization_users (
    organization_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL
        CHECK (role IN (
            'SUPER_ADMIN', 'MANAGER', 'ANALYST', 'VIEWER'
        )),
    created_at TEXT NOT NULL,
    PRIMARY KEY (organization_id, user_id),
    FOREIGN KEY (organization_id)
        REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE websites (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    created_by TEXT NOT NULL,
    domain TEXT NOT NULL,
    hash_id TEXT NOT NULL UNIQUE,
    api_key_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled')),
    created_at TEXT NOT NULL,
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id)
        REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, created_by)
        REFERENCES organization_users(organization_id, user_id)
);

CREATE TABLE website_users (
    website_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    permission TEXT NOT NULL DEFAULT 'read'
        CHECK (permission IN ('read', 'investigate')),
    created_at TEXT NOT NULL,
    PRIMARY KEY (website_id, user_id),
    FOREIGN KEY (website_id)
        REFERENCES websites(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE invitations (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    email TEXT NOT NULL COLLATE NOCASE,
    role TEXT NOT NULL
        CHECK (role IN ('MANAGER', 'ANALYST', 'VIEWER')),
    token_hash TEXT NOT NULL UNIQUE,
    invited_by TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    accepted_at TEXT,
    revoked_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (organization_id)
        REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, invited_by)
        REFERENCES organization_users(organization_id, user_id)
);

CREATE TABLE logs (
    id TEXT PRIMARY KEY,
    website_id TEXT NOT NULL,
    ip TEXT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER NOT NULL
        CHECK (status BETWEEN 100 AND 599),
    user_agent TEXT,
    country TEXT,
    city TEXT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL
        CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    created_at TEXT NOT NULL,
    FOREIGN KEY (website_id)
        REFERENCES websites(id) ON DELETE CASCADE
);

CREATE TABLE alerts (
    id TEXT PRIMARY KEY,
    website_id TEXT NOT NULL,
    severity TEXT NOT NULL
        CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    type TEXT NOT NULL,
    message TEXT NOT NULL,
    ip TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (website_id)
        REFERENCES websites(id) ON DELETE CASCADE
);

CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    user_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (organization_id)
        REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE SET NULL
);