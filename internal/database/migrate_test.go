package database

import (
	"context"
	"path/filepath"
	"testing"
)

func TestMigrateCreatesInitialSchema(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "migration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("first migration failed: %v", err)
	}

	var count int
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM sqlite_master
		WHERE type = 'table'
		  AND name IN ('organizations', 'users', 'websites', 'logs', 'alerts')
	`).Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Fatalf("expected 5 core tables, got %d", count)
	}

	rows, err := db.QueryContext(ctx, `PRAGMA table_info(alerts)`)
	if err != nil {
		t.Fatal(err)
	}

	columns := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, primaryKey int
		var defaultValue any

		if err := rows.Scan(
			&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey,
		); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		columns[name] = true
	}

	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{
		"organization_id",
		"status",
		"acknowledged_by",
		"acknowledged_at",
		"resolved_by",
		"resolved_at",
		"rule_key",
		"details",
	} {
		if !columns[name] {
			t.Errorf("expected alerts table to contain column %q", name)
		}
	}

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("second migration failed: %v", err)
	}

	var applied int
	if err := db.QueryRowContext(
		ctx,
		"SELECT COUNT(*) FROM schema_migrations",
	).Scan(&applied); err != nil {
		t.Fatal(err)
	}

	if applied != 3 {
		t.Fatalf("expected 3 recorded migrations, got %d", applied)
	}
}

func TestAlertLifecycleDefaultsAndStatusConstraint(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "alert-lifecycle.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	statements := []string{
		`INSERT INTO organizations (id, name, created_at)
		 VALUES ('org-test', 'Test Org', '2026-10-23T00:00:00Z')`,
		`INSERT INTO users (id, name, email, password_hash, created_at)
		 VALUES ('user-test', 'Test User', 'test@example.com', 'test-hash', '2026-10-23T00:00:00Z')`,
		`INSERT INTO organization_users (organization_id, user_id, role, created_at)
		 VALUES ('org-test', 'user-test', 'SUPER_ADMIN', '2026-10-23T00:00:00Z')`,
		`INSERT INTO websites (
			id, organization_id, created_by, domain, hash_id, api_key_hash, created_at
		 ) VALUES (
			'website-test', 'org-test', 'user-test', 'example.com',
			'hash-test', 'api-hash-test', '2026-10-23T00:00:00Z'
		 )`,
		`INSERT INTO alerts (
			id, website_id, organization_id, severity, type, message, created_at
		 ) VALUES (
			'alert-test', 'website-test', 'org-test', 'high',
			'brute_force', 'Repeated login failures', '2026-10-23T00:00:00Z'
		 )`,
	}

	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("insert test fixture: %v", err)
		}
	}

	var organizationID, status string
	err = db.QueryRowContext(ctx, `
		SELECT organization_id, status
		FROM alerts
		WHERE id = 'alert-test'
	`).Scan(&organizationID, &status)
	if err != nil {
		t.Fatal(err)
	}

	if organizationID != "org-test" {
		t.Fatalf("expected organization_id org-test, got %q", organizationID)
	}
	if status != "open" {
		t.Fatalf("expected default status open, got %q", status)
	}

	_, err = db.ExecContext(ctx, `
		UPDATE alerts
		SET status = 'invalid'
		WHERE id = 'alert-test'
	`)
	if err == nil {
		t.Fatal("expected invalid alert status to be rejected")
	}
}

func TestAlertLifecycleMigrationPreservesExistingAlerts(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "existing-alert.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()

	// Simulate the original schema before migration 003.
	statements := []string{
		`CREATE TABLE organizations (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL CHECK (length(trim(name)) > 0),
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE users (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			email TEXT NOT NULL COLLATE NOCASE UNIQUE,
			password_hash TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active'
				CHECK (status IN ('active', 'disabled')),
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE organization_users (
			organization_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			role TEXT NOT NULL CHECK (
				role IN ('SUPER_ADMIN', 'MANAGER', 'ANALYST', 'VIEWER')
			),
			created_at TEXT NOT NULL,
			PRIMARY KEY (organization_id, user_id)
		)`,
		`CREATE TABLE websites (
			id TEXT PRIMARY KEY,
			organization_id TEXT NOT NULL,
			created_by TEXT NOT NULL,
			domain TEXT NOT NULL,
			hash_id TEXT NOT NULL UNIQUE,
			api_key_hash TEXT NOT NULL UNIQUE,
			status TEXT NOT NULL DEFAULT 'active'
				CHECK (status IN ('active', 'disabled')),
			created_at TEXT NOT NULL,
			UNIQUE (organization_id, id)
		)`,
		`CREATE TABLE alerts (
			id TEXT PRIMARY KEY,
			website_id TEXT NOT NULL,
			severity TEXT NOT NULL
				CHECK (severity IN ('low', 'medium', 'high', 'critical')),
			type TEXT NOT NULL,
			message TEXT NOT NULL,
			ip TEXT,
			created_at TEXT NOT NULL,
			FOREIGN KEY (website_id) REFERENCES websites(id) ON DELETE CASCADE
		)`,
		`INSERT INTO organizations
		 VALUES ('org-old', 'Old Org', '2026-10-23T00:00:00Z')`,
		`INSERT INTO users
		 VALUES ('user-old', 'Old User', 'old@example.com', 'hash',
		 'active', '2026-10-23T00:00:00Z')`,
		`INSERT INTO websites VALUES (
			'website-old', 'org-old', 'user-old', 'old.example.com',
			'hash-old', 'api-old', 'active', '2026-10-23T00:00:00Z'
		)`,
		`INSERT INTO alerts VALUES (
			'alert-old', 'website-old', 'medium', 'authentication_failure',
			'Existing alert', '192.0.2.1', '2026-10-22T00:00:00Z'
		)`,
		`CREATE TABLE schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at TEXT NOT NULL
		)`,
		`INSERT INTO schema_migrations
		 VALUES (1, '001_initial_schema.sql', '2026-10-23T00:00:00Z')`,
		`INSERT INTO schema_migrations
		 VALUES (2, '002_sessions.sql', '2026-10-23T00:00:00Z')`,
	}

	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("prepare pre-migration fixture: %v", err)
		}
	}

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("apply new migration: %v", err)
	}

	var websiteOrgID, alertOrgID, status string
	err = db.QueryRowContext(ctx, `
		SELECT w.organization_id,
		       COALESCE(a.organization_id, '<NULL>'),
		       a.status
		FROM alerts a
		JOIN websites w ON w.id = a.website_id
		WHERE a.id = 'alert-old'
	`).Scan(&websiteOrgID, &alertOrgID, &status)
	if err != nil {
		t.Fatal(err)
	}

	if alertOrgID == "<NULL>" {
		t.Fatal("existing alert organization_id was not backfilled")
	}
	if alertOrgID != websiteOrgID || alertOrgID != "org-old" {
		t.Fatalf(
			"expected old alert organization org-old, website=%q alert=%q",
			websiteOrgID, alertOrgID,
		)
	}
	if status != "open" {
		t.Fatalf("expected old alert status open, got %q", status)
	}
}
