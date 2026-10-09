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

	// Applying migrations a second time must be safe.
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

	if applied != 2 {
		t.Fatalf("expected 2 recorded migrations, got %d", applied)
	}
}
