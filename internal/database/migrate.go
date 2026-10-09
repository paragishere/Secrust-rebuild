package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	migrationfiles "github.com/paragishere/secrust/migrations"
)

type migration struct {
	version int
	name    string
	content string
}

func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("database is nil")
	}

	files, err := fs.Glob(migrationfiles.FS, "*.sql")
	if err != nil {
		return fmt.Errorf("discover migrations: %w", err)
	}

	sort.Strings(files)
	loaded := make([]migration, 0, len(files))

	for _, name := range files {
		prefix, _, ok := strings.Cut(name, "_")
		if !ok {
			return fmt.Errorf("invalid migration filename: %s", name)
		}

		var version int
		if _, err := fmt.Sscanf(prefix, "%d", &version); err != nil || version < 1 {
			return fmt.Errorf("invalid migration version: %s", name)
		}

		content, err := migrationfiles.FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		loaded = append(loaded, migration{
			version: version,
			name:    name,
			content: string(content),
		})
	}

	for i := 1; i < len(loaded); i++ {
		if loaded[i-1].version == loaded[i].version {
			return fmt.Errorf("duplicate migration version: %d", loaded[i].version)
		}
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Close()

	// Keep migration execution on one connection and prevent
	// concurrent SQLite writers during schema changes.
	if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout = 5000"); err != nil {
		return fmt.Errorf("configure migration connection: %w", err)
	}

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()

	_, err = conn.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at TEXT NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("initialize migration tracking: %w", err)
	}

	for _, m := range loaded {
		var existingName string
		err := conn.QueryRowContext(
			ctx,
			"SELECT name FROM schema_migrations WHERE version = ?",
			m.version,
		).Scan(&existingName)

		switch {
		case err == nil:
			if existingName != m.name {
				return fmt.Errorf(
					"migration version %d name mismatch: database=%s file=%s",
					m.version, existingName, m.name,
				)
			}
			continue

		case !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("check migration %d: %w", m.version, err)
		}

		if _, err := conn.ExecContext(ctx, m.content); err != nil {
			return fmt.Errorf("apply migration %s: %w", m.name, err)
		}

		if _, err := conn.ExecContext(ctx, `
			INSERT INTO schema_migrations (version, name, applied_at)
			VALUES (?, ?, ?)
		`, m.version, m.name, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("record migration %s: %w", m.name, err)
		}
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("migration context cancelled: %w", err)
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}

	committed = true
	return nil
}
