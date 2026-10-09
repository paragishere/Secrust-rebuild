package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Open initializes and verifies the SQLite database.
func Open(databasePath string) (*sql.DB, error) {
	databasePath = strings.TrimSpace(databasePath)
	if databasePath == "" {
		return nil, errors.New("database path cannot be empty")
	}

	absolutePath, err := filepath.Abs(databasePath)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(absolutePath), 0750); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}

	// A file URL safely handles spaces and Windows paths.
	dsn := "file:" + filepath.ToSlash(absolutePath) +
		"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}

	// SQLite is our initial database. A small pool simplifies
	// connection management while we build the foundation.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connect to SQLite database: %w", err)
	}

	var foreignKeys int
	if err := db.QueryRowContext(
		ctx,
		"PRAGMA foreign_keys",
	).Scan(&foreignKeys); err != nil {
		db.Close()
		return nil, fmt.Errorf("verify foreign-key enforcement: %w", err)
	}

	if foreignKeys != 1 {
		db.Close()
		return nil, errors.New("SQLite foreign-key enforcement is disabled")
	}

	return db, nil
}
