package database

import (
	"path/filepath"
	"testing"
)

func TestOpenEnablesForeignKeys(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open() returned an error: %v", err)
	}
	defer db.Close()

	var enabled int
	if err := db.QueryRow("PRAGMA foreign_keys").Scan(&enabled); err != nil {
		t.Fatalf("failed to query foreign-key setting: %v", err)
	}

	if enabled != 1 {
		t.Fatalf("expected foreign_keys=1, got %d", enabled)
	}
}

func TestOpenRejectsEmptyPath(t *testing.T) {
	_, err := Open("")
	if err == nil {
		t.Fatal("expected an error for an empty database path")
	}
}
