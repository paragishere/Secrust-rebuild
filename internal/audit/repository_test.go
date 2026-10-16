package audit

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/paragishere/secrust/internal/database"
)

func newAuditTestRepository(t *testing.T) *Repository {
	t.Helper()

	db, err := database.Open(filepath.Join(t.TempDir(), "audit-test.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO organizations (id, name, created_at)
		VALUES ('org-a', 'Organization A', datetime('now'))
	`)
	if err != nil {
		t.Fatalf("insert organization: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO users (id, name, email, password_hash, status, created_at)
		VALUES ('user-a', 'Admin A', 'admin@example.com', 'test-hash', 'active', datetime('now'))
	`)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO organization_users (organization_id, user_id, role, created_at)
		VALUES ('org-a', 'user-a', 'SUPER_ADMIN', datetime('now'))
	`)
	if err != nil {
		t.Fatalf("insert membership: %v", err)
	}

	return NewRepository(db)
}

func TestRecordAuditEntry(t *testing.T) {
	repo := newAuditTestRepository(t)
	ctx := context.Background()

	err := repo.Record(ctx, Entry{
		OrganizationID: "org-a",
		UserID:         "user-a",
		Action:         "website.user.assigned",
		ResourceType:   "website",
		ResourceID:     "website-a",
		Metadata: map[string]any{
			"assigned_user_id": "user-b",
			"permission":       "read",
		},
	})
	if err != nil {
		t.Fatalf("record audit event: %v", err)
	}
}

func TestRecordAuditEntryPersistsFields(t *testing.T) {
	repo := newAuditTestRepository(t)
	ctx := context.Background()

	err := repo.Record(ctx, Entry{
		OrganizationID: "org-a",
		UserID:         "user-a",
		Action:         "website.user.unassigned",
		ResourceType:   "website",
		ResourceID:     "website-a",
		Metadata: map[string]any{
			"removed_user_id": "user-b",
		},
	})
	if err != nil {
		t.Fatalf("record audit event: %v", err)
	}

	var (
		organizationID string
		userID         string
		action         string
		resourceType   string
		resourceID     string
		metadata       string
		createdAt      string
	)

	err = repo.db.QueryRowContext(ctx, `
		SELECT organization_id, user_id, action, resource_type,
		       resource_id, metadata, created_at
		FROM audit_logs
		WHERE action = ?
	`, "website.user.unassigned").Scan(
		&organizationID,
		&userID,
		&action,
		&resourceType,
		&resourceID,
		&metadata,
		&createdAt,
	)
	if err != nil {
		t.Fatalf("read audit event: %v", err)
	}

	if organizationID != "org-a" || userID != "user-a" {
		t.Fatalf("unexpected actor or organization: %q, %q", organizationID, userID)
	}
	if action != "website.user.unassigned" || resourceType != "website" {
		t.Fatalf("unexpected action/resource: %q, %q", action, resourceType)
	}
	if resourceID != "website-a" || createdAt == "" {
		t.Fatalf("unexpected resource ID or timestamp: %q, %q", resourceID, createdAt)
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(metadata), &decoded); err != nil {
		t.Fatalf("metadata is not valid JSON: %v", err)
	}
	if decoded["removed_user_id"] != "user-b" {
		t.Fatalf("unexpected metadata: %#v", decoded)
	}
}

func TestRecordAuditEntryAllowsSystemActor(t *testing.T) {
	repo := newAuditTestRepository(t)

	err := repo.Record(context.Background(), Entry{
		OrganizationID: "org-a",
		Action:         "system.test",
		ResourceType:   "system",
	})
	if err != nil {
		t.Fatalf("record system audit event: %v", err)
	}
}

func TestRecordAuditEntryRejectsMissingRequiredFields(t *testing.T) {
	repo := newAuditTestRepository(t)

	tests := []struct {
		name  string
		entry Entry
	}{
		{
			name:  "missing organization",
			entry: Entry{Action: "test", ResourceType: "website"},
		},
		{
			name:  "missing action",
			entry: Entry{OrganizationID: "org-a", ResourceType: "website"},
		},
		{
			name:  "missing resource type",
			entry: Entry{OrganizationID: "org-a", Action: "test"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := repo.Record(context.Background(), tc.entry)
			if err == nil {
				t.Fatal("expected invalid audit entry to be rejected")
			}
		})
	}
}
