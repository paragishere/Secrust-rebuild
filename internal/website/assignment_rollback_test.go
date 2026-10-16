package website

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/paragishere/secrust/internal/audit"
	"github.com/paragishere/secrust/internal/database"
)

func TestAssignmentRollsBackWhenAuditFails(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "rollback-test.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}

	now := "2026-10-16T00:00:00Z"

	_, err = db.ExecContext(ctx, `
		INSERT INTO organizations (id, name, created_at)
		VALUES ('org-a', 'Organization A', ?)
	`, now)
	if err != nil {
		t.Fatalf("insert organization: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO users (id, name, email, password_hash, status, created_at)
		VALUES ('user-a', 'Admin A', 'admin@example.com', 'test-hash', 'active', ?)
	`, now)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO organization_users (organization_id, user_id, role, created_at)
		VALUES ('org-a', 'user-a', 'SUPER_ADMIN', ?)
	`, now)
	if err != nil {
		t.Fatalf("insert membership: %v", err)
	}

	websiteResult, err := NewService(NewRepository(db)).Create(
		ctx, "org-a", "user-a", "example.com",
	)
	if err != nil {
		t.Fatalf("create website: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		CREATE TRIGGER reject_assignment_audit
		BEFORE INSERT ON audit_logs
		WHEN NEW.action = 'website.user.assigned'
		BEGIN
			SELECT RAISE(ABORT, 'simulated audit failure');
		END;
	`)
	if err != nil {
		t.Fatalf("create audit failure trigger: %v", err)
	}

	service := NewAssignmentServiceWithAudit(
		db,
		NewAssignmentRepository(db),
		audit.NewRepository(db),
	)

	err = service.AssignByActor(
		ctx,
		"org-a",
		"user-a",
		websiteResult.Website.ID,
		"user-a",
		"read",
	)
	if err == nil {
		t.Fatal("expected assignment to fail when audit insert fails")
	}

	var assignmentCount int
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM website_users
		WHERE website_id = ? AND user_id = ?
	`, websiteResult.Website.ID, "user-a").Scan(&assignmentCount)
	if err != nil {
		t.Fatalf("count assignments: %v", err)
	}
	if assignmentCount != 0 {
		t.Fatalf("expected assignment rollback, got %d rows", assignmentCount)
	}

	var auditCount int
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM audit_logs
		WHERE action = 'website.user.assigned'
	`).Scan(&auditCount)
	if err != nil {
		t.Fatalf("count audit entries: %v", err)
	}
	if auditCount != 0 {
		t.Fatalf("expected no audit entry, got %d", auditCount)
	}
}
