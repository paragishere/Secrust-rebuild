package website

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/paragishere/secrust/internal/audit"
	"github.com/paragishere/secrust/internal/database"
)

func newAuditEnabledAssignmentService(t *testing.T) (*AssignmentService, *sql.DB) {
	t.Helper()

	db, err := database.Open(filepath.Join(t.TempDir(), "assignment-audit-test.db"))
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

	repo := NewAssignmentRepository(db)
	service := NewAssignmentServiceWithAudit(
		db,
		repo,
		audit.NewRepository(db),
	)

	return service, db
}

func createAuditTestWebsite(t *testing.T, db *sql.DB) string {
	t.Helper()

	result, err := NewService(NewRepository(db)).Create(
		context.Background(),
		"org-a",
		"user-a",
		"example.com",
	)
	if err != nil {
		t.Fatalf("create website: %v", err)
	}

	return result.Website.ID
}

func TestAssignmentServiceWritesAudit(t *testing.T) {
	service, db := newAuditEnabledAssignmentService(t)
	ctx := context.Background()
	websiteID := createAuditTestWebsite(t, db)

	err := service.AssignByActor(
		ctx, "org-a", "user-a", websiteID, "user-a", "investigate",
	)
	if err != nil {
		t.Fatalf("assign with audit: %v", err)
	}

	var count int
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM audit_logs
		WHERE organization_id = ?
			AND user_id = ?
			AND action = 'website.user.assigned'
			AND resource_id = ?
	`, "org-a", "user-a", websiteID).Scan(&count)
	if err != nil {
		t.Fatalf("count audit entries: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one assignment audit entry, got %d", count)
	}
}

func TestAssignmentServiceWritesUnassignmentAudit(t *testing.T) {
	service, db := newAuditEnabledAssignmentService(t)
	ctx := context.Background()
	websiteID := createAuditTestWebsite(t, db)

	if err := service.AssignByActor(
		ctx, "org-a", "user-a", websiteID, "user-a", "read",
	); err != nil {
		t.Fatalf("initial assignment: %v", err)
	}

	if err := service.UnassignByActor(
		ctx, "org-a", "user-a", websiteID, "user-a",
	); err != nil {
		t.Fatalf("unassign with audit: %v", err)
	}

	var count int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM audit_logs
		WHERE action = 'website.user.unassigned'
			AND resource_id = ?
	`, websiteID).Scan(&count)
	if err != nil {
		t.Fatalf("count unassignment audit entries: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one unassignment audit entry, got %d", count)
	}
}

func TestAssignmentServiceDoesNotAuditInvalidAssignment(t *testing.T) {
	service, db := newAuditEnabledAssignmentService(t)
	ctx := context.Background()
	websiteID := createAuditTestWebsite(t, db)

	err := service.AssignByActor(
		ctx, "org-b", "user-a", websiteID, "user-a", "read",
	)
	if !errors.Is(err, ErrInvalidAssignment) {
		t.Fatalf("expected ErrInvalidAssignment, got %v", err)
	}

	var count int
	err = db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM audit_logs",
	).Scan(&count)
	if err != nil {
		t.Fatalf("count audit entries: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected no audit entries, got %d", count)
	}
}
