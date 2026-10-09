package organization

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/paragishere/secrust/internal/database"
)

func TestListMembersIsOrganizationScoped(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "organization-test.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)

	_, err = db.ExecContext(ctx, `
		INSERT INTO organizations (id, name, created_at)
		VALUES
			('org-a', 'Organization A', ?),
			('org-b', 'Organization B', ?)
	`, now, now)
	if err != nil {
		t.Fatalf("insert organizations: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO users (id, name, email, password_hash, status, created_at)
		VALUES
			('user-a', 'Alice', 'alice@example.com', 'test-hash', 'active', ?),
			('user-b', 'Bob', 'bob@example.com', 'test-hash', 'active', ?)
	`, now, now)
	if err != nil {
		t.Fatalf("insert users: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO organization_users (organization_id, user_id, role, created_at)
		VALUES
			('org-a', 'user-a', 'SUPER_ADMIN', ?),
			('org-b', 'user-b', 'SUPER_ADMIN', ?)
	`, now, now)
	if err != nil {
		t.Fatalf("insert memberships: %v", err)
	}

	repo := NewRepository(db)

	membersA, err := repo.ListMembers(ctx, "org-a")
	if err != nil {
		t.Fatalf("list org-a members: %v", err)
	}

	if len(membersA) != 1 {
		t.Fatalf("expected 1 member for org-a, got %d", len(membersA))
	}
	if membersA[0].UserID != "user-a" {
		t.Fatalf("expected user-a, got %s", membersA[0].UserID)
	}

	membersB, err := repo.ListMembers(ctx, "org-b")
	if err != nil {
		t.Fatalf("list org-b members: %v", err)
	}

	if len(membersB) != 1 || membersB[0].UserID != "user-b" {
		t.Fatalf("unexpected org-b members: %+v", membersB)
	}
}

func TestListMembersForEmptyOrganization(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "empty-organization-test.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}

	repo := NewRepository(db)

	members, err := repo.ListMembers(ctx, "nonexistent-org")
	if err != nil {
		t.Fatalf("list empty organization: %v", err)
	}

	if len(members) != 0 {
		t.Fatalf("expected zero members, got %d", len(members))
	}
}
