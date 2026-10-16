package website

import (
	"context"
	"errors"
	"testing"
)

func TestAssignmentRepositoryAssign(t *testing.T) {
	service := newWebsiteTestService(t)
	ctx := context.Background()
	db := service.repo.db

	_, err := service.Create(ctx, "org-a", "user-a", "example.com")
	if err != nil {
		t.Fatalf("create website: %v", err)
	}

	repo := NewAssignmentRepository(db)

	err = repo.Assign(ctx, "org-a", "example.com", "user-a", "read")
	if err == nil {
		t.Fatal("expected assignment to a domain string to fail; website ID is required")
	}

	var websiteID string
	err = db.QueryRowContext(
		ctx,
		"SELECT id FROM websites WHERE domain = ?",
		"example.com",
	).Scan(&websiteID)
	if err != nil {
		t.Fatalf("get website ID: %v", err)
	}

	if err := repo.Assign(ctx, "org-a", websiteID, "user-a", "read"); err != nil {
		t.Fatalf("assign user: %v", err)
	}

	var permission string
	err = db.QueryRowContext(ctx, `
		SELECT permission FROM website_users
		WHERE website_id = ? AND user_id = ?
	`, websiteID, "user-a").Scan(&permission)
	if err != nil {
		t.Fatalf("read assignment: %v", err)
	}
	if permission != "read" {
		t.Fatalf("expected read permission, got %q", permission)
	}
}

func TestAssignmentRepositoryUpdatesPermission(t *testing.T) {
	service := newWebsiteTestService(t)
	ctx := context.Background()
	db := service.repo.db

	result, err := service.Create(ctx, "org-a", "user-a", "example.com")
	if err != nil {
		t.Fatalf("create website: %v", err)
	}

	repo := NewAssignmentRepository(db)

	if err := repo.Assign(ctx, "org-a", result.Website.ID, "user-a", "read"); err != nil {
		t.Fatalf("assign read permission: %v", err)
	}
	if err := repo.Assign(ctx, "org-a", result.Website.ID, "user-a", "investigate"); err != nil {
		t.Fatalf("update permission: %v", err)
	}

	var permission string
	err = db.QueryRowContext(ctx, `
		SELECT permission FROM website_users
		WHERE website_id = ? AND user_id = ?
	`, result.Website.ID, "user-a").Scan(&permission)
	if err != nil {
		t.Fatalf("read permission: %v", err)
	}
	if permission != "investigate" {
		t.Fatalf("expected investigate permission, got %q", permission)
	}

	var count int
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM website_users
		WHERE website_id = ? AND user_id = ?
	`, result.Website.ID, "user-a").Scan(&count)
	if err != nil {
		t.Fatalf("count assignments: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one assignment, got %d", count)
	}
}

func TestAssignmentRepositoryRejectsInvalidAssignment(t *testing.T) {
	service := newWebsiteTestService(t)
	ctx := context.Background()
	db := service.repo.db

	result, err := service.Create(ctx, "org-a", "user-a", "example.com")
	if err != nil {
		t.Fatalf("create website: %v", err)
	}

	repo := NewAssignmentRepository(db)

	tests := []struct {
		name       string
		orgID      string
		websiteID  string
		userID     string
		permission string
	}{
		{"invalid permission", "org-a", result.Website.ID, "user-a", "admin"},
		{"wrong organization", "org-b", result.Website.ID, "user-a", "read"},
		{"unknown user", "org-a", result.Website.ID, "missing-user", "read"},
		{"missing organization", "", result.Website.ID, "user-a", "read"},
		{"missing website", "org-a", "", "user-a", "read"},
		{"missing user", "org-a", result.Website.ID, "", "read"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := repo.Assign(ctx, tc.orgID, tc.websiteID, tc.userID, tc.permission)
			if !errors.Is(err, ErrInvalidAssignment) {
				t.Fatalf("expected ErrInvalidAssignment, got %v", err)
			}
		})
	}
}

func TestAssignmentRepositoryRejectsUserFromAnotherOrganization(t *testing.T) {
	service := newWebsiteTestService(t)
	ctx := context.Background()
	db := service.repo.db

	_, err := db.ExecContext(ctx, `
		INSERT INTO organizations (id, name, created_at)
		VALUES ('org-b', 'Organization B', datetime('now'))
	`)
	if err != nil {
		t.Fatalf("create second organization: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO users (id, name, email, password_hash, status, created_at)
		VALUES ('user-b', 'User B', 'user-b@example.com', 'test-hash', 'active', datetime('now'))
	`)
	if err != nil {
		t.Fatalf("create second user: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO organization_users (organization_id, user_id, role, created_at)
		VALUES ('org-b', 'user-b', 'ANALYST', datetime('now'))
	`)
	if err != nil {
		t.Fatalf("create second membership: %v", err)
	}

	result, err := service.Create(ctx, "org-a", "user-a", "example.com")
	if err != nil {
		t.Fatalf("create website: %v", err)
	}

	repo := NewAssignmentRepository(db)
	err = repo.Assign(ctx, "org-a", result.Website.ID, "user-b", "read")
	if !errors.Is(err, ErrInvalidAssignment) {
		t.Fatalf("expected cross-organization assignment rejection, got %v", err)
	}
}

func TestAssignmentRepositoryUnassign(t *testing.T) {
	service := newWebsiteTestService(t)
	ctx := context.Background()
	db := service.repo.db

	result, err := service.Create(ctx, "org-a", "user-a", "example.com")
	if err != nil {
		t.Fatalf("create website: %v", err)
	}

	repo := NewAssignmentRepository(db)
	if err := repo.Assign(ctx, "org-a", result.Website.ID, "user-a", "read"); err != nil {
		t.Fatalf("assign user: %v", err)
	}

	if err := repo.Unassign(ctx, "org-a", result.Website.ID, "user-a"); err != nil {
		t.Fatalf("unassign user: %v", err)
	}

	var count int
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM website_users
		WHERE website_id = ? AND user_id = ?
	`, result.Website.ID, "user-a").Scan(&count)
	if err != nil {
		t.Fatalf("count assignments: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected assignment to be removed, got %d rows", count)
	}

	err = repo.Unassign(ctx, "org-a", result.Website.ID, "user-a")
	if !errors.Is(err, ErrAssignmentNotFound) {
		t.Fatalf("expected ErrAssignmentNotFound, got %v", err)
	}
}
