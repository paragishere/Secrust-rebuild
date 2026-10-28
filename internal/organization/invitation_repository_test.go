package organization

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/paragishere/secrust/internal/audit"
	"github.com/paragishere/secrust/internal/database"
)

func setupInvitationTestDB(t *testing.T) (*sql.DB, context.Context) {
	t.Helper()

	db, err := database.Open(filepath.Join(t.TempDir(), "invitation-test.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}

	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)

	_, err = db.ExecContext(ctx, `
		INSERT INTO organizations (id, name, created_at)
		VALUES ('org-a', 'Organization A', ?)
	`, now)
	if err != nil {
		t.Fatalf("insert organization: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO users (id, name, email, password_hash, status, created_at)
		VALUES
			('admin-a', 'Admin', 'admin@example.com', 'test-hash', 'active', ?),
			('manager-a', 'Manager', 'manager@example.com', 'test-hash', 'active', ?)
	`, now, now)
	if err != nil {
		t.Fatalf("insert users: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO organization_users (organization_id, user_id, role, created_at)
		VALUES
			('org-a', 'admin-a', 'SUPER_ADMIN', ?),
			('org-a', 'manager-a', 'MANAGER', ?)
	`, now, now)
	if err != nil {
		t.Fatalf("insert memberships: %v", err)
	}

	return db, ctx
}

func TestCreateInvitationStoresOnlyTokenHash(t *testing.T) {
	db, ctx := setupInvitationTestDB(t)
	repo := NewInvitationRepository(db)

	expiry := time.Now().UTC().Add(time.Hour)
	inv, rawToken, err := repo.Create(
		ctx, "org-a", "NewUser@example.com", "ANALYST", "admin-a", expiry,
	)
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	if rawToken == "" {
		t.Fatal("expected raw invitation token")
	}
	if inv.ID == "" || inv.Email != "newuser@example.com" {
		t.Fatalf("unexpected invitation: %+v", inv)
	}

	sum := sha256.Sum256([]byte(rawToken))
	expectedHash := hex.EncodeToString(sum[:])

	var storedHash string
	err = db.QueryRowContext(ctx, `
		SELECT token_hash FROM invitations WHERE id = ?
	`, inv.ID).Scan(&storedHash)
	if err != nil {
		t.Fatalf("read token hash: %v", err)
	}

	if storedHash != expectedHash {
		t.Fatal("stored token hash does not match SHA-256")
	}
	if storedHash == rawToken {
		t.Fatal("raw token must not be stored")
	}

	var auditCount int
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM audit_logs
		WHERE organization_id = ?
		  AND action = 'INVITATION_CREATED'
		  AND resource_id = ?
	`, "org-a", inv.ID).Scan(&auditCount)
	if err != nil {
		t.Fatalf("count audit records: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("expected one creation audit record, got %d", auditCount)
	}
}

func TestCreateInvitationRejectsDuplicateActiveInvitation(t *testing.T) {
	db, ctx := setupInvitationTestDB(t)
	repo := NewInvitationRepository(db)

	expiry := time.Now().UTC().Add(time.Hour)

	_, _, err := repo.Create(
		ctx, "org-a", "newuser@example.com", "ANALYST", "admin-a", expiry,
	)
	if err != nil {
		t.Fatalf("create first invitation: %v", err)
	}

	_, _, err = repo.Create(
		ctx, "org-a", "NEWUSER@example.com", "VIEWER", "admin-a", expiry,
	)
	if !errors.Is(err, ErrInvitationConflict) {
		t.Fatalf("expected ErrInvitationConflict, got %v", err)
	}
}

func TestCreateInvitationRejectsNonSuperAdmin(t *testing.T) {
	db, ctx := setupInvitationTestDB(t)
	repo := NewInvitationRepository(db)

	_, _, err := repo.Create(
		ctx,
		"org-a",
		"newuser@example.com",
		"ANALYST",
		"manager-a",
		time.Now().UTC().Add(time.Hour),
	)
	if err == nil {
		t.Fatal("expected non-SUPER_ADMIN creation to fail")
	}

	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM invitations
	`).Scan(&count); err != nil {
		t.Fatalf("count invitations: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected no invitations, got %d", count)
	}
}

func TestInvitationListIsOrganizationScoped(t *testing.T) {
	db, ctx := setupInvitationTestDB(t)
	repo := NewInvitationRepository(db)

	_, _, err := repo.Create(
		ctx, "org-a", "one@example.com", "ANALYST", "admin-a",
		time.Now().UTC().Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	items, err := repo.List(ctx, "org-a")
	if err != nil {
		t.Fatalf("list invitations: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one invitation, got %d", len(items))
	}

	items, err = repo.List(ctx, "other-org")
	if err != nil {
		t.Fatalf("list other organization: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected no invitations for other organization, got %d", len(items))
	}
}

func TestRevokeInvitationAndAudit(t *testing.T) {
	db, ctx := setupInvitationTestDB(t)
	repo := NewInvitationRepository(db)

	inv, _, err := repo.Create(
		ctx, "org-a", "newuser@example.com", "VIEWER", "admin-a",
		time.Now().UTC().Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	if err := repo.Revoke(ctx, "org-a", inv.ID, "manager-a"); err == nil {
		t.Fatal("expected manager revocation to fail")
	}

	if err := repo.Revoke(ctx, "org-a", inv.ID, "admin-a"); err != nil {
		t.Fatalf("revoke invitation: %v", err)
	}

	var revokedAt sql.NullString
	err = db.QueryRowContext(ctx, `
		SELECT revoked_at FROM invitations WHERE id = ?
	`, inv.ID).Scan(&revokedAt)
	if err != nil {
		t.Fatalf("read revoked invitation: %v", err)
	}
	if !revokedAt.Valid || revokedAt.String == "" {
		t.Fatal("expected revoked_at to be set")
	}

	var auditCount int
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM audit_logs
		WHERE organization_id = ?
		  AND action = 'INVITATION_REVOKED'
		  AND resource_id = ?
	`, "org-a", inv.ID).Scan(&auditCount)
	if err != nil {
		t.Fatalf("count revocation audit: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("expected one revocation audit, got %d", auditCount)
	}

	err = repo.Revoke(ctx, "org-a", inv.ID, "admin-a")
	if !errors.Is(err, ErrInvitationNotFound) {
		t.Fatalf("expected ErrInvitationNotFound for second revoke, got %v", err)
	}
}

func TestInvitationCreationAuditFailureRollsBack(t *testing.T) {
	db, ctx := setupInvitationTestDB(t)
	repo := NewInvitationRepository(db)

	// Force the audit insert to fail. Invitation creation must roll back too.
	_, err := db.ExecContext(ctx, `
		CREATE TRIGGER reject_invitation_audit
		BEFORE INSERT ON audit_logs
		WHEN NEW.action = 'INVITATION_CREATED'
		BEGIN
			SELECT RAISE(ABORT, 'forced audit failure');
		END;
	`)
	if err != nil {
		t.Fatalf("create test trigger: %v", err)
	}

	_, _, err = repo.Create(
		ctx,
		"org-a",
		"newuser@example.com",
		"ANALYST",
		"admin-a",
		time.Now().UTC().Add(time.Hour),
	)
	if err == nil {
		t.Fatal("expected invitation creation to fail when audit fails")
	}

	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM invitations
	`).Scan(&count); err != nil {
		t.Fatalf("count invitations: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected rollback to leave zero invitations, got %d", count)
	}
}

func TestInvitationRejectsInvalidRoleAndExpiredDate(t *testing.T) {
	db, ctx := setupInvitationTestDB(t)
	repo := NewInvitationRepository(db)

	_, _, err := repo.Create(
		ctx, "org-a", "newuser@example.com", "SUPER_ADMIN", "admin-a",
		time.Now().UTC().Add(time.Hour),
	)
	if !errors.Is(err, ErrInvalidInviteRole) {
		t.Fatalf("expected ErrInvalidInviteRole, got %v", err)
	}

	_, _, err = repo.Create(
		ctx, "org-a", "newuser@example.com", "ANALYST", "admin-a",
		time.Now().UTC().Add(-time.Minute),
	)
	if !errors.Is(err, ErrInvitationExpired) {
		t.Fatalf("expected ErrInvitationExpired, got %v", err)
	}
}

// Keep the audit package referenced in this test file to make the
// transaction/audit relationship explicit for future test extensions.
var _ = audit.ErrInvalidEntry

func TestAcceptNewInvitationCreatesAccountAndMembership(t *testing.T) {
	db, ctx := setupInvitationTestDB(t)
	repo := NewInvitationRepository(db)

	inv, token, err := repo.Create(
		ctx,
		"org-a",
		"newuser@example.com",
		"ANALYST",
		"admin-a",
		time.Now().UTC().Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	result, err := repo.AcceptNew(
		ctx,
		token,
		"New User",
		"correct-horse-battery-2026",
	)
	if err != nil {
		t.Fatalf("accept invitation: %v", err)
	}

	if result.Email != inv.Email ||
		result.OrganizationID != "org-a" ||
		result.Role != "ANALYST" {
		t.Fatalf("unexpected acceptance result: %+v", result)
	}

	var membershipRole string
	err = db.QueryRowContext(ctx, `
		SELECT role FROM organization_users
		WHERE organization_id = 'org-a' AND user_id = ?
	`, result.UserID).Scan(&membershipRole)
	if err != nil {
		t.Fatalf("read membership: %v", err)
	}
	if membershipRole != "ANALYST" {
		t.Fatalf("expected ANALYST membership, got %s", membershipRole)
	}

	var acceptedAt sql.NullString
	err = db.QueryRowContext(ctx, `
		SELECT accepted_at FROM invitations WHERE id = ?
	`, inv.ID).Scan(&acceptedAt)
	if err != nil {
		t.Fatalf("read invitation: %v", err)
	}
	if !acceptedAt.Valid || acceptedAt.String == "" {
		t.Fatal("expected invitation to be marked accepted")
	}

	// The same token must not be usable a second time.
	_, err = repo.AcceptNew(
		ctx,
		token,
		"Another User",
		"correct-horse-battery-2026",
	)
	if !errors.Is(err, ErrInvitationInactive) {
		t.Fatalf("expected reused token to be rejected, got %v", err)
	}
}

func TestAcceptExistingInvitationRequiresMatchingEmail(t *testing.T) {
	db, ctx := setupInvitationTestDB(t)
	repo := NewInvitationRepository(db)

	_, token, err := repo.Create(
		ctx,
		"org-a",
		"newuser@example.com",
		"VIEWER",
		"admin-a",
		time.Now().UTC().Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	_, err = repo.AcceptExisting(ctx, token, "manager-a")
	if err == nil {
		t.Fatal("expected invitation for a different email to be rejected")
	}

	var count int
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM organization_users
		WHERE organization_id = 'org-a' AND user_id = 'manager-a'
	`).Scan(&count)
	if err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected existing membership count to remain 1, got %d", count)
	}
}

func TestAcceptExistingInvitationAddsMatchingUser(t *testing.T) {
	db, ctx := setupInvitationTestDB(t)
	repo := NewInvitationRepository(db)

	now := time.Now().UTC().Format(time.RFC3339Nano)

	_, err := db.ExecContext(ctx, `
		INSERT INTO users
			(id, name, email, password_hash, status, created_at)
		VALUES ('user-b', 'New User', 'newuser@example.com', 'test-hash', 'active', ?)
	`, now)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	_, token, err := repo.Create(
		ctx,
		"org-a",
		"newuser@example.com",
		"VIEWER",
		"admin-a",
		time.Now().UTC().Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	result, err := repo.AcceptExisting(ctx, token, "user-b")
	if err != nil {
		t.Fatalf("accept invitation: %v", err)
	}

	if result.UserID != "user-b" || result.Role != "VIEWER" {
		t.Fatalf("unexpected acceptance result: %+v", result)
	}

	var count int
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM audit_logs
		WHERE organization_id = 'org-a'
		  AND action = 'INVITATION_ACCEPTED'
	`).Scan(&count)
	if err != nil {
		t.Fatalf("count acceptance audit records: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one acceptance audit record, got %d", count)
	}
}

func TestAcceptNewInvitationAuditFailureRollsBack(t *testing.T) {
	db, ctx := setupInvitationTestDB(t)
	repo := NewInvitationRepository(db)

	inv, token, err := repo.Create(
		ctx,
		"org-a",
		"newuser@example.com",
		"ANALYST",
		"admin-a",
		time.Now().UTC().Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		CREATE TRIGGER reject_invitation_acceptance_audit
		BEFORE INSERT ON audit_logs
		WHEN NEW.action = 'INVITATION_ACCEPTED'
		BEGIN
			SELECT RAISE(ABORT, 'forced acceptance audit failure');
		END;
	`)
	if err != nil {
		t.Fatalf("create test trigger: %v", err)
	}

	_, err = repo.AcceptNew(
		ctx,
		token,
		"New User",
		"correct-horse-battery-2026",
	)
	if err == nil {
		t.Fatal("expected acceptance to fail when audit insertion fails")
	}

	var userCount, membershipCount int
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM users WHERE email = 'newuser@example.com'
	`).Scan(&userCount); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM organization_users
		WHERE organization_id = 'org-a' AND user_id LIKE 'user_%'
	`).Scan(&membershipCount); err != nil {
		t.Fatalf("count memberships: %v", err)
	}

	if userCount != 0 || membershipCount != 0 {
		t.Fatalf("expected account and membership rollback; users=%d memberships=%d",
			userCount, membershipCount)
	}

	var acceptedAt sql.NullString
	if err := db.QueryRowContext(ctx, `
		SELECT accepted_at FROM invitations WHERE id = ?
	`, inv.ID).Scan(&acceptedAt); err != nil {
		t.Fatalf("read invitation: %v", err)
	}
	if acceptedAt.Valid {
		t.Fatal("invitation must remain unaccepted after rollback")
	}
}

func TestFindInvitationByIDIsOrganizationScoped(t *testing.T) {
	db, ctx := setupInvitationTestDB(t)
	repo := NewInvitationRepository(db)

	inv, _, err := repo.Create(
		ctx,
		"org-a",
		"invitee@example.com",
		"ANALYST",
		"admin-a",
		time.Now().UTC().Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	found, err := repo.FindByID(ctx, "org-a", inv.ID)
	if err != nil {
		t.Fatalf("find invitation: %v", err)
	}
	if found.ID != inv.ID {
		t.Fatalf("expected invitation %q, got %q", inv.ID, found.ID)
	}

	_, err = repo.FindByID(ctx, "other-org", inv.ID)
	if !errors.Is(err, ErrInvitationNotFound) {
		t.Fatalf("expected organization-scoped not-found, got %v", err)
	}
}

func TestAcceptNewExpiredInvitationIsRejected(t *testing.T) {
	db, ctx := setupInvitationTestDB(t)
	repo := NewInvitationRepository(db)

	inv, token, err := repo.Create(
		ctx,
		"org-a",
		"expired-user@example.com",
		"ANALYST",
		"admin-a",
		time.Now().UTC().Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	// Expire the invitation after creation.
	_, err = db.ExecContext(ctx, `
		UPDATE invitations
		SET expires_at = ?
		WHERE id = ?
	`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), inv.ID)
	if err != nil {
		t.Fatalf("expire invitation: %v", err)
	}

	_, err = repo.AcceptNew(
		ctx,
		token,
		"Expired User",
		"correct-horse-battery-2026",
	)
	if !errors.Is(err, ErrInvitationExpired) {
		t.Fatalf("expected ErrInvitationExpired, got %v", err)
	}

	var count int
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM users
		WHERE email = 'expired-user@example.com'
	`).Scan(&count)
	if err != nil {
		t.Fatalf("count users: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected no user to be created, got %d", count)
	}
}

func TestAcceptNewRevokedInvitationIsRejected(t *testing.T) {
	db, ctx := setupInvitationTestDB(t)
	repo := NewInvitationRepository(db)

	inv, token, err := repo.Create(
		ctx,
		"org-a",
		"revoked-user@example.com",
		"ANALYST",
		"admin-a",
		time.Now().UTC().Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	if err := repo.Revoke(ctx, "org-a", inv.ID, "admin-a"); err != nil {
		t.Fatalf("revoke invitation: %v", err)
	}

	_, err = repo.AcceptNew(
		ctx,
		token,
		"Revoked User",
		"correct-horse-battery-2026",
	)
	if !errors.Is(err, ErrInvitationInactive) {
		t.Fatalf("expected ErrInvitationInactive, got %v", err)
	}

	var count int
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM users
		WHERE email = 'revoked-user@example.com'
	`).Scan(&count)
	if err != nil {
		t.Fatalf("count users: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected no user to be created, got %d", count)
	}
}
