package auth

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/paragishere/secrust/internal/database"
	"github.com/paragishere/secrust/migrations"
	"golang.org/x/crypto/bcrypt"
)

func newAuthTestService(t *testing.T) *Service {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "auth-test.db")

	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	ctx := context.Background()
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}

	// Ensure the test database starts with the expected schema.
	var migrationCount int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM schema_migrations",
	).Scan(&migrationCount); err != nil {
		t.Fatalf("check migrations: %v", err)
	}
	if migrationCount < 2 {
		t.Fatalf("expected at least 2 migrations, got %d", migrationCount)
	}

	_ = migrations.FS // Confirm the embedded migrations package is available.

	repo := NewRepository(db)
	return NewService(repo, time.Hour)
}

func seedAuthUser(t *testing.T, service *Service, status string) {
	t.Helper()

	repo := service.repo
	ctx := context.Background()

	password := "Correct-Horse-42!"
	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	_, err = repo.db.ExecContext(ctx, `
		INSERT INTO organizations (id, name, created_at)
		VALUES ('org-test', 'Test Organization', ?)
	`, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		t.Fatalf("insert organization: %v", err)
	}

	_, err = repo.db.ExecContext(ctx, `
		INSERT INTO users (id, name, email, password_hash, status, created_at)
		VALUES ('user-test', 'Test User', 'test@example.com', ?, ?, ?)
	`, string(hash), status, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	_, err = repo.db.ExecContext(ctx, `
		INSERT INTO organization_users (organization_id, user_id, role, created_at)
		VALUES ('org-test', 'user-test', 'SUPER_ADMIN', ?)
	`, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		t.Fatalf("insert membership: %v", err)
	}
}

func TestLoginAndSessionLifecycle(t *testing.T) {
	service := newAuthTestService(t)
	seedAuthUser(t, service, "active")
	ctx := context.Background()

	result, err := service.Login(ctx, " TEST@example.com ", "Correct-Horse-42!")
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	if len(result.Token) != 64 {
		t.Fatalf("expected 64-character token, got %d", len(result.Token))
	}
	if result.Session.OrganizationID != "org-test" {
		t.Fatalf("unexpected organization: %s", result.Session.OrganizationID)
	}
	if result.Session.Role != "SUPER_ADMIN" {
		t.Fatalf("unexpected role: %s", result.Session.Role)
	}

	session, err := service.ValidateSession(ctx, result.Token)
	if err != nil {
		t.Fatalf("validate session: %v", err)
	}
	if session.UserID != "user-test" {
		t.Fatalf("unexpected user ID: %s", session.UserID)
	}

	if err := service.Logout(ctx, result.Token); err != nil {
		t.Fatalf("logout: %v", err)
	}

	if _, err := service.ValidateSession(ctx, result.Token); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("expected invalid session after logout, got %v", err)
	}
}

func TestLoginRejectsInvalidCredentials(t *testing.T) {
	service := newAuthTestService(t)
	seedAuthUser(t, service, "active")

	_, err := service.Login(context.Background(), "test@example.com", "wrong-password")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	_, err = service.Login(context.Background(), "missing@example.com", "some-password")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for unknown user, got %v", err)
	}
}

func TestLoginRejectsDisabledAccount(t *testing.T) {
	service := newAuthTestService(t)
	seedAuthUser(t, service, "disabled")

	_, err := service.Login(context.Background(), "test@example.com", "Correct-Horse-42!")
	if !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("expected ErrAccountDisabled, got %v", err)
	}
}

func TestValidateSessionRejectsMalformedToken(t *testing.T) {
	service := newAuthTestService(t)

	for _, token := range []string{"", "short", "not-a-valid-token"} {
		if _, err := service.ValidateSession(context.Background(), token); !errors.Is(err, ErrSessionInvalid) {
			t.Errorf("token %q: expected ErrSessionInvalid, got %v", token, err)
		}
	}
}

func TestLogoutIgnoresMalformedToken(t *testing.T) {
	service := newAuthTestService(t)

	if err := service.Logout(context.Background(), "invalid"); err != nil {
		t.Fatalf("logout with malformed token should be harmless: %v", err)
	}
}

func TestFindUserByEmailMissing(t *testing.T) {
	service := newAuthTestService(t)

	_, err := service.repo.FindUserByEmail(context.Background(), "missing@example.com")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestDatabaseHandleIsValid(t *testing.T) {
	service := newAuthTestService(t)

	if err := service.repo.db.Ping(); err != nil && !errors.Is(err, sql.ErrConnDone) {
		t.Fatalf("database ping failed: %v", err)
	}
}
