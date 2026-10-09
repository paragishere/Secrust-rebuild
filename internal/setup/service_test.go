package setup

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/paragishere/secrust/internal/database"
	"golang.org/x/crypto/bcrypt"
)

func TestCreateInitialSetup(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "setup.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := database.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}

	service := NewService(db)
	ctx := context.Background()

	err = service.CreateInitialSetup(ctx, InitialSetup{
		OrganizationName: "Secrust Labs",
		AdminName:        "Admin User",
		Email:            "ADMIN@example.com",
		Password:         "a-long-test-password",
	})
	if err != nil {
		t.Fatalf("CreateInitialSetup failed: %v", err)
	}

	initialized, err := service.IsInitialized(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !initialized {
		t.Fatal("expected setup to be initialized")
	}

	var role string
	err = db.QueryRowContext(ctx, `
		SELECT ou.role
		FROM organization_users ou
		JOIN users u ON u.id = ou.user_id
		WHERE u.email = ?
	`, "admin@example.com").Scan(&role)
	if err != nil {
		t.Fatal(err)
	}
	if role != "SUPER_ADMIN" {
		t.Fatalf("expected SUPER_ADMIN, got %q", role)
	}

	var passwordHash string
	if err := db.QueryRowContext(
		ctx,
		"SELECT password_hash FROM users WHERE email = ?",
		"admin@example.com",
	).Scan(&passwordHash); err != nil {
		t.Fatal(err)
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(passwordHash),
		[]byte("a-long-test-password"),
	); err != nil {
		t.Fatal("stored password hash did not verify")
	}
}

func TestSetupCannotRunTwice(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "setup.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := database.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}

	service := NewService(db)
	input := InitialSetup{
		OrganizationName: "Secrust Labs",
		AdminName:        "Admin User",
		Email:            "admin@example.com",
		Password:         "a-long-test-password",
	}

	if err := service.CreateInitialSetup(context.Background(), input); err != nil {
		t.Fatal(err)
	}

	err = service.CreateInitialSetup(context.Background(), input)
	if !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("expected ErrAlreadyInitialized, got %v", err)
	}
}
