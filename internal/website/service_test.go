package website

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/paragishere/secrust/internal/database"
)

func newWebsiteTestService(t *testing.T) *Service {
	t.Helper()

	db, err := database.Open(filepath.Join(t.TempDir(), "website-test.db"))
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

	return NewService(NewRepository(db))
}

func TestCreateWebsite(t *testing.T) {
	service := newWebsiteTestService(t)

	result, err := service.Create(
		context.Background(),
		"org-a",
		"user-a",
		"Example.COM",
	)
	if err != nil {
		t.Fatalf("create website: %v", err)
	}

	if result.Website.Domain != "example.com" {
		t.Fatalf("expected normalized domain, got %q", result.Website.Domain)
	}
	if result.Website.Status != "active" {
		t.Fatalf("expected active status, got %q", result.Website.Status)
	}
	if len(result.APIKey) != 64 {
		t.Fatalf("expected 64-character API key, got %d", len(result.APIKey))
	}
}

func TestCreateWebsiteStoresOnlyAPIKeyHash(t *testing.T) {
	service := newWebsiteTestService(t)

	result, err := service.Create(
		context.Background(),
		"org-a",
		"user-a",
		"example.com",
	)
	if err != nil {
		t.Fatalf("create website: %v", err)
	}

	sum := sha256.Sum256([]byte(result.APIKey))
	expectedHash := hex.EncodeToString(sum[:])

	var storedHash string
	err = service.repo.db.QueryRowContext(
		context.Background(),
		"SELECT api_key_hash FROM websites WHERE id = ?",
		result.Website.ID,
	).Scan(&storedHash)
	if err != nil {
		t.Fatalf("read stored API key hash: %v", err)
	}

	if storedHash != expectedHash {
		t.Fatal("database does not contain the expected API key hash")
	}
	if storedHash == result.APIKey {
		t.Fatal("plain API key must not be stored")
	}
}

func TestCreateWebsiteRejectsInvalidDomain(t *testing.T) {
	service := newWebsiteTestService(t)

	invalidDomains := []string{
		"",
		"https://example.com",
		"example.com/path",
		"example.com:8080",
		"-invalid.com",
		"invalid domain",
	}

	for _, domain := range invalidDomains {
		t.Run(domain, func(t *testing.T) {
			_, err := service.Create(
				context.Background(),
				"org-a",
				"user-a",
				domain,
			)
			if err != ErrInvalidWebsite {
				t.Fatalf("expected ErrInvalidWebsite, got %v", err)
			}
		})
	}
}

func TestListWebsitesIsOrganizationScoped(t *testing.T) {
	service := newWebsiteTestService(t)
	ctx := context.Background()

	_, err := service.Create(ctx, "org-a", "user-a", "example.com")
	if err != nil {
		t.Fatalf("create website: %v", err)
	}

	websites, err := service.List(ctx, "org-a")
	if err != nil {
		t.Fatalf("list websites: %v", err)
	}
	if len(websites) != 1 {
		t.Fatalf("expected 1 website, got %d", len(websites))
	}

	otherOrgWebsites, err := service.List(ctx, "org-b")
	if err != nil {
		t.Fatalf("list other organization websites: %v", err)
	}
	if len(otherOrgWebsites) != 0 {
		t.Fatalf("expected 0 websites for org-b, got %d", len(otherOrgWebsites))
	}
}

func TestCreateWebsiteRequiresOrganizationAndCreator(t *testing.T) {
	service := newWebsiteTestService(t)

	cases := []struct {
		name string
		org  string
		user string
	}{
		{name: "missing organization", org: "", user: "user-a"},
		{name: "missing creator", org: "org-a", user: ""},
		{name: "unknown organization", org: "org-missing", user: "user-a"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := service.Create(
				context.Background(),
				tc.org,
				tc.user,
				"example.com",
			)
			if err == nil {
				t.Fatal("expected website creation to fail")
			}
		})
	}
}
