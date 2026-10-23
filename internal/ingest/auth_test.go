package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/paragishere/secrust/internal/database"
)

func newIngestTestRepository(t *testing.T) (*Repository, string) {
	t.Helper()

	db, err := database.Open(filepath.Join(t.TempDir(), "ingest-test.db"))
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
		VALUES ('user-a', 'User A', 'user-a@example.com', 'test-hash', 'active', ?)
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

	rawKey := "test-ingest-api-key-123456789"
	sum := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(sum[:])

	_, err = db.ExecContext(ctx, `
		INSERT INTO websites (
			id, organization_id, created_by, domain,
			hash_id, api_key_hash, status, created_at
		)
		VALUES (
			'website-a', 'org-a', 'user-a', 'example.com',
			'hash-a', ?, 'active', ?
		)
	`, keyHash, now)
	if err != nil {
		t.Fatalf("insert website: %v", err)
	}

	return NewRepository(db), rawKey
}

func requestWithAPIKey(repo *Repository, key string) *httptest.ResponseRecorder {
	router := gin.New()
	router.Use(APIKeyAuth(repo))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, c.GetString(ContextWebsiteID))
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestAPIKeyAuthAcceptsValidKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	repo, key := newIngestTestRepository(t)
	rec := requestWithAPIKey(repo, key)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "website-a" {
		t.Fatalf("expected website-a, got %q", rec.Body.String())
	}
}

func TestAPIKeyAuthRejectsInvalidKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	repo, _ := newIngestTestRepository(t)
	rec := requestWithAPIKey(repo, "invalid-key")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestAPIKeyAuthRejectsDisabledWebsite(t *testing.T) {
	gin.SetMode(gin.TestMode)

	repo, key := newIngestTestRepository(t)

	_, err := repo.db.ExecContext(context.Background(), `
		UPDATE websites SET status = 'disabled' WHERE id = 'website-a'
	`)
	if err != nil {
		t.Fatalf("disable website: %v", err)
	}

	rec := requestWithAPIKey(repo, key)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}
