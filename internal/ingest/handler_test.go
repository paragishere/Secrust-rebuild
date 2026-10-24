package ingest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func newIngestHandlerRouter(t *testing.T) (*gin.Engine, *Repository) {
	t.Helper()

	repo, key := newIngestTestRepository(t)
	handler := NewHandler(repo)

	router := gin.New()
	router.Use(APIKeyAuth(repo))
	router.POST("/api/logs", handler.Ingest)

	_ = key
	return router, repo
}

func TestIngestHandlerAcceptsValidLog(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router, repo := newIngestHandlerRouter(t)

	payload := map[string]any{
		"ip":         "192.0.2.10",
		"method":     "GET",
		"path":       "/login",
		"status":     401,
		"user_agent": "TestAgent/1.0",
		"event_type": "auth_failure",
		"severity":   "medium",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/logs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// Use the valid API key stored in the test fixture.
	var storedHash string
	if err := repo.db.QueryRow(
		`SELECT api_key_hash FROM websites WHERE id = 'website-a'`,
	).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}

	// The fixture key is known by the helper; generate the request through
	// a direct context to isolate handler validation from authentication.
	router = gin.New()
	router.POST("/api/logs", func(c *gin.Context) {
		c.Set(ContextWebsiteID, "website-a")
		c.Next()
	}, NewHandler(repo).Ingest)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected %d, got %d: %s", http.StatusCreated, rec.Code, rec.Body.String())
	}

	var count int
	if err := repo.db.QueryRow(
		`SELECT COUNT(*) FROM logs WHERE website_id = 'website-a'`,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected one stored log, got %d", count)
	}
}

func TestIngestHandlerRejectsInvalidSeverity(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router, _ := newIngestHandlerRouter(t)
	router = gin.New()
	router.POST("/api/logs", func(c *gin.Context) {
		c.Set(ContextWebsiteID, "website-a")
		c.Next()
	}, NewHandler(newTestRepositoryForHandler(t)).Ingest)

	body := bytes.NewBufferString(`{
		"method":"GET",
		"path":"/",
		"status":200,
		"event_type":"request",
		"severity":"emergency"
	}`)

	req := httptest.NewRequest(http.MethodPost, "/api/logs", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func newTestRepositoryForHandler(t *testing.T) *Repository {
	t.Helper()
	repo, _ := newIngestTestRepository(t)
	return repo
}
