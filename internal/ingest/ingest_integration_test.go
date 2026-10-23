package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestIngestHTTPIntegration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	repo, validKey := newIngestTestRepository(t)
	handler := NewHandler(repo)

	router := gin.New()
	router.Use(APIKeyAuth(repo))
	router.POST("/api/logs", handler.Ingest)

	send := func(key string, payload any) *httptest.ResponseRecorder {
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}

		req := httptest.NewRequest(
			http.MethodPost,
			"/api/logs",
			bytes.NewReader(body),
		)
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("X-API-Key", key)
		}

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	validPayload := map[string]any{
		"ip":         "192.0.2.10",
		"method":     "GET",
		"path":       "/login",
		"status":     401,
		"user_agent": "IntegrationTest/1.0",
		"event_type": "authentication_failure",
		"severity":   "medium",
	}

	t.Run("valid key stores log", func(t *testing.T) {
		rec := send(validKey, validPayload)
		if rec.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
		}

		var count int
		err := repo.db.QueryRowContext(
			context.Background(),
			`SELECT COUNT(*) FROM logs WHERE website_id = 'website-a'`,
		).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("expected one stored log, got %d", count)
		}
	})

	t.Run("missing key rejected", func(t *testing.T) {
		rec := send("", validPayload)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("invalid key rejected", func(t *testing.T) {
		rec := send("invalid-api-key", validPayload)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("invalid severity rejected", func(t *testing.T) {
		payload := map[string]any{
			"method":     "GET",
			"path":       "/",
			"status":     200,
			"event_type": "request",
			"severity":   "emergency",
		}
		rec := send(validKey, payload)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("invalid status rejected", func(t *testing.T) {
		payload := map[string]any{
			"method":     "GET",
			"path":       "/",
			"status":     700,
			"event_type": "request",
			"severity":   "low",
		}
		rec := send(validKey, payload)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("invalid IP rejected", func(t *testing.T) {
		payload := map[string]any{
			"ip":         "not-an-ip",
			"method":     "GET",
			"path":       "/",
			"status":     200,
			"event_type": "request",
			"severity":   "low",
		}
		rec := send(validKey, payload)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("valid IPv6 accepted", func(t *testing.T) {
		payload := map[string]any{
			"ip":         "2001:db8::1",
			"method":     "GET",
			"path":       "/ipv6",
			"status":     200,
			"event_type": "request",
			"severity":   "info",
		}
		rec := send(validKey, payload)
		if rec.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("malformed JSON rejected", func(t *testing.T) {
		req := httptest.NewRequest(
			http.MethodPost,
			"/api/logs",
			bytes.NewBufferString(`{"method":`),
		)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", validKey)

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("oversized payload rejected", func(t *testing.T) {
		payload := map[string]any{
			"method":     "GET",
			"path":       "/" + string(bytes.Repeat([]byte("a"), 17*1024)),
			"status":     200,
			"event_type": "request",
			"severity":   "low",
		}
		rec := send(validKey, payload)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("disabled website rejected", func(t *testing.T) {
		_, err := repo.db.ExecContext(
			context.Background(),
			`UPDATE websites SET status = 'disabled' WHERE id = 'website-a'`,
		)
		if err != nil {
			t.Fatal(err)
		}

		rec := send(validKey, validPayload)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})
}
