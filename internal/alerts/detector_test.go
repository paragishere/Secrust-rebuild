package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/paragishere/secrust/internal/ingest"
)

func TestDetectorCreatesAndSuppressesHTTP5xxAlerts(t *testing.T) {
	repo, ctx := setupAlertRepository(t)

	now := time.Now().UTC()
	recent := now.Add(-2 * time.Minute).Format(time.RFC3339Nano)

	for i := 0; i < 3; i++ {
		_, err := repo.db.ExecContext(ctx, `
			INSERT INTO logs (
				id, website_id, method, path, status,
				event_type, severity, created_at
			) VALUES (?, 'website-a', 'GET', '/', 500,
				'http_request', 'info', ?)
		`, "detector-log-"+string(rune('a'+i)), recent)
		if err != nil {
			t.Fatalf("insert log: %v", err)
		}
	}

	detector, err := NewDetector(repo, DetectorConfig{
		Window:                 15 * time.Minute,
		MinimumCount:           3,
		BruteForceMinimumCount: 10,
		SuppressFor:            30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewDetector() error: %v", err)
	}

	first, err := detector.RunHTTP5xxSpikeDetection(ctx)
	if err != nil {
		t.Fatalf("first detection run: %v", err)
	}
	if first.CandidatesFound != 1 || first.AlertsCreated != 1 {
		t.Fatalf("unexpected first result: %+v", first)
	}

	second, err := detector.RunHTTP5xxSpikeDetection(ctx)
	if err != nil {
		t.Fatalf("second detection run: %v", err)
	}
	if second.AlertsCreated != 0 || second.AlertsSuppressed != 1 {
		t.Fatalf("expected duplicate suppression, got %+v", second)
	}

	alerts, err := repo.List(ctx, "org-a", "open", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected exactly one open alert, got %d", len(alerts))
	}
	if alerts[0].RuleKey != HTTP5xxSpikeRuleKey {
		t.Fatalf("unexpected rule key: %q", alerts[0].RuleKey)
	}
}

func TestNewDetectorRejectsInvalidConfiguration(t *testing.T) {
	repo, _ := setupAlertRepository(t)

	_, err := NewDetector(repo, DetectorConfig{
		Window:       0,
		MinimumCount: 3,
		SuppressFor:  time.Minute,
	})
	if err == nil {
		t.Fatal("expected invalid window to be rejected")
	}
}

func TestDetectorCreatesAndSuppressesBruteForceAlerts(t *testing.T) {
	repo, ctx := setupAlertRepository(t)

	now := time.Now().UTC()
	recent := now.Add(-2 * time.Minute).Format(time.RFC3339Nano)

	// Three authentication failures from the same IP.
	for i := 0; i < 3; i++ {
		_, err := repo.db.ExecContext(ctx, `
			INSERT INTO logs (
				id, website_id, ip, method, path, status,
				event_type, severity, created_at
			) VALUES (?, 'website-a', '192.0.2.10', 'POST', '/login',
				401, 'auth_failure', 'low', ?)
		`, "brute-force-log-"+string(rune('a'+i)), recent)
		if err != nil {
			t.Fatalf("insert authentication failure: %v", err)
		}
	}

	detector, err := NewDetector(repo, DetectorConfig{
		Window:                 15 * time.Minute,
		MinimumCount:           3,
		BruteForceMinimumCount: 3,
		SuppressFor:            30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewDetector() error: %v", err)
	}

	first, err := detector.RunBruteForceDetection(ctx)
	if err != nil {
		t.Fatalf("first brute-force detection: %v", err)
	}
	if first.CandidatesFound != 1 || first.AlertsCreated != 1 {
		t.Fatalf("unexpected first detection result: %+v", first)
	}

	second, err := detector.RunBruteForceDetection(ctx)
	if err != nil {
		t.Fatalf("second brute-force detection: %v", err)
	}
	if second.AlertsCreated != 0 || second.AlertsSuppressed != 1 {
		t.Fatalf("expected duplicate suppression, got %+v", second)
	}

	alerts, err := repo.List(ctx, "org-a", "open", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected one open alert, got %d", len(alerts))
	}

	alert := alerts[0]
	if alert.RuleKey != BruteForceRuleKey {
		t.Errorf("expected rule key %q, got %q", BruteForceRuleKey, alert.RuleKey)
	}
	if alert.IP != "192.0.2.10" {
		t.Errorf("expected source IP 192.0.2.10, got %q", alert.IP)
	}
	if alert.Type != "brute_force" {
		t.Errorf("expected type brute_force, got %q", alert.Type)
	}
}

func TestDetectorDoesNotSuppressDifferentBruteForceIPs(t *testing.T) {
	repo, ctx := setupAlertRepository(t)

	now := time.Now().UTC()
	recent := now.Add(-time.Minute).Format(time.RFC3339Nano)

	for i, ip := range []string{"192.0.2.10", "192.0.2.20"} {
		for j := 0; j < 3; j++ {
			id := fmt.Sprintf("different-ip-%d-%d", i, j)
			_, err := repo.db.ExecContext(ctx, `
				INSERT INTO logs (
					id, website_id, ip, method, path, status,
					event_type, severity, created_at
				) VALUES (?, 'website-a', ?, 'POST', '/login',
					401, 'auth_failure', 'low', ?)
			`, id, ip, recent)
			if err != nil {
				t.Fatalf("insert authentication failure: %v", err)
			}
		}
	}

	detector, err := NewDetector(repo, DetectorConfig{
		Window:                 15 * time.Minute,
		MinimumCount:           3,
		BruteForceMinimumCount: 3,
		SuppressFor:            30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewDetector() error: %v", err)
	}

	result, err := detector.RunBruteForceDetection(ctx)
	if err != nil {
		t.Fatalf("RunBruteForceDetection() error: %v", err)
	}

	if result.CandidatesFound != 2 || result.AlertsCreated != 2 {
		t.Fatalf("expected two independently created alerts, got %+v", result)
	}

	alerts, err := repo.List(ctx, "org-a", "open", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 2 {
		t.Fatalf("expected two open alerts, got %d", len(alerts))
	}
}

func TestAuthenticationFailureIngestionCreatesBruteForceAlert(t *testing.T) {
	gin.SetMode(gin.TestMode)

	alertRepo, ctx := setupAlertRepository(t)

	ingestRepo := ingest.NewRepository(alertRepo.db)
	ingestHandler := ingest.NewHandler(ingestRepo)

	router := gin.New()
	router.POST("/api/logs", func(c *gin.Context) {
		c.Set(ingest.ContextWebsiteID, "website-a")
		c.Next()
	}, ingestHandler.Ingest)

	// Send three authentication failures through the ingestion HTTP handler.
	for i := 0; i < 3; i++ {
		payload := map[string]any{
			"ip":         "192.0.2.99",
			"method":     "POST",
			"path":       "/login",
			"status":     401,
			"user_agent": "IntegrationTest/1.0",
			"event_type": "auth_failure",
			"severity":   "low",
		}

		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}

		req := httptest.NewRequest(
			http.MethodPost,
			"/api/logs",
			bytes.NewReader(body),
		)
		req.Header.Set("Content-Type", "application/json")

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusCreated {
			t.Fatalf("ingestion %d: expected 201, got %d: %s",
				i+1, rec.Code, rec.Body.String())
		}
	}

	// Confirm that ingestion stored the expected event type and source IP.
	var storedCount int
	err := alertRepo.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM logs
		WHERE website_id = 'website-a'
		  AND event_type = 'auth_failure'
		  AND ip = '192.0.2.99'
	`).Scan(&storedCount)
	if err != nil {
		t.Fatal(err)
	}
	if storedCount != 3 {
		t.Fatalf("expected 3 stored failures, got %d", storedCount)
	}

	detector, err := NewDetector(alertRepo, DetectorConfig{
		Window:                 5 * time.Minute,
		MinimumCount:           10,
		BruteForceMinimumCount: 3,
		SuppressFor:            30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := detector.RunBruteForceDetection(ctx)
	if err != nil {
		t.Fatalf("brute-force detection: %v", err)
	}
	if result.CandidatesFound != 1 || result.AlertsCreated != 1 {
		t.Fatalf("expected one brute-force alert, got %+v", result)
	}

	alerts, err := alertRepo.List(ctx, "org-a", "open", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected one open alert, got %d", len(alerts))
	}

	alert := alerts[0]
	if alert.RuleKey != BruteForceRuleKey {
		t.Errorf("expected rule key %q, got %q",
			BruteForceRuleKey, alert.RuleKey)
	}
	if alert.IP != "192.0.2.99" {
		t.Errorf("expected source IP 192.0.2.99, got %q", alert.IP)
	}
	if alert.Type != "brute_force" {
		t.Errorf("expected type brute_force, got %q", alert.Type)
	}
}
