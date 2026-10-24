package alerts

import (
	// "context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestSchedulerRunsAllDetectionRules(t *testing.T) {
	repo, ctx := setupAlertRepository(t)

	now := time.Now().UTC()
	recent := now.Add(-time.Minute).Format(time.RFC3339Nano)

	// Insert enough HTTP 5xx errors to trigger the first rule.
	for i := 0; i < 3; i++ {
		_, err := repo.db.ExecContext(ctx, `
			INSERT INTO logs (
				id, website_id, ip, method, path, status,
				event_type, severity, created_at
			) VALUES (?, 'website-a', '192.0.2.50', 'GET', '/',
				500, 'http_request', 'high', ?)
		`, "scheduler-http-"+string(rune('a'+i)), recent)
		if err != nil {
			t.Fatalf("insert HTTP error log: %v", err)
		}
	}

	// Insert enough HTTP 404 responses to trigger the third rule.
	for i := 0; i < 10; i++ {
		_, err := repo.db.ExecContext(ctx, `
		INSERT INTO logs (
			id, website_id, ip, method, path, status,
			event_type, severity, created_at
		) VALUES (?, 'website-a', '192.0.2.70', 'GET', ?,
			404, 'http_request', 'info', ?)
	`, fmt.Sprintf("scheduler-404-%d", i), fmt.Sprintf("/missing-%d", i), recent)
		if err != nil {
			t.Fatalf("insert HTTP 404 log: %v", err)
		}
	}

	// Insert authentication failures to trigger the second rule.
	for i := 0; i < 3; i++ {
		_, err := repo.db.ExecContext(ctx, `
			INSERT INTO logs (
				id, website_id, ip, method, path, status,
				event_type, severity, created_at
			) VALUES (?, 'website-a', '192.0.2.60', 'POST', '/login',
				401, 'auth_failure', 'low', ?)
		`, "scheduler-auth-"+string(rune('a'+i)), recent)
		if err != nil {
			t.Fatalf("insert authentication failure log: %v", err)
		}
	}

	// Insert 100 requests from one IP to trigger request-rate detection.
	for i := 0; i < 100; i++ {
		_, err := repo.db.ExecContext(ctx, `
			INSERT INTO logs (
				id, website_id, ip, method, path, status,
				event_type, severity, created_at
			) VALUES (?, 'website-a', '192.0.2.90', 'GET', ?,
				200, 'http_request', 'info', ?)
		`, fmt.Sprintf("scheduler-rate-%d", i),
			fmt.Sprintf("/page-%d", i), recent)
		if err != nil {
			t.Fatalf("insert request-rate log: %v", err)
		}
	}

	detector, err := NewDetector(repo, DetectorConfig{
		Window:                  10 * time.Minute,
		MinimumCount:            3,
		BruteForceMinimumCount:  3,
		NotFoundMinimumCount:    10,
		SuppressFor:             30 * time.Minute,
		RequestRateMinimumCount: 100,
	})
	if err != nil {
		t.Fatalf("NewDetector() error: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	scheduler := NewScheduler(detector, time.Minute, logger)

	scheduler.runDetection(ctx)

	alerts, err := repo.List(ctx, "org-a", "open", 50, 0)
	if err != nil {
		t.Fatalf("list alerts: %v", err)
	}

	foundRules := make(map[string]bool)
	for _, alert := range alerts {
		foundRules[alert.RuleKey] = true
	}

	if !foundRules[HTTP5xxSpikeRuleKey] {
		t.Error("expected HTTP 5xx spike alert")
	}
	if len(alerts) != 5 {
		t.Fatalf("expected 5 alerts from scheduler, got %d: %+v", len(alerts), alerts)
	}
	if !foundRules[BruteForceRuleKey] {
		t.Error("expected brute-force alert")
	}
	if !foundRules[NotFoundRuleKey] {
		t.Error("expected HTTP 404 spike alert")
	}
	if !foundRules[RequestRateRuleKey] {
		t.Error("expected request-rate alert")
	}
}
