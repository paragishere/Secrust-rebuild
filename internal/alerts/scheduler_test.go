package alerts

import (
	// "context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestSchedulerRunsBothDetectionRules(t *testing.T) {
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

	detector, err := NewDetector(repo, DetectorConfig{
		Window:                 10 * time.Minute,
		MinimumCount:           3,
		BruteForceMinimumCount: 3,
		SuppressFor:            30 * time.Minute,
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

	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts from scheduler, got %d: %+v", len(alerts), alerts)
	}

	foundRules := make(map[string]bool)
	for _, alert := range alerts {
		foundRules[alert.RuleKey] = true
	}

	if !foundRules[HTTP5xxSpikeRuleKey] {
		t.Error("expected HTTP 5xx spike alert")
	}
	if !foundRules[BruteForceRuleKey] {
		t.Error("expected brute-force alert")
	}
}
