package alerts

import (
	"testing"
	"time"
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
