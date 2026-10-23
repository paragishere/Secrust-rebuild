package alerts

import (
	"testing"
	"time"
)

func TestFindHTTPErrorSpikesUsesThresholdAndTimeWindow(t *testing.T) {
	repo, ctx := setupAlertRepository(t)

	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-5 * time.Minute).Format(time.RFC3339Nano)
	old := now.Add(-2 * time.Hour).Format(time.RFC3339Nano)

	insertLog := func(id, websiteID string, status int, createdAt string) {
		t.Helper()
		_, err := repo.db.ExecContext(ctx, `
INSERT INTO logs (
id, website_id, method, path, status,
event_type, severity, created_at
) VALUES (?, ?, 'GET', '/', ?, 'http_request', 'info', ?)
`, id, websiteID, status, createdAt)
		if err != nil {
			t.Fatalf("insert test log: %v", err)
		}
	}

	insertLog("recent-1", "website-a", 500, recent)
	insertLog("recent-2", "website-a", 502, recent)
	insertLog("recent-3", "website-a", 503, recent)
	insertLog("recent-4", "website-b", 500, recent)
	insertLog("recent-5", "website-b", 502, recent)
	insertLog("old-1", "website-b", 500, old)
	insertLog("old-2", "website-b", 501, old)
	insertLog("old-3", "website-b", 503, old)

	candidates, err := repo.FindHTTPErrorSpikes(
		ctx, now.Add(-15*time.Minute), 3,
	)
	if err != nil {
		t.Fatalf("FindHTTPErrorSpikes() error: %v", err)
	}

	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d: %+v", len(candidates), candidates)
	}

	got := candidates[0]
	if got.OrganizationID != "org-a" {
		t.Errorf("expected org-a, got %q", got.OrganizationID)
	}
	if got.WebsiteID != "website-a" {
		t.Errorf("expected website-a, got %q", got.WebsiteID)
	}
	if got.ErrorCount != 3 {
		t.Errorf("expected 3 errors, got %d", got.ErrorCount)
	}
	if got.FirstSeen != recent || got.LastSeen != recent {
		t.Errorf("unexpected time range: first=%q last=%q", got.FirstSeen, got.LastSeen)
	}
}

func TestFindHTTPErrorSpikesRejectsInvalidThreshold(t *testing.T) {
	repo, ctx := setupAlertRepository(t)

	_, err := repo.FindHTTPErrorSpikes(
		ctx, time.Now().Add(-time.Hour), 0,
	)
	if err == nil {
		t.Fatal("expected an error for zero threshold")
	}
}
