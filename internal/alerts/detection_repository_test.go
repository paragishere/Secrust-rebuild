package alerts

import (
	"fmt"
	"testing"
	"time"
)

func TestFindBruteForceCandidates(t *testing.T) {
	repo, ctx := setupAlertRepository(t)

	now := time.Now().UTC()
	since := now.Add(-10 * time.Minute)

	insertLog := func(id, websiteID, ip, eventType string, createdAt time.Time) {
		t.Helper()

		_, err := repo.db.ExecContext(ctx, `
			INSERT INTO logs (
				id, website_id, ip, method, path, status,
				user_agent, country, city, event_type, severity, created_at
			) VALUES (?, ?, ?, 'POST', '/login', 401, 'test-agent',
				'', '', ?, 'low', ?)
		`,
			id, websiteID, ip, eventType,
			createdAt.UTC().Format(time.RFC3339Nano),
		)
		if err != nil {
			t.Fatalf("insert test log %s: %v", id, err)
		}
	}

	// Three failures from the same IP on website A.
	for i := 0; i < 3; i++ {
		insertLog(
			fmt.Sprintf("failure-a-%d", i),
			"website-a",
			"192.0.2.10",
			"auth_failure",
			now.Add(-time.Duration(i)*time.Minute),
		)
	}

	// Two failures from a different IP: below the threshold.
	for i := 0; i < 2; i++ {
		insertLog(
			fmt.Sprintf("failure-b-%d", i),
			"website-a",
			"192.0.2.20",
			"auth_failure",
			now.Add(-time.Duration(i)*time.Minute),
		)
	}

	// Failures on website B must be grouped separately.
	for i := 0; i < 3; i++ {
		insertLog(
			fmt.Sprintf("failure-c-%d", i),
			"website-b",
			"192.0.2.10",
			"auth_failure",
			now.Add(-time.Duration(i)*time.Minute),
		)
	}

	// A different event type must not count as an authentication failure.
	for i := 0; i < 5; i++ {
		insertLog(
			fmt.Sprintf("other-event-%d", i),
			"website-a",
			"192.0.2.30",
			"http_request",
			now.Add(-time.Duration(i)*time.Minute),
		)
	}

	// An authentication failure outside the detection window must be ignored.
	insertLog(
		"old-failure",
		"website-a",
		"192.0.2.40",
		"auth_failure",
		since.Add(-time.Minute),
	)

	// A blank IP must not produce a candidate.
	for i := 0; i < 3; i++ {
		insertLog(
			fmt.Sprintf("blank-ip-%d", i),
			"website-a",
			"",
			"auth_failure",
			now.Add(-time.Duration(i)*time.Minute),
		)
	}

	candidates, err := repo.FindBruteForceCandidates(ctx, since, 3)
	if err != nil {
		t.Fatalf("FindBruteForceCandidates() error: %v", err)
	}

	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d: %+v", len(candidates), candidates)
	}

	found := make(map[string]BruteForceCandidate)
	for _, candidate := range candidates {
		key := candidate.WebsiteID + "|" + candidate.IP
		found[key] = candidate
	}

	for _, key := range []string{
		"website-a|192.0.2.10",
		"website-b|192.0.2.10",
	} {
		candidate, ok := found[key]
		if !ok {
			t.Errorf("expected candidate %s", key)
			continue
		}

		if candidate.FailureCount != 3 {
			t.Errorf("%s: expected 3 failures, got %d", key, candidate.FailureCount)
		}
		if candidate.OrganizationID == "" {
			t.Errorf("%s: expected organization ID", key)
		}
		if candidate.FirstSeen == "" || candidate.LastSeen == "" {
			t.Errorf("%s: expected first and last seen timestamps", key)
		}
	}
}

func TestFindBruteForceCandidatesRejectsInvalidThreshold(t *testing.T) {
	repo, ctx := setupAlertRepository(t)

	_, err := repo.FindBruteForceCandidates(ctx, time.Now().UTC(), 0)
	if err == nil {
		t.Fatal("expected an error for zero threshold")
	}
}
