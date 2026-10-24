package alerts

import (
	"fmt"
	"testing"
	"time"
)

func TestAdvancedDetectionRules(t *testing.T) {
	repo, ctx := setupAlertRepository(t)
	now := time.Now().UTC()

	insertLog := func(id, ip, path, ua, eventType string, status int, createdAt time.Time) {
		t.Helper()
		_, err := repo.db.ExecContext(ctx, `
INSERT INTO logs (
id, website_id, ip, method, path, status,
user_agent, event_type, severity, created_at
) VALUES (?, 'website-a', ?, 'GET', ?, ?, ?, ?, 'info', ?)
`, id, ip, path, status, ua, eventType,
			createdAt.Format(time.RFC3339Nano))
		if err != nil {
			t.Fatalf("insert test log %s: %v", id, err)
		}
	}

	// Scanner User-Agent, injection pattern, and sensitive path.
	insertLog("advanced-ua", "192.0.2.11", "/", "Nuclei/3.0", "http_request", 200, now.Add(-time.Minute))
	insertLog("advanced-injection", "192.0.2.12", "/search?q=%3cscript", "Browser/1.0", "http_request", 400, now.Add(-time.Minute))
	insertLog("advanced-sensitive", "192.0.2.13", "/.env", "Browser/1.0", "http_request", 404, now.Add(-time.Minute))

	// Repeated denied responses from a single IP.
	for i := 0; i < 3; i++ {
		insertLog(fmt.Sprintf("advanced-denied-%d", i),
			"192.0.2.20", "/login", "Browser/1.0", "http_request", 401,
			now.Add(-time.Minute))
	}

	// Distributed authentication failures from three different IPs.
	for i, ip := range []string{"192.0.2.31", "192.0.2.32", "192.0.2.33"} {
		insertLog(fmt.Sprintf("advanced-distributed-%d", i),
			ip, "/login", "Browser/1.0", "auth_failure", 401,
			now.Add(-time.Minute))
	}

	// Historical baseline: 10 requests in the preceding window.
	for i := 0; i < 10; i++ {
		insertLog(fmt.Sprintf("advanced-baseline-%d", i),
			"192.0.2.40", "/home", "Browser/1.0", "http_request", 200,
			now.Add(-15*time.Minute))
	}

	// Current window: 100 requests, a 10x increase.
	for i := 0; i < 100; i++ {
		insertLog(fmt.Sprintf("advanced-current-%d", i),
			"192.0.2.40", "/home", "Browser/1.0", "http_request", 200,
			now.Add(-time.Minute))
	}

	detector, err := NewDetector(repo, DetectorConfig{
		Window:                  10 * time.Minute,
		MinimumCount:            3,
		BruteForceMinimumCount:  3,
		NotFoundMinimumCount:    10,
		RequestRateMinimumCount: 100,
		SuppressFor:             30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewDetector: %v", err)
	}

	result, err := detector.RunAdvancedDetection(ctx)
	if err != nil {
		t.Fatalf("RunAdvancedDetection: %v", err)
	}
	if result.AlertsCreated != 6 {
		t.Fatalf("expected 6 advanced alerts, got %+v", result)
	}

	alerts, err := repo.List(ctx, "org-a", "open", 50, 0)
	if err != nil {
		t.Fatalf("list alerts: %v", err)
	}

	found := make(map[string]bool)
	for _, alert := range alerts {
		found[alert.RuleKey] = true
	}

	for _, rule := range []string{
		SuspiciousUserAgentRuleKey,
		InjectionPatternRuleKey,
		SensitivePathRuleKey,
		DistributedBruteForceKey,
		TrafficAnomalyRuleKey,
		AuthDeniedSpikeRuleKey,
	} {
		if !found[rule] {
			t.Errorf("expected alert for rule %q", rule)
		}
	}
}
