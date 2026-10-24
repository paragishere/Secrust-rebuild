package alerts

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/paragishere/secrust/internal/database"
)

func setupAlertRepository(t *testing.T) (*Repository, context.Context) {
	t.Helper()

	db, err := database.Open(filepath.Join(t.TempDir(), "alerts.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
	})

	ctx := context.Background()
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	statements := []string{
		`INSERT INTO organizations (id, name, created_at)
		 VALUES ('org-a', 'Organization A', '2026-10-23T00:00:00Z')`,
		`INSERT INTO organizations (id, name, created_at)
		 VALUES ('org-b', 'Organization B', '2026-10-23T00:00:00Z')`,

		`INSERT INTO users (id, name, email, password_hash, created_at)
		 VALUES ('user-a', 'User A', 'a@example.com', 'hash', '2026-10-23T00:00:00Z')`,
		`INSERT INTO users (id, name, email, password_hash, created_at)
		 VALUES ('user-b', 'User B', 'b@example.com', 'hash', '2026-10-23T00:00:00Z')`,

		`INSERT INTO organization_users (organization_id, user_id, role, created_at)
		 VALUES ('org-a', 'user-a', 'SUPER_ADMIN', '2026-10-23T00:00:00Z')`,
		`INSERT INTO organization_users (organization_id, user_id, role, created_at)
		 VALUES ('org-b', 'user-b', 'SUPER_ADMIN', '2026-10-23T00:00:00Z')`,

		`INSERT INTO websites (
			id, organization_id, created_by, domain, hash_id, api_key_hash, created_at
		) VALUES (
			'website-a', 'org-a', 'user-a', 'a.example.com',
			'hash-a', 'api-hash-a', '2026-10-23T00:00:00Z'
		)`,
		`INSERT INTO websites (
			id, organization_id, created_by, domain, hash_id, api_key_hash, created_at
		) VALUES (
			'website-b', 'org-b', 'user-b', 'b.example.com',
			'hash-b', 'api-hash-b', '2026-10-23T00:00:00Z'
		)`,
	}

	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("prepare fixture: %v", err)
		}
	}

	// for _, statement := range statements {
	// 	if _, err := db.ExecContext(ctx, statement); err != nil {
	// 		t.Fatalf("prepare fixture: %v", err)
	// 	}
	// }

	return NewRepository(db), ctx
}

func TestCreateAlertResolvesOrganizationFromWebsite(t *testing.T) {
	repo, ctx := setupAlertRepository(t)

	alert, err := repo.Create(ctx, CreateInput{
		WebsiteID: "website-a",
		Severity:  "HIGH",
		Type:      "brute_force",
		Message:   "Repeated authentication failures",
		IP:        "192.0.2.10",
		RuleKey:   "auth.brute_force",
		Details:   map[string]any{"attempts": 10},
	})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if alert.ID == "" {
		t.Fatal("expected generated alert ID")
	}
	if alert.OrganizationID != "org-a" {
		t.Fatalf("expected organization org-a, got %q", alert.OrganizationID)
	}
	if alert.Status != "open" {
		t.Fatalf("expected status open, got %q", alert.Status)
	}
	if alert.Severity != "high" {
		t.Fatalf("expected normalized severity high, got %q", alert.Severity)
	}

	var storedOrg, storedStatus string
	err = repo.db.QueryRowContext(ctx, `
		SELECT organization_id, status
		FROM alerts WHERE id = ?
	`, alert.ID).Scan(&storedOrg, &storedStatus)
	if err != nil {
		t.Fatal(err)
	}
	if storedOrg != "org-a" || storedStatus != "open" {
		t.Fatalf("unexpected stored alert: organization=%q status=%q",
			storedOrg, storedStatus)
	}
}

func TestListAlertsIsOrganizationScoped(t *testing.T) {
	repo, ctx := setupAlertRepository(t)

	_, err := repo.Create(ctx, CreateInput{
		WebsiteID: "website-a",
		Severity:  "high",
		Type:      "test_alert",
		Message:   "Alert belonging to organization A",
	})
	if err != nil {
		t.Fatal(err)
	}

	alerts, err := repo.List(ctx, "org-b", "", 50, 0)
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("expected no alerts for org-b, got %d", len(alerts))
	}

	alerts, err = repo.List(ctx, "org-a", "open", 50, 0)
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert for org-a, got %d", len(alerts))
	}
}

func TestSetStatusEnforcesOrganizationAndTransitions(t *testing.T) {
	repo, ctx := setupAlertRepository(t)

	alert, err := repo.Create(ctx, CreateInput{
		WebsiteID: "website-a",
		Severity:  "medium",
		Type:      "test_alert",
		Message:   "Lifecycle test",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Another organization must not be able to modify this alert.
	err = repo.SetStatus(ctx, "org-b", alert.ID, "user-a", "acknowledged")
	if !errors.Is(err, ErrAlertNotFound) {
		t.Fatalf("expected ErrAlertNotFound for cross-organization access, got %v", err)
	}

	if err := repo.SetStatus(ctx, "org-a", alert.ID, "user-a", "acknowledged"); err != nil {
		t.Fatalf("acknowledge alert: %v", err)
	}

	// An acknowledged alert can be resolved.
	if err := repo.SetStatus(ctx, "org-a", alert.ID, "user-a", "resolved"); err != nil {
		t.Fatalf("resolve alert: %v", err)
	}

	// A resolved alert cannot be acknowledged again.
	err = repo.SetStatus(ctx, "org-a", alert.ID, "user-a", "acknowledged")
	if !errors.Is(err, ErrAlertNotFound) {
		t.Fatalf("expected ErrAlertNotFound for invalid transition, got %v", err)
	}

	alerts, err := repo.List(ctx, "org-a", "resolved", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected one resolved alert, got %d", len(alerts))
	}
	if alerts[0].ResolvedBy != "user-a" || alerts[0].ResolvedAt == "" {
		t.Fatal("expected resolver and resolution timestamp to be stored")
	}
}

func TestCreateRejectsInvalidInput(t *testing.T) {
	repo, ctx := setupAlertRepository(t)

	tests := []CreateInput{
		{
			WebsiteID: "website-a",
			Severity:  "unknown",
			Type:      "test",
			Message:   "Invalid severity",
		},
		{
			WebsiteID: "missing-website",
			Severity:  "high",
			Type:      "test",
			Message:   "Missing website",
		},
		{
			WebsiteID: "website-a",
			Severity:  "high",
			Type:      "",
			Message:   "Missing type",
		},
	}

	for _, input := range tests {
		_, err := repo.Create(ctx, input)
		if err == nil {
			t.Errorf("expected invalid input to be rejected: %+v", input)
		}
	}
}

func TestHasRecentOpenAlert(t *testing.T) {
	repo, ctx := setupAlertRepository(t)

	alert, err := repo.Create(ctx, CreateInput{
		WebsiteID: "website-a",
		Severity:  "high",
		Type:      "http_error_spike",
		Message:   "HTTP 5xx spike detected",
		RuleKey:   "http.5xx_spike",
	})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	since := time.Now().UTC().Add(-5 * time.Minute)

	exists, err := repo.HasRecentOpenAlert(
		ctx, "website-a", "http.5xx_spike", since,
	)
	if err != nil {
		t.Fatalf("HasRecentOpenAlert() error: %v", err)
	}
	if !exists {
		t.Fatal("expected recent open alert to exist")
	}

	// A different website must not match.
	exists, err = repo.HasRecentOpenAlert(
		ctx, "website-b", "http.5xx_spike", since,
	)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("unexpected alert found for another website")
	}

	// A different rule must not match.
	exists, err = repo.HasRecentOpenAlert(
		ctx, "website-a", "auth.brute_force", since,
	)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("unexpected alert found for another rule")
	}

	// A resolved alert should not count as an open duplicate.
	if err := repo.SetStatus(
		ctx, "org-a", alert.ID, "user-a", "resolved",
	); err != nil {
		t.Fatalf("resolve alert: %v", err)
	}

	exists, err = repo.HasRecentOpenAlert(
		ctx, "website-a", "http.5xx_spike", since,
	)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("resolved alert must not count as an open duplicate")
	}
}

func TestHasRecentOpenAlertRejectsInvalidInput(t *testing.T) {
	repo, ctx := setupAlertRepository(t)

	_, err := repo.HasRecentOpenAlert(
		ctx, "", "http.5xx_spike", time.Now().UTC(),
	)
	if err == nil {
		t.Fatal("expected error for empty website ID")
	}
}

func TestGetAlertIsOrganizationScoped(t *testing.T) {
	repo, ctx := setupAlertRepository(t)

	created, err := repo.Create(ctx, CreateInput{
		WebsiteID: "website-a",
		Severity:  "high",
		Type:      "test_alert",
		Message:   "Test alert details",
		IP:        "192.0.2.10",
		RuleKey:   "test_rule",
		Details:   map[string]any{"source": "test"},
	})
	if err != nil {
		t.Fatalf("create alert: %v", err)
	}

	got, err := repo.Get(ctx, "org-a", created.ID)
	if err != nil {
		t.Fatalf("get alert: %v", err)
	}
	if got.ID != created.ID {
		t.Fatalf("expected alert ID %q, got %q", created.ID, got.ID)
	}
	if got.OrganizationID != "org-a" {
		t.Fatalf("expected organization org-a, got %q", got.OrganizationID)
	}

	_, err = repo.Get(ctx, "org-b", created.ID)
	if !errors.Is(err, ErrAlertNotFound) {
		t.Fatalf("expected ErrAlertNotFound for another organization, got %v", err)
	}
}

func TestGetAlertNotFound(t *testing.T) {
	repo, ctx := setupAlertRepository(t)

	_, err := repo.Get(ctx, "org-a", "missing-alert")
	if !errors.Is(err, ErrAlertNotFound) {
		t.Fatalf("expected ErrAlertNotFound, got %v", err)
	}
}

func TestGetAlertRejectsInvalidInput(t *testing.T) {
	repo, ctx := setupAlertRepository(t)

	tests := []struct {
		name string
		org  string
		id   string
	}{
		{name: "missing organization", org: "", id: "alert-1"},
		{name: "missing alert ID", org: "org-a", id: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := repo.Get(ctx, tt.org, tt.id)
			if !errors.Is(err, ErrInvalidAlert) {
				t.Fatalf("expected ErrInvalidAlert, got %v", err)
			}
		})
	}
}
