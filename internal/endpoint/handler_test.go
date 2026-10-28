package endpoint

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/paragishere/secrust/internal/database"
)

func newEndpointTestSetup(t *testing.T) (*Repository, string, *gin.Engine) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db, err := database.Open(filepath.Join(t.TempDir(), "endpoint-test.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatalf("migrate database: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = db.ExecContext(ctx, `
		INSERT INTO organizations (id, name, created_at)
		VALUES ('org-test', 'Test Org', ?)
	`, now)
	if err != nil {
		t.Fatalf("insert organization: %v", err)
	}

	repo := NewRepository(db)

	rawKey := "test-agent-key-12345678901234567890"
	sum := sha256.Sum256([]byte(rawKey))
	err = repo.CreateHost(ctx, CreateHostInput{
		ID:             "host-test",
		OrganizationID: "org-test",
		Hostname:       "test-machine",
		OSType:         "windows",
		AgentVersion:   "0.1.0",
		CredentialHash: hex.EncodeToString(sum[:]),
	})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}

	handler := NewHandler(repo)
	router := gin.New()
	router.POST("/api/endpoint/events", AgentKeyAuth(repo), handler.IngestEvents)
	router.POST("/api/endpoint/heartbeat", AgentKeyAuth(repo), handler.Heartbeat)

	return repo, rawKey, router
}
func addTestOrganization(t *testing.T, repo *Repository, orgID, hostname, hostID string) {
	t.Helper()

	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339Nano)

	_, err := repo.db.ExecContext(ctx, `
		INSERT INTO organizations (id, name, created_at)
		VALUES (?, ?, ?)
	`, orgID, orgID, now)
	if err != nil {
		t.Fatalf("insert test organization %s: %v", orgID, err)
	}

	sum := sha256.Sum256([]byte("key-" + hostID))
	err = repo.CreateHost(ctx, CreateHostInput{
		ID:             hostID,
		OrganizationID: orgID,
		Hostname:       hostname,
		OSType:         "linux",
		AgentVersion:   "0.1.0",
		CredentialHash: hex.EncodeToString(sum[:]),
	})
	if err != nil {
		t.Fatalf("create test host %s: %v", hostID, err)
	}
}

func sendJSON(
	t *testing.T,
	router http.Handler,
	path, key string,
	payload any,
) *httptest.ResponseRecorder {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("X-Agent-Key", key)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func validEndpointEvent() Event {
	return Event{
		EventUID:    "event-unique-1",
		EventID:     4625,
		EventType:   "failed_logon",
		Severity:    "medium",
		RiskScore:   50,
		OccurredAt:  time.Now().UTC().Format(time.RFC3339Nano),
		SourceIP:    "192.0.2.10",
		AccountName: "test-user",
		Details: map[string]any{
			"computer": "test-machine",
		},
	}
}

func TestAgentKeyAuthRejectsInvalidKey(t *testing.T) {
	repo, _, router := newEndpointTestSetup(t)
	_ = repo

	rec := sendJSON(t, router, "/api/endpoint/heartbeat", "wrong-key", map[string]any{})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestEndpointEventIngestionAndDuplicateProtection(t *testing.T) {
	repo, key, router := newEndpointTestSetup(t)

	payload := map[string]any{
		"events": []Event{validEndpointEvent()},
	}

	first := sendJSON(t, router, "/api/endpoint/events", key, payload)
	if first.Code != http.StatusOK {
		t.Fatalf("expected first ingestion 200, got %d: %s", first.Code, first.Body.String())
	}

	second := sendJSON(t, router, "/api/endpoint/events", key, payload)
	if second.Code != http.StatusOK {
		t.Fatalf("expected duplicate ingestion 200, got %d: %s", second.Code, second.Body.String())
	}

	var count int
	err := repo.db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM endpoint_events
		WHERE host_id = 'host-test' AND event_uid = 'event-unique-1'
	`).Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected one event after duplicate delivery, got %d", count)
	}

	var response struct {
		Accepted   int `json:"accepted"`
		Duplicates int `json:"duplicates"`
	}
	if err := json.Unmarshal(second.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Duplicates != 1 || response.Accepted != 0 {
		t.Fatalf("unexpected duplicate response: %+v", response)
	}
}

func TestEndpointHeartbeat(t *testing.T) {
	repo, key, router := newEndpointTestSetup(t)

	rec := sendJSON(t, router, "/api/endpoint/heartbeat", key, map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var heartbeat string
	err := repo.db.QueryRowContext(context.Background(), `
		SELECT last_heartbeat FROM endpoint_hosts WHERE id = 'host-test'
	`).Scan(&heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	if heartbeat == "" {
		t.Fatal("expected heartbeat timestamp to be stored")
	}
}

func TestEndpointEventRejectsInvalidSeverity(t *testing.T) {
	_, key, router := newEndpointTestSetup(t)

	event := validEndpointEvent()
	event.Severity = "emergency"

	rec := sendJSON(t, router, "/api/endpoint/events", key, map[string]any{
		"events": []Event{event},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDisabledEndpointCredentialRejected(t *testing.T) {
	repo, key, router := newEndpointTestSetup(t)

	_, err := repo.db.ExecContext(context.Background(), `
		UPDATE endpoint_hosts SET status = 'disabled' WHERE id = 'host-test'
	`)
	if err != nil {
		t.Fatal(err)
	}

	rec := sendJSON(t, router, "/api/endpoint/heartbeat", key, map[string]any{})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for disabled host, got %d", rec.Code)
	}
}
func TestListHostsOrganizationIsolation(t *testing.T) {
	repo, _, _ := newEndpointTestSetup(t)

	addTestOrganization(t, repo, "org-other", "linux-machine", "host-other")

	hosts, err := repo.ListHosts(context.Background(), "org-test")
	if err != nil {
		t.Fatalf("list hosts: %v", err)
	}

	if len(hosts) != 1 {
		t.Fatalf("expected 1 host for org-test, got %d", len(hosts))
	}
	if hosts[0].ID != "host-test" {
		t.Fatalf("unexpected host returned: %s", hosts[0].ID)
	}

	otherHosts, err := repo.ListHosts(context.Background(), "org-other")
	if err != nil {
		t.Fatalf("list other organization hosts: %v", err)
	}
	if len(otherHosts) != 1 || otherHosts[0].ID != "host-other" {
		t.Fatalf("unexpected other organization hosts: %+v", otherHosts)
	}
}

func TestListEventsOrganizationIsolation(t *testing.T) {
	repo, _, _ := newEndpointTestSetup(t)

	addTestOrganization(t, repo, "org-other", "linux-machine", "host-other")

	event := validEndpointEvent()
	event.ID = "event-other-id"
	event.HostID = "host-other"

	inserted, err := repo.InsertEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("insert other organization's event: %v", err)
	}
	if !inserted {
		t.Fatal("expected event to be inserted")
	}

	// An organization must not retrieve another organization's host events.
	events, err := repo.ListEvents(
		context.Background(), "org-test", "host-other", 50, 0,
	)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no cross-organization events, got %d", len(events))
	}

	// The owning organization should be able to retrieve its event.
	events, err = repo.ListEvents(
		context.Background(), "org-other", "host-other", 50, 0,
	)
	if err != nil {
		t.Fatalf("list owning organization's events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
}

func TestListEventsPagination(t *testing.T) {
	repo, _, _ := newEndpointTestSetup(t)
	ctx := context.Background()

	for i, uid := range []string{"page-event-1", "page-event-2", "page-event-3"} {
		event := validEndpointEvent()
		event.ID = fmt.Sprintf("page-id-%d", i+1)
		event.HostID = "host-test"
		event.EventUID = uid
		event.OccurredAt = time.Date(
			2026, 10, 29, 10, i, 0, 0, time.UTC,
		).Format(time.RFC3339Nano)

		inserted, err := repo.InsertEvent(ctx, event)
		if err != nil {
			t.Fatalf("insert event %s: %v", uid, err)
		}
		if !inserted {
			t.Fatalf("expected event %s to be inserted", uid)
		}
	}

	firstPage, err := repo.ListEvents(ctx, "org-test", "host-test", 2, 0)
	if err != nil {
		t.Fatalf("list first page: %v", err)
	}
	if len(firstPage) != 2 {
		t.Fatalf("expected 2 events on first page, got %d", len(firstPage))
	}

	secondPage, err := repo.ListEvents(ctx, "org-test", "host-test", 2, 2)
	if err != nil {
		t.Fatalf("list second page: %v", err)
	}
	if len(secondPage) != 1 {
		t.Fatalf("expected 1 event on second page, got %d", len(secondPage))
	}

	if firstPage[0].EventUID == secondPage[0].EventUID ||
		firstPage[1].EventUID == secondPage[0].EventUID {
		t.Fatal("pagination returned a duplicate event")
	}
}

func TestListEventsInvalidHostReturnsEmpty(t *testing.T) {
	repo, _, _ := newEndpointTestSetup(t)

	events, err := repo.ListEvents(
		context.Background(), "org-test", "missing-host", 50, 0,
	)
	if err != nil {
		t.Fatalf("expected empty result for missing host, got error: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no events, got %d", len(events))
	}
}
func TestListHostsRequiresOrganizationContext(t *testing.T) {
	_, _, _ = newEndpointTestSetup(t)

	gin.SetMode(gin.TestMode)
	handler := NewHandler(nil)

	router := gin.New()
	router.GET("/api/endpoints", handler.ListHosts)

	req := httptest.NewRequest(http.MethodGet, "/api/endpoints", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without organization context, got %d: %s",
			rec.Code, rec.Body.String())
	}
}

func TestListHostEventsRequiresOrganizationContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewHandler(nil)

	router := gin.New()
	router.GET("/api/endpoints/:hostID/events", handler.ListHostEvents)

	req := httptest.NewRequest(
		http.MethodGet,
		"/api/endpoints/host-test/events",
		nil,
	)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without organization context, got %d: %s",
			rec.Code, rec.Body.String())
	}
}
