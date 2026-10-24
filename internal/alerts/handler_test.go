package alerts

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func setupAlertHandlerTest(t *testing.T) (*Handler, *Repository) {
	t.Helper()

	repo, ctx := setupAlertRepository(t)

	// Create alerts in two separate organizations.
	_, err := repo.Create(ctx, CreateInput{
		WebsiteID: "website-a",
		Severity:  "high",
		Type:      "http_error_spike",
		Message:   "Organization A alert",
		RuleKey:   HTTP5xxSpikeRuleKey,
	})
	if err != nil {
		t.Fatalf("create org-a alert: %v", err)
	}

	_, err = repo.Create(ctx, CreateInput{
		WebsiteID: "website-b",
		Severity:  "medium",
		Type:      "test_alert",
		Message:   "Organization B alert",
		RuleKey:   "test.rule",
	})
	if err != nil {
		t.Fatalf("create org-b alert: %v", err)
	}

	return NewHandler(repo), repo
}

func TestAlertHandlerListIsOrganizationScoped(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _ := setupAlertHandlerTest(t)

	router := gin.New()
	router.GET("/api/alerts", func(c *gin.Context) {
		c.Set(contextOrganizationID, "org-a")
		c.Set(contextUserID, "user-a")
		handler.List(c)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/alerts", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s",
			http.StatusOK, rec.Code, rec.Body.String())
	}

	var response struct {
		Alerts []Alert `json:"alerts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if len(response.Alerts) != 1 {
		t.Fatalf("expected 1 organization-scoped alert, got %d",
			len(response.Alerts))
	}
	if response.Alerts[0].OrganizationID != "org-a" {
		t.Fatalf("expected org-a alert, got organization %q",
			response.Alerts[0].OrganizationID)
	}
	if response.Alerts[0].Message != "Organization A alert" {
		t.Fatalf("unexpected alert returned: %q",
			response.Alerts[0].Message)
	}
}

func TestAlertHandlerListFiltersByStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, repo := setupAlertHandlerTest(t)

	// Resolve the org-a alert so only the org-b alert remains open.
	alerts, err := repo.List(t.Context(), "org-a", "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 org-a alert, got %d", len(alerts))
	}
	if err := repo.SetStatus(
		t.Context(), "org-a", alerts[0].ID, "user-a", "resolved",
	); err != nil {
		t.Fatalf("resolve alert: %v", err)
	}

	router := gin.New()
	router.GET("/api/alerts", func(c *gin.Context) {
		c.Set(contextOrganizationID, "org-a")
		c.Set(contextUserID, "user-a")
		handler.List(c)
	})

	req := httptest.NewRequest(
		http.MethodGet, "/api/alerts?status=resolved", nil,
	)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s",
			http.StatusOK, rec.Code, rec.Body.String())
	}

	var response struct {
		Alerts []Alert `json:"alerts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Alerts) != 1 || response.Alerts[0].Status != "resolved" {
		t.Fatalf("expected one resolved alert, got %+v", response.Alerts)
	}
}

func TestAlertHandlerListRejectsInvalidQuery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _ := setupAlertHandlerTest(t)

	router := gin.New()
	router.GET("/api/alerts", func(c *gin.Context) {
		c.Set(contextOrganizationID, "org-a")
		handler.List(c)
	})

	req := httptest.NewRequest(
		http.MethodGet, "/api/alerts?limit=invalid", nil,
	)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s",
			http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

func TestAlertHandlerListRequiresOrganization(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _ := setupAlertHandlerTest(t)

	router := gin.New()
	router.GET("/api/alerts", handler.List)

	req := httptest.NewRequest(http.MethodGet, "/api/alerts", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d",
			http.StatusUnauthorized, rec.Code)
	}
}

func TestAlertHandlerResolveIsOrganizationScoped(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, repo := setupAlertHandlerTest(t)

	orgBAlerts, err := repo.List(t.Context(), "org-b", "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(orgBAlerts) != 1 {
		t.Fatalf("expected one org-b alert, got %d", len(orgBAlerts))
	}

	router := gin.New()
	router.PATCH("/api/alerts/:alertID/resolve", func(c *gin.Context) {
		c.Set(contextOrganizationID, "org-a")
		c.Set(contextUserID, "user-a")
		handler.Resolve(c)
	})

	req := httptest.NewRequest(
		http.MethodPatch,
		"/api/alerts/"+orgBAlerts[0].ID+"/resolve",
		nil,
	)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d: %s",
			http.StatusNotFound, rec.Code, rec.Body.String())
	}

	// The alert belonging to org-b must remain open.
	updated, err := repo.List(t.Context(), "org-b", "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated) != 1 || updated[0].Status != "open" {
		t.Fatalf("org-b alert should remain open, got %+v", updated)
	}
}

func TestAlertHandlerResolveSucceeds(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, repo := setupAlertHandlerTest(t)

	orgAAlerts, err := repo.List(t.Context(), "org-a", "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(orgAAlerts) != 1 {
		t.Fatalf("expected one org-a alert, got %d", len(orgAAlerts))
	}

	router := gin.New()
	router.PATCH("/api/alerts/:alertID/resolve", func(c *gin.Context) {
		c.Set(contextOrganizationID, "org-a")
		c.Set(contextUserID, "user-a")
		handler.Resolve(c)
	})

	req := httptest.NewRequest(
		http.MethodPatch,
		"/api/alerts/"+orgAAlerts[0].ID+"/resolve",
		nil,
	)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s",
			http.StatusOK, rec.Code, rec.Body.String())
	}

	updated, err := repo.List(t.Context(), "org-a", "resolved", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated) != 1 {
		t.Fatalf("expected one resolved alert, got %d", len(updated))
	}
	if updated[0].ResolvedBy != "user-a" {
		t.Fatalf("expected resolved_by user-a, got %q", updated[0].ResolvedBy)
	}
}
