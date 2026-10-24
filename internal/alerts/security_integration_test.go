package alerts

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/paragishere/secrust/internal/auth"
	"github.com/paragishere/secrust/internal/database"
	"golang.org/x/crypto/bcrypt"
)

func TestAlertMutationSecurityMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := database.Open(filepath.Join(t.TempDir(), "security.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte("Correct-Horse-42!"),
		bcrypt.MinCost,
	)
	if err != nil {
		t.Fatal(err)
	}

	statements := []struct {
		query string
		args  []any
	}{
		{
			`INSERT INTO organizations (id, name, created_at) VALUES (?, ?, ?)`,
			[]any{"org-security", "Security Test Org", now},
		},
		{
			`INSERT INTO users (id, name, email, password_hash, status, created_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			[]any{"user-security", "Security User", "security@example.com",
				string(passwordHash), "active", now},
		},
		{
			`INSERT INTO organization_users (organization_id, user_id, role, created_at)
			 VALUES (?, ?, ?, ?)`,
			[]any{"org-security", "user-security", auth.RoleViewer, now},
		},
		{
			`INSERT INTO websites
			 (id, organization_id, created_by, domain, hash_id, api_key_hash, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			[]any{"site-security", "org-security", "user-security",
				"security.example.com", "hash-security", "api-hash-security", now},
		},
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed test database: %v", err)
		}
	}

	repo := auth.NewRepository(db)
	service := auth.NewService(repo, time.Hour)
	login, err := service.Login(ctx, "security@example.com", "Correct-Horse-42!")
	if err != nil {
		t.Fatalf("login test user: %v", err)
	}

	alertRepo := NewRepository(db)
	alert, err := alertRepo.Create(ctx, CreateInput{
		WebsiteID: "site-security",
		Severity:  "high",
		Type:      "security_test",
		Message:   "Test alert",
		RuleKey:   "test.security",
	})
	if err != nil {
		t.Fatalf("create test alert: %v", err)
	}

	authHandler := auth.NewHandler(service, false)
	alertHandler := NewHandler(alertRepo)

	router := gin.New()
	mutations := router.Group("/api/alerts")
	mutations.Use(authHandler.RequireAuth())
	mutations.PATCH(
		"/:alertID/resolve",
		auth.RequireRoles(auth.RoleSuperAdmin, auth.RoleManager, auth.RoleAnalyst),
		authHandler.RequireCSRFHeader(),
		alertHandler.Resolve,
	)

	tests := []struct {
		name       string
		csrfCookie string
		csrfHeader string
		wantStatus int
	}{
		{
			name:       "viewer cannot resolve alert",
			csrfCookie: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			csrfHeader: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "missing csrf token is rejected",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "invalid csrf token is rejected",
			csrfCookie: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			csrfHeader: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(
				http.MethodPatch,
				"/api/alerts/"+alert.ID+"/resolve",
				nil,
			)
			req.AddCookie(&http.Cookie{
				Name:  auth.SessionCookieName,
				Value: login.Token,
			})
			if tc.csrfCookie != "" {
				req.AddCookie(&http.Cookie{
					Name:  auth.CSRFCookieName,
					Value: tc.csrfCookie,
				})
			}
			if tc.csrfHeader != "" {
				req.Header.Set("X-CSRF-Token", tc.csrfHeader)
			}

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("expected HTTP %d, got %d: %s",
					tc.wantStatus, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAlertMutationAllowsAnalystWithValidCSRF(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := database.Open(filepath.Join(t.TempDir(), "analyst-security.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	if err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte("Correct-Horse-42!"),
		bcrypt.MinCost,
	)
	if err != nil {
		t.Fatal(err)
	}

	statements := []struct {
		query string
		args  []any
	}{
		{
			`INSERT INTO organizations (id, name, created_at) VALUES (?, ?, ?)`,
			[]any{"org-analyst", "Analyst Organization", now},
		},
		{
			`INSERT INTO users (id, name, email, password_hash, status, created_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			[]any{"user-analyst", "Analyst User", "analyst@example.com",
				string(passwordHash), "active", now},
		},
		{
			`INSERT INTO organization_users (organization_id, user_id, role, created_at)
			 VALUES (?, ?, ?, ?)`,
			[]any{"org-analyst", "user-analyst", auth.RoleAnalyst, now},
		},
		{
			`INSERT INTO websites
			 (id, organization_id, created_by, domain, hash_id, api_key_hash, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			[]any{"site-analyst", "org-analyst", "user-analyst",
				"analyst.example.com", "hash-analyst", "api-hash-analyst", now},
		},
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed test database: %v", err)
		}
	}

	authService := auth.NewService(auth.NewRepository(db), time.Hour)
	login, err := authService.Login(ctx, "analyst@example.com", "Correct-Horse-42!")
	if err != nil {
		t.Fatalf("login analyst: %v", err)
	}

	alertRepo := NewRepository(db)
	alert, err := alertRepo.Create(ctx, CreateInput{
		WebsiteID: "site-analyst",
		Severity:  "high",
		Type:      "security_test",
		Message:   "Analyst test alert",
		RuleKey:   "test.analyst",
	})
	if err != nil {
		t.Fatalf("create test alert: %v", err)
	}

	authHandler := auth.NewHandler(authService, false)
	alertHandler := NewHandler(alertRepo)

	router := gin.New()
	mutations := router.Group("/api/alerts")
	mutations.Use(authHandler.RequireAuth())
	mutations.PATCH(
		"/:alertID/resolve",
		auth.RequireRoles(auth.RoleSuperAdmin, auth.RoleManager, auth.RoleAnalyst),
		authHandler.RequireCSRFHeader(),
		alertHandler.Resolve,
	)

	token := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	req := httptest.NewRequest(
		http.MethodPatch,
		"/api/alerts/"+alert.ID+"/resolve",
		nil,
	)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: login.Token})
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: token})
	req.Header.Set("X-CSRF-Token", token)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP %d, got %d: %s",
			http.StatusOK, rec.Code, rec.Body.String())
	}

	resolved, err := alertRepo.List(ctx, "org-analyst", "resolved", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 {
		t.Fatalf("expected one resolved alert, got %d", len(resolved))
	}
	if resolved[0].ResolvedBy != "user-analyst" {
		t.Fatalf("expected resolved_by user-analyst, got %q", resolved[0].ResolvedBy)
	}
}
