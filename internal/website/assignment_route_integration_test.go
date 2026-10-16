package website

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/paragishere/secrust/internal/audit"
	"github.com/paragishere/secrust/internal/auth"
	"golang.org/x/crypto/bcrypt"
)

func TestAssignmentRouteRBACIntegration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		role       string
		withCookie bool
		wantStatus int
	}{
		{"super admin allowed", auth.RoleSuperAdmin, true, http.StatusOK},
		{"manager allowed", auth.RoleManager, true, http.StatusOK},
		{"analyst forbidden", auth.RoleAnalyst, true, http.StatusForbidden},
		{"viewer forbidden", auth.RoleViewer, true, http.StatusForbidden},
		{"missing session redirects", "", false, http.StatusSeeOther},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			websiteService := newWebsiteTestService(t)
			db := websiteService.repo.db
			ctx := context.Background()

			// Create a real authenticated user in the existing test organization.
			password := "Integration-Test-42!"
			passwordHash, err := bcrypt.GenerateFromPassword(
				[]byte(password),
				bcrypt.DefaultCost,
			)
			if err != nil {
				t.Fatalf("hash password: %v", err)
			}

			_, err = db.ExecContext(ctx, `
				INSERT INTO users
					(id, name, email, password_hash, status, created_at)
				VALUES
					('route-admin', 'Route Admin', 'route-admin@example.com',
					 ?, 'active', datetime('now'))
			`, string(passwordHash))
			if err != nil {
				t.Fatalf("insert route user: %v", err)
			}

			role := tc.role
			if role == "" {
				role = auth.RoleSuperAdmin
			}

			_, err = db.ExecContext(ctx, `
				INSERT INTO organization_users
					(organization_id, user_id, role, created_at)
				VALUES ('org-a', 'route-admin', ?, datetime('now'))
			`, role)
			if err != nil {
				t.Fatalf("insert organization membership: %v", err)
			}

			created, err := websiteService.Create(
				ctx, "org-a", "user-a", "example.com",
			)
			if err != nil {
				t.Fatalf("create website: %v", err)
			}

			authService := auth.NewService(
				auth.NewRepository(db),
				time.Hour,
			)
			authHandler := auth.NewHandler(authService, false)

			assignmentService := NewAssignmentServiceWithAudit(
				db,
				NewAssignmentRepository(db),
				audit.NewRepository(db),
			)
			assignmentHandler := NewAssignmentHandler(assignmentService)

			router := gin.New()
			routes := router.Group("/api/websites")
			routes.Use(authHandler.RequireAuth())
			routes.Use(auth.RequireRoles(
				auth.RoleSuperAdmin,
				auth.RoleManager,
			))
			routes.PUT("/:websiteID/users/:userID", assignmentHandler.Assign)

			req := httptest.NewRequest(
				http.MethodPut,
				"/api/websites/"+created.Website.ID+"/users/user-a",
				bytes.NewBufferString(`{"permission":"read"}`),
			)
			req.Header.Set("Content-Type", "application/json")

			if tc.withCookie {
				login, err := authService.Login(
					ctx,
					"route-admin@example.com",
					password,
				)
				if err != nil {
					t.Fatalf("login: %v", err)
				}

				req.AddCookie(&http.Cookie{
					Name:  auth.SessionCookieName,
					Value: login.Token,
				})
			}

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)

			if recorder.Code != tc.wantStatus {
				t.Fatalf(
					"expected status %d, got %d; response: %s",
					tc.wantStatus,
					recorder.Code,
					recorder.Body.String(),
				)
			}
		})
	}
}

func TestAssignmentRoutesAuditLogging(t *testing.T) {
	gin.SetMode(gin.TestMode)

	websiteService := newWebsiteTestService(t)
	db := websiteService.repo.db
	ctx := context.Background()

	password := "Integration-Test-42!"
	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO users
			(id, name, email, password_hash, status, created_at)
		VALUES
			('audit-actor', 'Audit Actor', 'audit-actor@example.com',
			 ?, 'active', datetime('now'))
	`, string(passwordHash))
	if err != nil {
		t.Fatalf("insert actor: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO organization_users
			(organization_id, user_id, role, created_at)
		VALUES ('org-a', 'audit-actor', 'SUPER_ADMIN', datetime('now'))
	`)
	if err != nil {
		t.Fatalf("insert actor membership: %v", err)
	}

	created, err := websiteService.Create(
		ctx, "org-a", "user-a", "audit-example.com",
	)
	if err != nil {
		t.Fatalf("create website: %v", err)
	}

	authService := auth.NewService(auth.NewRepository(db), time.Hour)
	login, err := authService.Login(ctx, "audit-actor@example.com", password)
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	assignmentService := NewAssignmentServiceWithAudit(
		db,
		NewAssignmentRepository(db),
		audit.NewRepository(db),
	)
	assignmentHandler := NewAssignmentHandler(assignmentService)
	authHandler := auth.NewHandler(authService, false)

	router := gin.New()
	routes := router.Group("/api/websites")
	routes.Use(authHandler.RequireAuth())
	routes.Use(auth.RequireRoles(auth.RoleSuperAdmin, auth.RoleManager))
	routes.PUT("/:websiteID/users/:userID", assignmentHandler.Assign)
	routes.DELETE("/:websiteID/users/:userID", assignmentHandler.Unassign)

	path := "/api/websites/" + created.Website.ID + "/users/user-a"

	doRequest := func(method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		req.AddCookie(&http.Cookie{
			Name:  auth.SessionCookieName,
			Value: login.Token,
		})

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}

	putResponse := doRequest(http.MethodPut, `{"permission":"read"}`)
	if putResponse.Code != http.StatusOK {
		t.Fatalf("PUT: expected %d, got %d: %s",
			http.StatusOK, putResponse.Code, putResponse.Body.String())
	}

	deleteResponse := doRequest(http.MethodDelete, "")
	if deleteResponse.Code != http.StatusOK {
		t.Fatalf("DELETE: expected %d, got %d: %s",
			http.StatusOK, deleteResponse.Code, deleteResponse.Body.String())
	}

	for _, action := range []string{
		"website.user.assigned",
		"website.user.unassigned",
	} {
		var count int
		err := db.QueryRowContext(ctx, `
			SELECT COUNT(*)
			FROM audit_logs
			WHERE organization_id = ?
			  AND user_id = ?
			  AND action = ?
			  AND resource_id = ?
		`, "org-a", "audit-actor", action, created.Website.ID).Scan(&count)
		if err != nil {
			t.Fatalf("query audit action %q: %v", action, err)
		}
		if count != 1 {
			t.Errorf("expected exactly one audit entry for %q, got %d", action, count)
		}
	}
}
