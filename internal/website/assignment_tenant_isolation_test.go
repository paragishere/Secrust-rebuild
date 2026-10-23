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

func TestAssignmentRoutesRejectCrossOrganizationWebsite(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := newWebsiteTestService(t)
	db := service.repo.db
	ctx := context.Background()

	_, err := db.ExecContext(ctx, `
		INSERT INTO organizations (id, name, created_at)
		VALUES ('org-b', 'Organization B', datetime('now'))
	`)
	if err != nil {
		t.Fatalf("create organization B: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO users
			(id, name, email, password_hash, status, created_at)
		VALUES ('user-b', 'User B', 'user-b@example.com', 'unused', 'active', datetime('now'))
	`)
	if err != nil {
		t.Fatalf("create user B: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO organization_users
			(organization_id, user_id, role, created_at)
		VALUES ('org-b', 'user-b', 'ANALYST', datetime('now'))
	`)
	if err != nil {
		t.Fatalf("create membership B: %v", err)
	}

	websiteB, err := service.Create(ctx, "org-b", "user-b", "org-b.example.com")
	if err != nil {
		t.Fatalf("create website B: %v", err)
	}

	password := "Tenant-Test-42!"
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO users
			(id, name, email, password_hash, status, created_at)
		VALUES ('admin-a', 'Admin A', 'admin-a@example.com', ?, 'active', datetime('now'))
	`, string(passwordHash))
	if err != nil {
		t.Fatalf("create admin A: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO organization_users
			(organization_id, user_id, role, created_at)
		VALUES ('org-a', 'admin-a', 'SUPER_ADMIN', datetime('now'))
	`)
	if err != nil {
		t.Fatalf("create membership A: %v", err)
	}

	authService := auth.NewService(auth.NewRepository(db), time.Hour)
	login, err := authService.Login(ctx, "admin-a@example.com", password)
	if err != nil {
		t.Fatalf("login admin A: %v", err)
	}

	handler := NewAssignmentHandler(NewAssignmentServiceWithAudit(
		db,
		NewAssignmentRepository(db),
		audit.NewRepository(db),
	))

	router := gin.New()
	routes := router.Group("/api/websites")
	routes.Use(auth.NewHandler(authService, false).RequireAuth())
	routes.Use(auth.RequireRoles(auth.RoleSuperAdmin, auth.RoleManager))
	routes.PUT("/:websiteID/users/:userID", handler.Assign)
	routes.DELETE("/:websiteID/users/:userID", handler.Unassign)

	doRequest := func(method string) *httptest.ResponseRecorder {
		var body *bytes.Reader
		if method == http.MethodPut {
			body = bytes.NewReader([]byte(`{"permission":"read"}`))
		} else {
			body = bytes.NewReader(nil)
		}

		req := httptest.NewRequest(
			method,
			"/api/websites/"+websiteB.Website.ID+"/users/user-b",
			body,
		)
		if method == http.MethodPut {
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

	putResponse := doRequest(http.MethodPut)
	if putResponse.Code != http.StatusUnprocessableEntity {
		t.Fatalf("cross-organization PUT: expected %d, got %d: %s",
			http.StatusUnprocessableEntity, putResponse.Code, putResponse.Body.String())
	}

	deleteResponse := doRequest(http.MethodDelete)
	if deleteResponse.Code != http.StatusNotFound {
		t.Fatalf("cross-organization DELETE: expected %d, got %d: %s",
			http.StatusNotFound, deleteResponse.Code, deleteResponse.Body.String())
	}

	var auditCount int
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM audit_logs
		WHERE organization_id = 'org-a'
		  AND user_id = 'admin-a'
		  AND resource_id = ?
	`, websiteB.Website.ID).Scan(&auditCount)
	if err != nil {
		t.Fatalf("check cross-organization audit entries: %v", err)
	}
	if auditCount != 0 {
		t.Fatalf("failed cross-organization requests unexpectedly created %d audit entries", auditCount)
	}
}
