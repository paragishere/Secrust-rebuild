package website

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/paragishere/secrust/internal/auth"
)

func TestAssignmentHandlerAssign(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := newWebsiteTestService(t)
	ctx := context.Background()
	db := service.repo.db

	result, err := service.Create(ctx, "org-a", "user-a", "example.com")
	if err != nil {
		t.Fatalf("create website: %v", err)
	}

	handler := NewAssignmentHandler(
		NewAssignmentService(NewAssignmentRepository(db)),
	)

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{"valid assignment", `{"permission":"read"}`, http.StatusOK},
		{"invalid permission", `{"permission":"admin"}`, http.StatusBadRequest},
		{"invalid JSON", `{`, http.StatusBadRequest},
		{"empty permission", `{"permission":""}`, http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(
				http.MethodPut,
				"/api/websites/"+result.Website.ID+"/users/user-a",
				bytes.NewBufferString(tc.body),
			)
			req.Header.Set("Content-Type", "application/json")

			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = req
			c.Params = gin.Params{
				{Key: "websiteID", Value: result.Website.ID},
				{Key: "userID", Value: "user-a"},
			}
			c.Set(auth.ContextOrganizationID, "org-a")

			handler.Assign(c)

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

func TestAssignmentHandlerRejectsCrossOrganizationAssignment(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := newWebsiteTestService(t)
	ctx := context.Background()
	db := service.repo.db

	_, err := db.ExecContext(ctx, `
		INSERT INTO organizations (id, name, created_at)
		VALUES ('org-b', 'Organization B', datetime('now'))
	`)
	if err != nil {
		t.Fatalf("create organization: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO users (id, name, email, password_hash, status, created_at)
		VALUES ('user-b', 'User B', 'user-b@example.com', 'test-hash', 'active', datetime('now'))
	`)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO organization_users (organization_id, user_id, role, created_at)
		VALUES ('org-b', 'user-b', 'ANALYST', datetime('now'))
	`)
	if err != nil {
		t.Fatalf("create membership: %v", err)
	}

	result, err := service.Create(ctx, "org-a", "user-a", "example.com")
	if err != nil {
		t.Fatalf("create website: %v", err)
	}

	handler := NewAssignmentHandler(
		NewAssignmentService(NewAssignmentRepository(db)),
	)

	req := httptest.NewRequest(
		http.MethodPut,
		"/api/websites/"+result.Website.ID+"/users/user-b",
		bytes.NewBufferString(`{"permission":"read"}`),
	)
	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = req
	c.Params = gin.Params{
		{Key: "websiteID", Value: result.Website.ID},
		{Key: "userID", Value: "user-b"},
	}
	c.Set(auth.ContextOrganizationID, "org-a")

	handler.Assign(c)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf(
			"expected status %d, got %d; response: %s",
			http.StatusUnprocessableEntity,
			recorder.Code,
			recorder.Body.String(),
		)
	}
}
