package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAuthenticationAndRBACIntegration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		role       string
		withCookie bool
		wantStatus int
	}{
		{
			name:       "super admin allowed",
			role:       RoleSuperAdmin,
			withCookie: true,
			wantStatus: http.StatusOK,
		},
		{
			name:       "manager allowed",
			role:       RoleManager,
			withCookie: true,
			wantStatus: http.StatusOK,
		},
		{
			name:       "analyst forbidden",
			role:       RoleAnalyst,
			withCookie: true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "viewer forbidden",
			role:       RoleViewer,
			withCookie: true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "missing session redirects to login",
			withCookie: false,
			wantStatus: http.StatusSeeOther,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service := newAuthTestService(t)
			seedAuthUser(t, service, "active")

			if tc.withCookie {
				_, err := service.repo.db.ExecContext(
					context.Background(),
					`UPDATE organization_users
					 SET role = ?
					 WHERE organization_id = 'org-test'
					   AND user_id = 'user-test'`,
					tc.role,
				)
				if err != nil {
					t.Fatalf("set test role: %v", err)
				}
			}

			router := gin.New()
			authHandler := NewHandler(service, false)

			protected := router.Group("/protected")
			protected.Use(authHandler.RequireAuth())
			protected.Use(RequireRoles(RoleSuperAdmin, RoleManager))
			protected.GET("", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{
					"userID":         c.GetString(ContextUserID),
					"organizationID": c.GetString(ContextOrganizationID),
					"role":           c.GetString(ContextRole),
				})
			})

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)

			if tc.withCookie {
				login, err := service.Login(
					context.Background(),
					"test@example.com",
					"Correct-Horse-42!",
				)
				if err != nil {
					t.Fatalf("create authenticated session: %v", err)
				}

				req.AddCookie(&http.Cookie{
					Name:  SessionCookieName,
					Value: login.Token,
				})
			}

			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)

			if recorder.Code != tc.wantStatus {
				t.Fatalf(
					"expected status %d, got %d; body: %s",
					tc.wantStatus,
					recorder.Code,
					recorder.Body.String(),
				)
			}

			if tc.withCookie && tc.wantStatus == http.StatusOK {
				if recorder.Body.String() == "" {
					t.Fatal("expected authenticated response")
				}
			}
		})
	}
}
