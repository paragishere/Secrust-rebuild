package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRequireRoles(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		role       string
		allowed    []string
		wantStatus int
	}{
		{
			name:       "super admin allowed",
			role:       RoleSuperAdmin,
			allowed:    []string{RoleSuperAdmin, RoleManager},
			wantStatus: http.StatusOK,
		},
		{
			name:       "manager allowed",
			role:       RoleManager,
			allowed:    []string{RoleSuperAdmin, RoleManager},
			wantStatus: http.StatusOK,
		},
		{
			name:       "viewer forbidden",
			role:       RoleViewer,
			allowed:    []string{RoleSuperAdmin, RoleManager},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "analyst forbidden",
			role:       RoleAnalyst,
			allowed:    []string{RoleSuperAdmin},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "missing role unauthorized",
			role:       "",
			allowed:    []string{RoleSuperAdmin},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()

			router.Use(func(c *gin.Context) {
				if tt.role != "" {
					c.Set(ContextRole, tt.role)
				}
				c.Next()
			})

			router.GET("/protected", RequireRoles(tt.allowed...), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d", tt.wantStatus, rec.Code)
			}
		})
	}
}
