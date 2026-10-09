package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	RoleSuperAdmin = "SUPER_ADMIN"
	RoleManager    = "MANAGER"
	RoleAnalyst    = "ANALYST"
	RoleViewer     = "VIEWER"
)

// RequireRoles restricts a route to the specified organization roles.
// RequireAuth must run before this middleware.
func RequireRoles(allowedRoles ...string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(allowedRoles))
	for _, role := range allowedRoles {
		allowed[role] = struct{}{}
	}

	return func(c *gin.Context) {
		role := c.GetString(ContextRole)
		if role == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "authentication required",
			})
			return
		}

		if _, ok := allowed[role]; !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "insufficient permissions",
			})
			return
		}

		c.Next()
	}
}
