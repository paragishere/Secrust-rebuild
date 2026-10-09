package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	ContextUserID         = "userID"
	ContextOrganizationID = "organizationID"
	ContextRole           = "role"
)

// RequireAuth validates the session cookie before allowing access.
func (h *Handler) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie(SessionCookieName)
		if err != nil || token == "" {
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}

		session, err := h.service.ValidateSession(c.Request.Context(), token)
		if err != nil {
			c.SetCookie(
				SessionCookieName,
				"",
				-1,
				"/",
				"",
				h.secure,
				true,
			)
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}

		c.Set(ContextUserID, session.UserID)
		c.Set(ContextOrganizationID, session.OrganizationID)
		c.Set(ContextRole, session.Role)

		c.Next()
	}
}
