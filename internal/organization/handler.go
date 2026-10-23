package organization

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/paragishere/secrust/internal/auth"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(
	router *gin.Engine,
	authHandler *auth.Handler,
) {
	group := router.Group("/api/organization")
	group.Use(authHandler.RequireAuth())
	group.Use(auth.RequireRoles(
		auth.RoleSuperAdmin,
		auth.RoleManager,
	))

	group.GET("/members", h.ListMembers)
}

func (h *Handler) ListMembers(c *gin.Context) {
	organizationID := c.GetString(auth.ContextOrganizationID)

	members, err := h.service.ListMembers(
		c.Request.Context(),
		organizationID,
	)
	if err != nil {
		if errors.Is(err, ErrOrganizationRequired) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "organization context required",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to list organization members",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"members": members,
	})
}
