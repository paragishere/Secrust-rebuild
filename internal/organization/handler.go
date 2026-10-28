package organization

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/paragishere/secrust/internal/auth"
)

type Handler struct {
	service           *Service
	invitationService *InvitationService
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func NewHandlerWithInvitations(
	service *Service,
	invitationService *InvitationService,
) *Handler {
	return &Handler{
		service:           service,
		invitationService: invitationService,
	}
}

func (h *Handler) RegisterRoutes(
	router *gin.Engine,
	authHandler *auth.Handler,
) {
	// All authenticated organization roles can read member information.
	group := router.Group("/api/organization")
	group.Use(authHandler.RequireAuth())
	group.Use(auth.RequireRoles(
		auth.RoleSuperAdmin,
		auth.RoleManager,
		auth.RoleAnalyst,
		auth.RoleViewer,
	))

	group.GET("/members", h.ListMembers)

	// Invitation management is restricted to Super Admin.
	if h.invitationService != nil {
		invitations := group.Group("/invitations")
		invitations.Use(auth.RequireRoles(auth.RoleSuperAdmin))

		invitations.GET("", h.ListInvitations)

		invitations.POST(
			"",
			authHandler.RequireCSRFHeader(),
			h.CreateInvitation,
		)

		invitations.DELETE(
			"/:invitationID",
			authHandler.RequireCSRFHeader(),
			h.RevokeInvitation,
		)

		invitations.POST(
			"/:invitationID/resend",
			authHandler.RequireCSRFHeader(),
			h.ResendInvitation,
		)
	}
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

func (h *Handler) ListInvitations(c *gin.Context) {
	invitations, err := h.invitationService.List(
		c.Request.Context(),
		c.GetString(auth.ContextOrganizationID),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to list invitations",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"invitations": invitations,
	})
}

type createInvitationRequest struct {
	Email string `json:"email" binding:"required"`
	Role  string `json:"role" binding:"required"`
}

func (h *Handler) CreateInvitation(c *gin.Context) {
	var req createInvitationRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "valid email and role are required",
		})
		return
	}

	invitation, err := h.invitationService.CreateAndSend(
		c.Request.Context(),
		c.GetString(auth.ContextOrganizationID),
		req.Email,
		req.Role,
		c.GetString(auth.ContextUserID),
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidInviteEmail),
			errors.Is(err, ErrInvalidInviteRole):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})

		case errors.Is(err, ErrInvitationConflict):
			c.JSON(http.StatusConflict, gin.H{
				"error": "an active invitation or membership already exists",
			})

		case errors.Is(err, ErrInvitationDeliveryFailed):
			c.JSON(http.StatusBadGateway, gin.H{
				"error": "invitation email could not be delivered",
			})

		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to create invitation",
			})
		}
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"invitation": invitation,
	})
}

func (h *Handler) RevokeInvitation(c *gin.Context) {
	err := h.invitationService.Revoke(
		c.Request.Context(),
		c.GetString(auth.ContextOrganizationID),
		c.Param("invitationID"),
		c.GetString(auth.ContextUserID),
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvitationNotFound):
			c.JSON(http.StatusNotFound, gin.H{
				"error": "active invitation not found",
			})

		case errors.Is(err, ErrInvitationInactive),
			errors.Is(err, ErrInvitationExpired):
			c.JSON(http.StatusConflict, gin.H{
				"error": "invitation is no longer active",
			})

		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to revoke invitation",
			})
		}
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *Handler) ResendInvitation(c *gin.Context) {
	invitation, err := h.invitationService.Resend(
		c.Request.Context(),
		c.GetString(auth.ContextOrganizationID),
		c.Param("invitationID"),
		c.GetString(auth.ContextUserID),
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvitationNotFound):
			c.JSON(http.StatusNotFound, gin.H{
				"error": "invitation not found",
			})

		case errors.Is(err, ErrInvitationInactive),
			errors.Is(err, ErrInvitationExpired):
			c.JSON(http.StatusConflict, gin.H{
				"error": "invitation is no longer active",
			})

		case errors.Is(err, ErrInvitationDeliveryFailed):
			c.JSON(http.StatusBadGateway, gin.H{
				"error": "invitation email delivery failed",
			})

		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "unable to resend invitation",
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"invitation": invitation,
	})
}
