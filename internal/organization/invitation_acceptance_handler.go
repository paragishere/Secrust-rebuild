package organization

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/paragishere/secrust/internal/auth"
)

type InvitationAcceptanceHandler struct {
	service *InvitationService
}

func NewInvitationAcceptanceHandler(
	service *InvitationService,
) *InvitationAcceptanceHandler {
	return &InvitationAcceptanceHandler{service: service}
}

type acceptNewInvitationRequest struct {
	Token    string `json:"token" binding:"required"`
	Name     string `json:"name" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type acceptExistingInvitationRequest struct {
	Token string `json:"token" binding:"required"`
}

func (h *InvitationAcceptanceHandler) RegisterRoutes(
	router *gin.Engine,
	authHandler *auth.Handler,
) {
	// Email link opens this page in the browser.
	router.GET("/invitations/accept", func(c *gin.Context) {
		token := strings.TrimSpace(c.Query("token"))
		if token == "" {
			c.HTML(http.StatusBadRequest, "accept_invitation.html", gin.H{
				"InvalidLink": true,
			})
			return
		}

		c.HTML(http.StatusOK, "accept_invitation.html", gin.H{
			"InvalidLink": false,
		})
	})

	// API used by the acceptance page.
	router.POST("/api/invitations/accept", h.AcceptNew)

	// Existing signed-in account accepts the invitation.
	router.POST(
		"/api/organization/invitations/accept-existing",
		authHandler.RequireAuth(),
		authHandler.RequireCSRFHeader(),
		h.AcceptExisting,
	)
}

func (h *InvitationAcceptanceHandler) AcceptNew(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(
		c.Writer,
		c.Request.Body,
		16*1024,
	)

	var req acceptNewInvitationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "token, name and password are required",
		})
		return
	}

	if strings.TrimSpace(req.Token) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid invitation token"})
		return
	}

	result, err := h.service.AcceptNew(
		c.Request.Context(),
		req.Token,
		req.Name,
		req.Password,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvitationNotFound),
			errors.Is(err, ErrInvitationInactive),
			errors.Is(err, ErrInvitationExpired):
			c.JSON(http.StatusGone, gin.H{
				"error": "invitation is invalid, expired or already used",
			})
		case errors.Is(err, ErrInvitationConflict):
			c.JSON(http.StatusConflict, gin.H{
				"error": "an account with this email already exists",
				"hint":  "sign in to your existing account and accept the invitation there",
			})
		default:
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to accept invitation; check the supplied details",
			})
		}
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":         "account created and invitation accepted",
		"user_id":         result.UserID,
		"organization_id": result.OrganizationID,
		"role":            result.Role,
	})
}

func (h *InvitationAcceptanceHandler) AcceptExisting(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(
		c.Writer,
		c.Request.Body,
		16*1024,
	)

	var req acceptExistingInvitationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invitation token is required",
		})
		return
	}

	result, err := h.service.AcceptExisting(
		c.Request.Context(),
		req.Token,
		c.GetString(auth.ContextUserID),
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvitationNotFound),
			errors.Is(err, ErrInvitationInactive),
			errors.Is(err, ErrInvitationExpired):
			c.JSON(http.StatusGone, gin.H{
				"error": "invitation is invalid, expired or already used",
			})
		case errors.Is(err, ErrInvitationConflict):
			c.JSON(http.StatusConflict, gin.H{
				"error": "invitation conflicts with existing organization membership",
			})
		default:
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "unable to accept invitation",
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":         "invitation accepted",
		"user_id":         result.UserID,
		"organization_id": result.OrganizationID,
		"role":            result.Role,
	})
}
