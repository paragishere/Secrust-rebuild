package alerts

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	contextOrganizationID = "organizationID"
	contextUserID         = "userID"
)

type Handler struct {
	repo *Repository
}

func NewHandler(repo *Repository) *Handler {
	return &Handler{repo: repo}
}

// List returns alerts scoped to the authenticated organization.
func (h *Handler) List(c *gin.Context) {
	organizationID := c.GetString(contextOrganizationID)
	if organizationID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication required",
		})
		return
	}

	status := strings.ToLower(strings.TrimSpace(c.Query("status")))
	switch status {
	case "", "open", "acknowledged", "resolved":
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid alert status",
		})
		return
	}

	limit := 50
	offset := 0

	if value := c.Query("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 100 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "limit must be between 1 and 100",
			})
			return
		}
		limit = parsed
	}

	if value := c.Query("offset"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "offset must be a non-negative integer",
			})
			return
		}
		offset = parsed
	}

	alerts, err := h.repo.List(
		c.Request.Context(),
		organizationID,
		status,
		limit,
		offset,
	)
	if err != nil {
		if errors.Is(err, ErrInvalidAlert) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid alert query",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to retrieve alerts",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"alerts": alerts,
		"limit":  limit,
		"offset": offset,
		"status": status,
	})
}

func (h *Handler) Get(c *gin.Context) {
	organizationID, ok := c.Get("organizationID")
	if !ok {
		organizationID, ok = c.Get("organization_id")
	}
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "organization context missing",
		})
		return
	}

	orgID, ok := organizationID.(string)
	if !ok || strings.TrimSpace(orgID) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "organization context missing",
		})
		return
	}

	alert, err := h.repo.Get(
		c.Request.Context(),
		orgID,
		c.Param("alertID"),
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidAlert):
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid alert"})
		case errors.Is(err, ErrAlertNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "alert not found"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "failed to retrieve alert",
			})
		}
		return
	}

	c.JSON(http.StatusOK, alert)
}

// Acknowledge marks an open alert as acknowledged.
func (h *Handler) Acknowledge(c *gin.Context) {
	h.updateStatus(c, "acknowledged")
}

// Resolve marks an open or acknowledged alert as resolved.
func (h *Handler) Resolve(c *gin.Context) {
	h.updateStatus(c, "resolved")
}

func (h *Handler) updateStatus(c *gin.Context, status string) {
	organizationID := c.GetString(contextOrganizationID)
	userID := c.GetString(contextUserID)
	alertID := strings.TrimSpace(c.Param("alertID"))

	if organizationID == "" || userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication required",
		})
		return
	}
	if alertID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "alert ID is required",
		})
		return
	}

	err := h.repo.SetStatusWithAudit(
		c.Request.Context(),
		organizationID,
		alertID,
		userID,
		status,
	)
	if err != nil {
		if errors.Is(err, ErrInvalidAlert) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid alert request",
			})
			return
		}
		if errors.Is(err, ErrAlertNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "alert not found or status transition not allowed",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to update alert",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   status,
		"alert_id": alertID,
	})
}
