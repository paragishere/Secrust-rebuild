package website

import (
	// "encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/paragishere/secrust/internal/auth"
)

type AssignmentHandler struct {
	service *AssignmentService
}

func NewAssignmentHandler(service *AssignmentService) *AssignmentHandler {
	return &AssignmentHandler{service: service}
}

type assignmentRequest struct {
	Permission string `json:"permission"`
}

func (h *AssignmentHandler) Assign(c *gin.Context) {
	organizationID := c.GetString(auth.ContextOrganizationID)
	websiteID := c.Param("websiteID")
	userID := c.Param("userID")

	var request assignmentRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid JSON request",
		})
		return
	}

	if err := h.service.AssignByActor(
		c.Request.Context(),
		organizationID,
		c.GetString(auth.ContextUserID),
		websiteID,
		userID,
		request.Permission,
	); err != nil {
		switch {
		case errors.Is(err, ErrInvalidAssignmentRequest):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid assignment request",
			})
		case errors.Is(err, ErrInvalidAssignment):
			c.JSON(http.StatusUnprocessableEntity, gin.H{
				"error": "website or user is invalid for this organization",
			})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "could not assign user",
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "website access assigned",
	})
}

func (h *AssignmentHandler) Unassign(c *gin.Context) {
	organizationID := c.GetString(auth.ContextOrganizationID)
	websiteID := c.Param("websiteID")
	userID := c.Param("userID")

	if err := h.service.UnassignByActor(
		c.Request.Context(),
		organizationID,
		c.GetString(auth.ContextUserID),
		websiteID,
		userID,
	); err != nil {
		switch {
		case errors.Is(err, ErrInvalidAssignmentRequest):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid assignment request",
			})
		case errors.Is(err, ErrAssignmentNotFound):
			c.JSON(http.StatusNotFound, gin.H{
				"error": "assignment not found",
			})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "could not remove assignment",
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "website access removed",
	})

	// c.JSON(http.StatusOK, gin.H{"message": "website access removed"})
}

// Keep the JSON decoder import used for strict request parsing in future changes.
// var _ = json.Valid
