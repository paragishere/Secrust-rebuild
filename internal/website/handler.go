package website

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

func (h *Handler) RegisterRoutes(router *gin.Engine) {
	group := router.Group("/api/websites")
	group.Use(auth.RequireRoles(
		auth.RoleSuperAdmin,
		auth.RoleManager,
	))
	group.GET("", h.List)
	group.POST("", h.Create)
}

func (h *Handler) List(c *gin.Context) {
	websites, err := h.service.List(
		c.Request.Context(),
		c.GetString(auth.ContextOrganizationID),
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "unable to list websites",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"websites": websites})
}

func (h *Handler) Create(c *gin.Context) {
	var request struct {
		Domain string `json:"domain"`
	}

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request body",
		})
		return
	}

	result, err := h.service.Create(
		c.Request.Context(),
		c.GetString(auth.ContextOrganizationID),
		c.GetString(auth.ContextUserID),
		request.Domain,
	)
	if err != nil {
		if errors.Is(err, ErrInvalidWebsite) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid organization, creator or domain",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to create website",
		})
		return
	}

	c.JSON(http.StatusCreated, result)
}
