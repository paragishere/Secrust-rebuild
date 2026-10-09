package setup

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"html/template"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	service    *Service
	production bool
}

func NewHandler(service *Service, production bool) *Handler {
	return &Handler{
		service:    service,
		production: production,
	}
}

func (h *Handler) RegisterRoutes(router *gin.Engine) {
	router.GET("/setup", h.Show)
	router.POST("/setup", h.Create)
}

func (h *Handler) Show(c *gin.Context) {
	initialized, err := h.service.IsInitialized(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Unable to check setup status",
		})
		return
	}

	if initialized {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	token, err := newCSRFToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Unable to initialize setup form",
		})
		return
	}

	h.setCSRFCookie(c, token)

	c.HTML(http.StatusOK, "setup.html", gin.H{
		"CSRFToken": token,
	})
}

func (h *Handler) Create(c *gin.Context) {
	initialized, err := h.service.IsInitialized(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Unable to check setup status",
		})
		return
	}

	if initialized {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)

	if err := c.Request.ParseForm(); err != nil {
		c.String(http.StatusBadRequest, "Invalid form submission")
		return
	}

	cookie, err := c.Cookie("secrust_csrf")
	if err != nil {
		c.String(http.StatusForbidden, "Invalid or missing CSRF token")
		return
	}

	formToken := c.PostForm("csrf_token")
	if len(cookie) != 64 ||
		len(formToken) != 64 ||
		subtle.ConstantTimeCompare([]byte(cookie), []byte(formToken)) != 1 {
		c.String(http.StatusForbidden, "Invalid or missing CSRF token")
		return
	}

	input := InitialSetup{
		OrganizationName: strings.TrimSpace(c.PostForm("organization_name")),
		AdminName:        strings.TrimSpace(c.PostForm("admin_name")),
		Email:            strings.TrimSpace(c.PostForm("email")),
		Password:         c.PostForm("password"),
	}

	if len(input.OrganizationName) > 120 ||
		len(input.AdminName) > 120 ||
		len(input.Email) > 254 ||
		len(input.Password) > 72 {
		c.String(http.StatusBadRequest, "One or more fields are too long")
		return
	}

	err = h.service.CreateInitialSetup(c.Request.Context(), input)
	if err != nil {
		if errors.Is(err, ErrAlreadyInitialized) {
			c.Redirect(http.StatusSeeOther, "/login")
			return
		}

		// Avoid exposing internal database errors to clients.
		if strings.Contains(err.Error(), "required") ||
			strings.Contains(err.Error(), "password must") ||
			strings.Contains(err.Error(), "exceed the allowed length") {
			c.HTML(http.StatusBadRequest, "setup.html", gin.H{
				"CSRFToken": formToken,
				"Error":     err.Error(),
			})
			return
		}

		c.String(http.StatusInternalServerError, "Unable to complete setup")
		return
	}

	c.SetCookie(
		"secrust_csrf", "", -1, "/",
		"", h.production, true,
	)

	c.HTML(http.StatusCreated, "setup.html", gin.H{
		"Complete": true,
	})
}

func (h *Handler) setCSRFCookie(c *gin.Context, token string) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		"secrust_csrf",
		token,
		600,
		"/",
		"",
		h.production,
		true,
	)
}

func newCSRFToken() (string, error) {

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return hex.EncodeToString(token), nil
}

// Ensure template data is rendered through html/template by Gin.
var _ = template.HTMLEscapeString
