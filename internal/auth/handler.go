package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	SessionCookieName = "secrust_session"
	CSRFCookieName    = "secrust_csrf"
	CSRFFormField     = "csrf_token"
)

type Handler struct {
	service *Service
	secure  bool
}

func NewHandler(service *Service, secure bool) *Handler {
	return &Handler{
		service: service,
		secure:  secure,
	}
}

func (h *Handler) RegisterRoutes(router *gin.Engine) {
	router.GET("/login", h.ShowLogin)
	router.POST("/login", h.Login)
	router.POST("/logout", h.Logout)
}

func (h *Handler) newCSRFToken() (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return hex.EncodeToString(token), nil
}

func (h *Handler) setCSRFCookie(c *gin.Context, token string) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		CSRFCookieName,
		token,
		3600,
		"/",
		"",
		h.secure,
		false,
	)
}

func (h *Handler) validCSRF(c *gin.Context) bool {
	cookieToken, err := c.Cookie(CSRFCookieName)
	if err != nil || len(cookieToken) != 64 {
		return false
	}

	formToken := c.PostForm(CSRFFormField)
	if len(formToken) != 64 {
		return false
	}

	return subtle.ConstantTimeCompare(
		[]byte(cookieToken),
		[]byte(formToken),
	) == 1
}

func (h *Handler) ShowLogin(c *gin.Context) {
	token, err := h.newCSRFToken()
	if err != nil {
		c.String(http.StatusInternalServerError, "Unable to prepare login")
		return
	}

	h.setCSRFCookie(c, token)
	c.HTML(http.StatusOK, "login.html", gin.H{
		"CSRFToken": token,
	})
}

func (h *Handler) Login(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)

	if err := c.Request.ParseForm(); err != nil {
		c.String(http.StatusBadRequest, "Invalid form submission")
		return
	}

	if !h.validCSRF(c) {
		c.String(http.StatusForbidden, "Invalid or expired form token. Refresh the page and try again.")
		return
	}

	email := strings.TrimSpace(c.PostForm("email"))
	password := c.PostForm("password")

	result, err := h.service.Login(c.Request.Context(), email, password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) ||
			errors.Is(err, ErrAccountDisabled) {
			token, tokenErr := h.newCSRFToken()
			if tokenErr != nil {
				c.String(http.StatusInternalServerError, "Unable to prepare login")
				return
			}

			h.setCSRFCookie(c, token)
			c.HTML(http.StatusUnauthorized, "login.html", gin.H{
				"Error":     "Invalid email or password",
				"CSRFToken": token,
			})
			return
		}

		c.String(http.StatusInternalServerError, "Unable to log in")
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		SessionCookieName,
		result.Token,
		int(time.Until(result.Session.ExpiresAt).Seconds()),
		"/",
		"",
		h.secure,
		true,
	)

	// Rotate the CSRF token after successful authentication.
	token, tokenErr := h.newCSRFToken()
	if tokenErr != nil {
		_ = h.service.Logout(c.Request.Context(), result.Token)
		c.SetCookie(SessionCookieName, "", -1, "/", "", h.secure, true)
		c.String(http.StatusInternalServerError, "Unable to complete login")
		return
	}
	h.setCSRFCookie(c, token)

	c.Redirect(http.StatusSeeOther, "/dashboard")
}

func (h *Handler) Logout(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)

	if err := c.Request.ParseForm(); err != nil {
		c.String(http.StatusBadRequest, "Invalid form submission")
		return
	}

	if !h.validCSRF(c) {
		c.String(http.StatusForbidden, "Invalid or expired form token. Refresh the page and try again.")
		return
	}

	token, err := c.Cookie(SessionCookieName)
	if err == nil {
		if err := h.service.Logout(c.Request.Context(), token); err != nil {
			c.String(http.StatusInternalServerError, "Unable to log out")
			return
		}
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(SessionCookieName, "", -1, "/", "", h.secure, true)

	c.Redirect(http.StatusSeeOther, "/login")
}
func (h *Handler) NewDashboardCSRFToken(c *gin.Context) (string, error) {
	token, err := h.newCSRFToken()
	if err != nil {
		return "", err
	}

	h.setCSRFCookie(c, token)
	return token, nil
}
