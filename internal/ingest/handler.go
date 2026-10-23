package ingest

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	repo *Repository
}

func NewHandler(repo *Repository) *Handler {
	return &Handler{repo: repo}
}

type ingestRequest struct {
	IP        string `json:"ip"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	UserAgent string `json:"user_agent"`
	EventType string `json:"event_type"`
	Severity  string `json:"severity"`
}

// Ingest accepts logs authenticated by a website API key.
func (h *Handler) Ingest(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(
		c.Writer,
		c.Request.Body,
		16*1024,
	)

	var request ingestRequest

	if err := c.ShouldBindJSON(&request); err != nil {
		var maxBytesErr *http.MaxBytesError

		if errors.As(err, &maxBytesErr) || errors.Is(err, io.EOF) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid request body",
			})
			return
		}

		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request body",
		})
		return
	}

	request.IP = strings.TrimSpace(request.IP)
	request.Method = strings.TrimSpace(request.Method)
	request.Path = strings.TrimSpace(request.Path)
	request.EventType = strings.TrimSpace(request.EventType)
	request.Severity = strings.ToLower(
		strings.TrimSpace(request.Severity),
	)

	if request.IP != "" && net.ParseIP(request.IP) == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid IP address",
		})
		return
	}

	if request.Method == "" || len(request.Method) > 16 ||
		request.Path == "" || len(request.Path) > 2048 ||
		request.Status < 100 || request.Status > 599 ||
		request.EventType == "" || len(request.EventType) > 100 ||
		len(request.UserAgent) > 512 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid log fields",
		})
		return
	}

	switch request.Severity {
	case "info", "low", "medium", "high", "critical":
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid severity",
		})
		return
	}

	websiteID := c.GetString(ContextWebsiteID)
	if websiteID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "website authentication required",
		})
		return
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to process log",
		})
		return
	}

	log := Log{
		ID:        hex.EncodeToString(idBytes),
		WebsiteID: websiteID,
		IP:        request.IP,
		Method:    request.Method,
		Path:      request.Path,
		Status:    request.Status,
		UserAgent: request.UserAgent,
		EventType: request.EventType,
		Severity:  request.Severity,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}

	if err := h.repo.InsertLog(c.Request.Context(), log); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to store log",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"status": "accepted",
		"id":     log.ID,
	})
}

// List returns logs belonging only to the authenticated user's organization.
func (h *Handler) List(c *gin.Context) {
	organizationID := c.GetString("organizationID")
	if organizationID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "authentication required",
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

	logs, err := h.repo.ListLogs(
		c.Request.Context(),
		organizationID,
		limit,
		offset,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to retrieve logs",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":   logs,
		"limit":  limit,
		"offset": offset,
	})
}
