package endpoint

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/paragishere/secrust/internal/auth"
)

type Handler struct {
	repo *Repository
}

func NewHandler(repo *Repository) *Handler {
	return &Handler{repo: repo}
}

type registerHostRequest struct {
	Hostname     string `json:"hostname" binding:"required"`
	OSType       string `json:"os_type" binding:"required"`
	AgentVersion string `json:"agent_version"`
}

func (h *Handler) RegisterHost(c *gin.Context) {
	var req registerHostRequest

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16*1024)
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid registration request"})
		return
	}

	hostname := strings.TrimSpace(req.Hostname)
	osType := strings.ToLower(strings.TrimSpace(req.OSType))
	version := strings.TrimSpace(req.AgentVersion)

	if hostname == "" || len(hostname) > 255 || len(version) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host fields"})
		return
	}
	if osType != "windows" && osType != "linux" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "os_type must be windows or linux"})
		return
	}

	organizationID := c.GetString(auth.ContextOrganizationID)
	if organizationID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "organization context required"})
		return
	}

	idBytes := make([]byte, 16)
	keyBytes := make([]byte, 32)

	if _, err := rand.Read(idBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to register endpoint"})
		return
	}
	if _, err := rand.Read(keyBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to register endpoint"})
		return
	}

	hostID := hex.EncodeToString(idBytes)
	agentKey := hex.EncodeToString(keyBytes)
	keyHash := sha256.Sum256([]byte(agentKey))

	err := h.repo.CreateHost(c.Request.Context(), CreateHostInput{
		ID:             hostID,
		OrganizationID: organizationID,
		Hostname:       hostname,
		OSType:         osType,
		AgentVersion:   version,
		CredentialHash: hex.EncodeToString(keyHash[:]),
	})
	if err != nil {
		if errors.Is(err, ErrHostConflict) {
			c.JSON(http.StatusConflict, gin.H{"error": "host is already registered"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to register endpoint"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"host": gin.H{
			"id":            hostID,
			"hostname":      hostname,
			"os_type":       osType,
			"agent_version": version,
			"status":        "active",
		},
		"agent_key": agentKey,
		"warning":   "Save this key securely. It will not be shown again.",
	})
}

type ingestEventsRequest struct {
	Events []Event `json:"events" binding:"required"`
}

func (h *Handler) IngestEvents(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 256*1024)

	var req ingestEventsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event request"})
		return
	}

	if len(req.Events) == 0 || len(req.Events) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "events must contain 1 to 100 items"})
		return
	}

	hostID := c.GetString(ContextHostID)
	if hostID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "agent authentication required"})
		return
	}

	accepted := 0
	duplicates := 0

	for _, event := range req.Events {
		event.ID = randomID()
		event.HostID = hostID
		event.EventUID = strings.TrimSpace(event.EventUID)
		event.EventType = strings.TrimSpace(event.EventType)
		event.Severity = strings.ToLower(strings.TrimSpace(event.Severity))
		event.SourceIP = strings.TrimSpace(event.SourceIP)
		event.AccountName = strings.TrimSpace(event.AccountName)

		if event.EventUID == "" || len(event.EventUID) > 200 ||
			event.EventID < 0 || event.EventID > 1000000 ||
			event.EventType == "" || len(event.EventType) > 100 ||
			len(event.SourceIP) > 45 || len(event.AccountName) > 255 ||
			event.RiskScore < 0 || event.RiskScore > 100 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event fields"})
			return
		}

		switch event.Severity {
		case "info", "low", "medium", "high", "critical":
		default:
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event severity"})
			return
		}

		if event.SourceIP != "" && net.ParseIP(event.SourceIP) == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event source IP"})
			return
		}

		if _, err := time.Parse(time.RFC3339Nano, event.OccurredAt); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "event timestamp must be RFC3339"})
			return
		}

		inserted, err := h.repo.InsertEvent(c.Request.Context(), event)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to store endpoint events"})
			return
		}
		if inserted {
			accepted++
		} else {
			duplicates++
		}
	}

	if err := h.repo.UpdateHeartbeat(c.Request.Context(), hostID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to update endpoint heartbeat"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":     "accepted",
		"accepted":   accepted,
		"duplicates": duplicates,
	})
}

func (h *Handler) Heartbeat(c *gin.Context) {
	hostID := c.GetString(ContextHostID)
	if hostID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "agent authentication required"})
		return
	}

	if err := h.repo.UpdateHeartbeat(c.Request.Context(), hostID); err != nil {
		if errors.Is(err, ErrHostNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "endpoint unavailable"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to update heartbeat"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "online",
		"time":   time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

// Ensure a malformed or oversized JSON body is handled by Gin's binder.
var _ io.Reader

type listEventsQuery struct {
	Limit  int `form:"limit"`
	Offset int `form:"offset"`
}

// ListHosts returns hosts belonging to the authenticated user's organization.
func (h *Handler) ListHosts(c *gin.Context) {
	orgID := strings.TrimSpace(c.GetString(auth.ContextOrganizationID))
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "organization context missing",
		})
		return
	}

	hosts, err := h.repo.ListHosts(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to retrieve endpoint hosts",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"hosts": hosts,
		"count": len(hosts),
	})
}

// ListHostEvents returns paginated events for a host in the user's organization.
func (h *Handler) ListHostEvents(c *gin.Context) {
	orgID := strings.TrimSpace(c.GetString(auth.ContextOrganizationID))
	if orgID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "organization context missing",
		})
		return
	}

	hostID := strings.TrimSpace(c.Param("hostID"))
	if hostID == "" || len(hostID) > 100 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid host ID",
		})
		return
	}

	var query listEventsQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid pagination parameters",
		})
		return
	}

	if query.Limit == 0 {
		query.Limit = 50
	}
	if query.Limit < 1 || query.Limit > 200 ||
		query.Offset < 0 || query.Offset > 1000000 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "limit must be 1-200 and offset must be 0-1000000",
		})
		return
	}

	events, err := h.repo.ListEvents(
		c.Request.Context(),
		orgID,
		hostID,
		query.Limit,
		query.Offset,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to retrieve endpoint events",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"host_id": hostID,
		"events":  events,
		"count":   len(events),
		"limit":   query.Limit,
		"offset":  query.Offset,
	})
}
func (h *Handler) RotateHostKey(c *gin.Context) {
	organizationID := c.GetString(auth.ContextOrganizationID)
	hostID := strings.TrimSpace(c.Param("hostID"))

	if organizationID == "" || hostID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "organization and host ID are required",
		})
		return
	}

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to generate agent credential",
		})
		return
	}

	agentKey := hex.EncodeToString(keyBytes)
	sum := sha256.Sum256([]byte(agentKey))
	keyHash := hex.EncodeToString(sum[:])

	if err := h.repo.RotateHostCredential(
		c.Request.Context(),
		organizationID,
		hostID,
		keyHash,
	); err != nil {
		if errors.Is(err, ErrHostNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "active endpoint not found",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "unable to rotate agent credential",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"host_id":   hostID,
		"agent_key": agentKey,
		"warning":   "Save this key securely. It will not be shown again.",
	})
}
