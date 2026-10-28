package endpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	ContextHostID         = "endpointHostID"
	ContextOrganizationID = "endpointOrganizationID"
)

func AgentKeyAuth(repo *Repository) gin.HandlerFunc {
	return func(c *gin.Context) {
		agentKey := strings.TrimSpace(c.GetHeader("X-Agent-Key"))

		if agentKey == "" || len(agentKey) > 256 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid agent credential",
			})
			return
		}

		sum := sha256.Sum256([]byte(agentKey))
		credentialHash := hex.EncodeToString(sum[:])

		host, err := repo.FindActiveHostByCredentialHash(
			c.Request.Context(),
			credentialHash,
		)
		if err != nil || host.ID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid agent credential",
			})
			return
		}

		c.Set(ContextHostID, host.ID)
		c.Set(ContextOrganizationID, host.OrganizationID)
		c.Next()
	}
}
