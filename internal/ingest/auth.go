package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const ContextWebsiteID = "ingestWebsiteID"

func APIKeyAuth(repo *Repository) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := strings.TrimSpace(c.GetHeader("X-API-Key"))
		if apiKey == "" || len(apiKey) > 256 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid API key",
			})
			return
		}

		sum := sha256.Sum256([]byte(apiKey))
		keyHash := hex.EncodeToString(sum[:])

		websiteID, err := repo.FindActiveWebsiteByAPIKeyHash(
			c.Request.Context(),
			keyHash,
		)
		if err != nil || websiteID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid API key",
			})
			return
		}

		c.Set(ContextWebsiteID, websiteID)
		c.Next()
	}
}
