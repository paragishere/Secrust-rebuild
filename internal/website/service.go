package website

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var ErrInvalidWebsite = errors.New("invalid website details")

type CreateResult struct {
	Website Website `json:"website"`
	APIKey  string  `json:"api_key"`
}

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) Create(
	ctx context.Context,
	organizationID, createdBy, domain string,
) (CreateResult, error) {
	organizationID = strings.TrimSpace(organizationID)
	createdBy = strings.TrimSpace(createdBy)
	domain = strings.ToLower(strings.TrimSpace(domain))

	if organizationID == "" || createdBy == "" || !validDomain(domain) {
		return CreateResult{}, ErrInvalidWebsite
	}

	id, err := randomHex(16)
	if err != nil {
		return CreateResult{}, fmt.Errorf("generate website ID: %w", err)
	}

	hashID, err := randomHex(16)
	if err != nil {
		return CreateResult{}, fmt.Errorf("generate hash ID: %w", err)
	}

	apiKey, err := randomHex(32)
	if err != nil {
		return CreateResult{}, fmt.Errorf("generate API key: %w", err)
	}

	sum := sha256.Sum256([]byte(apiKey))
	apiKeyHash := hex.EncodeToString(sum[:])
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)

	if err := s.repo.Create(
		ctx, id, organizationID, createdBy, domain,
		hashID, apiKeyHash, createdAt,
	); err != nil {
		return CreateResult{}, err
	}

	return CreateResult{
		Website: Website{
			ID:        id,
			Domain:    domain,
			HashID:    hashID,
			Status:    "active",
			CreatedAt: createdAt,
		},
		APIKey: apiKey,
	}, nil
}

func (s *Service) List(
	ctx context.Context,
	organizationID string,
) ([]Website, error) {
	if strings.TrimSpace(organizationID) == "" {
		return nil, ErrInvalidWebsite
	}

	return s.repo.ListByOrganization(ctx, organizationID)
}

func randomHex(bytesCount int) (string, error) {
	b := make([]byte, bytesCount)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

func validDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}

	// Accept hostnames and IP addresses; reject URLs, paths and ports.
	if strings.Contains(domain, "://") ||
		strings.ContainsAny(domain, "/?#@ ") {
		return false
	}

	if net.ParseIP(domain) != nil {
		return true
	}

	if strings.Contains(domain, ":") {
		return false
	}

	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}

		for _, ch := range label {
			if !((ch >= 'a' && ch <= 'z') ||
				(ch >= '0' && ch <= '9') || ch == '-') {
				return false
			}
		}
	}

	return true
}
