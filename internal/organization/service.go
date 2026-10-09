package organization

import (
	"context"
	"errors"
	"strings"
)

var ErrOrganizationRequired = errors.New("organization ID is required")

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) ListMembers(
	ctx context.Context,
	organizationID string,
) ([]Member, error) {
	organizationID = strings.TrimSpace(organizationID)
	if organizationID == "" {
		return nil, ErrOrganizationRequired
	}

	return s.repo.ListMembers(ctx, organizationID)
}
