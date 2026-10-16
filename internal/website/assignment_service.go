package website

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/paragishere/secrust/internal/audit"
)

var ErrInvalidAssignmentRequest = errors.New("invalid assignment request")

type AssignmentService struct {
	db        *sql.DB
	repo      *AssignmentRepository
	auditRepo *audit.Repository
}

func NewAssignmentService(repo *AssignmentRepository) *AssignmentService {
	return &AssignmentService{
		db:   repo.db,
		repo: repo,
	}
}

// NewAssignmentServiceWithAudit enables atomic audit logging.
func NewAssignmentServiceWithAudit(
	db *sql.DB,
	repo *AssignmentRepository,
	auditRepo *audit.Repository,
) *AssignmentService {
	return &AssignmentService{
		db:        db,
		repo:      repo,
		auditRepo: auditRepo,
	}
}

func (s *AssignmentService) Assign(
	ctx context.Context,
	organizationID string,
	websiteID string,
	userID string,
	permission string,
) error {
	return s.AssignByActor(
		ctx,
		organizationID,
		"",
		websiteID,
		userID,
		permission,
	)
}

func (s *AssignmentService) AssignByActor(
	ctx context.Context,
	organizationID string,
	actorUserID string,
	websiteID string,
	userID string,
	permission string,
) error {
	if organizationID == "" || websiteID == "" || userID == "" {
		return ErrInvalidAssignmentRequest
	}
	if permission != "read" && permission != "investigate" {
		return ErrInvalidAssignmentRequest
	}
	if s.auditRepo == nil {
		return s.repo.Assign(ctx, organizationID, websiteID, userID, permission)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin assignment transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.repo.AssignWithExecutor(
		ctx, tx, organizationID, websiteID, userID, permission,
	); err != nil {
		return err
	}

	if err := audit.RecordWithExecutor(ctx, tx, audit.Entry{
		OrganizationID: organizationID,
		UserID:         actorUserID,
		Action:         "website.user.assigned",
		ResourceType:   "website",
		ResourceID:     websiteID,
		Metadata: map[string]any{
			"assigned_user_id": userID,
			"permission":       permission,
		},
	}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit assignment transaction: %w", err)
	}

	return nil
}

func (s *AssignmentService) Unassign(
	ctx context.Context,
	organizationID string,
	websiteID string,
	userID string,
) error {
	return s.UnassignByActor(ctx, organizationID, "", websiteID, userID)
}

func (s *AssignmentService) UnassignByActor(
	ctx context.Context,
	organizationID string,
	actorUserID string,
	websiteID string,
	userID string,
) error {
	if organizationID == "" || websiteID == "" || userID == "" {
		return ErrInvalidAssignmentRequest
	}
	if s.auditRepo == nil {
		return s.repo.Unassign(ctx, organizationID, websiteID, userID)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin unassignment transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.repo.UnassignWithExecutor(
		ctx, tx, organizationID, websiteID, userID,
	); err != nil {
		return err
	}

	if err := audit.RecordWithExecutor(ctx, tx, audit.Entry{
		OrganizationID: organizationID,
		UserID:         actorUserID,
		Action:         "website.user.unassigned",
		ResourceType:   "website",
		ResourceID:     websiteID,
		Metadata: map[string]any{
			"removed_user_id": userID,
		},
	}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit unassignment transaction: %w", err)
	}

	return nil
}
