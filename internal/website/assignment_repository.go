package website

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

var (
	ErrAssignmentNotFound = errors.New("website assignment not found")
	ErrInvalidAssignment  = errors.New("invalid website assignment")
)

// AssignmentRepository manages user access to websites.
type AssignmentRepository struct {
	db *sql.DB
}

// AssignmentExecutor allows assignment queries through either
// a database connection or a transaction.
type AssignmentExecutor interface {
	ExecContext(
		ctx context.Context,
		query string,
		args ...any,
	) (sql.Result, error)
}

func NewAssignmentRepository(db *sql.DB) *AssignmentRepository {
	return &AssignmentRepository{db: db}
}

// Assign adds or updates website access for a user in the same organization.
func (r *AssignmentRepository) Assign(
	ctx context.Context,
	organizationID string,
	websiteID string,
	userID string,
	permission string,
) error {
	return r.AssignWithExecutor(
		ctx,
		r.db,
		organizationID,
		websiteID,
		userID,
		permission,
	)
}

// AssignWithExecutor supports atomic assignment and audit operations
// when the caller passes a *sql.Tx.
func (r *AssignmentRepository) AssignWithExecutor(
	ctx context.Context,
	executor AssignmentExecutor,
	organizationID string,
	websiteID string,
	userID string,
	permission string,
) error {
	if executor == nil ||
		organizationID == "" ||
		websiteID == "" ||
		userID == "" {
		return ErrInvalidAssignment
	}

	if permission != "read" && permission != "investigate" {
		return ErrInvalidAssignment
	}

	result, err := executor.ExecContext(ctx, `
		INSERT INTO website_users (
			website_id,
			user_id,
			permission,
			created_at
		)
		SELECT w.id, ou.user_id, ?, datetime('now')
		FROM websites w
		JOIN organization_users ou
			ON ou.organization_id = w.organization_id
		WHERE w.id = ?
			AND w.organization_id = ?
			AND ou.user_id = ?
			AND w.status = 'active'
		ON CONFLICT (website_id, user_id)
		DO UPDATE SET permission = excluded.permission
	`, permission, websiteID, organizationID, userID)
	if err != nil {
		return fmt.Errorf("assign user to website: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check assignment result: %w", err)
	}
	if rows == 0 {
		return ErrInvalidAssignment
	}

	return nil
}

// Unassign removes access only from a website in the given organization.
func (r *AssignmentRepository) Unassign(
	ctx context.Context,
	organizationID string,
	websiteID string,
	userID string,
) error {
	return r.UnassignWithExecutor(
		ctx,
		r.db,
		organizationID,
		websiteID,
		userID,
	)
}

// UnassignWithExecutor supports atomic removal and audit operations
// when the caller passes a *sql.Tx.
func (r *AssignmentRepository) UnassignWithExecutor(
	ctx context.Context,
	executor AssignmentExecutor,
	organizationID string,
	websiteID string,
	userID string,
) error {
	if executor == nil ||
		organizationID == "" ||
		websiteID == "" ||
		userID == "" {
		return ErrInvalidAssignment
	}

	result, err := executor.ExecContext(ctx, `
		DELETE FROM website_users
		WHERE website_id = ?
			AND user_id = ?
			AND EXISTS (
				SELECT 1
				FROM websites w
				WHERE w.id = website_users.website_id
					AND w.organization_id = ?
			)
	`, websiteID, userID, organizationID)
	if err != nil {
		return fmt.Errorf("unassign user from website: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check unassignment result: %w", err)
	}
	if rows == 0 {
		return ErrAssignmentNotFound
	}

	return nil
}
