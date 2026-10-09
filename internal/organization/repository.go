package organization

import (
	"context"
	"database/sql"
	"fmt"
)

type Member struct {
	UserID   string `json:"user_id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Status   string `json:"status"`
	JoinedAt string `json:"joined_at"`
}

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// ListMembers only returns members belonging to the requested organization.
func (r *Repository) ListMembers(
	ctx context.Context,
	organizationID string,
) ([]Member, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT
			u.id,
			u.name,
			u.email,
			ou.role,
			u.status,
			ou.created_at
		FROM organization_users ou
		JOIN users u ON u.id = ou.user_id
		WHERE ou.organization_id = ?
		ORDER BY ou.created_at ASC, u.name ASC
	`, organizationID)
	if err != nil {
		return nil, fmt.Errorf("list organization members: %w", err)
	}
	defer rows.Close()

	members := make([]Member, 0)

	for rows.Next() {
		var member Member
		if err := rows.Scan(
			&member.UserID,
			&member.Name,
			&member.Email,
			&member.Role,
			&member.Status,
			&member.JoinedAt,
		); err != nil {
			return nil, fmt.Errorf("scan organization member: %w", err)
		}

		members = append(members, member)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate organization members: %w", err)
	}

	return members, nil
}
