package website

import (
	"context"
	"database/sql"
	"fmt"
)

type Website struct {
	ID        string `json:"id"`
	Domain    string `json:"domain"`
	HashID    string `json:"hash_id"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) Create(
	ctx context.Context,
	id, organizationID, createdBy, domain, hashID, apiKeyHash, createdAt string,
) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO websites (
			id, organization_id, created_by, domain,
			hash_id, api_key_hash, status, created_at
		)
		VALUES (?, ?, ?, ?, ?, ?, 'active', ?)
	`,
		id, organizationID, createdBy, domain,
		hashID, apiKeyHash, createdAt,
	)
	if err != nil {
		return fmt.Errorf("create website: %w", err)
	}

	return nil
}

func (r *Repository) ListByOrganization(
	ctx context.Context,
	organizationID string,
) ([]Website, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, domain, hash_id, status, created_at
		FROM websites
		WHERE organization_id = ?
		ORDER BY created_at DESC, id ASC
	`, organizationID)
	if err != nil {
		return nil, fmt.Errorf("list websites: %w", err)
	}
	defer rows.Close()

	websites := make([]Website, 0)

	for rows.Next() {
		var website Website
		if err := rows.Scan(
			&website.ID,
			&website.Domain,
			&website.HashID,
			&website.Status,
			&website.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan website: %w", err)
		}

		websites = append(websites, website)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate websites: %w", err)
	}

	return websites, nil
}
