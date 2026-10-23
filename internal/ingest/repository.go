package ingest

import (
	"context"
	"database/sql"
	"fmt"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

type Log struct {
	ID        string
	WebsiteID string
	IP        string
	Method    string
	Path      string
	Status    int
	UserAgent string
	EventType string
	Severity  string
	CreatedAt string
}

func (r *Repository) FindActiveWebsiteByAPIKeyHash(
	ctx context.Context,
	apiKeyHash string,
) (string, error) {
	var websiteID string

	err := r.db.QueryRowContext(ctx, `
		SELECT id
		FROM websites
		WHERE api_key_hash = ?
		  AND status = 'active'
	`, apiKeyHash).Scan(&websiteID)

	if err != nil {
		return "", err
	}

	return websiteID, nil
}

func (r *Repository) InsertLog(ctx context.Context, log Log) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO logs (
			id, website_id, ip, method, path, status,
			user_agent, country, city, event_type, severity, created_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?)
	`,
		log.ID,
		log.WebsiteID,
		nullableString(log.IP),
		log.Method,
		log.Path,
		log.Status,
		nullableString(log.UserAgent),
		log.EventType,
		log.Severity,
		log.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert log: %w", err)
	}

	return nil
}

func (r *Repository) ListLogs(
	ctx context.Context,
	organizationID string,
	limit, offset int,
) ([]Log, error) {
	if organizationID == "" {
		return nil, fmt.Errorf("organization ID is required")
	}

	if limit < 1 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT
			l.id,
			l.website_id,
			COALESCE(l.ip, ''),
			l.method,
			l.path,
			l.status,
			COALESCE(l.user_agent, ''),
			l.event_type,
			l.severity,
			l.created_at
		FROM logs l
		JOIN websites w ON w.id = l.website_id
		WHERE w.organization_id = ?
		ORDER BY l.created_at DESC, l.id DESC
		LIMIT ? OFFSET ?
	`, organizationID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list organization logs: %w", err)
	}
	defer rows.Close()

	logs := make([]Log, 0, limit)

	for rows.Next() {
		var log Log
		if err := rows.Scan(
			&log.ID,
			&log.WebsiteID,
			&log.IP,
			&log.Method,
			&log.Path,
			&log.Status,
			&log.UserAgent,
			&log.EventType,
			&log.Severity,
			&log.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan log: %w", err)
		}

		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate logs: %w", err)
	}

	return logs, nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
