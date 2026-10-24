package alerts

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidAlert  = errors.New("invalid alert")
	ErrAlertNotFound = errors.New("alert not found")
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

type Alert struct {
	ID             string         `json:"id"`
	OrganizationID string         `json:"organization_id"`
	WebsiteID      string         `json:"website_id"`
	Severity       string         `json:"severity"`
	Type           string         `json:"type"`
	Message        string         `json:"message"`
	IP             string         `json:"ip"`
	Status         string         `json:"status"`
	RuleKey        string         `json:"rule_key"`
	Details        map[string]any `json:"details"`
	CreatedAt      string         `json:"created_at"`
	AcknowledgedBy string         `json:"acknowledged_by,omitempty"`
	AcknowledgedAt string         `json:"acknowledged_at,omitempty"`
	ResolvedBy     string         `json:"resolved_by,omitempty"`
	ResolvedAt     string         `json:"resolved_at,omitempty"`
}

type CreateInput struct {
	WebsiteID string
	Severity  string
	Type      string
	Message   string
	IP        string
	RuleKey   string
	Details   map[string]any
}

func (r *Repository) Create(ctx context.Context, input CreateInput) (Alert, error) {
	if r == nil || r.db == nil ||
		strings.TrimSpace(input.WebsiteID) == "" ||
		strings.TrimSpace(input.Type) == "" ||
		strings.TrimSpace(input.Message) == "" {
		return Alert{}, ErrInvalidAlert
	}

	severity := strings.ToLower(strings.TrimSpace(input.Severity))
	switch severity {
	case "low", "medium", "high", "critical":
	default:
		return Alert{}, ErrInvalidAlert
	}

	// Resolve organization from the trusted website record.
	// Do not accept organization_id from an ingestion payload.
	var organizationID string
	err := r.db.QueryRowContext(ctx, `
		SELECT organization_id
		FROM websites
		WHERE id = ? AND status = 'active'
	`, input.WebsiteID).Scan(&organizationID)
	if errors.Is(err, sql.ErrNoRows) {
		return Alert{}, ErrAlertNotFound
	}
	if err != nil {
		return Alert{}, fmt.Errorf("resolve alert organization: %w", err)
	}

	if input.Details == nil {
		input.Details = map[string]any{}
	}
	detailsJSON, err := json.Marshal(input.Details)
	if err != nil {
		return Alert{}, fmt.Errorf("encode alert details: %w", err)
	}

	id, err := newAlertID()
	if err != nil {
		return Alert{}, fmt.Errorf("generate alert ID: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO alerts (
			id, website_id, organization_id, severity, type,
			message, ip, created_at, status, rule_key, details
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)
	`,
		id,
		input.WebsiteID,
		organizationID,
		severity,
		strings.TrimSpace(input.Type),
		strings.TrimSpace(input.Message),
		nullableString(strings.TrimSpace(input.IP)),
		now,
		nullableString(strings.TrimSpace(input.RuleKey)),
		string(detailsJSON),
	)
	if err != nil {
		return Alert{}, fmt.Errorf("create alert: %w", err)
	}

	return Alert{
		ID:             id,
		OrganizationID: organizationID,
		WebsiteID:      input.WebsiteID,
		Severity:       severity,
		Type:           strings.TrimSpace(input.Type),
		Message:        strings.TrimSpace(input.Message),
		IP:             input.IP,
		Status:         "open",
		RuleKey:        input.RuleKey,
		Details:        input.Details,
		CreatedAt:      now,
	}, nil
}

func (r *Repository) List(
	ctx context.Context,
	organizationID string,
	status string,
	limit, offset int,
) ([]Alert, error) {
	if r == nil || r.db == nil || strings.TrimSpace(organizationID) == "" {
		return nil, ErrInvalidAlert
	}

	status = strings.ToLower(strings.TrimSpace(status))
	switch status {
	case "", "open", "acknowledged", "resolved":
	default:
		return nil, ErrInvalidAlert
	}

	if limit < 1 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT id, organization_id, website_id, severity, type,
		       message, COALESCE(ip, ''), status, COALESCE(rule_key, ''),
		       details, created_at, COALESCE(acknowledged_by, ''),
		       COALESCE(acknowledged_at, ''), COALESCE(resolved_by, ''),
		       COALESCE(resolved_at, '')
		FROM alerts
		WHERE organization_id = ?
	`
	args := []any{organizationID}

	if status != "" {
		query += ` AND status = ?`
		args = append(args, status)
	}

	query += ` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list alerts: %w", err)
	}
	defer rows.Close()

	result := make([]Alert, 0, limit)
	for rows.Next() {
		var alert Alert
		var detailsJSON string

		if err := rows.Scan(
			&alert.ID,
			&alert.OrganizationID,
			&alert.WebsiteID,
			&alert.Severity,
			&alert.Type,
			&alert.Message,
			&alert.IP,
			&alert.Status,
			&alert.RuleKey,
			&detailsJSON,
			&alert.CreatedAt,
			&alert.AcknowledgedBy,
			&alert.AcknowledgedAt,
			&alert.ResolvedBy,
			&alert.ResolvedAt,
		); err != nil {
			return nil, fmt.Errorf("scan alert: %w", err)
		}

		alert.Details = make(map[string]any)
		if err := json.Unmarshal([]byte(detailsJSON), &alert.Details); err != nil {
			return nil, fmt.Errorf("decode alert details: %w", err)
		}
		result = append(result, alert)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate alerts: %w", err)
	}

	return result, nil
}

func (r *Repository) SetStatus(
	ctx context.Context,
	organizationID, alertID, userID, newStatus string,
) error {
	if r == nil || r.db == nil ||
		strings.TrimSpace(organizationID) == "" ||
		strings.TrimSpace(alertID) == "" ||
		strings.TrimSpace(userID) == "" {
		return ErrInvalidAlert
	}

	newStatus = strings.ToLower(strings.TrimSpace(newStatus))
	if newStatus != "acknowledged" && newStatus != "resolved" {
		return ErrInvalidAlert
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)

	var result sql.Result
	var err error

	if newStatus == "acknowledged" {
		result, err = r.db.ExecContext(ctx, `
			UPDATE alerts
			SET status = 'acknowledged',
			    acknowledged_by = ?,
			    acknowledged_at = ?
			WHERE id = ?
			  AND organization_id = ?
			  AND status = 'open'
		`, userID, now, alertID, organizationID)
	} else {
		result, err = r.db.ExecContext(ctx, `
			UPDATE alerts
			SET status = 'resolved',
			    resolved_by = ?,
			    resolved_at = ?
			WHERE id = ?
			  AND organization_id = ?
			  AND status IN ('open', 'acknowledged')
		`, userID, now, alertID, organizationID)
	}

	if err != nil {
		return fmt.Errorf("update alert status: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check alert status update: %w", err)
	}
	if affected == 0 {
		return ErrAlertNotFound
	}

	return nil
}

func newAlertID() (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return "alert_" + hex.EncodeToString(randomBytes), nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (r *Repository) HasRecentOpenAlert(
	ctx context.Context,
	websiteID string,
	ruleKey string,
	since time.Time,
) (bool, error) {
	if r == nil || r.db == nil ||
		strings.TrimSpace(websiteID) == "" ||
		strings.TrimSpace(ruleKey) == "" {
		return false, ErrInvalidAlert
	}

	var exists int
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM alerts
			WHERE website_id = ?
			  AND rule_key = ?
			  AND status = 'open'
			  AND created_at >= ?
		)
	`, websiteID, ruleKey, since.UTC().Format(time.RFC3339Nano)).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check recent open alert: %w", err)
	}

	return exists == 1, nil
}

func (r *Repository) HasRecentOpenAlertForIP(
	ctx context.Context,
	websiteID string,
	ruleKey string,
	ip string,
	since time.Time,
) (bool, error) {
	if r == nil || r.db == nil {
		return false, fmt.Errorf("alert repository is not initialized")
	}

	var exists int
	err := r.db.QueryRowContext(ctx, `
		SELECT 1
		FROM alerts
		WHERE website_id = ?
		  AND rule_key = ?
		  AND ip = ?
		  AND status = 'open'
		  AND created_at >= ?
		LIMIT 1
	`, websiteID, ruleKey, ip, since.UTC().Format(time.RFC3339Nano)).Scan(&exists)

	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check recent IP alert: %w", err)
	}

	return true, nil
}
