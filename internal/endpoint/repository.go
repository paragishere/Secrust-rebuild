package endpoint

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrHostNotFound = errors.New("endpoint host not found")
	ErrHostConflict = errors.New("endpoint host already registered")
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

type Host struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organization_id"`
	Hostname       string `json:"hostname"`
	OSType         string `json:"os_type"`
	AgentVersion   string `json:"agent_version"`
	Status         string `json:"status"`
	LastHeartbeat  string `json:"last_heartbeat,omitempty"`
	CreatedAt      string `json:"created_at"`
}

type Event struct {
	ID          string         `json:"id"`
	HostID      string         `json:"host_id"`
	EventUID    string         `json:"event_uid"`
	EventID     int            `json:"event_id"`
	EventType   string         `json:"event_type"`
	Severity    string         `json:"severity"`
	RiskScore   int            `json:"risk_score"`
	OccurredAt  string         `json:"occurred_at"`
	ReceivedAt  string         `json:"received_at"`
	SourceIP    string         `json:"source_ip,omitempty"`
	AccountName string         `json:"account,omitempty"`
	Details     map[string]any `json:"details,omitempty"`
}

type CreateHostInput struct {
	ID             string
	OrganizationID string
	Hostname       string
	OSType         string
	AgentVersion   string
	CredentialHash string
}

func (r *Repository) CreateHost(
	ctx context.Context,
	input CreateHostInput,
) error {
	input.ID = strings.TrimSpace(input.ID)
	input.OrganizationID = strings.TrimSpace(input.OrganizationID)
	input.Hostname = strings.TrimSpace(input.Hostname)
	input.OSType = strings.ToLower(strings.TrimSpace(input.OSType))
	input.AgentVersion = strings.TrimSpace(input.AgentVersion)

	if input.ID == "" || input.OrganizationID == "" ||
		input.Hostname == "" || input.CredentialHash == "" {
		return errors.New("required host fields are missing")
	}

	if len(input.Hostname) > 255 || len(input.AgentVersion) > 100 {
		return errors.New("host field exceeds maximum length")
	}

	if input.OSType != "windows" && input.OSType != "linux" {
		return errors.New("unsupported operating system")
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO endpoint_hosts (
			id, organization_id, hostname, os_type, agent_version,
			credential_hash, status, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)
	`,
		input.ID,
		input.OrganizationID,
		input.Hostname,
		input.OSType,
		input.AgentVersion,
		input.CredentialHash,
		now,
		now,
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
			return ErrHostConflict
		}
		return fmt.Errorf("create endpoint host: %w", err)
	}

	return nil
}

func (r *Repository) FindActiveHostByCredentialHash(
	ctx context.Context,
	credentialHash string,
) (Host, error) {
	var host Host

	err := r.db.QueryRowContext(ctx, `
		SELECT id, organization_id, hostname, os_type,
		       agent_version, status, COALESCE(last_heartbeat, ''),
		       created_at
		FROM endpoint_hosts
		WHERE credential_hash = ? AND status = 'active'
	`, credentialHash).Scan(
		&host.ID,
		&host.OrganizationID,
		&host.Hostname,
		&host.OSType,
		&host.AgentVersion,
		&host.Status,
		&host.LastHeartbeat,
		&host.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, ErrHostNotFound
	}
	if err != nil {
		return Host{}, fmt.Errorf("find endpoint host: %w", err)
	}

	return host, nil
}

func (r *Repository) UpdateHeartbeat(
	ctx context.Context,
	hostID string,
) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)

	result, err := r.db.ExecContext(ctx, `
		UPDATE endpoint_hosts
		SET last_heartbeat = ?, updated_at = ?
		WHERE id = ? AND status = 'active'
	`, now, now, hostID)
	if err != nil {
		return fmt.Errorf("update endpoint heartbeat: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check heartbeat update: %w", err)
	}
	if affected == 0 {
		return ErrHostNotFound
	}

	return nil
}

func (r *Repository) InsertEvent(
	ctx context.Context,
	event Event,
) (bool, error) {
	if event.Details == nil {
		event.Details = map[string]any{}
	}

	detailsJSON, err := json.Marshal(event.Details)
	if err != nil {
		return false, fmt.Errorf("encode endpoint event details: %w", err)
	}

	if event.ID == "" || event.HostID == "" || event.EventUID == "" {
		return false, errors.New("event ID, host ID, and event UID are required")
	}

	if event.OccurredAt == "" {
		return false, errors.New("event timestamp is required")
	}

	if _, err := time.Parse(time.RFC3339Nano, event.OccurredAt); err != nil {
		return false, errors.New("event timestamp must be RFC3339")
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)

	result, err := r.db.ExecContext(ctx, `
		INSERT INTO endpoint_events (
			id, host_id, event_uid, event_id, event_type, severity,
			risk_score, occurred_at, received_at, source_ip,
			account_name, details
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host_id, event_uid) DO NOTHING
	`,
		event.ID,
		event.HostID,
		event.EventUID,
		event.EventID,
		event.EventType,
		event.Severity,
		event.RiskScore,
		event.OccurredAt,
		now,
		nullable(event.SourceIP),
		nullable(event.AccountName),
		string(detailsJSON),
	)
	if err != nil {
		return false, fmt.Errorf("insert endpoint event: %w", err)
	}

	inserted, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("check endpoint event insert: %w", err)
	}

	return inserted == 1, nil
}

func nullable(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

// ListHosts returns endpoint hosts belonging to one organization.
func (r *Repository) ListHosts(
	ctx context.Context,
	organizationID string,
) ([]Host, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, organization_id, hostname, os_type,
		       agent_version, status,
		       COALESCE(last_heartbeat, ''), created_at
		FROM endpoint_hosts
		WHERE organization_id = ?
		ORDER BY hostname ASC
	`, organizationID)
	if err != nil {
		return nil, fmt.Errorf("list endpoint hosts: %w", err)
	}
	defer rows.Close()

	hosts := make([]Host, 0)

	for rows.Next() {
		var host Host

		if err := rows.Scan(
			&host.ID,
			&host.OrganizationID,
			&host.Hostname,
			&host.OSType,
			&host.AgentVersion,
			&host.Status,
			&host.LastHeartbeat,
			&host.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan endpoint host: %w", err)
		}

		hosts = append(hosts, host)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate endpoint hosts: %w", err)
	}

	return hosts, nil
}

// ListEvents returns paginated events for a host in the given organization.
func (r *Repository) ListEvents(
	ctx context.Context,
	organizationID string,
	hostID string,
	limit int,
	offset int,
) ([]Event, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT e.id, e.host_id, e.event_uid, e.event_id,
		       e.event_type, e.severity, e.risk_score,
		       e.occurred_at, e.received_at,
		       COALESCE(e.source_ip, ''),
		       COALESCE(e.account_name, ''),
		       e.details
		FROM endpoint_events e
		INNER JOIN endpoint_hosts h ON h.id = e.host_id
		WHERE h.organization_id = ?
		  AND h.id = ?
		ORDER BY e.occurred_at DESC, e.id DESC
		LIMIT ? OFFSET ?
	`, organizationID, hostID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list endpoint events: %w", err)
	}
	defer rows.Close()

	events := make([]Event, 0)

	for rows.Next() {
		var event Event
		var detailsJSON string

		if err := rows.Scan(
			&event.ID,
			&event.HostID,
			&event.EventUID,
			&event.EventID,
			&event.EventType,
			&event.Severity,
			&event.RiskScore,
			&event.OccurredAt,
			&event.ReceivedAt,
			&event.SourceIP,
			&event.AccountName,
			&detailsJSON,
		); err != nil {
			return nil, fmt.Errorf("scan endpoint event: %w", err)
		}

		if err := json.Unmarshal(
			[]byte(detailsJSON),
			&event.Details,
		); err != nil {
			return nil, fmt.Errorf("decode endpoint event details: %w", err)
		}

		events = append(events, event)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate endpoint events: %w", err)
	}

	return events, nil
}
func (r *Repository) RotateHostCredential(
	ctx context.Context,
	organizationID string,
	hostID string,
	credentialHash string,
) error {
	result, err := r.db.ExecContext(ctx, `
        UPDATE endpoint_hosts
        SET credential_hash = ?, updated_at = ?
        WHERE id = ?
          AND organization_id = ?
          AND status = 'active'
    `,
		credentialHash,
		time.Now().UTC().Format(time.RFC3339Nano),
		strings.TrimSpace(hostID),
		strings.TrimSpace(organizationID),
	)
	if err != nil {
		return fmt.Errorf("rotate endpoint credential: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check credential rotation: %w", err)
	}
	if affected == 0 {
		return ErrHostNotFound
	}

	return nil
}
