package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"crypto/rand"
	"encoding/hex"
)

var ErrInvalidEntry = errors.New("invalid audit entry")

type Executor interface {
	ExecContext(
		ctx context.Context,
		query string,
		args ...any,
	) (sql.Result, error)
}

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

type Entry struct {
	OrganizationID string
	UserID         string
	Action         string
	ResourceType   string
	ResourceID     string
	Metadata       map[string]any
}

func (r *Repository) Record(ctx context.Context, entry Entry) error {
	return RecordWithExecutor(ctx, r.db, entry)
}

// RecordWithExecutor supports both *sql.DB and *sql.Tx.
// Pass a transaction to make the audit insert atomic with another operation.
func RecordWithExecutor(
	ctx context.Context,
	executor Executor,
	entry Entry,
) error {
	if executor == nil ||
		entry.OrganizationID == "" ||
		entry.Action == "" ||
		entry.ResourceType == "" {
		return ErrInvalidEntry
	}

	metadata := entry.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("encode audit metadata: %w", err)
	}

	id, err := newAuditID()
	if err != nil {
		return fmt.Errorf("generate audit ID: %w", err)
	}

	var userID any
	if entry.UserID != "" {
		userID = entry.UserID
	}

	_, err = executor.ExecContext(ctx, `
		INSERT INTO audit_logs (
			id,
			organization_id,
			user_id,
			action,
			resource_type,
			resource_id,
			metadata,
			created_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`,
		id,
		entry.OrganizationID,
		userID,
		entry.Action,
		entry.ResourceType,
		nullableString(entry.ResourceID),
		string(metadataJSON),
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}

	return nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func newAuditID() (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	return "audit_" + hex.EncodeToString(randomBytes), nil
}
