package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrAccountDisabled    = errors.New("account is disabled")
	ErrSessionInvalid     = errors.New("session is invalid or expired")
)

type User struct {
	ID           string
	Name         string
	Email        string
	PasswordHash string
	Status       string
}

type Membership struct {
	OrganizationID string
	Role           string
}

type Session struct {
	UserID         string
	OrganizationID string
	Role           string
	ExpiresAt      time.Time
}

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) FindUserByEmail(
	ctx context.Context,
	email string,
) (User, error) {
	var user User

	err := r.db.QueryRowContext(ctx, `
		SELECT id, name, email, password_hash, status
		FROM users
		WHERE email = ? COLLATE NOCASE
	`, email).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.PasswordHash,
		&user.Status,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrInvalidCredentials
	}
	if err != nil {
		return User{}, fmt.Errorf("find user: %w", err)
	}

	return user, nil
}

func (r *Repository) FindMembership(
	ctx context.Context,
	userID string,
) (Membership, error) {
	var membership Membership

	err := r.db.QueryRowContext(ctx, `
		SELECT organization_id, role
		FROM organization_users
		WHERE user_id = ?
		ORDER BY created_at ASC, organization_id ASC
		LIMIT 1
	`, userID).Scan(
		&membership.OrganizationID,
		&membership.Role,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return Membership{}, ErrInvalidCredentials
	}
	if err != nil {
		return Membership{}, fmt.Errorf("find organization membership: %w", err)
	}

	return membership, nil
}

func (r *Repository) CreateSession(
	ctx context.Context,
	tokenHash string,
	userID string,
	organizationID string,
	expiresAt time.Time,
) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO sessions (
			id_hash, user_id, organization_id, expires_at, created_at
		)
		VALUES (?, ?, ?, ?, ?)
	`,
		tokenHash,
		userID,
		organizationID,
		expiresAt.UTC().Format(time.RFC3339Nano),
		now,
	)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	return nil
}

func (r *Repository) FindSession(
	ctx context.Context,
	tokenHash string,
) (Session, error) {
	var session Session
	var expiresAt string

	err := r.db.QueryRowContext(ctx, `
		SELECT s.user_id, s.organization_id, ou.role, s.expires_at
		FROM sessions s
		JOIN users u ON u.id = s.user_id
		JOIN organization_users ou
		  ON ou.user_id = s.user_id
		 AND ou.organization_id = s.organization_id
		WHERE s.id_hash = ?
		  AND u.status = 'active'
	`, tokenHash).Scan(
		&session.UserID,
		&session.OrganizationID,
		&session.Role,
		&expiresAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrSessionInvalid
	}
	if err != nil {
		return Session{}, fmt.Errorf("find session: %w", err)
	}

	session.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return Session{}, fmt.Errorf("parse session expiry: %w", err)
	}

	if !session.ExpiresAt.After(time.Now().UTC()) {
		_, _ = r.db.ExecContext(ctx,
			"DELETE FROM sessions WHERE id_hash = ?", tokenHash)
		return Session{}, ErrSessionInvalid
	}

	return session, nil
}

func (r *Repository) DeleteSession(
	ctx context.Context,
	tokenHash string,
) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM sessions WHERE id_hash = ?", tokenHash)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	return nil
}
