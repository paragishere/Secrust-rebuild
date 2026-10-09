package setup

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var ErrAlreadyInitialized = errors.New("initial setup is already complete")

type Service struct {
	db *sql.DB
}

func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

type InitialSetup struct {
	OrganizationName string
	AdminName        string
	Email            string
	Password         string
}

func (s *Service) IsInitialized(ctx context.Context) (bool, error) {
	var count int
	err := s.db.QueryRowContext(
		ctx,
		"SELECT COUNT(*) FROM organizations",
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check initial setup: %w", err)
	}

	return count > 0, nil
}

func (s *Service) CreateInitialSetup(
	ctx context.Context,
	input InitialSetup,
) error {
	input.OrganizationName = strings.TrimSpace(input.OrganizationName)
	input.AdminName = strings.TrimSpace(input.AdminName)
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))

	if input.OrganizationName == "" ||
		input.AdminName == "" ||
		input.Email == "" {
		return errors.New("organization name, admin name and email are required")
	}

	if len(input.Password) < 12 || len(input.Password) > 72 {
		return errors.New("password must be between 12 and 72 bytes")
	}

	if len(input.OrganizationName) > 120 ||
		len(input.AdminName) > 120 ||
		len(input.Email) > 254 {
		return errors.New("one or more fields exceed the allowed length")
	}

	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte(input.Password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return fmt.Errorf("hash initial admin password: %w", err)
	}

	orgID, err := newID()
	if err != nil {
		return err
	}

	userID, err := newID()
	if err != nil {
		return err
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin setup transaction: %w", err)
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRowContext(
		ctx,
		"SELECT COUNT(*) FROM organizations",
	).Scan(&count); err != nil {
		return fmt.Errorf("check setup state: %w", err)
	}

	if count != 0 {
		return ErrAlreadyInitialized
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO organizations (id, name, created_at)
		VALUES (?, ?, ?)
	`, orgID, input.OrganizationName, now); err != nil {
		return fmt.Errorf("create organization: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO users (
			id, name, email, password_hash, status, created_at
		)
		VALUES (?, ?, ?, ?, 'active', ?)
	`, userID, input.AdminName, input.Email, string(passwordHash), now); err != nil {
		return fmt.Errorf("create initial administrator: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO organization_users (
			organization_id, user_id, role, created_at
		)
		VALUES (?, ?, 'SUPER_ADMIN', ?)
	`, orgID, userID, now); err != nil {
		return fmt.Errorf("assign administrator role: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit initial setup: %w", err)
	}

	return nil
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate identifier: %w", err)
	}

	return hex.EncodeToString(b), nil
}
