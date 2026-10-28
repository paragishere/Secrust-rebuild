package organization

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/paragishere/secrust/internal/audit"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvitationNotFound = errors.New("invitation not found")
	ErrInvitationExpired  = errors.New("invitation expired")
	ErrInvitationInactive = errors.New("invitation is no longer active")
	ErrInvitationConflict = errors.New("an active invitation or membership already exists")
	ErrInvalidInviteRole  = errors.New("invalid invitation role")
	ErrInvalidInviteEmail = errors.New("invalid invitation email")
)

type Invitation struct {
	ID             string  `json:"id"`
	OrganizationID string  `json:"organization_id"`
	Email          string  `json:"email"`
	Role           string  `json:"role"`
	InvitedBy      string  `json:"invited_by"`
	ExpiresAt      string  `json:"expires_at"`
	AcceptedAt     *string `json:"accepted_at,omitempty"`
	RevokedAt      *string `json:"revoked_at,omitempty"`
	CreatedAt      string  `json:"created_at"`
}

type InvitationRepository struct {
	db *sql.DB
}

func NewInvitationRepository(db *sql.DB) *InvitationRepository {
	return &InvitationRepository{db: db}
}

func validInvitationRole(role string) bool {
	switch strings.ToUpper(strings.TrimSpace(role)) {
	case "MANAGER", "ANALYST", "VIEWER":
		return true
	default:
		return false
	}
}

func newInvitationID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "inv_" + hex.EncodeToString(b), nil
}

// GenerateInvitationToken returns the raw token for email delivery and its
// SHA-256 hash for database storage. Never persist or log the raw token.
func GenerateInvitationToken() (rawToken, tokenHash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate invitation token: %w", err)
	}

	rawToken = hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(rawToken))
	tokenHash = hex.EncodeToString(sum[:])
	return rawToken, tokenHash, nil
}

func hashInvitationToken(rawToken string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(rawToken)))
	return hex.EncodeToString(sum[:])
}

func (r *InvitationRepository) Create(
	ctx context.Context,
	organizationID string,
	email string,
	role string,
	invitedBy string,
	expiresAt time.Time,
) (Invitation, string, error) {
	var invitation Invitation

	organizationID = strings.TrimSpace(organizationID)
	email = strings.ToLower(strings.TrimSpace(email))
	role = strings.ToUpper(strings.TrimSpace(role))
	invitedBy = strings.TrimSpace(invitedBy)

	if organizationID == "" || invitedBy == "" {
		return invitation, "", ErrOrganizationRequired
	}
	if !validInvitationRole(role) {
		return invitation, "", ErrInvalidInviteRole
	}
	if email == "" || !strings.Contains(email, "@") ||
		strings.ContainsAny(email, "\r\n\t ") {
		return invitation, "", ErrInvalidInviteEmail
	}
	if !expiresAt.After(time.Now().UTC()) {
		return invitation, "", ErrInvitationExpired
	}

	id, err := newInvitationID()
	if err != nil {
		return invitation, "", err
	}
	rawToken, tokenHash, err := GenerateInvitationToken()
	if err != nil {
		return invitation, "", err
	}

	now := time.Now().UTC()
	createdAt := now.Format(time.RFC3339Nano)
	expiry := expiresAt.UTC().Format(time.RFC3339Nano)

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return invitation, "", fmt.Errorf("begin invitation transaction: %w", err)
	}
	defer tx.Rollback()

	// The inviter must be a member of this organization.
	var inviterRole string
	err = tx.QueryRowContext(ctx, `
		SELECT role
		FROM organization_users
		WHERE organization_id = ? AND user_id = ?
	`, organizationID, invitedBy).Scan(&inviterRole)
	if errors.Is(err, sql.ErrNoRows) {
		return invitation, "", ErrOrganizationRequired
	}
	if err != nil {
		return invitation, "", fmt.Errorf("verify invitation creator: %w", err)
	}
	if inviterRole != "SUPER_ADMIN" {
		return invitation, "", errors.New("only SUPER_ADMIN can create invitations")
	}

	// An existing account may be invited to another organization, but not
	// added twice to this organization.
	var membershipCount int
	err = tx.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM organization_users ou
		JOIN users u ON u.id = ou.user_id
		WHERE ou.organization_id = ? AND lower(u.email) = lower(?)
	`, organizationID, email).Scan(&membershipCount)
	if err != nil {
		return invitation, "", fmt.Errorf("check existing membership: %w", err)
	}
	if membershipCount > 0 {
		return invitation, "", ErrInvitationConflict
	}

	var activeCount int
	err = tx.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM invitations
		WHERE organization_id = ?
		  AND lower(email) = lower(?)
		  AND accepted_at IS NULL
		  AND revoked_at IS NULL
		  AND expires_at > ?
	`, organizationID, email, createdAt).Scan(&activeCount)
	if err != nil {
		return invitation, "", fmt.Errorf("check active invitations: %w", err)
	}
	if activeCount > 0 {
		return invitation, "", ErrInvitationConflict
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO invitations (
			id, organization_id, email, role, token_hash,
			invited_by, expires_at, accepted_at, revoked_at, created_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)
	`, id, organizationID, email, role, tokenHash,
		invitedBy, expiry, createdAt)
	if err != nil {
		return invitation, "", fmt.Errorf("insert invitation: %w", err)
	}

	err = audit.RecordWithExecutor(ctx, tx, audit.Entry{
		OrganizationID: organizationID,
		UserID:         invitedBy,
		Action:         "INVITATION_CREATED",
		ResourceType:   "invitation",
		ResourceID:     id,
		Metadata: map[string]any{
			"email": email,
			"role":  role,
		},
	})
	if err != nil {
		return invitation, "", fmt.Errorf("audit invitation creation: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return invitation, "", fmt.Errorf("commit invitation: %w", err)
	}

	invitation = Invitation{
		ID:             id,
		OrganizationID: organizationID,
		Email:          email,
		Role:           role,
		InvitedBy:      invitedBy,
		ExpiresAt:      expiry,
		CreatedAt:      createdAt,
	}

	return invitation, rawToken, nil
}

func (r *InvitationRepository) List(
	ctx context.Context,
	organizationID string,
) ([]Invitation, error) {
	organizationID = strings.TrimSpace(organizationID)
	if organizationID == "" {
		return nil, ErrOrganizationRequired
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, organization_id, email, role, invited_by,
		       expires_at, accepted_at, revoked_at, created_at
		FROM invitations
		WHERE organization_id = ?
		ORDER BY created_at DESC
	`, organizationID)
	if err != nil {
		return nil, fmt.Errorf("list invitations: %w", err)
	}
	defer rows.Close()

	items := make([]Invitation, 0)
	for rows.Next() {
		var item Invitation
		if err := rows.Scan(
			&item.ID, &item.OrganizationID, &item.Email, &item.Role,
			&item.InvitedBy, &item.ExpiresAt, &item.AcceptedAt,
			&item.RevokedAt, &item.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan invitation: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate invitations: %w", err)
	}
	return items, nil
}

func (r *InvitationRepository) Revoke(
	ctx context.Context,
	organizationID string,
	invitationID string,
	actorID string,
) error {
	organizationID = strings.TrimSpace(organizationID)
	invitationID = strings.TrimSpace(invitationID)
	actorID = strings.TrimSpace(actorID)

	if organizationID == "" || invitationID == "" || actorID == "" {
		return ErrOrganizationRequired
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin revoke transaction: %w", err)
	}
	defer tx.Rollback()

	var role string
	err = tx.QueryRowContext(ctx, `
		SELECT role
		FROM organization_users
		WHERE organization_id = ? AND user_id = ?
	`, organizationID, actorID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvitationNotFound
	}
	if err != nil {
		return fmt.Errorf("verify revocation actor: %w", err)
	}
	if role != "SUPER_ADMIN" {
		return errors.New("only SUPER_ADMIN can revoke invitations")
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, `
		UPDATE invitations
		SET revoked_at = ?
		WHERE id = ?
		  AND organization_id = ?
		  AND accepted_at IS NULL
		  AND revoked_at IS NULL
		  AND expires_at > ?
	`, now, invitationID, organizationID, now)
	if err != nil {
		return fmt.Errorf("revoke invitation: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check revoked invitation: %w", err)
	}
	if affected == 0 {
		return ErrInvitationNotFound
	}

	if err := audit.RecordWithExecutor(ctx, tx, audit.Entry{
		OrganizationID: organizationID,
		UserID:         actorID,
		Action:         "INVITATION_REVOKED",
		ResourceType:   "invitation",
		ResourceID:     invitationID,
	}); err != nil {
		return fmt.Errorf("audit invitation revocation: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit revocation: %w", err)
	}
	return nil
}

type AcceptInvitationResult struct {
	UserID         string
	OrganizationID string
	Role           string
	Email          string
}

// AcceptExisting atomically verifies an invitation, matches the authenticated
// user's email, adds the organization membership, and records the audit event.
func (r *InvitationRepository) AcceptExisting(
	ctx context.Context,
	rawToken string,
	userID string,
) (AcceptInvitationResult, error) {
	var result AcceptInvitationResult

	rawToken = strings.TrimSpace(rawToken)
	userID = strings.TrimSpace(userID)
	if rawToken == "" || userID == "" {
		return result, ErrInvitationNotFound
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return result, fmt.Errorf("begin acceptance transaction: %w", err)
	}
	defer tx.Rollback()

	var invitationID, orgID, email, role, expiresAt string
	var acceptedAt, revokedAt sql.NullString

	err = tx.QueryRowContext(ctx, `
		SELECT id, organization_id, email, role, expires_at,
		       accepted_at, revoked_at
		FROM invitations
		WHERE token_hash = ?
	`, hashInvitationToken(rawToken)).Scan(
		&invitationID, &orgID, &email, &role, &expiresAt,
		&acceptedAt, &revokedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrInvitationNotFound
	}
	if err != nil {
		return result, fmt.Errorf("find invitation: %w", err)
	}

	if acceptedAt.Valid || revokedAt.Valid {
		return result, ErrInvitationInactive
	}

	expiry, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return result, fmt.Errorf("parse invitation expiry: %w", err)
	}
	if !expiry.After(time.Now().UTC()) {
		return result, ErrInvitationExpired
	}

	var userEmail, status string
	err = tx.QueryRowContext(ctx, `
		SELECT email, status FROM users WHERE id = ?
	`, userID).Scan(&userEmail, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrInvitationNotFound
	}
	if err != nil {
		return result, fmt.Errorf("find accepting user: %w", err)
	}
	if status != "active" || !strings.EqualFold(userEmail, email) {
		return result, ErrInvalidInviteEmail
	}

	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = tx.ExecContext(ctx, `
		INSERT INTO organization_users (
			organization_id, user_id, role, created_at
		) VALUES (?, ?, ?, ?)
	`, orgID, userID, role, createdAt)
	if err != nil {
		return result, fmt.Errorf("add organization membership: %w", err)
	}

	updated, err := tx.ExecContext(ctx, `
		UPDATE invitations
		SET accepted_at = ?
		WHERE id = ?
		  AND accepted_at IS NULL
		  AND revoked_at IS NULL
		  AND expires_at > ?
	`, createdAt, invitationID, createdAt)
	if err != nil {
		return result, fmt.Errorf("mark invitation accepted: %w", err)
	}
	affected, err := updated.RowsAffected()
	if err != nil {
		return result, fmt.Errorf("check invitation acceptance: %w", err)
	}
	if affected != 1 {
		return result, ErrInvitationInactive
	}

	if err := audit.RecordWithExecutor(ctx, tx, audit.Entry{
		OrganizationID: orgID,
		UserID:         userID,
		Action:         "INVITATION_ACCEPTED",
		ResourceType:   "invitation",
		ResourceID:     invitationID,
		Metadata: map[string]any{
			"email": email,
			"role":  role,
		},
	}); err != nil {
		return result, fmt.Errorf("audit invitation acceptance: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return result, fmt.Errorf("commit invitation acceptance: %w", err)
	}

	return AcceptInvitationResult{
		UserID:         userID,
		OrganizationID: orgID,
		Role:           role,
		Email:          email,
	}, nil
}

func (r *InvitationRepository) AcceptNew(
	ctx context.Context,
	rawToken string,
	name string,
	password string,
) (AcceptInvitationResult, error) {
	var result AcceptInvitationResult

	rawToken = strings.TrimSpace(rawToken)
	name = strings.TrimSpace(name)

	if rawToken == "" {
		return result, ErrInvitationNotFound
	}
	if name == "" || len(name) > 100 {
		return result, errors.New("name must be between 1 and 100 characters")
	}
	if len(password) < 12 || len(password) > 72 {
		return result, errors.New("password must be between 12 and 72 bytes")
	}

	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return result, fmt.Errorf("hash account password: %w", err)
	}

	userID, err := newUserID()
	if err != nil {
		return result, err
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return result, fmt.Errorf("begin new-account acceptance: %w", err)
	}
	defer tx.Rollback()

	var invitationID, orgID, email, role, expiresAt string
	var acceptedAt, revokedAt sql.NullString

	err = tx.QueryRowContext(ctx, `
		SELECT id, organization_id, email, role, expires_at,
		       accepted_at, revoked_at
		FROM invitations
		WHERE token_hash = ?
	`, hashInvitationToken(rawToken)).Scan(
		&invitationID, &orgID, &email, &role, &expiresAt,
		&acceptedAt, &revokedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrInvitationNotFound
	}
	if err != nil {
		return result, fmt.Errorf("find invitation: %w", err)
	}

	if acceptedAt.Valid || revokedAt.Valid {
		return result, ErrInvitationInactive
	}

	expiry, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return result, fmt.Errorf("parse invitation expiry: %w", err)
	}
	if !expiry.After(time.Now().UTC()) {
		return result, ErrInvitationExpired
	}

	// Do not create a duplicate account. Existing accounts must use
	// AcceptExisting after authenticating with the invited email.
	var existingUserID string
	err = tx.QueryRowContext(ctx, `
		SELECT id FROM users WHERE email = ? COLLATE NOCASE
	`, email).Scan(&existingUserID)
	if err == nil {
		return result, ErrInvitationConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return result, fmt.Errorf("check existing account: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)

	_, err = tx.ExecContext(ctx, `
		INSERT INTO users (
			id, name, email, password_hash, status, created_at
		) VALUES (?, ?, ?, ?, 'active', ?)
	`, userID, name, email, string(passwordHash), now)
	if err != nil {
		return result, fmt.Errorf("create invited user: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO organization_users (
			organization_id, user_id, role, created_at
		) VALUES (?, ?, ?, ?)
	`, orgID, userID, role, now)
	if err != nil {
		return result, fmt.Errorf("create organization membership: %w", err)
	}

	updated, err := tx.ExecContext(ctx, `
		UPDATE invitations
		SET accepted_at = ?
		WHERE id = ?
		  AND accepted_at IS NULL
		  AND revoked_at IS NULL
		  AND expires_at > ?
	`, now, invitationID, now)
	if err != nil {
		return result, fmt.Errorf("consume invitation: %w", err)
	}

	affected, err := updated.RowsAffected()
	if err != nil {
		return result, fmt.Errorf("check invitation consumption: %w", err)
	}
	if affected != 1 {
		return result, ErrInvitationInactive
	}

	if err := audit.RecordWithExecutor(ctx, tx, audit.Entry{
		OrganizationID: orgID,
		UserID:         userID,
		Action:         "INVITATION_ACCEPTED",
		ResourceType:   "invitation",
		ResourceID:     invitationID,
		Metadata: map[string]any{
			"email": email,
			"role":  role,
			"flow":  "new_account",
		},
	}); err != nil {
		return result, fmt.Errorf("audit new-account acceptance: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return result, fmt.Errorf("commit new-account acceptance: %w", err)
	}

	return AcceptInvitationResult{
		UserID:         userID,
		OrganizationID: orgID,
		Role:           role,
		Email:          email,
	}, nil
}

func newUserID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate user ID: %w", err)
	}
	return "user_" + hex.EncodeToString(b), nil
}

func (r *InvitationRepository) FindByID(
	ctx context.Context,
	organizationID string,
	invitationID string,
) (Invitation, error) {
	var inv Invitation

	err := r.db.QueryRowContext(ctx, `
		SELECT id, organization_id, email, role, invited_by,
		       expires_at, accepted_at, revoked_at, created_at
		FROM invitations
		WHERE id = ? AND organization_id = ?
	`, invitationID, organizationID).Scan(
		&inv.ID,
		&inv.OrganizationID,
		&inv.Email,
		&inv.Role,
		&inv.InvitedBy,
		&inv.ExpiresAt,
		&inv.AcceptedAt,
		&inv.RevokedAt,
		&inv.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Invitation{}, ErrInvitationNotFound
		}
		return Invitation{}, err
	}

	return inv, nil
}
