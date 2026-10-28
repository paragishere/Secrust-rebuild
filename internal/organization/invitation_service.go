package organization

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"time"
)

var ErrInvitationDeliveryFailed = errors.New("invitation email delivery failed")

type InvitationMailer interface {
	SendInvitation(
		to string,
		organization string,
		role string,
		invitationURL string,
		expiresAt time.Time,
	) error
}

type InvitationService struct {
	repo       *InvitationRepository
	mailer     InvitationMailer
	appBaseURL string
	ttl        time.Duration
	configErr  error
}

func NewInvitationService(
	repo *InvitationRepository,
	mailer InvitationMailer,
	appBaseURL string,
	ttl time.Duration,
) *InvitationService {
	validatedURL, err := validateAppBaseURL(appBaseURL)

	return &InvitationService{
		repo:       repo,
		mailer:     mailer,
		appBaseURL: validatedURL,
		ttl:        ttl,
		configErr:  err,
	}
}

func validateAppBaseURL(value string) (string, error) {
	value = strings.TrimSpace(value)
	u, err := url.Parse(value)
	if err != nil ||
		u == nil ||
		!strings.EqualFold(u.Scheme, "https") ||
		u.Hostname() == "" ||
		u.User != nil ||
		u.RawQuery != "" ||
		u.Fragment != "" {
		return "", errors.New("APP_BASE_URL must be an absolute HTTPS URL without credentials, query, or fragment")
	}

	if _, err := url.ParseRequestURI(value); err != nil {
		return "", errors.New("APP_BASE_URL is invalid")
	}

	return strings.TrimRight(value, "/"), nil
}

func validateInvitationEmail(value string) (string, error) {
	value = strings.TrimSpace(value)

	address, err := mail.ParseAddress(value)
	if err != nil || !strings.EqualFold(address.Address, value) {
		return "", ErrInvalidInviteEmail
	}

	return strings.ToLower(value), nil
}

func (s *InvitationService) validateConfig(requireMailer bool) error {
	if s == nil || s.repo == nil {
		return errors.New("invitation service is not configured")
	}
	if s.configErr != nil || s.appBaseURL == "" {
		return errors.New("APP_BASE_URL must be a valid absolute HTTPS URL")
	}
	if requireMailer && s.mailer == nil {
		return errors.New("invitation mailer is not configured")
	}
	if s.ttl <= 0 {
		return errors.New("invitation expiry must be positive")
	}
	return nil
}

func (s *InvitationService) CreateAndSend(
	ctx context.Context,
	organizationID string,
	email string,
	role string,
	actorID string,
) (Invitation, error) {
	var empty Invitation

	if err := s.validateConfig(true); err != nil {
		return empty, err
	}

	email, err := validateInvitationEmail(email)
	if err != nil {
		return empty, err
	}

	expiresAt := time.Now().UTC().Add(s.ttl)

	invitation, rawToken, err := s.repo.Create(
		ctx, organizationID, email, role, actorID, expiresAt,
	)
	if err != nil {
		return empty, err
	}

	// The raw token is only emailed; it is never returned by this API.
	invitationURL := s.appBaseURL + "/invitations/accept?token=" + url.QueryEscape(rawToken)

	var organizationName string
	err = s.repo.db.QueryRowContext(ctx, `
		SELECT name FROM organizations WHERE id = ?
	`, organizationID).Scan(&organizationName)
	if err != nil {
		return empty, s.revokeAfterDeliveryFailure(
			ctx, organizationID, invitation.ID, actorID,
			errors.New("unable to prepare invitation email"),
		)
	}

	if err := s.mailer.SendInvitation(
		email,
		organizationName,
		invitation.Role,
		invitationURL,
		expiresAt,
	); err != nil {
		return empty, s.revokeAfterDeliveryFailure(
			ctx, organizationID, invitation.ID, actorID,
			ErrInvitationDeliveryFailed,
		)
	}

	return invitation, nil
}

// revokeAfterDeliveryFailure prevents a failed delivery from being reported as
// safely handled if the compensating revocation itself fails.
func (s *InvitationService) revokeAfterDeliveryFailure(
	ctx context.Context,
	organizationID string,
	invitationID string,
	actorID string,
	cause error,
) error {
	if err := s.repo.Revoke(ctx, organizationID, invitationID, actorID); err != nil {
		return fmt.Errorf("%w: delivery failed and invitation revocation also failed", errors.Join(cause, err))
	}
	return cause
}

func (s *InvitationService) List(
	ctx context.Context,
	organizationID string,
) ([]Invitation, error) {
	if s == nil || s.repo == nil {
		return nil, errors.New("invitation service is not configured")
	}
	return s.repo.List(ctx, organizationID)
}

func (s *InvitationService) Revoke(
	ctx context.Context,
	organizationID string,
	invitationID string,
	actorID string,
) error {
	if s == nil || s.repo == nil {
		return errors.New("invitation service is not configured")
	}
	return s.repo.Revoke(ctx, organizationID, invitationID, actorID)
}

func (s *InvitationService) AcceptExisting(
	ctx context.Context,
	token string,
	userID string,
) (AcceptInvitationResult, error) {
	if s == nil || s.repo == nil {
		return AcceptInvitationResult{}, errors.New("invitation service is not configured")
	}
	return s.repo.AcceptExisting(ctx, token, userID)
}

func (s *InvitationService) AcceptNew(
	ctx context.Context,
	token string,
	name string,
	password string,
) (AcceptInvitationResult, error) {
	if s == nil || s.repo == nil {
		return AcceptInvitationResult{}, errors.New("invitation service is not configured")
	}
	return s.repo.AcceptNew(ctx, token, name, password)
}

func (s *InvitationService) Resend(
	ctx context.Context,
	organizationID string,
	invitationID string,
	actorID string,
) (Invitation, error) {
	if err := s.validateConfig(true); err != nil {
		return Invitation{}, err
	}

	old, err := s.repo.FindByID(ctx, organizationID, invitationID)
	if err != nil {
		return Invitation{}, err
	}

	now := time.Now().UTC()
	if old.AcceptedAt != nil || old.RevokedAt != nil {
		return Invitation{}, ErrInvitationInactive
	}

	expiry, err := time.Parse(time.RFC3339Nano, old.ExpiresAt)
	if err != nil {
		expiry, err = time.Parse(time.RFC3339, old.ExpiresAt)
	}
	if err != nil {
		expiry, err = time.Parse("2006-01-02 15:04:05", old.ExpiresAt)
	}
	if err != nil {
		return Invitation{}, fmt.Errorf("parse invitation expiry: %w", err)
	}

	if !expiry.After(now) {
		return Invitation{}, ErrInvitationExpired
	}

	// Revoke first: the old token must not remain usable after resend.
	// If the new delivery fails, the old invitation remains revoked.
	if err := s.repo.Revoke(ctx, organizationID, invitationID, actorID); err != nil {
		return Invitation{}, err
	}

	return s.CreateAndSend(ctx, organizationID, old.Email, old.Role, actorID)
}
