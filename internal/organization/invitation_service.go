package organization

import (
	"context"
	"errors"
	"fmt"
	"log"
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

// NewInvitationService preserves the original constructor signature.
//
// For backward compatibility, this constructor uses production-safe URL
// validation: HTTPS is required. Existing tests and callers can continue
// using this constructor without being changed.
func NewInvitationService(
	repo *InvitationRepository,
	mailer InvitationMailer,
	appBaseURL string,
	ttl time.Duration,
) *InvitationService {
	return NewInvitationServiceWithEnvironment(
		repo,
		mailer,
		appBaseURL,
		ttl,
		"production",
	)
}

// NewInvitationServiceWithEnvironment configures invitation URL validation
// according to the application's environment.
//
// HTTP is permitted only for localhost/127.0.0.1 in development.
// HTTPS remains mandatory for all other hosts and environments.
func NewInvitationServiceWithEnvironment(
	repo *InvitationRepository,
	mailer InvitationMailer,
	appBaseURL string,
	ttl time.Duration,
	environment string,
) *InvitationService {
	environment = strings.TrimSpace(environment)

	allowLocalHTTP := strings.EqualFold(environment, "development")

	validatedURL, err := validateAppBaseURL(appBaseURL, allowLocalHTTP)

	return &InvitationService{
		repo:       repo,
		mailer:     mailer,
		appBaseURL: validatedURL,
		ttl:        ttl,
		configErr:  err,
	}
}

// validateAppBaseURL validates the public base URL used in invitation links.
//
// HTTPS is always accepted when the URL is otherwise valid.
// HTTP is accepted only when allowLocalHTTP is true and the hostname is
// localhost or 127.0.0.1. This exception is intended for local development.
func validateAppBaseURL(value string, allowLocalHTTP bool) (string, error) {
	value = strings.TrimSpace(value)

	u, err := url.Parse(value)
	if err != nil ||
		u == nil ||
		u.Hostname() == "" ||
		u.User != nil ||
		u.RawQuery != "" ||
		u.Fragment != "" {
		return "", errors.New(
			"APP_BASE_URL must be an absolute URL without credentials, query, or fragment",
		)
	}

	isHTTPS := strings.EqualFold(u.Scheme, "https")

	isLocalHTTP := allowLocalHTTP &&
		strings.EqualFold(u.Scheme, "http") &&
		(strings.EqualFold(u.Hostname(), "localhost") ||
			strings.EqualFold(u.Hostname(), "127.0.0.1"))

	if !isHTTPS && !isLocalHTTP {
		return "", errors.New(
			"APP_BASE_URL must use HTTPS, except localhost HTTP in development",
		)
	}

	// Reject malformed request-URI values before storing the base URL.
	if _, err := url.ParseRequestURI(value); err != nil {
		return "", errors.New("APP_BASE_URL is invalid")
	}

	// Remove trailing slashes so invitation paths are constructed consistently.
	return strings.TrimRight(value, "/"), nil
}

// validateInvitationEmail normalizes the email address before storing or
// sending an invitation.
func validateInvitationEmail(value string) (string, error) {
	value = strings.TrimSpace(value)

	address, err := mail.ParseAddress(value)
	if err != nil || !strings.EqualFold(address.Address, value) {
		return "", ErrInvalidInviteEmail
	}

	return strings.ToLower(value), nil
}

// validateConfig checks the service dependencies and configuration before
// creating or resending an invitation.
func (s *InvitationService) validateConfig(requireMailer bool) error {
	if s == nil || s.repo == nil {
		return errors.New("invitation service is not configured")
	}

	if s.configErr != nil || s.appBaseURL == "" {
		// Keep the public-facing error generic; the detailed validation error
		// remains available internally through configErr.
		return errors.New(
			"APP_BASE_URL must be a valid HTTPS URL, or localhost HTTP in development",
		)
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

	// Create stores the invitation and returns the raw token separately.
	// The raw token must never be returned directly by the API.
	invitation, rawToken, err := s.repo.Create(
		ctx,
		organizationID,
		email,
		role,
		actorID,
		expiresAt,
	)
	if err != nil {
		return empty, err
	}

	// The raw token is only emailed; it is never returned by this API.
	invitationURL := s.appBaseURL +
		"/invitations/accept?token=" +
		url.QueryEscape(rawToken)

	// Load the organization name for the invitation email.
	var organizationName string
	err = s.repo.db.QueryRowContext(ctx, `
		SELECT name FROM organizations WHERE id = ?
	`, organizationID).Scan(&organizationName)
	if err != nil {
		return empty, s.revokeAfterDeliveryFailure(
			ctx,
			organizationID,
			invitation.ID,
			actorID,
			errors.New("unable to prepare invitation email"),
		)
	}

	// Send the invitation. If delivery fails, revoke the invitation so that
	// an undelivered token cannot remain active.
	if err := s.mailer.SendInvitation(
		email,
		organizationName,
		invitation.Role,
		invitationURL,
		expiresAt,
	); err != nil {
		// Log the underlying error for local debugging.
		// Never log the invitation token, SMTP password, or credentials.
		log.Printf("invitation email delivery failed: %v", err)

		return empty, s.revokeAfterDeliveryFailure(
			ctx,
			organizationID,
			invitation.ID,
			actorID,
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
		return fmt.Errorf(
			"%w: delivery failed and invitation revocation also failed",
			errors.Join(cause, err),
		)
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

	// Support the timestamp formats that may be returned by the database.
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
	if err := s.repo.Revoke(
		ctx,
		organizationID,
		invitationID,
		actorID,
	); err != nil {
		return Invitation{}, err
	}

	// Create a new invitation with a fresh token and expiry.
	return s.CreateAndSend(
		ctx,
		organizationID,
		old.Email,
		old.Role,
		actorID,
	)
}
