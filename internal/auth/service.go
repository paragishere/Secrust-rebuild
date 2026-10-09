package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	repo            *Repository
	sessionDuration time.Duration
}

func NewService(repo *Repository, sessionDuration time.Duration) *Service {
	return &Service{
		repo:            repo,
		sessionDuration: sessionDuration,
	}
}

type LoginResult struct {
	Token   string
	Session Session
}

func (s *Service) Login(
	ctx context.Context,
	email string,
	password string,
) (LoginResult, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	if email == "" || password == "" || len(password) > 72 {
		return LoginResult{}, ErrInvalidCredentials
	}

	user, err := s.repo.FindUserByEmail(ctx, email)
	if err != nil {
		return LoginResult{}, err
	}

	if user.Status != "active" {
		return LoginResult{}, ErrAccountDisabled
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(user.PasswordHash),
		[]byte(password),
	); err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}

	membership, err := s.repo.FindMembership(ctx, user.ID)
	if err != nil {
		return LoginResult{}, err
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return LoginResult{}, fmt.Errorf("generate session token: %w", err)
	}

	token := hex.EncodeToString(tokenBytes)
	tokenHash := hashToken(token)

	expiresAt := time.Now().UTC().Add(s.sessionDuration)
	if s.sessionDuration <= 0 {
		return LoginResult{}, errors.New("session duration must be positive")
	}

	if err := s.repo.CreateSession(
		ctx,
		tokenHash,
		user.ID,
		membership.OrganizationID,
		expiresAt,
	); err != nil {
		return LoginResult{}, err
	}

	return LoginResult{
		Token: token,
		Session: Session{
			UserID:         user.ID,
			OrganizationID: membership.OrganizationID,
			Role:           membership.Role,
			ExpiresAt:      expiresAt,
		},
	}, nil
}

func (s *Service) ValidateSession(
	ctx context.Context,
	token string,
) (Session, error) {
	if len(token) != 64 {
		return Session{}, ErrSessionInvalid
	}

	if _, err := hex.DecodeString(token); err != nil {
		return Session{}, ErrSessionInvalid
	}

	return s.repo.FindSession(ctx, hashToken(token))
}

func (s *Service) Logout(ctx context.Context, token string) error {
	if len(token) != 64 {
		return nil
	}

	if _, err := hex.DecodeString(token); err != nil {
		return nil
	}

	return s.repo.DeleteSession(ctx, hashToken(token))
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
