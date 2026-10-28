package organization

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeInvitationMailer struct {
	err   error
	calls int
}

func (f *fakeInvitationMailer) SendInvitation(
	to string,
	organization string,
	role string,
	invitationURL string,
	expiresAt time.Time,
) error {
	f.calls++

	if !strings.HasPrefix(invitationURL, "https://") {
		return errors.New("invitation URL must use HTTPS")
	}

	return f.err
}

func TestCreateAndSendRevokesInvitationWhenDeliveryFails(t *testing.T) {
	db, ctx := setupInvitationTestDB(t)
	repo := NewInvitationRepository(db)

	fakeMailer := &fakeInvitationMailer{
		err: errors.New("simulated SMTP failure"),
	}

	service := NewInvitationService(
		repo,
		fakeMailer,
		"https://secrust.example.com",
		72*time.Hour,
	)

	_, err := service.CreateAndSend(
		ctx,
		"org-a",
		"invitee@example.com",
		"ANALYST",
		"admin-a",
	)
	if !errors.Is(err, ErrInvitationDeliveryFailed) {
		t.Fatalf("expected delivery failure, got %v", err)
	}

	if fakeMailer.calls != 1 {
		t.Fatalf("expected one mail attempt, got %d", fakeMailer.calls)
	}

	var revokedAt string
	err = db.QueryRowContext(ctx, `
		SELECT revoked_at FROM invitations
		WHERE organization_id = 'org-a'
		  AND email = 'invitee@example.com'
	`).Scan(&revokedAt)
	if err != nil {
		t.Fatalf("read revoked invitation: %v", err)
	}
	if revokedAt == "" {
		t.Fatal("expected failed-delivery invitation to be revoked")
	}
}

func TestCreateAndSendRejectsInvalidBaseURL(t *testing.T) {
	db, _ := setupInvitationTestDB(t)
	repo := NewInvitationRepository(db)

	service := NewInvitationService(
		repo,
		&fakeInvitationMailer{},
		"http://secrust.example.com",
		72*time.Hour,
	)

	_, err := service.CreateAndSend(
		context.Background(),
		"org-a",
		"invitee@example.com",
		"ANALYST",
		"admin-a",
	)
	if err == nil {
		t.Fatal("expected HTTP base URL to be rejected")
	}
}

func TestCreateAndSendReportsRevocationFailure(t *testing.T) {
	db, ctx := setupInvitationTestDB(t)
	repo := NewInvitationRepository(db)

	_, err := db.ExecContext(ctx, `
		CREATE TRIGGER reject_invitation_revocation
		BEFORE UPDATE OF revoked_at ON invitations
		WHEN NEW.revoked_at IS NOT NULL
		BEGIN
			SELECT RAISE(ABORT, 'forced revocation failure');
		END;
	`)
	if err != nil {
		t.Fatalf("create test trigger: %v", err)
	}

	fakeMailer := &fakeInvitationMailer{
		err: errors.New("simulated SMTP failure"),
	}
	service := NewInvitationService(
		repo,
		fakeMailer,
		"https://secrust.example.com",
		72*time.Hour,
	)

	_, err = service.CreateAndSend(
		ctx,
		"org-a",
		"invitee@example.com",
		"ANALYST",
		"admin-a",
	)
	if !errors.Is(err, ErrInvitationDeliveryFailed) {
		t.Fatalf("expected delivery failure to remain discoverable, got %v", err)
	}

	if !strings.Contains(err.Error(), "revocation also failed") {
		t.Fatalf("expected revocation failure to be reported, got %v", err)
	}

	var revokedAt *string
	err = db.QueryRowContext(ctx, `
		SELECT revoked_at FROM invitations
		WHERE organization_id = 'org-a'
		  AND email = 'invitee@example.com'
	`).Scan(&revokedAt)
	if err != nil {
		t.Fatalf("read invitation: %v", err)
	}
	if revokedAt != nil {
		t.Fatal("expected trigger to prevent revocation")
	}
}

func TestResendRevokesOldInvitationAndCreatesNewOne(t *testing.T) {
	db, ctx := setupInvitationTestDB(t)
	repo := NewInvitationRepository(db)
	mailer := &fakeInvitationMailer{}

	service := NewInvitationService(
		repo,
		mailer,
		"https://secrust.example.com",
		72*time.Hour,
	)

	old, oldToken, err := repo.Create(
		ctx,
		"org-a",
		"resend-user@example.com",
		"ANALYST",
		"admin-a",
		time.Now().UTC().Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("create original invitation: %v", err)
	}

	fresh, err := service.Resend(ctx, "org-a", old.ID, "admin-a")
	if err != nil {
		t.Fatalf("resend invitation: %v", err)
	}

	if fresh.ID == old.ID {
		t.Fatal("expected resend to create a new invitation ID")
	}
	if fresh.Email != old.Email || fresh.Role != old.Role {
		t.Fatalf("unexpected resent invitation: %+v", fresh)
	}
	if mailer.calls != 1 {
		t.Fatalf("expected one email attempt, got %d", mailer.calls)
	}

	var oldRevokedAt *string
	err = db.QueryRowContext(ctx, `
		SELECT revoked_at FROM invitations WHERE id = ?
	`, old.ID).Scan(&oldRevokedAt)
	if err != nil {
		t.Fatalf("read original invitation: %v", err)
	}
	if oldRevokedAt == nil || *oldRevokedAt == "" {
		t.Fatal("expected original invitation to be revoked")
	}

	_, err = repo.AcceptNew(
		ctx,
		oldToken,
		"Resend User",
		"correct-horse-battery-2026",
	)
	if !errors.Is(err, ErrInvitationInactive) {
		t.Fatalf("expected old token to be inactive, got %v", err)
	}
}

func TestResendDeliveryFailureLeavesOldInvitationRevoked(t *testing.T) {
	db, ctx := setupInvitationTestDB(t)
	repo := NewInvitationRepository(db)

	mailer := &fakeInvitationMailer{
		err: errors.New("simulated SMTP failure"),
	}
	service := NewInvitationService(
		repo,
		mailer,
		"https://secrust.example.com",
		72*time.Hour,
	)

	old, _, err := repo.Create(
		ctx,
		"org-a",
		"resend-failure@example.com",
		"ANALYST",
		"admin-a",
		time.Now().UTC().Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("create original invitation: %v", err)
	}

	_, err = service.Resend(ctx, "org-a", old.ID, "admin-a")
	if !errors.Is(err, ErrInvitationDeliveryFailed) {
		t.Fatalf("expected delivery failure, got %v", err)
	}

	var oldRevokedAt *string
	err = db.QueryRowContext(ctx, `
		SELECT revoked_at FROM invitations WHERE id = ?
	`, old.ID).Scan(&oldRevokedAt)
	if err != nil {
		t.Fatalf("read original invitation: %v", err)
	}
	if oldRevokedAt == nil || *oldRevokedAt == "" {
		t.Fatal("expected old invitation to remain revoked after delivery failure")
	}

	var activeCount int
	err = db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM invitations
		WHERE organization_id = 'org-a'
		  AND email = 'resend-failure@example.com'
		  AND accepted_at IS NULL
		  AND revoked_at IS NULL
	`).Scan(&activeCount)
	if err != nil {
		t.Fatalf("count active invitations: %v", err)
	}
	if activeCount != 0 {
		t.Fatalf("expected no active invitation after failed delivery, got %d", activeCount)
	}
}
