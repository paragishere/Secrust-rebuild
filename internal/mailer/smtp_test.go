package mailer

import (
	"strings"
	"testing"
	"time"
)

func TestSendInvitationRejectsNilMailer(t *testing.T) {
	var m *Mailer

	err := m.SendInvitation(
		"user@example.com",
		"Organization A",
		"ANALYST",
		"https://example.com/invitations/accept?token=abc",
		time.Now().Add(time.Hour),
	)

	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected configuration error, got %v", err)
	}
}

func TestSendInvitationRejectsIncompleteConfiguration(t *testing.T) {
	m := New(SMTPConfig{})

	err := m.SendInvitation(
		"user@example.com",
		"Organization A",
		"ANALYST",
		"https://example.com/invitations/accept?token=abc",
		time.Now().Add(time.Hour),
	)

	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("expected incomplete configuration error, got %v", err)
	}
}

func TestSendInvitationRejectsUnsupportedPort(t *testing.T) {
	m := New(SMTPConfig{
		Host:     "smtp.example.com",
		Port:     "465",
		Username: "sender@example.com",
		Password: "test-password",
		From:     "sender@example.com",
	})

	err := m.SendInvitation(
		"user@example.com",
		"Organization A",
		"ANALYST",
		"https://example.com/invitations/accept?token=abc",
		time.Now().Add(time.Hour),
	)

	if err == nil || !strings.Contains(err.Error(), "587") {
		t.Fatalf("expected STARTTLS port error, got %v", err)
	}
}

func TestSendInvitationRejectsInvalidAddresses(t *testing.T) {
	tests := []struct {
		name string
		from string
		to   string
	}{
		{
			name: "invalid sender",
			from: "not-an-email",
			to:   "user@example.com",
		},
		{
			name: "invalid recipient",
			from: "sender@example.com",
			to:   "not-an-email",
		},
		{
			name: "sender display name",
			from: "Sender <sender@example.com>",
			to:   "user@example.com",
		},
		{
			name: "recipient display name",
			from: "sender@example.com",
			to:   "User <user@example.com>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(SMTPConfig{
				Host:     "smtp.example.com",
				Port:     "587",
				Username: "sender@example.com",
				Password: "test-password",
				From:     tt.from,
			})

			err := m.SendInvitation(
				tt.to,
				"Organization A",
				"ANALYST",
				"https://example.com/invitations/accept?token=abc",
				time.Now().Add(time.Hour),
			)

			if err == nil {
				t.Fatal("expected invalid address to be rejected")
			}
		})
	}
}

func TestSendInvitationRejectsNonHTTPSURL(t *testing.T) {
	m := New(SMTPConfig{
		Host:     "smtp.example.com",
		Port:     "587",
		Username: "sender@example.com",
		Password: "test-password",
		From:     "sender@example.com",
	})

	err := m.SendInvitation(
		"user@example.com",
		"Organization A",
		"ANALYST",
		"http://example.com/invitations/accept?token=abc",
		time.Now().Add(time.Hour),
	)

	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected HTTPS validation error, got %v", err)
	}
}

func TestSendInvitationRejectsMalformedSMTPPort(t *testing.T) {
	m := New(SMTPConfig{
		Host:     "smtp.example.com",
		Port:     "invalid",
		Username: "sender@example.com",
		Password: "test-password",
		From:     "sender@example.com",
	})

	err := m.SendInvitation(
		"user@example.com",
		"Organization A",
		"ANALYST",
		"https://example.com/invitations/accept?token=abc",
		time.Now().Add(time.Hour),
	)

	if err == nil {
		t.Fatal("expected invalid SMTP port to be rejected")
	}
}
