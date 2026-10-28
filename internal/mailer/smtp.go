package mailer

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

type SMTPConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
}

type Mailer struct {
	config SMTPConfig
}

func New(cfg SMTPConfig) *Mailer {
	return &Mailer{config: cfg}
}

// SendInvitation sends an invitation email over SMTP with mandatory STARTTLS.
func (m *Mailer) SendInvitation(
	to string,
	organization string,
	role string,
	invitationURL string,
	expiresAt time.Time,
) error {
	if m == nil {
		return errors.New("mailer is not configured")
	}

	cfg := m.config
	cfg.Host = strings.TrimSpace(cfg.Host)
	cfg.Port = strings.TrimSpace(cfg.Port)
	cfg.Username = strings.TrimSpace(cfg.Username)
	cfg.From = strings.TrimSpace(cfg.From)

	if cfg.Host == "" || cfg.Port == "" ||
		cfg.Username == "" || cfg.Password == "" || cfg.From == "" {
		return errors.New("SMTP configuration is incomplete")
	}

	port, err := strconv.Atoi(cfg.Port)
	if err != nil || port != 587 {
		return errors.New("SMTP port must be 587 (STARTTLS)")
	}

	from, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return fmt.Errorf("invalid SMTP_FROM address: %w", err)
	}

	recipient, err := mail.ParseAddress(strings.TrimSpace(to))
	if err != nil {
		return fmt.Errorf("invalid recipient address: %w", err)
	}

	if !strings.EqualFold(from.Address, cfg.From) {
		return errors.New("SMTP_FROM must contain a single email address")
	}

	if !strings.EqualFold(recipient.Address, strings.TrimSpace(to)) {
		return errors.New("recipient must contain a single email address")
	}

	if !strings.HasPrefix(invitationURL, "https://") {
		return errors.New("invitation URL must use HTTPS")
	}

	host := strings.TrimSuffix(cfg.Host, ".")
	address := net.JoinHostPort(host, cfg.Port)

	timeout := 15 * time.Second
	dialer := net.Dialer{Timeout: timeout}

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("connect to SMTP server: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("initialize SMTP client: %w", err)
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); !ok {
		return errors.New("SMTP server does not support STARTTLS")
	}

	tlsConfig := &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}

	if err := client.StartTLS(tlsConfig); err != nil {
		return fmt.Errorf("start SMTP TLS: %w", err)
	}

	auth := smtp.PlainAuth("", cfg.Username, cfg.Password, host)
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("SMTP authentication failed")
	}

	subject := "You're invited to join Secrust"
	body := fmt.Sprintf(
		"Hello,\r\n\r\n"+
			"You have been invited to join %s on Secrust.\r\n"+
			"Assigned role: %s\r\n\r\n"+
			"Accept your invitation using this link:\r\n%s\r\n\r\n"+
			"This invitation expires at %s UTC. "+
			"If you were not expecting this email, you can ignore it.\r\n\r\n"+
			"Secrust Security Platform\r\n",
		organization,
		role,
		invitationURL,
		expiresAt.UTC().Format(time.RFC3339),
	)

	// Reject header injection in fields that become part of the message.
	for _, value := range []string{subject, from.Address, recipient.Address} {
		if strings.ContainsAny(value, "\r\n") {
			return errors.New("invalid email header")
		}
	}

	message := []byte(
		"From: " + from.String() + "\r\n" +
			"To: " + recipient.String() + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/plain; charset=UTF-8\r\n" +
			"\r\n" + body,
	)

	if err := client.Mail(from.Address); err != nil {
		return fmt.Errorf("set SMTP sender: %w", err)
	}

	if err := client.Rcpt(recipient.Address); err != nil {
		return fmt.Errorf("set SMTP recipient: %w", err)
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("open SMTP message: %w", err)
	}

	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return fmt.Errorf("write SMTP message: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("finish SMTP message: %w", err)
	}

	if err := client.Quit(); err != nil {
		return fmt.Errorf("close SMTP session: %w", err)
	}

	return nil
}
