package mail

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/resend/resend-go/v2"
)

// ResendMailSender handles email operations for KeyPub.sh via Resend API
type ResendMailSender struct {
	client    *resend.Client
	fromEmail string
	fromName  string
}

// NewResendMailSender creates a new ResendMailSender instance
// keyPath is the path to the file containing the Resend API key
func NewResendMailSender(keyPath string, fromEmail string, fromName string) (MailSender, error) {
	content, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("cannot load resend api key: %w", err)
	}

	apiKey := strings.TrimSpace(string(content))
	apiKey = strings.ReplaceAll(apiKey, "\n", " ")
	apiKey = strings.ReplaceAll(apiKey, "\r", "")

	return &ResendMailSender{
		client:    resend.NewClient(apiKey),
		fromEmail: fromEmail,
		fromName:  fromName,
	}, nil
}

func (m *ResendMailSender) Send(ctx context.Context, to []string, subject, html string) error {
	fromField := fmt.Sprintf("%s <%s>", m.fromName, m.fromEmail)

	params := &resend.SendEmailRequest{
		From:    fromField,
		To:      to,
		Subject: subject,
		Html:    html,
	}
	_, err := m.client.Emails.Send(params)
	return err
}

// SendConfirmation sends a confirmation email with the provided confirmation number
func (m *ResendMailSender) SendConfirmation(ctx context.Context, to, confirmationNumber, keyFingerprint string) error {
	to_list := []string{to}
	subject := fmt.Sprintf("Complete KeyPub.sh Registration for Key %s...", keyFingerprint)
	htmlContent := fmt.Sprintf(confirmationMailTemplate, keyFingerprint, confirmationNumber, confirmationNumber)

	err := m.Send(ctx, to_list, subject, htmlContent)
	if err != nil {
		return fmt.Errorf("failed to send confirmation email: %w", err)
	}

	return nil
}
