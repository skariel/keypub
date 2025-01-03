package mail

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
)

type SMTPMailSender struct {
	host      string
	port      int
	username  string
	password  string
	secure    bool
	fromEmail string
	fromName  string
}

func NewSTMPMailSender(host string, port int, username, password string, secure bool, fromEmail, fromName string) MailSender {
	return &SMTPMailSender{
		host:      host,
		port:      port,
		username:  username,
		password:  password,
		secure:    secure,
		fromEmail: fromEmail,
		fromName:  fromName,
	}
}

func (m *SMTPMailSender) Send(ctx context.Context, to []string, subject, html string) error {
	addr := fmt.Sprintf("%s:%d", m.host, m.port)
	auth := smtp.PlainAuth("", m.username, m.password, m.host)
	toHeader := strings.Join(to, ", ")
	from := fmt.Sprintf("%s <%s>", m.fromName, m.fromEmail)
	message := fmt.Sprintf(
		"From: %s\nTo: %s\nSubject: %s\nMIME-Version: 1.0\nContent-Type: text/html; charset=\"UTF-8\"\n\n%s",
		from, toHeader, subject, html,
	)

	if m.secure {
		conn, err := tls.Dial("tcp", addr, &tls.Config{
			ServerName: addr,
		})
		if err != nil {
			return err
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, addr)
		if err != nil {
			return err
		}
		defer client.Quit() //nolint

		if err = client.Auth(auth); err != nil {
			return err
		}

		if err = client.Mail(m.fromEmail); err != nil {
			return err
		}
		for _, recipient := range to {
			if err = client.Rcpt(recipient); err != nil {
				return err
			}
		}

		writer, err := client.Data()
		if err != nil {
			return err
		}
		_, err = writer.Write([]byte(message))
		if err != nil {
			return err
		}
		err = writer.Close()
		if err != nil {
			return err
		}
	} else {
		err := smtp.SendMail(addr, auth, m.fromEmail, to, []byte(message))
		if err != nil {
			return err
		}
	}
	return nil
}
func (m *SMTPMailSender) SendConfirmation(ctx context.Context, to, confirmationNumber, keyFingerprint string) error {
	to_list := []string{to}
	subject := fmt.Sprintf("Complete KeyPub.sh Registration for Key %s...", keyFingerprint)
	htmlContent := fmt.Sprintf(confirmationMailTemplate, keyFingerprint, confirmationNumber, confirmationNumber)

	err := m.Send(ctx, to_list, subject, htmlContent)
	if err != nil {
		return fmt.Errorf("failed to send confirmation email: %w", err)
	}

	return nil
}
