package mail

import (
	"context"
)

type MailSender interface {
	Send(ctx context.Context, to []string, subject, html string) error
	SendConfirmation(ctx context.Context, to, confirmationNumber, keyFingerprint string) error
}

const confirmationMailTemplate = `
<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
	<h2>Welcome to KeyPub.sh!</h2>
	<p>Thank you for registering. You are confirming a key with fingerprint:</p>
	<div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
		<p style="font-family: monospace; font-size: 16px; margin: 0;">%s...</p>
	</div>
	<p>To complete your registration, please use the confirmation number below:</p>
	<div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
		<p style="font-size: 18px; margin: 0;">Your confirmation number: <strong>%s</strong></p>
	</div>
	<p>Run the following command:</p>
	<pre style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto;">ssh keypub.sh confirm %s</pre>
	<p style="color: #666; margin-top: 20px; font-size: 14px;">
		If you didn't request this registration, please ignore this email.
	</p>
</div>
`
