package main

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	cmd "keypub/internal/command"
	"keypub/internal/db/.gen/table"
	"keypub/internal/mail"

	. "github.com/go-jet/jet/v2/sqlite"
	_ "github.com/mattn/go-sqlite3"
)

func registerCommandAccount(registry *cmd.CommandRegistry) *cmd.CommandRegistry {

	registry.Register(cmd.Command{
		Name:        "whoami",
		Usage:       "whoami",
		Description: "Show your fingerprint, registered email, registration date, and list of users allowed to see your email.",
		Category:    "Account",
		Handler: func(ctx *cmd.CommandContext) (info string, err error) {
			return handleWhoami(ctx.DB, ctx.Fingerprint)
		},
	})

	registry.Register(cmd.Command{
		Name:        "register",
		Usage:       "register <email>",
		Description: "Register your SSH key with the given email address. You will receive a confirmation code via email.",
		Category:    "Account",
		Handler: func(ctx *cmd.CommandContext) (info string, err error) {
			return handleRegister(ctx.DB, ctx.MailSender, ctx.Args[1], ctx.Fingerprint)
		},
	})
	registry.Register(cmd.Command{
		Name:        "confirm",
		Usage:       "confirm <email>",
		Description: "Confirm your email address using the code you received. This completes your registration.",
		Category:    "Account",
		Handler: func(ctx *cmd.CommandContext) (info string, err error) {
			return handleConfirm(ctx.DB, ctx.Fingerprint, ctx.Args[1])
		},
	})
	registry.Register(cmd.Command{
		Name:        "unregister",
		Usage:       "unregister",
		Description: "Remove your registration and all associated permissions. This cannot be undone.",
		Category:    "Account",
		Handler: func(ctx *cmd.CommandContext) (info string, err error) {
			return handleUnregister(ctx.DB, ctx.Fingerprint)
		},
	})
	return registry
}

func handleWhoami(db *sql.DB, fingerprint string) (string, error) {
	// PRDONE!
	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		return "", fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			log.Printf("failed to rollback transaction: %v", err)
		}
	}()

	// First get the emails for the current fingerprint
	var userEmails []string
	err = SELECT(table.SSHKeys.Email).
		FROM(table.SSHKeys).
		WHERE(table.SSHKeys.Fingerprint.EQ(String(fingerprint))).
		Query(tx, &userEmails)

	if err != nil {
		return "", fmt.Errorf("failed to query user email: %w", err)
	}
	if len(userEmails) == 0 {
		return fmt.Sprintf("You are not registered. Your fingerprint is %s", fingerprint), nil
	}
	type KeyInfo struct {
		Fingerprint string
		CreatedAt   int32
	}
	var result strings.Builder
	for _, userEmail := range userEmails {
		// Get all fingerprints and their registration times for this email
		var keyInfos []KeyInfo
		err = SELECT(
			table.SSHKeys.Fingerprint.AS("key_info.fingerprint"),
			table.SSHKeys.CreatedAt.AS("key_info.created_at"),
		).FROM(
			table.SSHKeys,
		).WHERE(
			table.SSHKeys.Email.EQ(String(userEmail)),
		).ORDER_BY(
			table.SSHKeys.CreatedAt.ASC(),
		).Query(tx, &keyInfos)

		if err != nil {
			return "", fmt.Errorf("failed to query key info: %w", err)
		}

		// Get allowed users and their grant times
		var allowedUsers []struct {
			Email     string
			CreatedAt int32
		}
		err = SELECT(
			table.EmailPermissions.GranteeEmail.AS("email"),
			table.EmailPermissions.CreatedAt.AS("created_at"),
		).FROM(
			table.EmailPermissions,
		).WHERE(
			table.EmailPermissions.GranterEmail.EQ(String(userEmail)),
		).ORDER_BY(
			table.EmailPermissions.CreatedAt.ASC(),
		).Query(tx, &allowedUsers)

		if err != nil {
			return "", fmt.Errorf("failed to query allowed users: %w", err)
		}

		// Format user info
		result.WriteString(fmt.Sprintf("Email: %s\n\n", userEmail))
		result.WriteString("Registered Keys:\n")

		for _, key := range keyInfos {
			createdTime := time.Unix(int64(key.CreatedAt), 0)
			if key.Fingerprint == fingerprint {
				result.WriteString(fmt.Sprintf("* %s (current) - registered: %s\n",
					key.Fingerprint,
					createdTime.Format(time.RFC3339)))
			} else {
				result.WriteString(fmt.Sprintf("  %s - registered: %s\n",
					key.Fingerprint,
					createdTime.Format(time.RFC3339)))
			}
		}

		// Format allowed users
		if len(allowedUsers) == 0 {
			result.WriteString("\nNo users are allowed to see your email.")
		} else {
			result.WriteString("\nAllowed users:\n")
			for _, user := range allowedUsers {
				grantTime := time.Unix(int64(user.CreatedAt), 0)
				result.WriteString(fmt.Sprintf("- %s (granted: %s)\n",
					user.Email,
					grantTime.Format(time.RFC3339)))
			}
		}
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return "", fmt.Errorf("failed to commit transaction: %w", err)
	}

	return result.String(), nil
}

func generateVerificationCode() string {
	// TODO: this is not really uniform random
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 6

	// Create a byte slice to store the result
	result := make([]byte, length)

	// Use crypto/rand for secure random number generation
	for i := range result {
		// Read a random byte and map it to the charset
		b := make([]byte, 1)
		_, _ = rand.Read(b)
		result[i] = charset[b[0]%byte(len(charset))]
	}

	return string(result)
}

func handleRegister(db *sql.DB, mail_sender *mail.MailSender, to_email string, fingerprint string) (info string, err error) {
	// PRDONE!
	// Start transaction
	err = mail.ValidateEmail(to_email)
	if err != nil {
		return "", fmt.Errorf("mail address fails validation")
	}
	tx, err := db.Begin()
	if err != nil {
		return "", fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			log.Printf("failed to rollback transaction: %v", err)
		}
	}()

	// Generate verification code, we'll make sure the tuple (fingerprint, code) is unique so adding it actualy succeeds
	verificationCode := generateVerificationCode()
	for {
		var exists []int64
		err := table.VerificationCodes.SELECT(
			COUNT(table.VerificationCodes.Fingerprint),
		).WHERE(
			table.VerificationCodes.Fingerprint.EQ(String(fingerprint)).
				AND(table.VerificationCodes.Code.EQ(String(verificationCode))),
		).Query(db, &exists)
		if err != nil {
			return "", fmt.Errorf("error while querying verifications table for fingerprint and code existence: %w", err)
		}
		if len(exists) != 1 {
			return "", fmt.Errorf("failed to count fingerpint and code tuple on verifications table")
		}
		if exists[0] == 0 {
			break
		} else if exists[0] == 1 {
			// collision, should be rare. lets regenetare
			verificationCode = generateVerificationCode()
			continue
		}
		// more than 1 fingerprint, code tuple should not happen in this table due to the sql constraint:
		return "", fmt.Errorf("more than a single fingerprint, code tuple in verification table defies uniquness constraint")
	}

	// Insert verification code
	insertStmt := table.VerificationCodes.INSERT(
		table.VerificationCodes.Email,
		table.VerificationCodes.Fingerprint,
		table.VerificationCodes.Code,
	).VALUES(
		to_email,
		fingerprint,
		verificationCode,
	)
	_, err = insertStmt.Exec(tx)
	if err != nil {
		return "", fmt.Errorf("failed to insert verification code: %w", err)
	}

	err = mail_sender.SendConfirmation(to_email, verificationCode, fingerprint)
	if err != nil {
		return "", fmt.Errorf("Could not send confirmation mail: %s", err)
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return "", fmt.Errorf("failed to commit transaction: %w", err)
	}

	return "Success: Confirmation mail sent", nil
}

func handleConfirm(db *sql.DB, fingerprint string, code string) (info string, err error) {
	// PRDONE!
	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			log.Printf("failed to rollback transaction: %v", err)
		}
	}()

	// Get the verification record
	var emails []string
	err = SELECT(table.VerificationCodes.Email).
		FROM(table.VerificationCodes).
		WHERE(
			AND(
				table.VerificationCodes.Fingerprint.EQ(String(fingerprint)),
				table.VerificationCodes.Code.EQ(String(code)),
			),
		).
		Query(tx, &emails)

	if err != nil {
		return "", fmt.Errorf("could not find verification request for fingerprint and code: %s", err)
	}

	if len(emails) > 1 {
		// this should not happen due to uniqueness consrtain in schema and also the way that codes are assigned for verification
		return "", fmt.Errorf("too many matching verifications found: %d", len(emails))
	}

	if len(emails) == 0 {
		return "", fmt.Errorf("could not find verification request for fingerprint and code")
	}

	email := emails[0]

	// Delete the verification record
	_, err = table.VerificationCodes.DELETE().
		WHERE(
			AND(
				table.VerificationCodes.Fingerprint.EQ(String(fingerprint)),
				table.VerificationCodes.Code.EQ(String(code)),
			),
		).
		Exec(tx)

	if err != nil {
		return "", fmt.Errorf("could not delete verification: %s", err)
	}

	// Create the SSH key entry
	_, err = table.SSHKeys.INSERT(
		table.SSHKeys.Fingerprint,
		table.SSHKeys.Email,
	).
		VALUES(
			fingerprint,
			email,
		).
		Exec(tx)

	if err != nil {
		return "", fmt.Errorf("failed to register: %w", err)
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		return "", fmt.Errorf("failed to commit transaction: %w", err)
	}

	return fmt.Sprintf("Success: email %s is now associated with fingerprint %s", email, fingerprint), nil
}

func handleUnregister(db *sql.DB, fingerprint string) (info string, err error) {
	// PRDONE!
	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		return "", fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			log.Printf("failed to rollback transaction: %v", err)
		}
	}()

	// Delete the specific SSH key registration
	_, err = table.SSHKeys.DELETE().
		WHERE(table.SSHKeys.Fingerprint.EQ(String(fingerprint))).
		Exec(tx)
	if err != nil {
		return "", fmt.Errorf("failed to delete registration: %w", err)
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return "", fmt.Errorf("failed to commit transaction: %w", err)
	}

	return "Success: Your registration and all related permissions have been removed", nil
}
