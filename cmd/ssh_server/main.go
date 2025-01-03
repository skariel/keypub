package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	cmd "keypub/internal/command"
	"keypub/internal/config"
	"keypub/internal/mail"
	rl "keypub/internal/ratelimit"

	_ "github.com/mattn/go-sqlite3"

	db_utils "keypub/internal/db"
)

func main() {
	// Load configuration
	result, err := config.LoadFromFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		config.PrintUsage()
		os.Exit(1)
	}

	cfg := result.Config
	log.Printf("Starting server with %s", result.Source)

	// initialize rate limiter
	ratelimit := rl.NewRateLimiter(cfg.RateLimit.Limit, cfg.RateLimit.Duration, cfg.RateLimit.Strict)
	defer ratelimit.Stop()

	// initialize server
	hostKey, err := loadHostKey(cfg.Server.HostKey, cfg.Server.HostKeyPassphrase)
	if err != nil {
		log.Fatal(err)
	}

	server := ssh.Server{
		Addr:        fmt.Sprintf(":%d", cfg.Server.Port),
		HostSigners: []ssh.Signer{hostKey},
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			return true
		},
	}

	// open DB
	db, err := db_utils.NewDB(cfg.Database.Path)
	if err != nil {
		log.Fatalf("Cannot open db file: %s", err)
	}
	defer db.Close()

	// regular interval DB cleaner (currently only for verification codes)
	verification_cleaner := db_utils.NewVerificationCleaner(db, cfg.Verification.Duration)
	defer verification_cleaner.Close()

	// initialize mail sender
	var mail_sender mail.MailSender
	switch cfg.Email.EmailService {
	case "resend":
		mail_sender, err = mail.NewResendMailSender(cfg.Email.Resend.ResendKeyPath, cfg.Email.FromEmail, cfg.Email.FromName)
		if err != nil {
			log.Fatalf("Could not initialize ResendMailSender: %s", err)
		}
	case "smtp":
		mail_sender = mail.NewSTMPMailSender(
			cfg.Email.SMTP.Host,
			cfg.Email.SMTP.Port,
			cfg.Email.SMTP.Username,
			cfg.Email.SMTP.Password,
			cfg.Email.SMTP.Secure,
			cfg.Email.FromEmail,
			cfg.Email.FromName,
		)
	default:
		log.Fatalf("Invalid email_serivce option")
		return
	}

	// Only initialize backup if enabled
	if cfg.Backup.Enabled {
		bm, err := initializeBackup(cfg, db)
		if err != nil {
			log.Fatalf("could not create the backup manager: %s", err)
		}
		bm.Start()
		defer bm.Stop()
	}

	// Initialize command registry
	cmdRegistry := cmd.NewCommandRegistry()
	registerCommandInfo(cmdRegistry)
	registerCommandAccount(cmdRegistry)
	registerCommandRegistration(cmdRegistry)
	registerCommandAdmin(cmdRegistry)
	registerCommandLookup(cmdRegistry)

	// Handle SSH sessions
	server.Handle(func(s ssh.Session) {
		fingerprint := gossh.FingerprintSHA256(s.PublicKey())

		// Rate limiting check
		rl_res := ratelimit.Check(fingerprint)
		if !rl_res.Allowed {
			_, _ = io.WriteString(s, "Error: Rate-limited\n")
			return
		}

		// Create command context
		ctx := &cmd.CommandContext{
			DB:          db,
			Args:        s.Command(),
			Fingerprint: fingerprint,
			MailSender:  mail_sender,
			Server:      &server,
		}

		// Execute command
		if info, err := cmdRegistry.Execute(ctx); err != nil {
			_, _ = io.WriteString(s, fmt.Sprintf("Error: %s\n", err))
		} else {
			_, _ = io.WriteString(s, fmt.Sprintf("%s\n", info))
		}
	})

	log.Printf("Starting SSH server on port %d...", cfg.Server.Port)
	log.Fatal(server.ListenAndServe())
}

func initializeBackup(cfg *config.Config, db *sql.DB) (*db_utils.BackupManager, error) {
	s3access, err := os.ReadFile(cfg.Backup.S3AccessPath)
	if err != nil {
		return nil, fmt.Errorf("cannot load s3 access key: %v", err)
	}
	s3secret, err := os.ReadFile(cfg.Backup.S3SecretPath)
	if err != nil {
		return nil, fmt.Errorf("cannot load s3 secret: %v", err)
	}
	s3endpoint, err := os.ReadFile(cfg.Backup.S3EndpointPath)
	if err != nil {
		return nil, fmt.Errorf("cannot load s3 endpoint: %v", err)
	}

	return db_utils.NewBackupManager(db_utils.BackupConfig{
		DB: db,
		S3Creds: db_utils.S3Credentials{
			Region:          cfg.Backup.S3Region,
			AccessKeyID:     strings.TrimSpace(string(s3access)),
			SecretAccessKey: strings.TrimSpace(string(s3secret)),
			Endpoint:        strings.TrimSpace(string(s3endpoint)),
		},
		BucketName:     cfg.Backup.BucketName,
		BackupDelta:    cfg.Backup.Delta,
		RetentionCount: cfg.Backup.RetentionCount,
		TempDir:        cfg.Backup.TempDir,
		BackupLabel:    cfg.Backup.Label,
	})
}
