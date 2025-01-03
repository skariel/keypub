package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Config struct {
	Server struct {
		Port              int    `json:"port"`
		HostKey           string `json:"host_key_path"`
		HostKeyPassphrase string `json:"host_key_passphrase"`
	} `json:"server"`

	Database struct {
		Path string `json:"path"`
	} `json:"database"`

	RateLimit struct {
		Limit    float64       `json:"limit"`
		Duration time.Duration `json:"duration"`
		Strict   bool          `json:"strict"`
	} `json:"rate_limit"`

	Verification struct {
		Duration time.Duration `json:"duration"`
	} `json:"verification"`

	Email struct {
		EmailService string `json:"email_service"`
		FromEmail    string `json:"from_email"`
		FromName     string `json:"from_name"`
		Resend       struct {
			ResendKeyPath string `json:"resend_key_path"`
		} `json:"resend"`
		SMTP struct {
			Host     string `json:"host"`
			Port     int    `json:"port"`
			Username string `json:"username"`
			Password string `json:"password"`
			Secure   bool   `json:"secure"`
		} `json:"smtp"`
	} `json:"email"`

	Backup struct {
		Enabled        bool          `json:"enabled"`
		S3AccessPath   string        `json:"s3_access_path"`
		S3SecretPath   string        `json:"s3_secret_path"`
		S3EndpointPath string        `json:"s3_endpoint_path"`
		S3Region       string        `json:"s3_region"`
		BucketName     string        `json:"bucket_name"`
		Delta          time.Duration `json:"delta"`
		RetentionCount int           `json:"retention_count"`
		TempDir        string        `json:"temp_dir"`
		Label          string        `json:"label"`
	} `json:"backup"`
}

// DefaultConfig returns the default production configuration
func NewConfig() *Config {
	config := &Config{}

	// Server defaults
	config.Server.Port = 22
	config.Server.HostKey = "/home/ubuntu/.keys/.host"
	config.Server.HostKeyPassphrase = ""

	// Database defaults
	config.Database.Path = "/home/ubuntu/data/keysdb.sqlite3"

	// Rate limit defaults
	config.RateLimit.Limit = 600
	config.RateLimit.Duration = 10 * time.Hour
	config.RateLimit.Strict = false

	// Verification defaults
	config.Verification.Duration = 1 * time.Hour

	// Email defaults
	config.Email.EmailService = "resend"
	config.Email.Resend.ResendKeyPath = "/home/ubuntu/.keys/.resend"
	config.Email.FromEmail = "confirmations@keypub.sh"
	config.Email.FromName = "keypub.sh"

	// Backup defaults
	config.Backup.Enabled = true
	config.Backup.S3AccessPath = "/home/ubuntu/.keys/.s3access"
	config.Backup.S3SecretPath = "/home/ubuntu/.keys/.s3secret"
	config.Backup.S3EndpointPath = "/home/ubuntu/.keys/.s3endpoint"
	config.Backup.S3Region = "eu-central"
	config.Backup.BucketName = "keypub-db-backup"
	config.Backup.Delta = 5 * time.Hour
	config.Backup.RetentionCount = 100
	config.Backup.TempDir = "/tmp"
	config.Backup.Label = "keypub_db_backup"

	return config
}

// TestConfig returns a configuration suitable for testing
func NewTestConfig() *Config {
	config := &Config{}

	// Server test settings
	config.Server.Port = 2288
	config.Server.HostKey = "/home/ubuntu/.keys/.host"
	config.Server.HostKeyPassphrase = ""

	// Database test settings
	config.Database.Path = "/home/ubuntu/data_test/keysdb.sqlite3"

	// Rate limit test settings
	config.RateLimit.Limit = 1000
	config.RateLimit.Duration = 1 * time.Hour
	config.RateLimit.Strict = false

	// Verification test settings
	config.Verification.Duration = 5 * time.Minute

	// Email test settings
	config.Email.EmailService = "resend"
	config.Email.Resend.ResendKeyPath = "/home/ubuntu/.keys/.resend"
	config.Email.FromEmail = "test-confirmations@keypub.sh"
	config.Email.FromName = "keypub.sh-test"

	// Backup disabled for testing
	config.Backup.Enabled = false

	return config
}

// LoadConfig loads configuration from a JSON file
func (config *Config) LoadConfig(path string) error {
	file, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("error reading config file: %v", err)
	}

	if err := json.Unmarshal(file, &config); err != nil {
		return fmt.Errorf("error parsing config file: %v", err)
	}

	return nil
}
