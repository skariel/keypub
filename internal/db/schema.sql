-- SSH Keys table (main data store)
CREATE TABLE ssh_keys (
    email TEXT NOT NULL,                   -- Owner's email
    fingerprint TEXT NOT NULL,             -- SSH key fingerprint
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    UNIQUE(email, fingerprint)
);

CREATE INDEX idx_ssh_keys_email ON ssh_keys(email);
CREATE INDEX idx_ssh_keys_fingerprint ON ssh_keys(fingerprint);

-- Email verification codes (no foreign keys as these are pending verifications)
CREATE TABLE verification_codes (
    email TEXT NOT NULL,                   -- Email being verified
    fingerprint TEXT NOT NULL,             -- SSH key fingerprint used for verification
    code TEXT NOT NULL,                    -- Verification code
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    UNIQUE(fingerprint, code),             -- Only one code per fingerprint
    UNIQUE(email, fingerprint)             -- Only one active verification per email-fingerprint pair
);

CREATE INDEX idx_verification_codes_email ON verification_codes(email);
CREATE INDEX idx_verification_codes_code ON verification_codes(code);
CREATE INDEX idx_verification_codes_fingerprint ON verification_codes(fingerprint);

-- Email visibility permissions
CREATE TABLE email_permissions (
    granter_email TEXT NOT NULL,           -- User granting permission
    grantee_email TEXT NOT NULL,           -- User receiving permission
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    UNIQUE(granter_email, grantee_email),  -- Prevent duplicate permissions
    FOREIGN KEY (granter_email) REFERENCES ssh_keys(email)
    ON DELETE CASCADE,
    FOREIGN KEY (grantee_email) REFERENCES ssh_keys(email)
    ON DELETE CASCADE
);

CREATE INDEX idx_email_permissions_granter ON email_permissions(granter_email);
CREATE INDEX idx_email_permissions_grantee ON email_permissions(grantee_email);

-- Admin fingerprints table
CREATE TABLE admin_fingerprints (
    fingerprint TEXT NOT NULL PRIMARY KEY,  -- SSH key fingerprint of admin
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (fingerprint) REFERENCES ssh_keys(fingerprint)
    ON DELETE CASCADE
);

CREATE INDEX idx_admin_fingerprints_fp ON admin_fingerprints(fingerprint);