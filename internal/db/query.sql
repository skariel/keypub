-- name: GetUserEmailsWithFingerprint :many
SELECT email FROM ssh_keys
WHERE fingerprint = ?;

-- name: GetKeyInfosWithEmail :many
SELECT fingerprint, created_at FROM ssh_keys
WHERE email = ?
ORDER BY created_at ASC;

-- name: GetAllowedUsersWithGranterEmail :many
SELECT grantee_email, created_at FROM email_permissions
WHERE granter_email = ?
ORDER BY created_at ASC;

-- name: CountFingerprintWithEmailAndFingerPrint :one
SELECT COUNT(fingerprint) FROM ssh_keys
WHERE email = ? AND fingerprint = ?;

-- name: GetVerificationCodeEmailsWithFingerprintAndCode :many
SELECT email FROM verification_codes
WHERE fingerprint = ? AND code = ?;

-- name: CountFingerprintWithEmail :one
SELECT COUNT(fingerprint) FROM ssh_keys
WHERE email = ?;

-- name: AddVerificationCode :one
INSERT INTO verification_codes (email, fingerprint, code)
VALUES (?, ?, ?)
RETURNING *;

-- name: DeleteVerificationCodeWithFingerprintAndCode :exec
DELETE FROM verification_codes
WHERE fingerprint = ? and code = ?;

-- name: AddSSHKey :one
INSERT INTO ssh_keys (fingerprint, email)
VALUES (?, ?)
RETURNING *;

-- name: DeletePermissionsWithGranterEmail :exec
DELETE FROM email_permissions
WHERE granter_email = ?;

-- name: DeletePermissionsWithGranteeEmail :exec
DELETE FROM email_permissions
WHERE grantee_email = ?;

-- name: DeleteVerificationCodesWithFingerprint :exec
DELETE FROM verification_codes
WHERE fingerprint = ?;

--name DeleteAdminFingerprintsWithFingerprint :exec
DELETE FROM admin_fingerprints
WHERE fingerprint = ?;

--name DeleteSSHKeysWithFingerprint :exec
DELETE FROM ssh_keys
WHERE fingerprint = ?;
