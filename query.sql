-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = ?;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = ?;

-- name: CreateUser :exec
INSERT INTO users (email, password, uuid) VALUES (?, ?, ?);

-- name: GetClientByNamespace :one
SELECT * FROM clients WHERE namespace = ?;

-- name: CreateAuthorizeSession :exec
INSERT INTO sessions (auth_code, client_id, pkce_challenge, pkce_challenge_method, state, redirect_uri, expires_at, session_id)
VALUES (?, ?, ?, ?, ?, ?, NOW() + INTERVAL 10 MINUTE, UUID_TO_BIN(UUID()));

-- name: GetSessionByAuthCode :one
SELECT s.id, s.session_id, s.user_id, s.auth_code, s.client_id, s.pkce_challenge, s.pkce_challenge_method, s.state, s.redirect_uri, s.created_at, s.expires_at, u.email as user_email
FROM sessions s
LEFT JOIN users u ON s.user_id = u.id
WHERE s.auth_code = ?;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE auth_code = ?;

-- name: CreateUserSession :execresult
INSERT INTO sessions (session_id, user_id, expires_at)
VALUES (UUID_TO_BIN(UUID()), ?, NOW() + INTERVAL 24 HOUR);

-- name: GetUserSession :one
SELECT s.id, s.user_id, s.expires_at, u.email as user_email
FROM sessions s
JOIN users u ON s.user_id = u.id
WHERE s.session_id = UUID_TO_BIN(?);

-- name: DeleteUserSession :exec
DELETE FROM sessions WHERE session_id = UUID_TO_BIN(?);

-- name: GetUserByAuthCode :one
SELECT u.id, u.email, u.password 
FROM users u
JOIN sessions s ON u.id = s.user_id
WHERE s.auth_code = ?;

-- name: GetClientByID :one
SELECT id, namespace, name, created_at FROM clients WHERE id = ?;

-- name: GetUserSessionByUserID :one
SELECT s.id, BIN_TO_UUID(s.session_id) as session_id, s.user_id, s.expires_at, u.email as user_email
FROM sessions s
JOIN users u ON s.user_id = u.id
WHERE s.user_id = ?
ORDER BY s.created_at DESC LIMIT 1;

-- name: UpdateUserSession :exec
UPDATE sessions 
SET user_id = ?
WHERE auth_code = ?;