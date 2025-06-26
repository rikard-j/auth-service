CREATE TABLE clients (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  namespace VARCHAR(32) NOT NULL,
  name VARCHAR(191) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (namespace)
);

CREATE TABLE users (
  id   BIGINT  NOT NULL AUTO_INCREMENT PRIMARY KEY,
  uuid VARCHAR(36) NOT NULL,
  email VARCHAR(320)    NOT NULL,
  password VARCHAR(191) NOT NULL,
  UNIQUE (email),
  UNIQUE (uuid)
);

CREATE TABLE sessions (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  session_id BINARY(16) NOT NULL,
  user_id BIGINT,
  auth_code VARCHAR(255) NOT NULL,
  client_id BIGINT NOT NULL,
  pkce_challenge TEXT NOT NULL,
  pkce_challenge_method TEXT NOT NULL,
  state TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (client_id) REFERENCES clients(id),
  UNIQUE(session_id),
  UNIQUE(auth_code)
);
