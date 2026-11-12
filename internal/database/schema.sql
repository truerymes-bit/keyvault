CREATE TABLE providers (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX providers_name_nocase ON providers (name COLLATE NOCASE);

CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL,
    provider_id INTEGER NOT NULL REFERENCES providers(id) ON DELETE RESTRICT,
    label TEXT NOT NULL DEFAULT '',
    encrypted_key BLOB NOT NULL,
    nonce BLOB NOT NULL,
    fingerprint BLOB NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX api_keys_email_provider_fingerprint ON api_keys (email, provider_id, fingerprint);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
