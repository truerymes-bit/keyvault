# KeyVault

A lightweight, self-hosted web application for managing API keys across multiple
email accounts and providers. Encrypts keys at rest with AES-256-GCM (derived from
a master password via Argon2id), stores everything in a local SQLite database,
and lets you import your existing key collection in bulk.

**Primary purpose:** consolidate API keys scattered across text files into an
organized, searchable, encrypted vault — no cloud storage, no external services
required for normal operation.

---

## Features

- **Single master password** — set a master password on first run; unlocks with a
  session cookie + CSRF token. Password never stored, logged, or transmitted.
- **Encrypted at rest** — every API key is encrypted with AES-256-GCM using a
  subkey derived from the master password (HKDF-SHA256). The master password
  never leaves your machine.
- **Multiple providers & keys** — manage Google, GitHub, Stripe, etc. and multiple
  keys per email/provider combination.
- **Bulk import** — paste an existing key file (TXT or CSV); the parser
  auto-detects provider headings, handles ambiguous lines, and lets you review
  before committing.
- **Search & reveal** — search across email, provider, and label; reveal a key
  for copy (or delete it).
- **Dashboard** — live counts (total keys, providers, emails, recent keys).
- **Local-first** — runs as a normal user on your machine; no systemd service,
  no background daemon, no internet needed for normal operation.
- **Docker support** — reproducible deployment with a persistent `data/` volume.

## Quick start (Linux)

### 1. Install

```bash
# 1. Clone the repository
git clone https://github.com/<your-org>/keyvault.git
cd keyvault

# 2. Build the binary
go build -o bin/keyvault ./cmd/keyvault

# 3. Run
./bin/keyvault
```

The server listens on `http://127.0.0.1:8080` by default. Open that URL in your
browser.

### 2. First-run setup

1. The browser shows "Create an account" overlay.
2. Enter a master password (min 8 characters) and confirm.
3. The vault is created and you're automatically logged in.

### 3. Using the CLI

```bash
./bin/keyvault -addr 127.0.0.1:9090 -data-dir ./mydata
# → listens on 127.0.0.1:9090, database at ./mydata/keyvault.db
```

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `-addr` | `KEYVAULT_ADDR` | `127.0.0.1:8080` | Listen address |
| `-data-dir` | `KEYVAULT_DATA_DIR` | `data` | Directory for `keyvault.db` |
| `-session-timeout` | `KEYVAULT_SESSION_TIMEOUT` | `15m` | Idle session timeout |

## Docker

### Build & run

```bash
docker compose up -d
```

The app is available at `http://127.0.0.1:8080`.

### Ports

- The container **binds `0.0.0.0:8080` internally** (hardcoded in the image).
- The compose file **publishes only `127.0.0.1:8080:8080`** — other containers
  on the Docker network **cannot** reach the app directly. This is a security
  decision: the app is meant to be accessed through a reverse proxy in front of
  the container.

### Volumes

- `data/` — the SQLite database (`keyvault.db`) and any backups. Mount this
  volume for persistent storage across container recreates.

```yaml
volumes:
  data:
    driver: local
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KEYVAULT_ADDR` | `0.0.0.0:8080` | Listen address inside the container |
| `KEYVAULT_DATA_DIR` | `/data` | Directory for the database file |
| `KEYVAULT_SESSION_TIMEOUT` | `15m` | Idle session timeout |

## Configuration reference

| Setting | Flag | Env var | Default | Note |
|---------|------|---------|---------|------|
| Listen address | `-addr` | `KEYVAULT_ADDR` | `127.0.0.1:8080` | Local-only by default |
| Database directory | `-data-dir` | `KEYVAULT_DATA_DIR` | `data` | Created `0700` |
| Session idle timeout | `-session-timeout` | `KEYVAULT_SESSION_TIMEOUT` | `15m` | Any activity refreshes the timeout |

## Security

- **Master password** — never stored, logged, or transmitted. It is used only to
  derive an encryption subkey (HKDF-SHA256) and a verifier (sealed with the
  encryption subkey). The verifier is stored in the database to verify the
  password on unlock.
- **Key encryption** — AES-256-GCM, nonce per key, Argon2id parameters stored in
  the database.
- **CSRF** — all non-GET `/api/` routes require a CSRF token (from
  `GET /api/auth/status`) in the `X-CSRF-Token` header.
- **Session** — HTTP-only, SameSite=Strict cookie with a 15-minute idle timeout.
- **Network** — app binds to `127.0.0.1` by default (no network). Do not expose
  it publicly without a reverse proxy and explicit configuration.

## Backup & restore

- **Local backup** — in the Settings page, use the Backup/Restore feature. The
  backup is an encrypted envelope (magic bytes + version + Argon2id params +
  nonce + AES-GCM ciphertext) created from a `VACUUM INTO` snapshot of the
  database. Restoring on a fresh machine only needs the master password.
- **Google Drive** — optional cloud backup (out of scope for this session;
  T6.3–T6.5 deferred).

## Development

```bash
# Run the server
go run ./cmd/keyvault

# Run tests
go test ./...

# Format and vet
gofmt -w .
go vet ./...

# Build
go build -o bin/keyvault ./cmd/keyvault

# Run the frontend tests (node)
node --check web/js/app.js
```

## Project structure

```
cmd/keyvault/main.go       Server entry point (flags, routes, startup)
internal/database/         SQLite connection, migrations
internal/security/         Auth, sessions, CSRF, key encryption
internal/backup/           Backup envelope (AES-256-GCM + VACUUM INTO)
internal/handlers/         REST API handlers
internal/importer/         TXT/CSV import parser
web/                        Embedded frontend (go:embed)
  css/style.css
  js/app.js                 Frontend application
  index.html
```

## License

[UNLICENSED](LICENSE) — do not copy or distribute.
