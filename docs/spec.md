# KeyVault — Application Development Specification

## 1. Project Overview

Build a lightweight, self-hosted web application for managing API keys belonging to multiple email accounts and API providers.

The application is intended for personal, non-corporate use. It should be simple to operate, locally hosted, independent of external services during normal operation, and capable of optionally backing up its database to Google Drive.

The primary purpose is to consolidate API keys currently scattered across text files into an organized, searchable, encrypted database.

The application must support:
- Multiple email addresses.
- Multiple API providers per email address.
- Multiple API keys per provider and email combination.
- Provider-specific setup notes.
- Bulk import from existing text files.
- Individual key management.
- Optional Google Drive backup and restoration.

Project name: **KeyVault**

## 2. Technology Stack

Use the following technologies:

**Backend**
- Go (Golang).
- Standard Go HTTP server.
- REST-style JSON API.
- SQLite database.
- SQLite driver: modernc.org/sqlite (pure Go implementation).

**Frontend**
- HTML5.
- CSS3.
- Vanilla JavaScript.
- Fetch API for backend communication.
- No frontend framework required.
- No external CDN dependencies.

**Security**
- AES-256-GCM encryption for API keys.
- Argon2id for deriving an encryption key from the user's master password.
- Secure session handling.
- Local-only default network binding.

**Deployment**
- Native execution on Linux.
- Docker support.
- Persistent database storage.
- Configurable listening address and port.

## 3. Database Architecture

Use SQLite with foreign key enforcement enabled.

### Table: providers

| Column | Type | Description |
|---|---|---|
| id | INTEGER PRIMARY KEY | Unique provider identifier |
| name | TEXT | Provider name |
| notes | TEXT | Provider-specific setup instructions |
| created_at | DATETIME | Creation timestamp |
| updated_at | DATETIME | Modification timestamp |

Provider names should be unique using case-insensitive comparison.

Examples:
- Gemini
- OpenRouter
- ElevenLabs
- Anthropic
- OpenAI

### Table: api_keys

| Column | Type | Description |
|---|---|---|
| id | INTEGER PRIMARY KEY | Unique key identifier |
| email | TEXT | Associated email address |
| provider_id | INTEGER | Foreign key to providers |
| label | TEXT | Optional user-defined description |
| encrypted_key | BLOB | Encrypted API key |
| nonce | BLOB | AES-GCM nonce |
| created_at | DATETIME | Creation timestamp |
| updated_at | DATETIME | Modification timestamp |

Requirements:
- Multiple keys may belong to the same email/provider combination.
- The same email may use multiple providers.
- The same provider may be associated with multiple email addresses.
- Do not impose a uniqueness constraint on email/provider combinations.
- Deleting a provider should require confirmation and handle its associated keys safely.

### Table: settings

Store application configuration, including:
- Google OAuth client configuration.
- Google Drive connection status.
- Backup preferences.
- Backup timestamps.
- Database schema version.

Never store plaintext API keys in this table.

## 4. Application Interface

Use the previously generated KeyVault dashboard mockup as the visual reference.

Design requirements:
- Dark desktop interface.
- Practical modern dashboard aesthetic.
- Compact sidebar navigation.
- Blue-gray color palette.
- Clear typography.
- Rounded panels.
- Minimal unnecessary decoration.
- Responsive layout for smaller screens.

### Sidebar

Navigation items:
- Dashboard
- API Keys
- Providers
- Import
- Settings

### Dashboard

Display:
- Total API keys.
- Total providers.
- Total email accounts.
- Recently added keys.
- Recently modified records.

### API Keys View

Organize records by email address.

Each email address should be expandable to display its associated providers and keys.

Each key record should show:
- Provider name.
- Email address.
- Masked API key.
- Date added.
- Last modified.
- Reveal button.
- Copy button.
- Edit button.
- Delete button.

Provide search across:
- Email addresses.
- Provider names.
- Key labels.

Never expose plaintext keys in ordinary database queries or list responses.

### Providers View

Display all registered providers.

Selecting a provider should display:
- Provider name.
- Number of associated keys.
- Associated email addresses.
- Setup notes.
- Edit notes button.

Provider notes must be shared across all keys belonging to that provider.

### Add API Key

Provide a form with:

1. Email address.
2. Provider.
3. API key.
4. Optional description.

Allow selecting an existing provider or creating a new provider.

Validate email formatting and reject empty API keys.

### Provider Notes Editor

Each provider has an independent notes editor.

Notes should support multiline plain text.

Examples:

ElevenLabs:

Model ID: eleven_v4

Voice ID: PHAPuAHARHKi7JvhoY4v

OpenRouter:

ENDPOINT:
Authorization: Bearer $OPENROUTER_API_KEY

Content-Type: application/json

HTTP-Referer: optional — your site URL

X-Title: optional — your site name

Model: openrouter/free

Notes must persist independently of individual API key records.

## 5. Bulk Import System

This is a major application feature and should be implemented early.

The user already has a large text file containing API keys organized into provider sections.

The import system must support:
- TXT files.
- CSV files.
- Pasting raw text into an import editor.

### Example Input

Gemini API Key

user@example.com AQ.Ab8RN6KwaaGNVNX...
user@example.com AQ.Ab8RN6KwaaGNVNX...
user@example.com AQ.Ab8RN6KwaaGNVNX...

OpenRouter

user@example.com sk-or-v1-dd8a026...
user@example.com sk-or-v1-dd8a026...

ElevenLabs

user@example.com sk_227b6f7c...

Additional provider sections may appear anywhere throughout the document.

### Parsing Strategy

Use a state-based parser supported by case-insensitive regular expressions.

Do not attempt to identify providers solely by examining API key prefixes.

The parser should work as follows:

1. Read the input line by line.
2. Identify provider headings.
3. Set the current provider when a recognized heading is encountered.
4. Associate subsequent email/key pairs with that provider.
5. Continue until another provider heading is encountered.
6. Ignore blank lines.
7. Preserve unrecognized lines for manual review.

Use case-insensitive matching for provider headings and email detection.

The parser must support:
- Provider headings with optional punctuation.
- Email addresses containing standard valid characters.
- API keys containing punctuation and special characters.
- Multiple records under the same provider.
- Duplicate keys.
- Blank lines between records.
- Variable whitespace.
- Provider names containing spaces.

### Provider Detection

Maintain a provider recognition mechanism.

Initially include:
- Gemini
- Google AI
- Google Gemini
- OpenRouter
- ElevenLabs
- OpenAI
- Anthropic
- Claude

Allow users to add custom provider names.

Important parsing rule:

A line containing only a recognized provider name should be treated as a section heading.

An email/key line should be treated as a record belonging to the currently active provider.

Do not silently assign records when the provider context is unknown.

If an unrecognized heading or ambiguous line appears, flag it for review.

### Import Preview

Never import records immediately after parsing.

Display a preview containing:

| Email | Provider | API Key | Status |
|---|---|---|---|
| user@example.com | Gemini | ******** | Valid |
| user@example.com | OpenRouter | ******** | Valid |
| user@example.com | ElevenLabs | ******** | Valid |

The user must be able to:
- Edit the email address.
- Change the provider.
- Edit the API key.
- Remove individual records.
- Assign a provider to unmatched records.
- Review duplicates.
- Select all valid records.
- Import selected records.

### Duplicate Detection

Check for existing records using a comparison of:
- Email address.
- Provider.
- API key fingerprint.

Use a keyed HMAC-SHA256 fingerprint rather than storing a plaintext hash of the API key.

Provide duplicate handling options:
- Skip duplicates.
- Import duplicates.
- Review individually.

Do not discard duplicate records automatically.

### Import Completion

Display:
- Number of records imported.
- Number skipped.
- Number requiring attention.
- Number of duplicates detected.

All imported API keys must be encrypted before database insertion.

## 6. Security and Encryption

API keys are sensitive credentials.

Implement the following protections:

### Encryption

Use AES-256-GCM.

Each key must have:
- Unique nonce.
- Authenticated encryption.
- Encrypted database storage.

Never store API keys in plaintext.

### Master Password

On initial setup:
1. Ask the user to establish a master password.
2. Generate a random salt.
3. Derive a 256-bit encryption key using Argon2id.
4. Keep the derived encryption key in application memory while unlocked.
5. Require unlocking after application restart.

Never store the master password.

The encryption salt and Argon2id parameters must be stored separately from encrypted key records.

Provide a secure recovery warning: losing the master password without a separate encryption-key backup means encrypted API keys cannot be recovered.

### Application Access

For the initial version:
- Bind to 127.0.0.1 by default.
- Require an unlocked session to access API keys.
- Use HTTP-only session cookies.
- Apply SameSite cookie protections.
- Protect state-changing requests against CSRF.
- Never log API keys or decrypted credentials.
- Avoid placing API keys in URL parameters.

Do not expose the application to a public network without an explicitly configured secure deployment mode.

## 7. Google Drive Integration

Google Drive is an optional backup service.

It must not be required to use KeyVault.

Create a separate Settings section for Google Drive.

### OAuth Setup

Provide:
- Google OAuth Client ID.
- Google OAuth Client Secret.
- Connect Google Drive button.
- Connection status.
- Disconnect button.

Use OAuth 2.0 authorization code flow with PKCE where supported.

Request the narrowest practical Drive permissions, preferably app-specific file access.

Store refresh tokens securely.

### Backup

Support:
- Manual backup.
- Manual restoration.
- Optional scheduled backups.
- Backup history.
- Last successful backup timestamp.

Backups must contain the SQLite database in an encrypted backup format.

Do not upload an unencrypted database containing API keys.

Use an encrypted backup envelope with version information, integrity verification, and the necessary recovery information.

Google Drive must never receive plaintext API keys.

### Restore

Before restoration:
- Verify backup integrity.
- Verify encryption compatibility.
- Display backup date.
- Ask for confirmation.
- Preserve the current database as a rollback copy.

## 8. Backend API

Implement REST-style endpoints.

### API Keys

GET /api/keys

GET /api/keys/{id}

POST /api/keys

PUT /api/keys/{id}

DELETE /api/keys/{id}

POST /api/keys/{id}/reveal

POST /api/keys/{id}/copy

### Providers

GET /api/providers

GET /api/providers/{id}

POST /api/providers

PUT /api/providers/{id}

DELETE /api/providers/{id}

PUT /api/providers/{id}/notes

### Import

POST /api/import/parse

POST /api/import/validate

POST /api/import/commit

### Settings

GET /api/settings

PUT /api/settings

### Google Drive

GET /api/google/status

GET /api/google/connect

GET /api/google/callback

POST /api/google/disconnect

POST /api/google/backup

POST /api/google/restore

All endpoints must enforce application unlock and appropriate authorization.

## 9. Project Directory Structure

Use this organization:

keyvault/
├── cmd/
│   └── keyvault/
│       └── main.go
├── internal/
│   ├── database/
│   │   ├── database.go
│   │   ├── migrations.go
│   │   └── schema.sql
│   ├── encryption/
│   │   ├── encryption.go
│   │   └── password.go
│   ├── handlers/
│   │   ├── keys.go
│   │   ├── providers.go
│   │   ├── imports.go
│   │   ├── settings.go
│   │   └── google.go
│   ├── importer/
│   │   ├── parser.go
│   │   ├── patterns.go
│   │   └── validator.go
│   ├── backup/
│   │   └── backup.go
│   ├── google/
│   │   └── oauth.go
│   └── security/
│       ├── sessions.go
│       └── middleware.go
├── web/
│   ├── index.html
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   ├── app.js
│   │   ├── keys.js
│   │   ├── providers.js
│   │   ├── importer.js
│   │   └── settings.js
│   └── assets/
├── data/
├── config/
├── Dockerfile
├── docker-compose.yml
├── go.mod
├── .gitignore
└── README.md

## 10. Development Sequence

Implement in the following order.

### Phase 1 — Foundation
- Initialize Go project.
- Configure dependencies.
- Establish directory structure.
- Create SQLite connection.
- Create database migrations.
- Implement HTTP server.
- Serve static HTML.
- Verify local startup.

Deliverable: Running application with initialized database.

### Phase 2 — Encryption and Authentication
- Implement Argon2id password derivation.
- Implement AES-256-GCM encryption/decryption.
- Implement initial password setup.
- Implement unlock/lock functionality.
- Implement session management.
- Verify encrypted database records.

Deliverable: Secure local application access.

### Phase 3 — Database and Provider Management
- Implement provider CRUD.
- Implement API key CRUD.
- Implement provider notes.
- Implement database relationships.
- Implement validation and error handling.

Deliverable: Functional backend.

### Phase 4 — Bulk Import Engine
- Implement TXT parser.
- Implement CSV parser.
- Implement case-insensitive provider recognition.
- Implement state-based section detection.
- Implement email/key extraction.
- Implement unmatched-line detection.
- Implement duplicate fingerprints.
- Implement import preview.
- Implement import confirmation.

Deliverable: Ability to import the existing API key collection.

### Phase 5 — Frontend
- Implement dashboard.
- Implement sidebar navigation.
- Implement API key management.
- Implement provider management.
- Implement notes editor.
- Implement search.
- Implement reveal and copy controls.
- Implement import interface.

Deliverable: Complete usable KeyVault interface.

### Phase 6 — Google Drive
- Implement OAuth setup.
- Implement token storage.
- Implement encrypted backup.
- Implement restoration.
- Implement optional scheduled backups.

Deliverable: Working optional cloud backup.

### Phase 7 — Packaging
- Implement Dockerfile.
- Implement docker-compose.yml.
- Configure persistent volumes.
- Configure environment variables.
- Document native Linux installation.
- Document Docker installation.

Deliverable: Reproducible deployment.

### Phase 8 — Testing and Finalization
- Test all CRUD operations.
- Test import using realistic files.
- Test ambiguous provider headings.
- Test duplicate detection.
- Test encryption and decryption.
- Test application restart and unlocking.
- Test backup and restoration.
- Test database persistence.
- Test invalid input and malformed files.
- Test session expiration.
- Test security protections.

Deliverable: Fully functional, documented application.

## 11. Acceptance Criteria

The project is complete when:

1. KeyVault launches locally without requiring internet access.
2. The user can create multiple email accounts and providers.
3. Multiple API keys can exist under the same email/provider combination.
4. API keys are encrypted at rest.
5. Provider setup notes are independently editable.
6. The user can import a large TXT file containing multiple provider sections.
7. The parser correctly associates email/key pairs with their provider headings.
8. Case-insensitive provider recognition works.
9. Ambiguous records are flagged rather than incorrectly assigned.
10. Import preview allows editing before committing.
11. Duplicate detection works without exposing plaintext keys.
12. API keys can be searched, revealed, copied, edited, and deleted.
13. Google Drive can be connected independently.
14. Backups are encrypted before upload.
15. Database restoration works.
16. Docker deployment preserves database data.
17. The application remains usable without Google Drive.

## 12. Agent Implementation Instructions

Build the actual application, not a prototype or a collection of design mockups.

Important requirements:

- Work through the development phases sequentially.
- Write complete, executable source files.
- Do not leave placeholder implementations for required functionality.
- Do not substitute simulated data for database operations.
- Do not claim a feature is complete until it has been tested.
- Run Go formatting and tests regularly.
- Keep dependencies minimal.
- Preserve the established visual design.
- Maintain database migrations for future schema changes.
- Document configuration and startup instructions.
- Report completed phases, outstanding work, test results, and any blockers.

Start with Phase 1 and continue through the entire specification without stopping for approval between phases.

The final result must be a working, self-hosted API key management application, not merely a UI demonstration.
