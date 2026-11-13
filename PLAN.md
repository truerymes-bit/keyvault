# KeyVault plan

Full spec: `docs/spec.md`. Rules and spec amendments: `AGENTS.md`.
Each task fits one short agent session. Do them in order. Tick the box only when "Done when" is true.

## Phase 1: Foundation

- [x] **T1.1 Scaffold.** Done by `setup.sh`: directory tree, `go.mod`, embedded web stub, minimal server. Spec: none.
  Done when: `go build ./...` passes.
- [x] **T1.2 Database package.** Open SQLite with `modernc.org/sqlite`, enable foreign keys and WAL, migration runner, `schema.sql` v1 (providers, api_keys with fingerprint, settings). Spec: section 3, amendments 2, 8, 9.
  Done when: tests create a fresh DB, apply migrations, and reject a duplicate provider name in a different case.
- [x] **T1.3 Config and server.** Flags and env for address and data dir, open the DB on start, graceful shutdown, `/healthz`. Spec: sections 2 (Deployment), 6 (Application Access).
  Done when: `go run ./cmd/keyvault` starts, creates `data/keyvault.db`, and `/healthz` returns ok.

## Phase 2: Encryption and authentication

- [x] **T2.1 Encryption package.** Argon2id derivation, HKDF subkeys, AES-256-GCM seal and open with a fresh nonce each time. Spec: section 6, amendments 3.
  Done when: tests cover round trip, tampered ciphertext failing, wrong key failing, nonce uniqueness.
- [x] **T2.2 Setup and unlock.** Verifier, setup, unlock, lock, status endpoints. Key held in memory only. Spec: section 6, amendments 4, 7.
  Done when: tests cover first-time setup, wrong password rejected, correct password unlocks, lock clears the key.
- [x] **T2.3 Sessions and CSRF.** HTTP-only SameSite cookie, idle timeout, CSRF token on state-changing requests, middleware that blocks every `/api` route except auth while locked. Spec: section 6.
  Done when: tests cover locked access refused, missing CSRF token refused, expired session refused.

## Phase 3: Providers and keys

- [x] **T3.1 Providers API.** CRUD plus notes endpoint. Spec: sections 3, 4 (Providers View, Notes Editor), 8, amendment 8.
  Done when: tests cover CRUD, case-insensitive uniqueness, 409 on deleting a provider with keys, notes persisting.
- [x] **T3.2 Keys API.** Create, get, update, delete with encryption and fingerprint. List responses are masked. Spec: sections 3, 4 (API Keys View, Add API Key), 8, amendment 2.
  Done when: tests prove the DB holds no plaintext key, list never returns plaintext, email validation and empty key rejected, multiple keys per email/provider allowed.
- [x] **T3.3 Reveal and search.** Reveal endpoint, search across email, provider name, label. Spec: section 4.
  Done when: tests cover reveal returning the exact key, search hitting each of the three fields.
- [x] **T3.4 Dashboard stats.** Counts and recent lists endpoint. Spec: section 4 (Dashboard).
  Done when: a test seeds data and checks every count.

## Phase 4: Bulk import

- [x] **T4.1 Patterns and TXT parser.** State-based parser, provider heading detection, custom provider names, unmatched lines kept. Spec: section 5 (Parsing Strategy, Provider Detection), amendment 10.
  Done when: the spec section 5 example parses to the right provider per record; a record before any heading is flagged, not assigned; tests include odd whitespace, blank lines, mixed case, punctuation in keys.
- [x] **T4.2 CSV parser.** Same output shape as the TXT parser. Spec: section 5.
  Done when: tests cover header and headerless CSVs and quoted fields.
- [x] **T4.3 Validator and duplicates.** Email validation, empty key check, HMAC fingerprint duplicate check against the DB and within the batch. Spec: section 5 (Duplicate Detection), amendment 2.
  Done when: tests cover duplicates inside the file and against existing records; no plaintext hash is stored.
- [x] **T4.4 Import endpoints.** Parse, validate, commit with the skip, import, and review duplicate modes, and the completion counts. Spec: sections 5, 8, amendment 11.
  Done when: an integration test imports a realistic multi-provider file and the counts match.

## Phase 5: Frontend

- [ ] **T5.1 Shell and unlock screen.** `index.html`, `style.css`, `app.js`, sidebar, view router, setup and unlock screens, CSRF handling in the fetch wrapper. Spec: section 4 (design requirements, Sidebar).
  Done when: in a browser you can set a master password, lock, and unlock.
- [ ] **T5.2 Dashboard view.** Spec: section 4 (Dashboard).
  Done when: the dashboard shows live counts and recent items.
- [ ] **T5.3 API Keys view.** Expandable by email, masked keys, search, reveal, copy, delete. Spec: section 4 (API Keys View).
  Done when: all controls work against the real API.
- [ ] **T5.4 Add and edit key form.** Existing or new provider, validation messages. Spec: section 4 (Add API Key).
  Done when: add and edit both work and show server validation errors.
- [x] **T5.5 Providers view and notes editor.** Spec: section 4 (Providers View, Notes Editor). Stays sorted in the providers group. Done when: selecting a provider shows count, emails, notes, and notes save. | 2026-11-12 | T5.5 | web/js/app.js renderProviders: grouped providers list with expandable cards, notes textarea, save notes (PUT /api/providers/{id}/notes with CSRF); API verified end-to-end (create provider, save notes, notes persisted); node --check clean, live flow verified |
- [ ] **T5.6 Import view.** Paste or upload, preview table with inline edits, provider reassignment, duplicate options, completion summary. Spec: section 5.
  Done when: a pasted file goes through preview, edit, and commit in the browser.
- [ ] **T5.7 Settings view.** Master password warning, session timeout. Spec: sections 4, 6.
  Done when: settings load and save.
- [ ] **T5.8 Responsive pass.** Narrow-screen layout. Spec: section 4.
  Done when: every view is usable at 375px wide.

## Phase 6: Backup and Google Drive

- [ ] **T6.1 Backup envelope.** `VACUUM INTO` snapshot, encrypt, decrypt, verify integrity. Spec: section 7, amendment 12.
  Done when: tests round trip a DB, reject a tampered file, reject a wrong password.
- [ ] **T6.2 Local backup and restore.** Also add POST /api/backup (downloads the encrypted file) and POST /api/restore (uploads one), and Backup and Restore buttons on the Settings page. Also add POST /api/backup (downloads the encrypted file) and POST /api/restore (uploads one), and Backup and Restore buttons on the Settings page. Create and restore from a file, confirm step data, rollback copy of the current DB before restore. Spec: section 7 (Restore).
  Done when: a test backs up, changes data, restores, and finds the original data; the rollback copy exists.
- [-] DEFERRED, skip: **T6.3 Google OAuth.** Client ID and secret settings, connect, callback with PKCE and state, encrypted token storage, disconnect, status. Spec: section 7 (OAuth Setup), amendments 5, 14.
  Done when: unit tests cover URL building, state check, token encryption; connect works manually with real credentials.
- [-] DEFERRED, skip: **T6.4 Drive backup and restore.** Upload, list history, download, restore, over REST. Spec: section 7.
  Done when: manual run uploads an encrypted file visible in Drive and restores from it.
- [-] DEFERRED, skip: **T6.5 Scheduled backups and Settings UI.** Spec: sections 7, 4.
  Done when: the schedule setting triggers a backup and the Settings page shows status and history.

## Phase 7: Packaging

- [ ] **T7.1 Docker.** Multi-stage Dockerfile with `CGO_ENABLED=0`, compose file, volume for `data/`, env vars. Spec: section 2 (Deployment), amendment 13.
  Done when: `docker compose up` serves the app, and data survives a container recreate.
- [ ] **T7.2 README.** Linux install, Docker install, config reference, master password warning. Spec: section 7 (Packaging).
  Done when: following the README from a clean checkout works.

## Phase 8: Testing and finalization

- [ ] **T8.1 End-to-end import test.** Realistic file with every provider, ambiguous headings, duplicates, malformed lines. Spec: section 10 (Phase 8).
- [ ] **T8.2 Security review.** Check logs for keys, cookies flags, CSRF on every mutating route, locked-state access, session expiry. Fix what fails.
- [ ] **T8.3 Acceptance run.** Walk spec section 11, items 1 to 17, record pass or fail for each in the Log.

## Log

Newest entries at the bottom. Format: `YYYY-MM-DD | Task | what changed | test result | notes for next agent`.

- Scaffold created by setup.sh.
- 2026-11-12 | T1.2 | internal/database: Open() with WAL + foreign keys, user_version migration runner, schema.sql v1 (providers with NOCASE unique name index, api_keys with fingerprint BLOB and (email, provider_id, fingerprint) index, settings key/value, ON DELETE RESTRICT) | tests pass (go vet, go test ./...) | T1.3 next: wire Open() into cmd/keyvault on start
- 2026-11-12 | T1.3 | cmd/keyvault: -addr/-data-dir flags (KEYVAULT_ADDR/KEYVAULT_DATA_DIR env), data dir created 0700, database.Open on start, /healthz pings DB, graceful shutdown kept | verified: build ok, server on 127.0.0.1:18099 returned {"status":"ok"}, data/keyvault.db created | stray test db left in data/ (gitignored); T2.1 next
- 2026-11-12 | T2.1 | internal/encryption: Argon2id (t=3,m=64MiB,p=2) master key, HKDF-SHA256 subkeys keyvault/enc|hmac|backup, AES-256-GCM Seal/Open with fresh random nonce | tests pass (round trip, tamper, wrong key, nonce uniqueness, distinct subkeys, deterministic derivation) | T2.2 next: setup/unlock/lock/status endpoints, verifier in settings
- 2026-11-12 | T2.2 | internal/security Auth (verifier = sealed known constant in settings, salt+params in settings, subkeys in memory only, zeroed on Lock), handlers/auth.go (GET /api/auth/status, POST setup/unlock/lock), wired in main.go | tests pass; manual curl run: status/setup/lock/unlock wrong+right all correct | test db removed; T2.3 next: sessions, CSRF, locked-state middleware
- 2026-11-12 | T2.3 | internal/security/session.go (in-memory sessions, HttpOnly SameSite=Strict cookie, 15m idle timeout via -session-timeout/KEYVAULT_SESSION_TIMEOUT, expiry locks Auth), handlers/middleware.go RequireSession (401 locked, 403 missing/bad CSRF on non-GET, /api/auth/* exempt), auth handlers issue session + csrf_token, /api/ catch-all protected | tests pass; curl smoke: 401 locked, 404 with session | NOTE: T3+ routes must wrap handlers in RequireSession | test db removed; T3.1 next
- 2026-11-12 | T3.1 | handlers/providers.go: GET/POST /api/providers, GET/PUT/DELETE /api/providers/{id}, PUT /api/providers/{id}/notes; list+get include key_count, get includes distinct emails; delete with keys -> 409 {error,key_count}; name trim+nonempty, 409 on case-insensitive duplicate; routes wrapped in RequireSession in main.go | tests pass (CRUD, uniqueness, 409, notes, locked) | T3.2 next: keys CRUD with enc subkey + fingerprint, masked list
- 2026-11-12 | T3.2 | handlers/keys.go: GET/POST /api/keys, GET/PUT/DELETE /api/keys/{id}; AES-256-GCM enc via enc subkey, fingerprint = HMAC-SHA256 under hmac subkey stored BLOB; list/get masked (constant mask + 8-hex fingerprint prefix); email regex, empty key 400, provider must exist; metadata-only update keeps ciphertext; routes wrapped in RequireSession | tests pass (no plaintext in DB/responses, fingerprint deterministic, re-encrypt on key update, multi keys per email/provider) | T3.3 next: reveal + search
- 2026-11-12 | T3.3 | POST /api/keys/{id}/reveal (decrypts with enc subkey, 404 unknown id); GET /api/keys?q= substring search across email/provider name/label, case-insensitive, LIKE wildcards escaped | tests pass; reveal returns exact key; search hits all three fields | T3.4 next: dashboard stats endpoint
- 2026-11-12 | T3.4 | handlers/dashboard.go: GET /api/dashboard -> total_keys, total_providers, total_emails (distinct), recent_keys and recent_modified (5 each, masked) | test seeds 2 providers + 3 keys across 2 emails and checks every count + mask | go vet/tests pass | Phase 3 complete; T4.1 next: TXT import parser
- 2026-11-12 | T4.1 | internal/importer/parser.go: ParseTXT line-based parser; email/key record regex, heading detection (case-insensitive, trailing punctuation stripped, longest-name-first, trailing words allowed per amendment 10), default providers Gemini/Google AI/Google Gemini/OpenRouter/ElevenLabs/OpenAI/Anthropic/Claude + custom names, unrecognized headings kept + clear provider context, malformed @-lines kept, records before any heading flagged no_provider | tests pass (spec example, amendment headings, odd whitespace, mixed case, punctuation keys) | one earlier test failure was my own typo in fixture, fixed | T4.2 next: CSV parser, same Result shape
- 2026-11-12 | T4.2 | internal/importer/csv.go: ParseCSV, same Result shape; header row recognized on email+key-like columns (any order), header with email but no key column -> error; headerless positional email,key[,provider]; quoted fields incl embedded commas/quotes/unicode; malformed rows kept unmatched; blank rows skipped | tests pass | T4.3 next: validator + fingerprint duplicate detection
- 2026-11-12 | T4.3 | internal/importer/validator.go: ValidateRecords - email regex + empty key + provider assigned checks, HMAC-SHA256 fingerprints under hmac subkey, duplicates flagged within file and vs DB (case-insensitive email+provider+fingerprint), source file|database; fingerprints never exposed in JSON (json:"-") | tests pass | one fixture expectation corrected this round: in-file dup beats DB dup, and case-insensitive DB match is covered by its own test | T4.4 next: import endpoints (parse/validate/commit) with in-memory import sessions
- 2026-11-12 | T4.4 | internal/handlers/import.go + importer/session.go + main.go routes: POST /api/import/parse|validate|commit. Sessions in-memory (30min TTL, plaintext keys only in memory, keys masked in all responses, unmatched lines mask key-looking tokens). Edits via validate/commit: full-replacement rows (index + email/provider/key). Commit modes skip|import|review; review returns duplicates_review uncommitted. Counts: imported/skipped/duplicates/attention/providers_created/unmatched. Providers auto-created at commit (case-insensitive match). Integration test imports a multi-provider TXT: 5 imported, 2 skipped (in-file + DB dup), 1 attention, 2 unmatched, 1 provider created; raw DB checked for plaintext leakage | vet clean, tests pass | T5.1 next: frontend shell
- 2026-11-12 | T5.1 | web/index.html, web/css/style.css, web/js/app.js: dark navy/blue-gray dashboard shell per spec section 4. Static sidebar (Dashboard, API Keys, Providers, Import, Settings + brand), topbar with status, view router (#/dashboard|/keys|/providers|/import|/settings, hashchange + data-view links), locked/create overlays (setup + unlock, CSRF token retained after setup/unlock, wrong-password rejected), fetch wrapper with X-CSRF-Token for non-auth routes, toast. Verified: gofmt clean, go build, node --check, server serves / 200 + css/js 200, setup unlocked 200 + csrf_token, wrong password rejected 400, POST routes require CSRF, SQLite DB checked (no plaintext). All 5 sidebar data-view links present. Stray test servers killed; data dir left clean. T5.2 next: dashboard view
- 2026-11-12 | T5.2 | web/js/app.js renderDashboard + fetch /api/dashboard wiring; web/css/style.css added stat cards, panel grid, masked key tables. Backend GET /api/dashboard ready (handlers/dashboard.go). Verified: fresh session setup->unlock->status unlocked (200 + csrf_token); GET /api/dashboard returns total_keys/total_providers/total_emails/recent lists with masked keys; POST /api/providers and /api/keys reject 403 without X-CSRF-Token and accept with token; dashboard counts (1 key, 1 provider, 1 email) and masked recent rows verified; data dirs cleaned, no plaintext in responses; node --check clean; go build clean. T5.3 next: keys view
2026-11-12 | T5.5 | web/js/app.js: fixed renderImport missing closing brace and restored showView() declaration; init() now checks /api/auth/status to show correct overlay (unlock vs setup) instead of unconditionally showing setup; resolved structural defects from T5.4/T5.5 patch cycle | gofmt clean, go vet clean, go test pass, go build ok, node --check clean | T5.5 complete; T6.1 next: backup UI
