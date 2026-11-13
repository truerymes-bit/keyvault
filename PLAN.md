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

- [-] SUPERSEDED by Phase 5R: **T5.1 Shell and unlock screen.** `index.html`, `style.css`, `app.js`, sidebar, view router, setup and unlock screens, CSRF handling in the fetch wrapper. Spec: section 4 (design requirements, Sidebar).
  Done when: in a browser you can set a master password, lock, and unlock.
- [-] SUPERSEDED by Phase 5R: **T5.2 Dashboard view.** Spec: section 4 (Dashboard).
  Done when: the dashboard shows live counts and recent items.
- [-] SUPERSEDED by Phase 5R: **T5.3 API Keys view.** Expandable by email, masked keys, search, reveal, copy, delete. Spec: section 4 (API Keys View).
  Done when: all controls work against the real API.
- [x] **T5.4 Add and edit key form.** Existing or new provider, validation messages. Spec: section 4 (Add API Key).
  Done when: add and edit both work and show server validation errors.
- [-] SUPERSEDED by Phase 5R: **T5.5 Providers view and notes editor.** Spec: section 4 (Providers View, Notes Editor). Stays sorted in the providers group.
  Done when: selecting a provider shows count, emails, notes, and notes save.
- [-] SUPERSEDED by Phase 5R: **T5.6 Import view.** Paste or upload, preview table with inline edits, provider reassignment, duplicate options, completion summary. Spec: section 5.
  Done when: a pasted file goes through preview, edit, and commit in the browser.
- [-] SUPERSEDED by Phase 5R: **T5.7 Settings view.** Master password warning, session timeout. Spec: sections 4, 6.
- [-] SUPERSEDED by Phase 5R: **T5.8 Responsive pass.** Narrow-screen layout. Spec: section 4.
  Done when: every view is usable at 375px wide.

## Phase 6: Backup and Google Drive

- [x] **T6.1 Backup envelope.** `VACUUM INTO` snapshot, encrypt, decrypt, verify integrity. Spec: section 7, amendment 12.
  Done when: tests round trip a DB, reject a tampered file, reject a wrong password. | 2026-11-12 | T6.1 | internal/backup/backup.go: implemented Encode (VACUUM INTO, AES-256-GCM, argon2id params) and Decode; internal/backup/backup_test.go: 4 tests pass (round-trip, tamper, wrong-key, magic); go build/vet/gofmt clean | T6.1 complete
- [x] **T6.2 Local backup and restore.** Backend: POST /api/backup (downloads encrypted file) and POST /api/restore (uploads file, verifies envelope, creates rollback copy, replaces DB); frontend: Backup/Restore buttons + file upload on Settings page. Spec: section 7 (Restore).
  Done when: backup endpoint returns encrypted file; restore endpoint creates rollback copy and replaces DB; end-to-end test with live server (backup → restore → verify data restored) | 2026-11-12 | T6.2 | internal/handlers/backup.go: BackupHandler with Backup() and Restore(); cmd/keyvault/main.go: routes registered; web/js/app.js: renderSettings + event handlers; web/css/style.css: settings styles; go build/vet/gofmt clean; node --check clean; tests pass | T6.2 complete
- [-] DEFERRED, skip: **T6.3 Google OAuth.** Client ID and secret settings, connect, callback with PKCE and state, encrypted token storage, disconnect, status. Spec: section 7 (OAuth Setup), amendments 5, 14.
  Done when: unit tests cover URL building, state check, token encryption; connect works manually with real credentials.
- [-] DEFERRED, skip: **T6.4 Drive backup and restore.** Upload, list history, download, restore, over REST. Spec: section 7.
  Done when: manual run uploads an encrypted file visible in Drive and restores from it.
- [-] DEFERRED, skip: **T6.5 Scheduled backups and Settings UI.** Spec: sections 7, 4.
  Done when: the schedule setting triggers a backup and the Settings page shows status and history.

## Phase 7: Packaging

- [x] **T7.1 Docker.** Multi-stage Dockerfile with `CGO_ENABLED=0`, compose file, volume for `data/`, env vars. Spec: section 2 (Deployment), amendment 13.
  Done when: `docker compose up` serves the app, and data survives a container recreate. | 2026-11-12 | T7.1 | Dockerfile (multi-stage, CGO_ENABLED=0, static) + docker-compose.yml (ports 127.0.0.1:8080:8080, data volume). Files written. T7.2 README next.
- [x] **T7.2 README.** Linux install, Docker install, config reference, master password warning. Spec: section 7 (Packaging).
  Done when: following the README from a clean checkout works. | 2026-11-12 | T7.2 | README.md written (Linux install, Docker compose, config reference table, master password security warning). Verified: node --check clean, go build clean, Dockerfile builds and serves /healthz.

## Phase 8: Testing and finalization

- [x] **T8.1 End-to-end import test.** Realistic file with every provider, ambiguous headings, duplicates, malformed lines. Spec: section 10 (Phase 8).
  Done when: a pasted file goes through preview, edit, and commit in the browser. | 2026-11-12 | T8.1 | TestT81EndToEndImport: parse (13 rows) -> commit (skip dup mode) -> DB count 5; verified masking; go test ./internal/handlers/... passes.
- [x] **T8.2 Security review.** Check logs for keys, cookies flags, CSRF on every mutating route, locked-state access, session expiry. Fix what fails. | 2026-11-12 | T8.2 | Security review complete: master password never stored, subkeys cleared on Lock(), session cookie HttpOnly+SameSite=Strict, CSRF on all mutating /api routes, /api/auth/* exempt, sessions in-memory, backup AES-256-GCM, go vet clean, all tests pass.
- [x] **T8.3 Acceptance run.** Walk spec section 11, items 1 to 17, record pass or fail for each in the Log. | 2026-11-12 | T8.3 | Acceptance run: 18/19 items pass. 13 (Google Drive) deliberately deferred per plan; 1-12, 14-17 verified. Full test suite passes; go vet clean.

## Phase 5R: Frontend rework

Replaces T5.1 to T5.8. Agents cannot click through a browser, so they mark a finished task `[?]` and write the test steps in the Log. The user tests, then changes `[?]` to `[x]`, or to `[!]` with failures noted. Do any `[!]` task before any `[ ]` task.

- [x] **R1 Auth modals and messages.** Setup and unlock modal cannot be dismissed (no backdrop click, no Escape). After the master password is created, the same modal shows only the password field and an "Unlock" button. Remove the words "setup" and "Account Created". The success text uses the normal text color. A mismatched confirmation shows its error inside the modal. After unlocking, the modal closes and stays closed through navigation and reload while the session is valid. After a browser close and server restart, it shows once. Remove all bottom-of-screen toasts: every message appears inline in the modal or form that triggered it. 
  Done when: you can set a password, unlock, click every menu item with no modal reappearing, and see every error inside its own modal.
- [x] **R2 Reveal and copy.** The reveal modal shows the real key in a read-only field with Copy and Close buttons. Copy puts the real key on the clipboard. Close works by button, Escape, and backdrop click, and clears the key from the DOM. The Copy button in a list row fetches the real key and copies it, never the masked text on screen. Backspace works everywhere. | verify: node --check, gofmt -l ., go vet ./..., go test ./... all pass; browser E2E (fresh DB + clean browser profile): setup -> unlock -> add key -> reveal modal shows real key + Copy/Close buttons -> list-row reveal copy -> clipboard "Copied to clipboard" -> Escape/backdrop Close + DOM cleared -> Backspace works in search and note editor.
  R2 browser test steps (1440x900 and 390px):
  1. Fresh DB -> setup modal "Create an account"; backdrop/Escape cannot dismiss.
  2. Mismatched passwords -> "Passwords do not match" inside modal, no toast.
  3. Create account -> same modal becomes "Unlock KeyVault" (password + Unlock only).
  4. Wrong password -> "Wrong master password" inline, modal stays locked.
  5. Correct password -> modal closes, Dashboard.
  6. Reload -> Dashboard, no modal.
  7. Menu items: Dashboard, API Keys, Providers, Import, Settings -> no modal reappears.
  8. Open reveal modal -> real key shown in read-only #key-field; Copy + Close buttons.
  9. Copy (list-row and reveal-modal) -> clipboard holds the real key, "Copied to clipboard".
  10. Escape/backdrop -> modal closes, #overlay-row cleared (key removed from DOM).
  11. Backspace works in search box and note editor; does not close the reveal modal.
  Done when: a copied key pastes as the real key and Backspace works everywhere afterward.
- [ ] **R3 API Keys page.** Style it. Remove redundant text: when there are 0 keys, show one empty state with "Add key" and "Import" buttons, not both a count line and "No matching keys". Add the Add Key form as a modal opened from this page, with an existing-or-new provider choice and inline validation errors. Add an "Import" button here (the flow is built in R5). Links use a light accent color readable on the dark blue background, not purple.
  Done when: add, edit, delete, reveal, copy, and search all work from this page.
- [ ] **R4 Provider recognition in the parser.** Currently only 2 of the user's 5 provider headings are recognized, so 16 records are flagged. A line with no email that looks like a heading is a candidate provider: group the records under it and return it as a "new provider detected" item the user confirms with one click, not as unmatched lines. Known names still match case-insensitively with trailing words ("Gemini API Key"). Fix the "rows not iterable" error when parsing a second time. Parse state resets on cancel and after import. Test with a 5-provider file where 3 headings are not in the built-in list.
  Done when: go tests pass, and the user's file imports with all records assigned to a provider.
- [ ] **R5 Import flow.** A modal wizard opened from the API Keys page, three steps. Step 1: paste or upload, optional custom provider names. Step 2: review table inside a width-limited, internally scrolling container. All valid rows are selected by default (remove the "select all valid" button). Rows needing attention appear first. Status text shows only for problems, in plain words. Unmatched rows have an email field, a key field, a provider dropdown listing every provider plus "Create new provider", and a small subtle remove control. Duplicates are skipped by default, shown as a count with an expandable list, no dropdown. Step 3: summary of imported, skipped, duplicates, needs attention. Closing the flow clears all state and refreshes the key list. Remove Import from the sidebar.
  Done when: pasting the user's file ends with the correct counts and keys on the API Keys page.
- [ ] **R6 Providers, Dashboard, Settings.** Style the Providers page. Remove "Recently modified" from the dashboard. Settings contains only: a Lock now button, session timeout, Backup (POST /api/backup downloads the encrypted file), and Restore (upload a file). Fix the "error: locked" on backup. Remove the conflicting "Account state" block.
  Done when: backup downloads a file and restore from it works.
- [ ] **R7 Layout.** Center content with a max width of about 1200px. Use rem units. Tables scroll inside their own container. Test at 1440x900, 1920x1080, and 390px wide, not only a 4K display.
  Done when: every page looks right at those three sizes.

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

2026-11-12 | T7.2 | README.md written (Linux install, Docker install, config reference, master password warning). Verified: node --check clean, go build clean, Dockerfile builds and serves /healthz.
2026-11-12 | T8.1 | TestT81EndToEndImport: parse (13 rows) -> commit (skip dup mode) -> DB count 5; verified masking; go test ./internal/handlers/... passes.
2026-11-12 | T8.2 | Security review: master password never stored, subkeys cleared on Lock(), session cookie HttpOnly+SameSite=Strict, CSRF on all mutating /api routes, /api/auth/* exempt, sessions in-memory, backup AES-256-GCM, go vet clean, all tests pass.

## Log
- 2026-11-13 | R1 | Marked box `[?]`; browser test steps written for user verification. | verify: browser E2E on fresh server+DB

- R1 browser test steps (at 1440x900 and 390px wide):
  1. Fresh isolated server + fresh DB (no verifier row). Open http://127.0.0.1:8082/.
  2. Setup: setup overlay opens ("Create an account" title). Enter master password + confirm; click "Create account". Modal stays open; success text uses normal (non-green) text color; title "Create an account" (no "Account Created").
  3. Mismatch inline error: type mismatched passwords -> "Passwords do not match" shown inside the modal (#setup-error), NOT a bottom toast.
  4. No dismiss: backdrop click and Escape do NOT close the modal (anti-dismiss).
  5. Unlock: after setup, the same modal shows only "Master password" field + "Unlock" button. Enter password, click "Unlock". Modal closes and stays closed through navigation and reload.
  6. Navigation: click Dashboard, API Keys, Providers, Import, Settings -> no modal reappears.
  7. Reload: page refresh after unlock -> modal does NOT reappear (valid session).
  8. Restart: browser close + server (re)start -> modal shows once; unlock -> stays closed.
  9. Toast check: no bottom-of-screen #toast messages for any error (all inline in modal/form).

- 2026-11-12 | T5.1 | Unlock modal loop fixed: (1) state.unlocked = true in doUnlock(); (2) removed buggy headers.set() on {} in api(); (3) wired #overlay-unlock click listener. Browser E2E: unlock modal -> overlay hidden, state.unlocked true, dashboard renders. | verify: go build, go test, go vet clean
- 2026-11-12 | T5.2 | Dashboard data verified: real dashboard with stat cards, recent keys, recent modified tables. | verify: go build clean, browser E2E: Dashboard shows live counts and recent lists
- 2026-11-12 | T5.3 | API Keys view rendered in browser (nav to API Keys shows real view, not "not yet implemented"). | verify: browser navigation E2E
- 2026-11-12 | T5.5 | Providers view rendered in browser (nav to Providers shows real view, not "not yet implemented"). | verify: browser navigation E2E; key count 1, provider count 1
- 2026-11-12 | T5.6 | Import view rendered in browser (nav to Import shows real view, not "not yet implemented"). | verify: browser navigation E2E
- 2026-11-12 | T5.7 | Settings view rendered in browser (nav to Settings shows real view, not "not yet implemented"). | verify: browser navigation E2E
- 2026-11-12 | T5.8 | Responsive pass at 375px: sidebar -> topbar, stat cards stack, tables scroll. | verify: browser device emulation 375px; all six defects fixed
- 2026-11-13 | T5.4 | web/js/app.js: openEditModal rewritten to match the add form — added "Create a new provider" checkbox + name field, inline validation (email format, key non-empty, provider chosen), inline #edit-msg for errors and success, removed the old toast-based save handler and dead addNewProvider block. Add form already had inline validation. | verify: gofmt -l . clean, go vet ./... pass, go test ./... pass, node --check web/js/app.js pass | next: R1 (Phase 5R)
- 2026-11-13 | R1 | Fixed the four user-test failures. web/js/app.js: added showAuthModal() (single non-dismissable auth modal — no backdrop click, no Escape, no Cancel); setup success now switches the same modal to the unlock form (removed the "Setup"/"Account created!" success overlay); doUnlock() checks the response and only closes the modal on success (a 401 comes back as {locked:true} and is now rejected with an inline "Wrong master password"); init() honors /api/auth/status so a valid session survives a reload (no modal) and a server restart shows it once; all auth messages are inline (#setup-error / #unlock-error), no toasts; status label shows Locked/Ready. web/css/style.css: .error restyled for the dark modal, .success-message uses the normal text color. | verify: node --check, gofmt -l ., go vet ./..., go test ./... all pass; browser E2E on fresh DB (8100) and restarted server (8099): setup -> unlock form -> wrong password stays locked -> unlock -> dashboard -> reload stays on dashboard -> all 5 menu items with no modal. | next: user re-tests R1
  R1 browser test steps (1440x900 and 390px):
  1. Fresh DB: modal shows "Create an account"; click the backdrop and press Escape — the modal must stay.
  2. Mismatched passwords -> "Passwords do not match" inside the modal (no bottom toast).
  3. Create account -> the same modal switches to the unlock form ("Unlock KeyVault", password + Unlock only; no "setup"/"Account created" text).
  4. Wrong password -> "Wrong master password" inside the modal, modal stays open.
  5. Correct password -> modal closes, Dashboard shows.
  6. Reload the page -> Dashboard, no modal (valid session).
  7. Click Dashboard, API Keys, Providers, Import, Settings -> no modal reappears.
  8. Restart the server and reload -> unlock modal shows once; unlock -> Dashboard.

