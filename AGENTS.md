# KeyVault: agent instructions

Read this file and `PLAN.md`. Nothing else until you have picked a task.

## Session protocol

1. Run `git log --oneline -15` and `git status`.
2. Open `PLAN.md`. Pick the first unchecked task whose dependencies are checked. Do only that task.
3. Read only the spec sections the task lists in `docs/spec.md`. Do not read the whole spec.
4. Implement. Edit files in place. Do not rewrite whole files for small changes. Do not dump large files or long command output into the terminal; use `head`, `tail`, `grep`.
5. Verify: `gofmt -l .` prints nothing, `go vet ./...` passes, `go test ./...` passes. The task is not done until these pass and its "Done when" line is true.
6. Tick the box in `PLAN.md`. Append one entry to the Log at the bottom: date, task ID, what changed, test result, anything the next agent needs.
7. Commit: `git add -A && git commit -m "T2.1: short summary"`.
8. Stop. Tell the user the finished task ID and the next task ID.

If you are about to run out of budget mid-task, commit with the message `WIP T2.1: ...` and write exactly where you stopped in the Log. Do not tick the box.

## Rules

- Write real, working code. No stubs, no fake data, no simulated database calls.
- Allowed dependencies: `modernc.org/sqlite`, `golang.org/x/crypto`. Anything else, ask the user first.
- Google Drive uses `net/http` and `encoding/json` against the REST API. No Google SDK.
- Frontend is vanilla HTML/CSS/JS. No CDN, no framework.
- Never log API keys or decrypted values. Never put keys in URLs.
- Do not claim a feature works until a test or a manual run proved it.
- Visual reference: `docs/mockup.png` if it exists. Otherwise a dark blue-gray dashboard per spec section 4.

## Amendments to the spec

These override `docs/spec.md` where they conflict.

1. **Embedding.** Frontend files are embedded in the binary through `web/embed.go` (package `web`, `go:embed`). `go:embed` cannot reach outside its own package directory, so `main.go` imports `web`.
2. **Fingerprint column.** `api_keys` gets `fingerprint BLOB NOT NULL`: HMAC-SHA256 of the plaintext key under the HMAC subkey. Index on `(email, provider_id, fingerprint)`.
3. **Key hierarchy.** The Argon2id output is the master key. Derive subkeys with HKDF-SHA256 using distinct info strings: `keyvault/enc`, `keyvault/hmac`, `keyvault/backup`. Never use the master key directly.
4. **Password check.** `settings` stores a verifier: a known constant encrypted with the enc subkey. Unlock succeeds if it decrypts.
5. **Secrets in settings.** The Google client secret and refresh token are encrypted with the enc subkey. Same for any other credential-like value.
6. **No copy endpoint.** Drop `POST /api/keys/{id}/copy`. Copy happens in the browser after a reveal.
7. **Auth endpoints.** Add `GET /api/auth/status`, `POST /api/auth/setup`, `POST /api/auth/unlock`, `POST /api/auth/lock`. Session idle timeout is 15 minutes, configurable.
8. **Provider delete.** Foreign key is `ON DELETE RESTRICT`. Deleting a provider that has keys returns 409 with the key count. The user reassigns or deletes the keys first.
9. **Provider names.** Unique index with `COLLATE NOCASE`.
10. **Import headings.** A heading line may carry trailing words and punctuation: `Gemini API Key`, `OpenRouter:`, `ElevenLabs Keys` all resolve to their provider. The spec section 5 example must parse correctly.
11. **Import preview.** The server holds parsed rows in memory under an import session ID. List and preview responses mask keys. Edits send full replacement values.
12. **Backup format.** Snapshot with `VACUUM INTO`. Envelope: magic bytes, version, Argon2id salt and parameters, nonce, AES-GCM ciphertext under the backup subkey, header as additional data. Restoring on a fresh machine needs only the master password.
13. **Docker.** The container binds `0.0.0.0:8080` internally. Compose publishes `127.0.0.1:8080:8080` only.
14. **Google OAuth.** Redirect URI is `http://127.0.0.1:<port>/api/google/callback`. Scope is `https://www.googleapis.com/auth/drive.file`. Use `state` and PKCE.

## Deferred work

Tasks marked `[-]` in PLAN.md are deferred. Skip them. Google Drive integration (T6.3 to T6.5) is out of scope: do not build OAuth, Drive calls, or scheduled backups. In T5.7 leave out the Google Drive settings section. In T8.3 skip spec section 11 item 13, and read item 14 as: the local backup file is encrypted.

## Frontend rules (from user testing)

- Phase 5R replaces T5.x. For R tasks, set the box to `[?]`, write exact browser test steps in the Log, and stop. Only the user changes `[?]` to `[x]`. Do any `[!]` task first.
- Import is a flow opened from the API Keys page. There is no Import page or sidebar item.
- Add Key lives on the API Keys page.
- No toasts at the bottom of the screen. Messages appear inline in the modal or form that caused them.
- Modals for setup and unlock cannot be dismissed by clicking outside or pressing Escape.
- Never copy masked text. Copy always uses the revealed key.
- Test at 1440x900 and 390px wide, not only on a large display.
