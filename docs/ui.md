# KeyVault UI specification

Authority for the frontend. docs/mockup.png is the picture of this. If you cannot view images, this file is the mockup. Where this file and docs/spec.md conflict on the UI, this file wins.

## Landing page and navigation
- The landing page is Keys (#/keys). Opening the app, an empty hash, or an unknown hash all go to #/keys.
- There is no Dashboard page and no Dashboard sidebar item. Remove the page, its route, its code, and its reveal controls.
- Sidebar, top to bottom: Keys, Providers, Settings, About. The active item has a filled blue background. No Add Key, Import, Dashboard, or Backup items.
- Sidebar bottom: a small card with a green check, "Database Ready", and "SQLite • Encrypted". It shows "Locked" with a grey icon when the vault is locked.
- Top bar: lock icon and "KeyVault" with the subtitle "Your Personal API Key Store". Right side: a green dot with "Local Database", a divider, and the version, both from GET /api/info.

## Keys page
Center column, then right column. The bottom strip sits under the center column.

### Center column, top row
- Search field (magnifier icon, placeholder "Search by email, provider, or label...", clear X button when it has text). Filters as you type, 150 ms debounce, across email, provider name, and label. Groups with no matches are hidden. A match inside a group expands it.
- "Add API Key" button (primary blue, plus icon) right of the search. It moves focus to the Email field of the right panel and scrolls it into view on narrow screens.
- "Import" secondary button next to it. Opens the import wizard. This is the only place the wizard opens.
- A Sort control: Email A to Z (default), Most keys, Newest added. Applies to the groups.

### Center column, list
- Heading "Your API Keys" with a people icon.
- One card per email address (a group). Collapsed by default except the first one on first load.
- Group header: chevron (right when collapsed, down when expanded), envelope icon, the email, then on the right "3 providers • 3 keys" (singular for 1), and a kebab menu (three dots). The whole header toggles the group and works with Enter and Space. Expand and collapse works repeatedly.
- Kebab items: "Add key for this email" (fills the right panel's email field and focuses Provider), "Copy email".
- Expanded group: one row per key, separated by thin lines. Row, left to right: provider mark (a round colored badge with the provider's first letter, no logos and no external images), provider name with the optional label in muted text under it, masked key (first 8 characters then asterisks, for example sk-proj-************), "Added: Oct 24, 2026", then four square icon buttons: Reveal, Copy, Edit, Delete (Delete is red).
- Rows within a group sort by provider name, then newest first.
- Zero keys in the database: one centered message "No keys yet." with "Add API Key" and "Import" buttons. No count line and no "No matching keys" line. When a search matches nothing, show only "Nothing matches 'x'" with a Clear search link.

### Row buttons
- Reveal (eye-slash icon): calls POST /api/keys/{id}/reveal and replaces the masked text in that row with the real key. The icon becomes an eye. Clicking again, or 30 seconds passing, masks it again and drops the value from memory and the DOM. No modal.
- Copy: fetches the real key through the reveal endpoint, writes it to the clipboard, shows "Copied" on the button for 1.5 seconds, and never displays the key. It copies the real key, never the masked text.
- Edit: loads this key into the right panel in edit mode and scrolls it into view.
- Delete: the row turns into "Delete this key? [Delete] [Cancel]" in place. Delete calls DELETE /api/keys/{id}, then the list reloads and the counts update. If it was the last key of an email, the group disappears.
- Every message appears inline in its row or form. No toasts at the bottom of the screen.

### Center column, bottom strip "Settings & Information"
A panel with a gear icon and four cells in a row. Encryption: AES-256-GCM with a green "Active" pill. Database: keyvault.db and its size (for example 2.4 MB). Last Backup: the date and time of the last backup, or "Never". Version: 1.0.0. Values come from GET /api/info.

### Right column, card 1: Add New Key
- Title "Add New Key" with a plus icon.
- Fields: Email Address (required), Provider (required, dropdown listing every provider plus "New provider..." which swaps in a text field for the name), API Key (required, password-style input with an eye toggle button at its right), Label (optional).
- Buttons: "Save Key" (green, save icon) and "Clear Form" (outlined).
- Validation errors appear under the field. A key that already exists for that email (same fingerprint under any provider) shows "This key is already saved for <email>" and is not saved.
- After a successful save the form clears, the list reloads, the group for that email expands, and the new row is highlighted for 2 seconds.
- Edit mode: the title is "Edit Key", the fields are prefilled, the API Key field is empty with the placeholder "Leave blank to keep the current key", "Save Key" becomes "Save Changes", and "Clear Form" becomes "Cancel". Cancel and a successful save return it to Add mode.

### Right column, card 2: Backup
- Title "Backup" with a database icon. No Google Drive logo, no "Connect Google Drive", no scheduled backups (Google Drive is deferred).
- Text: "Your database is stored locally only."
- Buttons: "Backup Now" (downloads the encrypted backup file and records the time for Last Backup) and "Restore Backup" (file picker, then a confirm step that shows the backup date before replacing anything).

## Other pages
- Providers: as built (cards with notes, rename, merge). Keep.
- Settings: Lock now, session timeout display, and the master password recovery warning. No backup controls.
- About: KeyVault name, version, "Encryption: AES-256-GCM with Argon2id key derivation", and where the data is stored (the database file path).

## Visual rules
- Dark navy background, slightly lighter panels with rounded corners (about 12px) and 1px borders, primary blue buttons, green Save Key, red Delete. Reuse the palette variables already in style.css.
- Three columns on wide screens: sidebar 220px, center flexible, right column 380px. Under 1100px wide the right column moves below the list. Under 700px the sidebar becomes a top bar with icons only. Nothing needs horizontal scrolling at 1280, 1440, 1920, or 390 pixels wide.
- Links use a light blue, never purple.
