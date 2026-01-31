# IMAP Email Migration Tools

![CI](https://github.com/JCallico/imap-migration-tools/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/github/JCallico/imap-migration-tools/graph/badge.svg?token=SDF29GC5VV)](https://codecov.io/github/JCallico/imap-migration-tools)
![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Background
I was in need of migrating a Google account with more than 100,000 emails, and none of the freely available solutions worked reliably for me. They often timed out, crashed, or couldn't handle the volume. Hence, I created these simple, robust Python scripts that got the job done effectively.

### Disclaimer
These scripts are provided "as is", without warranty of any kind, express or implied. While they have been tested and used successfully for ONE large migration, the author assumes no liability for any data loss, corruption, or other issues that may arise from their use. Users are advised to review the code and test with non-critical data before performing large-scale operations. No support or maintenance is guaranteed.

## Project Overview
This repository contains a set of Python scripts designed to migrate emails between IMAP servers (supports Gmail, Outlook, etc.), verify the migration, and manage folder states.

### The Scripts

1. **`migrate_imap_emails.py`** (The Solution)
   - Migrates emails folder-by-folder.
   - **Multi-threaded**: Uses a thread pool to copy messages in parallel for high speed.
   - **Smart De-duplication**: Checks if a message already exists in the destination (matching Message-ID and Size) and skips it if found.
  - **Robust**: Preserves original dates and can preserve IMAP flags with `--preserve-flags`.
  - **Gmail Mode**: For Gmail -> Gmail migrations, use `--gmail-mode` to migrate `[Gmail]/All Mail` (no duplicates) and apply Gmail labels by copying messages into label folders.
   - **Cleanup**: Optionally deletes messages from the source after successful transfer (effectively a "Move" operation).
     - *Improved for Gmail*: Automatically detects "Trash" folders to ensure emails are properly binned rather than just archived.
   - **Sync Mode**: Optionally deletes emails from destination that no longer exist in source (`--dest-delete`).
   - **Configurable**: Adjustable concurrency and batch sizes to respect server rate limits.

2. **`compare_imap_folders.py`** (The Validator)
   - Connects to both Source and Destination accounts.
   - Prints a side-by-side comparison table of message counts for every folder.
  - Supports comparing IMAP to a local backup folder (`.eml` files) as either the source or destination.
  - Essential for verifying that the migration was successful and that counts match.

3. **`count_imap_emails.py`** (The Investigator)
  - Counts emails in all folders for a single IMAP account (initial assessment / sizing).
  - Also supports counting a local backup folder (`.eml` files) via `--path` (or `BACKUP_LOCAL_PATH`).

4. **`backup_imap_emails.py`** (The Backup)
   - Downloads emails from an IMAP account to a local disk.
   - **Format**: Saves emails as individual `.eml` files (RFC 5322), compatible with Outlook, Thunderbird, and Apple Mail.
   - **Structure**: Replicates the IMAP folder hierarchy locally.
   - **Incremental**: Skips emails that have already been downloaded (based on UID) so you can run it periodically to fetch new messages.
   - **Sync Mode**: Optionally deletes local `.eml` files that no longer exist on the server (`--dest-delete`).
   - **Gmail Labels Preservation**: Creates a `labels_manifest.json` file mapping each email's Message-ID to its Gmail labels, enabling proper restoration with labels intact.

5. **`restore_imap_emails.py`** (The Restore)
   - Uploads emails from a local backup to an IMAP server.
   - **Format**: Reads `.eml` files and uploads them preserving original dates.
   - **Structure**: Recreates the folder hierarchy on the destination server.
   - **Incremental**: Skips emails that already exist (based on Message-ID and size), but still syncs labels and flags.
   - **Sync Mode**: Optionally deletes emails from destination that no longer exist in local backup (`--dest-delete`).
   - **Gmail Labels Restoration**: Applies labels from `labels_manifest.json` to recreate the original Gmail label structure.

## Getting Started

### 1. Prerequisites
- **Python 3.6+**
- **No external installations required.**
  The scripts use only the Python Standard Library, which is installed automatically with Python. You do **not** need to install anything else (no `pip install`).
  *Used libraries: `imaplib`, `email`, `concurrent.futures`, `re`, `os`, `sys`, `threading`.*

### 2. Installation

Clone this repository or download the script files to your local machine.

#### macOS
macOS often comes with Python, but it's best to install the latest version.
- **Using Homebrew** (Recommended):
  ```bash
  brew install python
  ```
- **Manual**: Download the installer from [python.org](https://www.python.org/downloads/mac-osx/).

#### Linux (Ubuntu/Debian)
Most Linux distributions come with Python 3 pre-installed. To ensure you have it:
```bash
sudo apt-get update
sudo apt-get install python3
```

#### Windows
1. Download the Python 3 executable installer from [python.org](https://www.python.org/downloads/windows/).
2. Run the installer and **ensure you check the box "Add Python to PATH"** at the bottom of the setup screen before clicking Install.
3. Open PowerShell or Command Prompt and verify installation:
   ```powershell
   python --version
   ```

## Configuration & Running

You can configure the scripts using **Environment Variables** (recommended for security) or **Command Line Arguments**.

### Method 1: Environment Variables

#### Linux / macOS (Bash/Zsh)

1. **Set Variables:**
   ```bash
   # Source Account
   export SRC_IMAP_HOST="imap.gmail.com"
   export SRC_IMAP_USERNAME="source@gmail.com"
   export SRC_IMAP_PASSWORD="your-app-password"

   # Destination Account
   export DEST_IMAP_HOST="imap.destination.com"
   export DEST_IMAP_USERNAME="dest@domain.com"
   export DEST_IMAP_PASSWORD="dest-app-password"

   # Options (Optional)
   export DELETE_FROM_SOURCE="false"  # Set to "true" to delete from source after copy
   export DEST_DELETE="false"         # Set to "true" to delete orphans from destination (sync mode)
  export PRESERVE_FLAGS="false"      # Set to "true" to preserve IMAP flags (read/starred/etc)
  export GMAIL_MODE="false"          # Set to "true" for Gmail mode (All Mail + label application)
   export MAX_WORKERS=4               # Number of parallel threads
   export BATCH_SIZE=10               # Emails per batch
   ```

2. **Run:**
   ```bash
   python3 migrate_imap_emails.py
   ```

#### Windows (PowerShell)

1. **Set Variables:**
   ```powershell
   # Source Account
   $env:SRC_IMAP_HOST="imap.gmail.com"
   $env:SRC_IMAP_USERNAME="source@gmail.com"
   $env:SRC_IMAP_PASSWORD="your-app-password"

   # Same for DEST_* ...
   ```

2. **Run:**
   ```powershell
   python migrate_imap_emails.py
   ```

### Method 2: Command Line Arguments (Overrides)
All scripts support command-line arguments which take precedence over environment variables.

**Migration:**
```bash
python3 migrate_imap_emails.py \
  --src-host "imap.gmail.com" \
  --src-user "me@gmail.com" \
  --src-pass "your-app-password" \
  --dest-host "imap.other.com" \
  --dest-user "you@domain.com" \
  --dest-pass "your-app-password" \
  --workers 4 \
  --src-delete
```

**Comparison:**
```bash
python3 compare_imap_folders.py \
  --src-host "imap.gmail.com" \
  --src-user "me@gmail.com" \
  --src-pass "your-app-password" \
  --dest-host "imap.other.com" \
  --dest-user "you@domain.com" \
  --dest-pass "your-app-password"

# Compare IMAP source to a local backup folder
python3 compare_imap_folders.py \
  --src-host "imap.gmail.com" \
  --src-user "me@gmail.com" \
  --src-pass "your-app-password" \
  --dest-path "./my_backup"

# Compare a local backup folder to an IMAP destination
python3 compare_imap_folders.py \
  --src-path "./my_backup" \
  --dest-host "imap.other.com" \
  --dest-user "you@domain.com" \
  --dest-pass "your-app-password"
```

**Counting:**
```bash
python3 count_imap_emails.py --host "imap.gmail.com" --user "me@gmail.com" --pass "secret"

# Count a local backup folder
python3 count_imap_emails.py --path "./my_backup"

# Or via environment variable
export BACKUP_LOCAL_PATH="./my_backup"
python3 count_imap_emails.py
```

**Backup:**
```bash
python3 backup_imap_emails.py \
  --src-host "imap.gmail.com" \
  --src-user "me@gmail.com" \
  --src-pass "your-app-password" \
  --dest-path "./my_backup"
```

## Usage Examples

### 1. Full Migration
Migrate all folders from Source to Destination.
```bash
python3 migrate_imap_emails.py \
  --src-host "imap.gmail.com" \
  --src-user "source@gmail.com" \
  --src-pass "source-app-password" \
  --dest-host "imap.other.com" \
  --dest-user "dest@domain.com" \
  --dest-pass "dest-app-password"
```

### 1a. Gmail Mode Migration (Gmail -> Gmail)
For Gmail -> Gmail migrations, `--gmail-mode` migrates only `[Gmail]/All Mail` (no duplicates) and applies labels by copying messages into label folders.

```bash
python3 migrate_imap_emails.py \
  --gmail-mode \
  --src-host "imap.gmail.com" \
  --src-user "source@gmail.com" \
  --src-pass "source-app-password" \
  --dest-host "imap.gmail.com" \
  --dest-user "dest@gmail.com" \
  --dest-pass "dest-app-password"
```

Notes:
- `--preserve-flags` is enabled automatically in `--gmail-mode`.
- `--dest-delete` is not supported in `--gmail-mode`.

### 1b. Preserve Flags (Any IMAP Server)
Preserve IMAP flags (`\Seen`, `\Flagged`, `\Answered`, `\Draft`) during migration.

If an email already exists on the destination (duplicate), the script can still sync missing flags on the existing message.

```bash
python3 migrate_imap_emails.py \
  --preserve-flags \
  --src-host "imap.example.com" \
  --src-user "source@example.com" \
  --src-pass "source-password" \
  --dest-host "imap.example.com" \
  --dest-user "dest@example.com" \
  --dest-pass "dest-password"
```

### 2. Single Folder Migration
Migrate ONLY a specific folder (e.g., trying to fix just "Important" or "Sent").
```bash
# Syntax: python3 migrate_imap_emails.py "[Folder Name]"
python3 migrate_imap_emails.py \
  --src-host "imap.gmail.com" \
  --src-user "source@gmail.com" \
  --src-pass "source-app-password" \
  --dest-host "imap.other.com" \
  --dest-user "dest@domain.com" \
  --dest-pass "dest-app-password" \
  "[Gmail]/Important"
```

### 3. Move Instead of Copy
Migrate and **delete** from source immediately after verifying the copy.
```bash
# Using flag
python3 migrate_imap_emails.py \
  --src-host "imap.gmail.com" \
  --src-user "source@gmail.com" \
  --src-pass "source-app-password" \
  --dest-host "imap.other.com" \
  --dest-user "dest@domain.com" \
  --dest-pass "dest-app-password" \
  --src-delete

# Or specific folder with delete
python3 migrate_imap_emails.py \
  --src-host "imap.gmail.com" \
  --src-user "source@gmail.com" \
  --src-pass "source-app-password" \
  --dest-host "imap.other.com" \
  --dest-user "dest@domain.com" \
  --dest-pass "dest-app-password" \
  "INBOX" \
  --src-delete
```

### 4. Sync Mode (Delete from Destination)
Keep destination in sync by deleting emails that no longer exist in the source.

Note: `--dest-delete` is not supported in `--gmail-mode`.
```bash
# Migration: Delete destination emails not found in source
python3 migrate_imap_emails.py \
  --src-host "imap.gmail.com" \
  --src-user "source@gmail.com" \
  --src-pass "source-app-password" \
  --dest-host "imap.other.com" \
  --dest-user "dest@domain.com" \
  --dest-pass "dest-app-password" \
  --dest-delete

# Backup: Delete local .eml files not found on server
python3 backup_imap_emails.py \
  --src-host "imap.gmail.com" \
  --src-user "source@gmail.com" \
  --src-pass "source-app-password" \
  --dest-path "./backup" \
  --dest-delete

# Restore: Delete server emails not found in local backup
python3 restore_imap_emails.py \
  --src-path "./backup" \
  --dest-host "imap.other.com" \
  --dest-user "dest@domain.com" \
  --dest-pass "dest-app-password" \
  --dest-delete
```

**Warning:** The `--dest-delete` flag permanently removes emails/files from the destination. Use with caution and always verify your backup is complete before enabling this option.

### 5. Verify Migration
Compare counts between source and destination.
```bash
python3 compare_imap_folders.py \
  --src-host "imap.gmail.com" \
  --src-user "source@gmail.com" \
  --src-pass "source-app-password" \
  --dest-host "imap.other.com" \
  --dest-user "dest@domain.com" \
  --dest-pass "dest-app-password"

# IMAP source -> local backup destination
python3 compare_imap_folders.py \
  --src-host "imap.gmail.com" \
  --src-user "source@gmail.com" \
  --src-pass "source-app-password" \
  --dest-path "./my_backup"

# local backup source -> IMAP destination
python3 compare_imap_folders.py \
  --src-path "./my_backup" \
  --dest-host "imap.other.com" \
  --dest-user "dest@domain.com" \
  --dest-pass "dest-app-password"
```
*Output Example:*
```
Folder Name             | Source Count | Dest Count | Status
------------------------------------------------------------
INBOX                   | 1250         | 1250       | MATCH
...
```

### 6. Local Backup
Download all your emails to your computer as `.eml` files.
```bash
# Backup all folders from an IMAP account to a local folder
python3 backup_imap_emails.py \
  --src-host "imap.gmail.com" \
  --src-user "you@gmail.com" \
  --src-pass "your-app-password" \
  --dest-path "./backup_folder"

# Or via command line
python3 backup_imap_emails.py \
  --src-host "imap.gmail.com" \
  --src-user "you@gmail.com" \
  --src-pass "your-app-password" \
  --dest-path "/Users/jdoe/Documents/Emails"

# Backup single folder
python3 backup_imap_emails.py \
  --src-host "imap.gmail.com" \
  --src-user "you@gmail.com" \
  --src-pass "your-app-password" \
  --dest-path "./my_backup" \
  "[Gmail]/Sent Mail"
```

### 6a. Compare IMAP vs Local Backup
Use `compare_imap_folders.py` to validate an IMAP account against a local backup created by `backup_imap_emails.py`.

```bash
# Option 1: IMAP source -> local destination
python3 compare_imap_folders.py \
  --src-host "imap.gmail.com" \
  --src-user "you@gmail.com" \
  --src-pass "your-app-password" \
  --dest-path "./my_backup"

# Option 2: local source -> IMAP destination
python3 compare_imap_folders.py \
  --src-path "./my_backup" \
  --dest-host "imap.other.com" \
  --dest-user "you@domain.com" \
  --dest-pass "your-app-password"
```

You can also set local paths via environment variables:

```bash
export SRC_LOCAL_PATH="./my_backup"
export DEST_LOCAL_PATH="./my_backup"
```

### 6b. Count a Local Backup
Use `count_imap_emails.py` to get per-folder counts from a local backup created by `backup_imap_emails.py`.

```bash
# Option 1: explicit path
python3 count_imap_emails.py --path "./my_backup"

# Option 2: environment variable
export BACKUP_LOCAL_PATH="./my_backup"
python3 count_imap_emails.py
```

### 7. Gmail Backup with Labels Preservation
When backing up a Gmail account, use `--gmail-mode` for the recommended workflow. This backs up `[Gmail]/All Mail` (no duplicates) and creates a labels manifest for restoration.

```bash
# Recommended: Use --gmail-mode for simplest workflow
python3 backup_imap_emails.py \
  --src-host "imap.gmail.com" \
  --src-user "you@gmail.com" \
  --src-pass "your-app-password" \
  --dest-path "./gmail_backup" \
  --gmail-mode
```

This is equivalent to the more verbose:
```bash
python3 backup_imap_emails.py \
  --src-host "imap.gmail.com" \
  --src-user "you@gmail.com" \
  --src-pass "your-app-password" \
  --dest-path "./gmail_backup" \
  --preserve-labels \
  "[Gmail]/All Mail"
```

**For large accounts (100K+ emails)**, you can build the manifest first to test:
```bash
# Step 1: Build manifest only (fast, no download)
python3 backup_imap_emails.py \
  --src-host "imap.gmail.com" \
  --src-user "you@gmail.com" \
  --src-pass "your-app-password" \
  --dest-path "./gmail_backup" \
  --manifest-only

# Step 2: Download emails (can run later, manifest already exists)
python3 backup_imap_emails.py \
  --src-host "imap.gmail.com" \
  --src-user "you@gmail.com" \
  --src-pass "your-app-password" \
  --dest-path "./gmail_backup" \
  "[Gmail]/All Mail"
```

**How it works:**
1. The script scans ALL folders in your Gmail account to identify which emails have which labels
2. Creates a `labels_manifest.json` file mapping each email's `Message-ID` to its labels and IMAP flags
3. Downloads all emails from `[Gmail]/All Mail` (contains every email once, no duplicates)

**Example `labels_manifest.json`:**
```json
{
  "<CAExample123@mail.gmail.com>": {
    "labels": ["INBOX", "Work", "Projects/2024"],
    "flags": ["\\Seen"]
  },
  "<CAExample456@mail.gmail.com>": {
    "labels": ["Sent Mail", "Personal"],
    "flags": ["\\Seen", "\\Flagged"]
  }
}
```

**Preserved IMAP Flags:**
- `\Seen` - Email has been read
- `\Flagged` - Email is starred/flagged
- `\Answered` - Email has been replied to
- `\Draft` - Email is a draft

**Benefits:**
- ✅ No duplicate emails on disk (each email saved once)
- ✅ Labels are preserved for restoration
- ✅ Read/unread and starred status is preserved
- ✅ Includes system labels (INBOX, Sent Mail, Starred) and user labels
- ✅ Progress reporting for large accounts

**Note:** Gmail labels like "Important" that are auto-managed by Gmail are excluded from the manifest as they cannot be reliably restored.

### 8. Backup with Flags Only (Non-Gmail)
For non-Gmail servers, you can preserve read/starred status with `--preserve-flags`:

```bash
python3 backup_imap_emails.py \
  --src-host "imap.example.com" \
  --src-user "you@example.com" \
  --src-pass "your-password" \
  --dest-path "./my_backup" \
  --preserve-flags \
  "INBOX"
```

This creates a `flags_manifest.json` with the status of each email.

### 9. Restore Backup to IMAP Server
Restore emails from a local backup to any IMAP server.

```bash
# Restore all folders from backup
python3 restore_imap_emails.py \
  --src-path "./my_backup" \
  --dest-host "imap.gmail.com" \
  --dest-user "you@gmail.com" \
  --dest-pass "your-app-password"

# Restore with flags (read/starred status)
python3 restore_imap_emails.py \
  --src-path "./my_backup" \
  --dest-host "imap.example.com" \
  --dest-user "you@example.com" \
  --dest-pass "your-password" \
  --apply-flags

# Restore a specific folder
python3 restore_imap_emails.py \
  --src-path "./my_backup" \
  --dest-host "imap.gmail.com" \
  --dest-user "you@gmail.com" \
  --dest-pass "your-app-password" \
  "INBOX"
```

### 10. Gmail Restore with Labels
Restore a Gmail backup with full label structure using `--gmail-mode`:

```bash
python3 restore_imap_emails.py \
  --src-path "./gmail_backup" \
  --dest-host "imap.gmail.com" \
  --dest-user "newaccount@gmail.com" \
  --dest-pass "your-app-password" \
  --gmail-mode
```

**How Gmail restore works:**
1. Reads emails from the backup (typically `[Gmail]/All Mail`)
2. Uploads each email to the first usable label folder (preserving original flags)
  - If an email has no usable labels, it is uploaded to `Restored/Unlabeled`
3. Looks up the Message-ID in `labels_manifest.json`
4. Copies the email to each label folder (e.g., "Work", "Personal", "Projects/2024")

**Alternatively**, restore folders individually with labels and flags applied:
```bash
python3 restore_imap_emails.py \
  --src-path "./gmail_backup" \
  --dest-host "imap.gmail.com" \
  --dest-user "newaccount@gmail.com" \
  --dest-pass "your-app-password" \
  --apply-labels \
  --apply-flags
```

## Troubleshooting

- **"Too many simultaneous connections"**: 
  IMAP servers (especially Gmail) limit the number of active connections per IP or user (typically ~15). Since `migrate_imap_emails.py` uses multiple threads, you may hit this limit.
  **Solution**: Reduce `MAX_WORKERS` to `4` or `2` using the environment variable.

- **Authentication Errors**: 
  If you are using Gmail or Google Workspace, you generally **cannot** use your regular login password. You must enable 2-Step Verification and generate an **App Password**. Use that App Password in the `_PASSWORD` variable.

- **Timeouts / Socket Errors**:
  Migrating 100k+ emails is network intensive. If the script crashes, simply run it again. The built-in de-duplication will skip already migrated messages and resume where it left off.

### Gmail "All Mail" & Deletion
If you are migrating **from** a Gmail account and using the `--src-delete` option:
- The script attempts to detect your Trash folder (e.g., `[Gmail]/Trash` or `[Gmail]/Bin`).
- Instead of simply marking emails as deleted (which Gmail often treats as "Archive"), the script **copies the email to the Trash folder** and then marks the original as deleted.
- This ensures that the storage count in `[Gmail]/All Mail` actually decreases, as the emails are moved to the Trash (which is auto-emptied by Google after 30 days) rather than remaining in your "All Mail" archive.

## Development & Testing

### Setting Up the Development Environment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/JCallico/imap-migration-tools.git
   cd imap-migration-tools
   ```

2. **Create a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install development dependencies:**
   ```bash
   pip install -r requirements.txt
   # Or using Make:
   make install-dev
   ```

### Running Tests

The project uses `pytest` for testing with a custom mock IMAP server for integration tests.

```bash
# Run all tests
make test

# Run tests with verbose output
PYTHONPATH=src pytest test/ -v

# Run tests with coverage report
make coverage

# Run a specific test file
PYTHONPATH=src pytest test/test_migrate_imap_emails.py -v

# Run a specific test
PYTHONPATH=src pytest test/test_imap_common.py::TestNormalizeFolderName -v
```

### Code Quality

```bash
# Run linter
make lint

# Auto-format code
make format

# Check formatting without modifying
make format-check

# Run security scan
make security

# Run type checker
make typecheck

# Run all CI checks locally
make ci
```

### Test Structure

| Test File | Description |
|-----------|-------------|
| `test_migrate_imap_emails.py` | Email migration tests (basic, duplicates, deletion, folders) |
| `test_backup_imap_emails.py` | Backup functionality tests |
| `test_restore_imap_emails.py` | Restore functionality tests |
| `test_count_imap_emails.py` | Email counting tests |
| `test_compare_imap_folders.py` | Folder comparison tests |
| `test_imap_common.py` | Shared utility function tests |

### Continuous Integration

The project uses GitHub Actions for CI. On every push and pull request:
- **Lint**: Code style and formatting checks (Ruff)
- **Test**: Runs on Python 3.9, 3.10, 3.11, 3.12, and 3.13
- **Security**: Bandit security scanner
- **Type Check**: mypy static type analysis

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
