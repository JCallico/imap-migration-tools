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
   - **Robust**: Preserves read/unread status (flags) and original dates.
   - **Cleanup**: Optionally deletes messages from the source after successful transfer (effectively a "Move" operation).
     - *Improved for Gmail*: Automatically detects "Trash" folders to ensure emails are properly binned rather than just archived.
   - **Configurable**: Adjustable concurrency and batch sizes to respect server rate limits.

2. **`compare_imap_folders.py`** (The Validator)
   - Connects to both Source and Destination accounts.
   - Prints a side-by-side comparison table of message counts for every folder.
   - Essential for verifying that the migration was successful and that counts match.

3. **`count_imap_emails.py`** (The Investigator)
   - A simple utility to connect to a single account and count emails in all folders. Useful for initial assessment.

4. **`backup_imap_emails.py`** (The Backup)
   - Downloads emails from an IMAP account to a local disk.
   - **Format**: Saves emails as individual `.eml` files (RFC 5322), compatible with Outlook, Thunderbird, and Apple Mail.
   - **Structure**: Replicates the IMAP folder hierarchy locally.
   - **Incremental**: Skips emails that have already been downloaded (based on UID) so you can run it periodically to fetch new messages.

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
python3 migrate_imap_emails.py --src-user "me@gmail.com" --dest-user "you@domain.com" --workers 4 --delete
```

**Comparison:**
```bash
python3 compare_imap_folders.py --src-host "imap.gmail.com" --dest-host "imap.other.com"
```

**Counting:**
```bash
python3 count_imap_emails.py --host "imap.gmail.com" --user "me@gmail.com" --pass "secret"
```

**Backup:**
```bash
python3 backup_imap_emails.py --src-user "me@gmail.com" --dest-path "./my_backup"
```

## Usage Examples

### 1. Full Migration
Migrate all folders from Source to Destination.
```bash
python3 migrate_imap_emails.py
```

### 2. Single Folder Migration
Migrate ONLY a specific folder (e.g., trying to fix just "Important" or "Sent").
```bash
# Syntax: python3 migrate_imap_emails.py "[Folder Name]"
python3 migrate_imap_emails.py "[Gmail]/Important"
```

### 3. Move Instead of Copy
Migrate and **delete** from source immediately after verifying the copy.
```bash
# Using flag
python3 migrate_imap_emails.py --delete

# Or specific folder with delete
python3 migrate_imap_emails.py "Inbox" --delete
```

### 4. Verify Migration
Compare counts between source and destination.
```bash
python3 compare_imap_folders.py
```
*Output Example:*
```
Folder Name             | Source Count | Dest Count | Status
------------------------------------------------------------
INBOX                   | 1250         | 1250       | MATCH
...
```

### 5. Local Backup
Download all your emails to your computer as `.eml` files.
```bash
# Set destination path
export BACKUP_LOCAL_PATH="./backup_folder"
python3 backup_imap_emails.py

# Or via command line
python3 backup_imap_emails.py --dest-path "/Users/jdoe/Documents/Emails" 

# Backup single folder
python3 backup_imap_emails.py --dest-path "./my_backup" "[Gmail]/Sent Mail"
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
If you are migrating **from** a Gmail account and using the `--delete` option:
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
