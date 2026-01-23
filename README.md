# IMAP Email Migration Tools

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
   - **Configurable**: Adjustable concurrency and batch sizes to respect server rate limits.

2. **`compare_imap_folders.py`** (The Validator)
   - Connects to both Source and Destination accounts.
   - Prints a side-by-side comparison table of message counts for every folder.
   - Essential for verifying that the migration was successful and that counts match.

3. **`count_imap_emails.py`** (The Investigator)
   - A simple utility to connect to a single account and count emails in all folders. Useful for initial assessment.

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

The scripts use environment variables for configuration. Here is how to set them and run the scripts on different operating systems.

### Linux / macOS (Bash/Zsh)

1. **Set Environment Variables:**
   ```bash
   # Source Account
   export SRC_IMAP_SERVER="imap.gmail.com"
   export SRC_IMAP_USERNAME="source@gmail.com"
   export SRC_IMAP_PASSWORD="your-app-password"

   # Destination Account
   export DEST_IMAP_SERVER="imap.destination.com"
   export DEST_IMAP_USERNAME="dest@domain.com"
   export DEST_IMAP_PASSWORD="dest-app-password"

   # Options (Optional)
   export DELETE_FROM_SOURCE="false"  # Set to "true" to delete from source after copy
   export MAX_WORKERS=4               # Reduce threads if hitting connection limits
   export BATCH_SIZE=10               # Emails per batch
   ```

2. **Run the Script:**
   ```bash
   python3 migrate_imap_emails.py
   ```

### Windows (PowerShell)

1. **Set Environment Variables:**
   ```powershell
   # Source Account
   $env:SRC_IMAP_SERVER="imap.gmail.com"
   $env:SRC_IMAP_USERNAME="source@gmail.com"
   $env:SRC_IMAP_PASSWORD="your-app-password"

   # Destination Account
   $env:DEST_IMAP_SERVER="imap.destination.com"
   $env:DEST_IMAP_USERNAME="dest@domain.com"
   $env:DEST_IMAP_PASSWORD="dest-app-password"

   # Options (Optional)
   $env:DELETE_FROM_SOURCE="false"   # Set to "true" to delete from source after copy
   $env:MAX_WORKERS=4                # Reduce threads if hitting connection limits
   $env:BATCH_SIZE=10                # Emails per batch
   ```

2. **Run the Script:**
   ```powershell
   python migrate_imap_emails.py
   ```

## Usage

### 1. Run the Migration
The main migration process. It will create folders on the destination if they don't exist.
```bash
python3 migrate_imap_emails.py
```
*Note: If you interrupt the script (Ctrl+C), it handles the shutdown gracefully, finishing current batches before exiting.*

### 2. Verify the Migration
After migration, run this to see if the counts match up.
```bash
python3 compare_imap_folders.py
```
*Output Example:*
```
Folder Name             | Source Count | Dest Count | Status
------------------------------------------------------------
INBOX                   | 1250         | 1250       | MATCH
[Gmail]/Sent Mail       | 5432         | 5432       | MATCH
Archive                 | 200          | 150        | DIFF
```

### 3. Quick Count
To just check the source mailbox:
```bash
python3 count_imap_emails.py
```

## Troubleshooting

- **"Too many simultaneous connections"**: 
  IMAP servers (especially Gmail) limit the number of active connections per IP or user (typically ~15). Since `migrate_imap_emails.py` uses multiple threads, you may hit this limit.
  **Solution**: Reduce `MAX_WORKERS` to `4` or `2` using the environment variable.

- **Authentication Errors**: 
  If you are using Gmail or Google Workspace, you generally **cannot** use your regular login password. You must enable 2-Step Verification and generate an **App Password**. Use that App Password in the `_PASSWORD` variable.

- **Timeouts / Socket Errors**:
  Migrating 100k+ emails is network intensive. If the script crashes, simply run it again. The built-in de-duplication will skip already migrated messages and resume where it left off.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
