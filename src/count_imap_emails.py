"""IMAP Email Counting Script.

Counts emails per folder from either:
- An IMAP account, or
- A local backup folder created by ``backup_imap_emails.py`` (counts ``.eml`` files).

Configuration (Environment Variables):
    IMAP_HOST        : IMAP Host (e.g., imap.gmail.com)
    IMAP_USERNAME    : Username/Email
    IMAP_PASSWORD    : Password (or App Password)

Local backup counting:
    BACKUP_LOCAL_PATH : Local backup root (preferred)
    SRC_LOCAL_PATH    : Alternate local backup root

Examples:
    # Count an IMAP account
    export IMAP_HOST="imap.gmail.com"
    export IMAP_USERNAME="user@gmail.com"
    export IMAP_PASSWORD="secretpassword"
    python3 count_imap_emails.py

    # Count a local backup
    python3 count_imap_emails.py --path "./my_backup"

    # Or set a default local backup path via env var
    export BACKUP_LOCAL_PATH="./my_backup"
    python3 count_imap_emails.py
"""

import argparse
import imaplib
import os
import sys

import imap_common


def count_emails(imap_server, username, password):
    try:
        # Connect to the IMAP server (using SSL)
        print(f"Connecting to {imap_server}...")
        mail = imap_common.get_imap_connection(imap_server, username, password)
        if not mail:
            return

        # List all mailboxes
        print("Listing mailboxes...")
        folders = imap_common.list_selectable_folders(mail)

        if not folders:
            print("Failed to list mailboxes.")
            return

        total_all_folders = 0
        print(f"{'Folder Name':<40} {'Count':>10}")
        print("-" * 52)

        for folder_name in folders:
            display_name = folder_name

            try:
                # Select the mailbox (read-only is sufficient for counting)
                # folder_name extracted from list usually handles quotes correctly for select
                rv, _ = mail.select(f'"{folder_name}"', readonly=True)
                if rv != "OK":
                    print(f"{display_name:<40} {'Skipped':>10}")
                    continue

                # Search for all emails
                status, data = mail.search(None, "ALL")

                if status == "OK":
                    # data[0] is space separated IDs
                    email_ids = data[0].split()
                    count = len(email_ids)
                    print(f"{display_name:<40} {count:>10}")
                    total_all_folders += count
                else:
                    print(f"{display_name:<40} {'Error':>10}")

            except imaplib.IMAP4.error:
                print(f"{display_name:<40} {'Error':>10}")

        print("-" * 52)
        print(f"{'TOTAL':<40} {total_all_folders:>10}")

        # Logout
        mail.logout()

    except imaplib.IMAP4.error as e:
        print(f"IMAP Error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")


def _is_ignored_local_dir(dirname: str) -> bool:
    return dirname.startswith(".") or dirname == "__pycache__"


def list_local_folders(local_root: str) -> list[str]:
    """List all folders under a local backup root in IMAP-style names."""
    folders: set[str] = set()

    for dirpath, dirnames, _filenames in os.walk(local_root):
        dirnames[:] = [d for d in dirnames if not _is_ignored_local_dir(d)]

        if os.path.abspath(dirpath) == os.path.abspath(local_root):
            continue

        rel = os.path.relpath(dirpath, local_root)
        if rel == ".":
            continue

        parts = [p for p in rel.split(os.sep) if p and not _is_ignored_local_dir(p)]
        if not parts:
            continue

        folders.add("/".join(parts))

    return sorted(folders)


def get_local_email_count(local_root: str, folder_name: str):
    """Return the count of .eml files in a local folder, or None if missing/unreadable."""
    folder_path = os.path.join(local_root, *folder_name.split("/"))
    if not os.path.isdir(folder_path):
        return None

    try:
        count = 0
        for filename in os.listdir(folder_path):
            if not filename.endswith(".eml"):
                continue
            full_path = os.path.join(folder_path, filename)
            if os.path.isfile(full_path):
                count += 1
        return count
    except OSError:
        return None


def count_local_emails(local_path: str) -> None:
    print(f"Scanning local backup: {local_path}")

    folders = list_local_folders(local_path)
    if not folders:
        print("No folders found.")
        return

    total_all_folders = 0
    print(f"{'Folder Name':<40} {'Count':>10}")
    print("-" * 52)

    for folder_name in folders:
        count = get_local_email_count(local_path, folder_name)
        if count is None:
            print(f"{folder_name:<40} {'N/A':>10}")
            continue

        print(f"{folder_name:<40} {count:>10}")
        total_all_folders += count

    print("-" * 52)
    print(f"{'TOTAL':<40} {total_all_folders:>10}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Count emails in IMAP account.")

    default_path = os.getenv("BACKUP_LOCAL_PATH") or os.getenv("SRC_LOCAL_PATH")
    parser.add_argument(
        "--path",
        default=default_path,
        help="Local backup root to count (counts .eml files per folder). If set, IMAP args are ignored.",
    )

    # Try to unify var names for defaults. Priority: IMAP_* > SRC_IMAP_* > None
    default_host = os.getenv("IMAP_HOST") or os.getenv("SRC_IMAP_HOST")
    default_user = os.getenv("IMAP_USERNAME") or os.getenv("SRC_IMAP_USERNAME")
    default_pass = os.getenv("IMAP_PASSWORD") or os.getenv("SRC_IMAP_PASSWORD")

    parser.add_argument("--host", default=default_host, help="IMAP Server")
    parser.add_argument("--user", default=default_user, help="Username")
    parser.add_argument("--pass", dest="password", default=default_pass, help="Password")

    args = parser.parse_args()

    if args.path:
        if not os.path.isdir(args.path):
            print(f"Error: Local path does not exist or is not a directory: {args.path}")
            sys.exit(1)

        print("\n--- Configuration Summary ---")
        print(f"Local Path      : {args.path}")
        print("-----------------------------\n")
        count_local_emails(args.path)
        raise SystemExit(0)

    IMAP_SERVER = args.host
    USERNAME = args.user
    PASSWORD = args.password

    if not all([IMAP_SERVER, USERNAME, PASSWORD]):
        print("Error: Missing credentials.")
        print("Please provide --host, --user, --pass via CLI or set IMAP_* / SRC_IMAP_* environment variables.")
        sys.exit(1)

    print("\n--- Configuration Summary ---")
    print(f"Host            : {IMAP_SERVER}")
    print(f"User            : {USERNAME}")
    print("-----------------------------\n")

    count_emails(IMAP_SERVER, USERNAME, PASSWORD)
