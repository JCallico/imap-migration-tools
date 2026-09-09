"""Compatibility helpers for count callers using the original function API."""

import imaplib

from utils import imap_common


def count_emails(imap_server, username, password=None, oauth2_token=None):
    """Count an IMAP account and render the historical console table."""
    try:
        print(f"Connecting to {imap_server}...")
        mail = imap_common.get_imap_connection(imap_server, username, password, oauth2_token)
        if not mail:
            return
        print("Listing mailboxes...")
        folders = imap_common.list_selectable_folders(mail)
        if not folders:
            print("Failed to list mailboxes.")
            return
        total = 0
        print(f"{'Folder Name':<40} {'Count':>10}")
        print("-" * 52)
        for folder in folders:
            try:
                status, _ = mail.select(f'"{folder}"', readonly=True)
                if status != "OK":
                    print(f"{folder:<40} {'Skipped':>10}")
                    continue
                status, data = mail.search(None, "ALL")
                if status != "OK":
                    print(f"{folder:<40} {'Error':>10}")
                    continue
                count = len(data[0].split()) if data and data[0] else 0
                print(f"{folder:<40} {count:>10}")
                total += count
            except imaplib.IMAP4.error:
                print(f"{folder:<40} {'Error':>10}")
        print("-" * 52)
        print(f"{'TOTAL':<40} {total:>10}")
        mail.logout()
    except imaplib.IMAP4.error as exc:
        print(f"IMAP Error: {exc}")
    except Exception as exc:
        print(f"An error occurred: {exc}")


def count_local_emails(local_path: str) -> None:
    """Count a local backup and render the historical console table."""
    print(f"Scanning local backup: {local_path}")
    folders = imap_common.list_local_folders(local_path)
    if not folders:
        print("No folders found.")
        return
    total = 0
    print(f"{'Folder Name':<40} {'Count':>10}")
    print("-" * 52)
    for folder in folders:
        count = imap_common.get_local_email_count(local_path, folder)
        if count is None:
            print(f"{folder:<40} {'N/A':>10}")
            continue
        print(f"{folder:<40} {count:>10}")
        total += count
    print("-" * 52)
    print(f"{'TOTAL':<40} {total:>10}")
