"""
IMAP Email Counting Script

This script connects to an IMAP server, iterates through all available folders/mailboxes,
and counts the number of emails in each. It provides a progressive output of counts
per folder and a grand total at the end.

Configuration (Environment Variables):
  IMAP_SERVER   : IMAP Host (e.g., imap.gmail.com)
  IMAP_USERNAME : Username/Email
  IMAP_PASSWORD : Password (or App Password)

Usage Example:
  export IMAP_SERVER="imap.gmail.com"
  export IMAP_USERNAME="user@gmail.com"
  export IMAP_PASSWORD="secretpassword"
  
  python3 count_imap_emails.py
"""

import imaplib
import os
import sys
import re

def count_emails(imap_server, username, password):
    try:
        # Connect to the IMAP server (using SSL)
        print(f"Connecting to {imap_server}...")
        mail = imaplib.IMAP4_SSL(imap_server)

        # Login
        print(f"Logging in as {username}...")
        mail.login(username, password)

        # List all mailboxes
        print("Listing mailboxes...")
        status, folders = mail.list()
        
        if status != "OK":
            print("Failed to list mailboxes.")
            return

        total_all_folders = 0
        print(f"{'Folder Name':<40} {'Count':>10}")
        print("-" * 52)
        
        # Regex to extract folder name: (flags) "delimiter" name
        # Examples: 
        # (\HasNoChildren) "/" "INBOX"  -> Name is "INBOX"
        # (\HasNoChildren) "/" Drafts   -> Name is Drafts
        list_pattern = re.compile(r'\((?P<flags>.*?)\) "(?P<delimiter>.*)" (?P<name>.*)')

        for folder_info in folders:
            folder_info_str = folder_info.decode('utf-8')
            match = list_pattern.search(folder_info_str)
            if match:
                folder_name = match.group('name')
            else:
                # Fallback: simple split if regex fails, assumed last part
                # This might fail for names with spaces if not quoted properly, but list usually quotes them.
                parts = folder_info_str.split()
                folder_name = parts[-1]

            # Display name (remove quotes for printing)
            display_name = folder_name.strip('"')

            try:
                # Select the mailbox (read-only is sufficient for counting)
                # folder_name extracted from list usually handles quotes correctly for select
                rv, _ = mail.select(folder_name, readonly=True)
                if rv != 'OK':
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

if __name__ == "__main__":
    # Configuration - Replace these with your details
    # Ideally, load these from environment variables for security
    IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")
    USERNAME = os.getenv("IMAP_USERNAME", "")
    PASSWORD = os.getenv("IMAP_PASSWORD", "")

    if PASSWORD == "your_password":
        print("Please configure the script with your IMAP credentials.")
        print("You can set environment variables IMAP_SERVER, IMAP_USERNAME, and IMAP_PASSWORD.")
        print("Or edit the script directly (not recommended for shared code).")
        sys.exit(1)

    print("\n--- Configuration Summary ---")
    print(f"IMAP Server : {IMAP_SERVER}")
    print(f"Username    : {USERNAME}")
    print("-----------------------------\n")

    count_emails(IMAP_SERVER, USERNAME, PASSWORD)
