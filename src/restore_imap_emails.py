#!/usr/bin/env python3
"""
DEPRECATED: This script has been renamed.
Please use imap_restore.py instead.
"""

import sys

from imap_restore import main

if __name__ == "__main__":
    print(
        "WARNING: 'restore_imap_emails.py' is deprecated and will be removed in a future version. Exact functionality is now available via 'imap_restore.py'.",
        file=sys.stderr,
    )
    print("Redirecting to 'imap_restore.py'...", file=sys.stderr)
    try:
        main()
    except KeyboardInterrupt:
        print("\nProcess terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal Error: {e}")
        sys.exit(1)
