#!/usr/bin/env python3
"""
DEPRECATED: This script has been renamed.
Please use imap_migrate.py instead.
"""

import sys

# Safe print helper might be needed if imap_migrate relies on it,
# but main() usually handles execution.
from imap_migrate import main

if __name__ == "__main__":
    print(
        "WARNING: 'migrate_imap_emails.py' is deprecated and will be removed in a future version. Exact functionality is now available via 'imap_migrate.py'.",
        file=sys.stderr,
    )
    print("Redirecting to 'imap_migrate.py'...", file=sys.stderr)
    try:
        main()
    except KeyboardInterrupt:
        print("\nProcess terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal Error: {e}")
        sys.exit(1)
