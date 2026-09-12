"""Desktop bundle launcher, including its private subprocess worker mode."""

import sys

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--imap-worker":
        from ui.worker import main

        main(sys.argv[2:])
    else:
        from gui import main

        main()
