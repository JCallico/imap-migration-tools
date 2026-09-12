"""Console-capable worker bundled alongside the windowed desktop executable."""

import sys

from ui.worker import main

if __name__ == "__main__":
    main(sys.argv[2:] if sys.argv[1:2] == ["--imap-worker"] else sys.argv[1:])
