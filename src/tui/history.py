"""Compatibility alias for the shared history module."""

import sys

from ui import history as _implementation

sys.modules[__name__] = _implementation
