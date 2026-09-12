"""Compatibility alias for the shared layout module."""

import sys

from ui import layout as _implementation

sys.modules[__name__] = _implementation
