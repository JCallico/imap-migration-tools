"""Compatibility alias for the shared config module."""

import sys

from ui import config as _implementation

sys.modules[__name__] = _implementation
