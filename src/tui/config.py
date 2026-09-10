"""Compatibility alias for the shared config module."""

import sys

from ui_core import config as _implementation

sys.modules[__name__] = _implementation
