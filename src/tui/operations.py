"""Compatibility alias for the shared operations module."""

import sys

from ui_core import operations as _implementation

sys.modules[__name__] = _implementation
