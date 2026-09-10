"""Compatibility alias for the shared history module."""

import sys

from ui_core import history as _implementation

sys.modules[__name__] = _implementation
