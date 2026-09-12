"""Compatibility alias for the shared runner module."""

import sys

from ui import runner as _implementation

sys.modules[__name__] = _implementation
