"""Temporary bridge for legacy helpers during the compatibility extraction."""

from contextlib import contextmanager


@contextmanager
def progress_reporter(module, reporter):
    """Route a legacy module's safe_print calls through a service event sink."""
    previous = module.safe_print
    module.safe_print = reporter
    try:
        yield
    finally:
        module.safe_print = previous
