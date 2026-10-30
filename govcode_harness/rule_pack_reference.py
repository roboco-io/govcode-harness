"""Compatibility alias for :mod:`govcode_harness.project.reference`."""
from importlib import import_module as _import_module
import sys as _sys

_sys.modules[__name__] = _import_module('.project.reference', __package__)
