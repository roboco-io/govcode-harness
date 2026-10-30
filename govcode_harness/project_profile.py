"""Compatibility alias for :mod:`govcode_harness.project.profile`."""
from importlib import import_module as _import_module
import sys as _sys

_sys.modules[__name__] = _import_module('.project.profile', __package__)
