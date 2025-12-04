"""
Multi-Ecosystem Package Threat Scanner

Scans for compromised packages across npm, Maven/Gradle, Python, and Ruby ecosystems
"""

try:
    from importlib.metadata import version
    __version__ = version("package-scan")
except Exception:
    # Fallback for development installs
    __version__ = "0.0.0-dev"

from . import core
from . import adapters

__all__ = ['core', 'adapters', '__version__']
