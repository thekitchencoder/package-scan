"""
Multi-Ecosystem Package Threat Scanner

Scans for compromised packages across npm, Maven/Gradle, Python, and Ruby ecosystems
"""

__version__ = "0.2.0"

from . import core
from . import adapters

__all__ = ['core', 'adapters', '__version__']
