"""Ecosystem-specific scanning adapters"""

from .base import EcosystemAdapter
from .java_adapter import JavaAdapter
from .npm_adapter import NpmAdapter
from .python_adapter import PythonAdapter

__all__ = [
    'EcosystemAdapter',
    'NpmAdapter',
    'JavaAdapter',
    'PythonAdapter',
]

# Registry of available adapters
ADAPTER_REGISTRY = {
    'npm': NpmAdapter,
    'maven': JavaAdapter,
    'pip': PythonAdapter,
    # 'gem': RubyAdapter,     # Coming soon
}


def get_adapter_class(ecosystem: str):
    """
    Get adapter class for a specific ecosystem

    Args:
        ecosystem: Ecosystem name (npm, maven, pip, gem, etc.)

    Returns:
        Adapter class or None if not found
    """
    return ADAPTER_REGISTRY.get(ecosystem.lower())


def get_available_ecosystems():
    """
    Get list of ecosystems with implemented adapters

    Returns:
        List of ecosystem names
    """
    return list(ADAPTER_REGISTRY.keys())
