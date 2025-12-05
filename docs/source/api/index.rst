API Reference
=============

This section contains the API documentation for package-scan's core components and adapters.

.. toctree::
   :maxdepth: 2

   core
   adapters

Core Modules
------------

The core modules provide shared functionality used across all ecosystems:

* **models**: Data structure for threat findings
* **threat_database**: Threat database management
* **report_engine**: Report generation and formatting

Ecosystem Adapters
------------------

Adapters implement ecosystem-specific scanning logic:

* **npm_adapter**: JavaScript/Node.js ecosystem
* **java_adapter**: Maven/Gradle ecosystem
* **python_adapter**: Python/pip ecosystem

Each adapter implements the ``EcosystemAdapter`` interface defined in ``base.py``.
