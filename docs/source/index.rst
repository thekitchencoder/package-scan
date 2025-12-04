package-scan documentation
==========================

Welcome to the package-scan documentation!

🐙 **GitHub Repository**: https://github.com/thekitchencoder/package-scan

**package-scan** is a multi-ecosystem package threat scanner that detects compromised packages across npm, Maven/Gradle, and Python (pip) projects.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   introduction
   installation
   usage
   architecture
   api/index
   contributing

Introduction
============

package-scan is a Python CLI tool designed to detect compromised packages across multiple ecosystems. It scans projects against a CSV database of known compromised packages from various supply chain attacks.

**Supported Ecosystems:**

* **npm**: JavaScript/Node.js packages (package.json, lockfiles, node_modules)
* **maven**: Java packages via Maven (pom.xml) and Gradle (build.gradle)
* **pip**: Python packages via pip, Poetry, Pipenv, and conda

Quick Start
-----------

Install the package:

.. code-block:: bash

   pip install -e .

Scan your project:

.. code-block:: bash

   package-scan                        # Scan current directory
   package-scan --threat sha1-Hulud    # Scan for specific threat
   package-scan --ecosystem npm        # Scan npm only

Features
--------

* **Multi-Ecosystem Support**: Scans npm, Maven/Gradle, and Python projects
* **Threat-Based Scanning**: Target specific supply chain attacks
* **Version Range Matching**: Detects vulnerable versions in ranges (^, ~, >=, etc.)
* **Detailed Reporting**: JSON reports with remediation suggestions
* **Modular Architecture**: Easy to extend with new ecosystems
* **Docker Support**: Containerized scanning for CI/CD pipelines

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
