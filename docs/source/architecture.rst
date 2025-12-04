Architecture
============

Overview
--------

package-scan uses a modular architecture with ecosystem-specific adapters. This design allows easy extension to new package ecosystems while maintaining a consistent API.

.. code-block:: text

    src/package_scan/
    ├── cli.py                  # Multi-ecosystem CLI
    ├── core/                   # Shared components
    │   ├── models.py           # Finding, Remediation dataclasses
    │   ├── threat_database.py  # Multi-ecosystem CSV loading
    │   └── report_engine.py    # Unified reporting
    └── adapters/               # Ecosystem-specific scanners
        ├── base.py             # EcosystemAdapter interface
        ├── npm_adapter.py      # JavaScript/Node.js
        ├── java_adapter.py     # Maven/Gradle
        └── python_adapter.py   # pip/poetry/pipenv/conda

Core Components
---------------

CLI (cli.py)
~~~~~~~~~~~~

The main command-line interface built with Click. Responsibilities:

* Parse command-line arguments
* Load threat database
* Detect and instantiate appropriate adapters
* Coordinate scanning across ecosystems
* Aggregate and display results

**Key Functions:**

* ``cli()``: Main entry point
* ``npm_scan_cli()``: Legacy npm-only command

ThreatDatabase (core/threat_database.py)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Manages the threat database with multi-ecosystem support.

**Responsibilities:**

* Load threats from CSV files
* Support threat-specific loading (e.g., --threat sha1-Hulud)
* Query compromised versions by ecosystem and package
* Track which threats were loaded for reporting

**Key Methods:**

* ``load_threats()``: Load from threats directory or specific CSV
* ``get_compromised_versions(ecosystem, package)``: Query vulnerabilities
* ``get_all_packages()``: Get all packages in database
* ``get_ecosystems()``: Get list of ecosystems
* ``get_loaded_threats()``: Get list of loaded threat names

**Data Structure:**

.. code-block:: python

    {
        'npm': {
            'left-pad': ['1.3.0'],
            'lodash': ['4.17.20', '4.17.21']
        },
        'maven': {
            'org.springframework:spring-core': ['5.3.0']
        }
    }

ReportEngine (core/report_engine.py)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Aggregates findings from all adapters and generates reports.

**Responsibilities:**

* Collect findings from multiple adapters
* Generate summary statistics by ecosystem
* Format console output
* Export JSON reports

**Key Methods:**

* ``add_findings(findings)``: Add findings from an adapter
* ``print_report()``: Display formatted console output
* ``save_report(filepath)``: Export JSON report
* ``_generate_summary()``: Calculate statistics

Finding Model (core/models.py)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Standardized data structure for vulnerability findings.

**Fields:**

* ``ecosystem``: npm, maven, or pip
* ``finding_type``: manifest, lockfile, or installed
* ``file_path``: Location where found
* ``package_name``: Name of compromised package
* ``version``: Compromised version
* ``match_type``: exact or range
* ``declared_spec``: Original version specification (optional)
* ``remediation``: Remediation suggestions (optional)

**Methods:**

* ``to_dict()``: Convert to dictionary for JSON export
* ``from_legacy_npm_dict()``: Convert legacy format

Remediation Model (core/models.py)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Remediation suggestions for findings.

**Fields:**

* ``strategy``: upgrade, remove, pin, or review
* ``suggested_version``: Recommended version (optional)
* ``notes``: Additional information (optional)

Ecosystem Adapters
------------------

Base Adapter (adapters/base.py)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Abstract base class defining the adapter interface.

**Required Methods:**

* ``_get_ecosystem_name()``: Return ecosystem identifier
* ``get_manifest_files()``: List of manifest filenames
* ``get_lockfile_names()``: List of lockfile filenames
* ``detect_projects(root_dir)``: Find project directories
* ``scan_project(project_dir)``: Scan a single project

**Provided Methods:**

* ``scan(root_dir)``: Scan directory tree (implemented in base)

NpmAdapter (adapters/npm_adapter.py)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Handles JavaScript/Node.js ecosystem.

**Supported Files:**

* package.json (manifest)
* package-lock.json (npm lockfile, v1/v2/v3)
* yarn.lock (Yarn lockfile)
* pnpm-lock.yaml (pnpm lockfile)
* node_modules/ (installed packages)

**Version Matching:**

Uses ``semantic_version.NpmSpec`` for npm semver ranges:

* ``^1.2.3`` → >=1.2.3 <2.0.0
* ``~1.2.3`` → >=1.2.3 <1.3.0
* ``>=1.0.0 <2.0.0`` → range matching

**Key Methods:**

* ``_scan_package_json()``: Parse package.json
* ``_scan_package_lock_json()``: Parse package-lock.json
* ``_scan_yarn_lock()``: Parse yarn.lock
* ``_scan_pnpm_lock_yaml()``: Parse pnpm-lock.yaml
* ``_scan_node_modules()``: Scan installed packages

JavaAdapter (adapters/java_adapter.py)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Handles Maven and Gradle ecosystems.

**Supported Files:**

* pom.xml (Maven manifest)
* build.gradle (Gradle Groovy DSL)
* build.gradle.kts (Gradle Kotlin DSL)
* gradle.lockfile (Gradle lockfile)

**Version Matching:**

* Maven ranges: ``[1.0,2.0)``, ``[1.0,)``, ``(,2.0)``
* Gradle dynamic: ``1.2.+``
* Exact versions: ``1.2.3``

**Package Naming:**

Maven uses ``groupId:artifactId`` format:
``org.springframework:spring-core``

**Key Methods:**

* ``_scan_pom_xml()``: Parse Maven POM with XML
* ``_scan_gradle_build()``: Parse Gradle files with regex
* ``_is_maven_range()``: Detect version ranges
* ``_get_matching_maven_versions()``: Match version ranges

PythonAdapter (adapters/python_adapter.py)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Handles Python package ecosystem.

**Supported Files:**

* requirements.txt, requirements-\*.txt
* pyproject.toml (Poetry)
* poetry.lock
* Pipfile (pipenv)
* Pipfile.lock
* environment.yml (conda)

**Version Matching:**

PEP 440 specifiers:

* ``==1.2.3`` → exact match
* ``>=1.0,<2.0`` → range match
* ``~=1.2.0`` → compatible release
* Poetry caret: ``^1.2.3`` → >=1.2.3,<2.0.0
* Poetry tilde: ``~1.2.3`` → >=1.2.3,<1.3.0

**Package Naming:**

Normalized to lowercase (PyPI convention)

**Key Methods:**

* ``_scan_requirements_txt()``: Parse requirements files
* ``_scan_pyproject_toml()``: Parse Poetry manifests
* ``_scan_poetry_lock()``: Parse Poetry lockfiles
* ``_scan_pipfile()``: Parse Pipfile
* ``_scan_pipfile_lock()``: Parse Pipfile.lock
* ``_scan_conda_environment()``: Parse conda environments

Data Flow
---------

1. **CLI Parsing**

   * User runs ``package-scan --dir /path --threat sha1-Hulud``
   * CLI parses arguments and options

2. **Threat Loading**

   * ThreatDatabase loads specified threat(s)
   * CSV files parsed into in-memory structure

3. **Adapter Detection**

   * CLI determines which ecosystems to scan
   * Instantiates appropriate adapters

4. **Project Discovery**

   * Each adapter scans directory tree
   * Identifies relevant manifest/lockfiles

5. **Scanning**

   * Adapters parse files and extract packages
   * Version matching against threat database
   * Generate Finding objects

6. **Aggregation**

   * ReportEngine collects findings from all adapters
   * Calculates summary statistics

7. **Output**

   * Console: Formatted, grouped output
   * JSON: Structured report with metadata

Adding New Ecosystems
---------------------

To add support for a new ecosystem (e.g., Ruby/gem):

1. **Create Adapter**

   Create ``src/package_scan/adapters/ruby_adapter.py``

2. **Inherit from Base**

   .. code-block:: python

      from .base import EcosystemAdapter

      class RubyAdapter(EcosystemAdapter):
          def _get_ecosystem_name(self):
              return 'gem'

3. **Implement Required Methods**

   * ``get_manifest_files()`` → ['Gemfile']
   * ``get_lockfile_names()`` → ['Gemfile.lock']
   * ``detect_projects()`` → Find directories with Gemfile
   * ``scan_project()`` → Parse and scan Ruby files

4. **Register Adapter**

   In ``adapters/__init__.py``:

   .. code-block:: python

      from .ruby_adapter import RubyAdapter

      ADAPTER_REGISTRY = {
          'npm': NpmAdapter,
          'maven': JavaAdapter,
          'pip': PythonAdapter,
          'gem': RubyAdapter,  # Add new adapter
      }

5. **Add Test Fixtures**

   Create ``examples/test-ruby/`` with sample files

6. **Update Documentation**

   Add ecosystem to documentation and README

No changes to core components are needed!

Design Principles
-----------------

**Separation of Concerns**
   Core logic separate from ecosystem-specific code

**Open/Closed Principle**
   Open for extension (new adapters), closed for modification (core)

**Single Responsibility**
   Each component has one clear purpose

**Dependency Inversion**
   Core depends on adapter interface, not implementations

**Graceful Degradation**
   Optional dependencies handled with warnings

Performance Considerations
--------------------------

**Lazy Loading**
   Only load adapters for detected ecosystems

**Skip Patterns**
   Automatically skip node_modules, .git, venv, build directories

**Streaming**
   Parse large files line-by-line where possible

**No Execution**
   Pure static analysis, never executes package managers

**Single Pass**
   Each file parsed once, results cached

Security Considerations
-----------------------

**Sandboxed Execution**
   Only reads files, never executes commands

**Path Validation**
   Stays within specified scan directory

**No Network Access**
   No external API calls or downloads

**Read-Only**
   Never modifies scanned files or directories

**Static Analysis**
   Threat detection via file parsing only
