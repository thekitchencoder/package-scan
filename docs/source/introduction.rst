Introduction
============

Overview
--------

**package-scan** is a rapid-response tool for detecting compromised packages during active supply chain attacks. When a new attack emerges (like sha1-Hulud or event-stream), security teams need to quickly scan their infrastructure against lists of known compromised packages.

**This is NOT a comprehensive vulnerability scanner** like Snyk or npm audit. It's a **focused tool for incident response** that prioritizes speed, simplicity, and flexibility.

Why package-scan?
-----------------

**Use package-scan when:**

* A new supply chain attack is discovered
* You have a list of compromised packages to check against
* You need results in minutes, not hours
* You're scanning multiple ecosystems (npm, Maven, Python)
* You need to share threat intelligence via simple CSV files

**Use other tools for:**

* Ongoing vulnerability monitoring → Snyk, Dependabot
* CVE database scanning → npm audit, pip-audit
* SBOM generation → Syft, CycloneDX
* Static code analysis → Semgrep, CodeQL

Key Capabilities
----------------

**Rapid Deployment**
   Docker container ready in seconds, pip install in minutes

**Multi-Ecosystem**
   Scans npm, Maven/Gradle, Python (pip/Poetry/Pipenv/conda)

**Simple Threat Lists**
   CSV-based format that's easy to create and share

**Version Intelligence**
   Handles semver ranges (^, ~), Maven ranges ([,)), PEP 440 (>=, ~=)

**CI/CD Ready**
   JSON output, exit codes, minimal dependencies

The Incident Response Workflow
-------------------------------

1. **Attack Announced**: Security vendor publishes compromised package list
2. **Create Threat CSV**: Format packages as ``ecosystem,name,version``
3. **Deploy Scanner**: Use Docker for rapid deployment across infrastructure
4. **Scan Projects**: Identify which codebases are affected
5. **Share Results**: JSON reports for team analysis and remediation

Supported Ecosystems
--------------------

npm (JavaScript/Node.js)
~~~~~~~~~~~~~~~~~~~~~~~~

Scans:
* package.json manifests
* package-lock.json (npm)
* yarn.lock (Yarn)
* pnpm-lock.yaml (pnpm)
* node_modules/ installed packages

Maven/Gradle (Java)
~~~~~~~~~~~~~~~~~~~

Scans:
* pom.xml (Maven)
* build.gradle (Gradle Groovy DSL)
* build.gradle.kts (Gradle Kotlin DSL)
* gradle.lockfile (Gradle lockfiles)

pip (Python)
~~~~~~~~~~~~

Scans:
* requirements.txt files
* pyproject.toml (Poetry)
* poetry.lock
* Pipfile (pipenv)
* Pipfile.lock
* environment.yml (conda)

Threat Database
---------------

The tool uses CSV-based threat databases located in the ``threats/`` directory. Each CSV file represents a specific supply chain attack or threat campaign.

**Format**::

   ecosystem,name,version
   npm,left-pad,1.3.0
   maven,org.springframework:spring-core,5.3.0
   pip,requests,2.8.1

**Built-in Threats:**

* **sha1-Hulud.csv**: sha1-Hulud worm (790 packages, 1,056 versions)
* **sample-threats.csv**: Test threats for all ecosystems

You can also provide custom threat databases using the ``--csv`` option.

How It Works
------------

1. **Detection**: Scans directories for package manifests and lockfiles
2. **Parsing**: Extracts package names and versions from various formats
3. **Matching**: Compares against threat database with intelligent version matching
4. **Reporting**: Generates detailed findings with file locations and remediation

The scanner uses ecosystem-specific adapters that understand each package manager's file formats and version semantics.
