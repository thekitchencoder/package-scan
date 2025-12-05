Usage
=====

Basic Usage
-----------

Scan Current Directory
~~~~~~~~~~~~~~~~~~~~~~

Scan the current directory for all threats::

    package-scan

Scan Specific Directory
~~~~~~~~~~~~~~~~~~~~~~~

::

    package-scan --dir /path/to/project

Threat Selection
----------------

Scan for Specific Threat
~~~~~~~~~~~~~~~~~~~~~~~~~

::

    package-scan --threat sha1-Hulud

Scan for Multiple Threats
~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    package-scan --threat sha1-Hulud --threat custom-threat

Use Custom CSV File
~~~~~~~~~~~~~~~~~~~

::

    package-scan --csv /path/to/custom-threats.csv

Ecosystem Selection
-------------------

Scan Specific Ecosystem
~~~~~~~~~~~~~~~~~~~~~~~~

::

    package-scan --ecosystem npm        # npm only
    package-scan --ecosystem maven      # Maven/Gradle only
    package-scan --ecosystem pip        # Python only

Scan Multiple Ecosystems
~~~~~~~~~~~~~~~~~~~~~~~~~

::

    package-scan --ecosystem npm,maven,pip

List Available Ecosystems
~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    package-scan --list-ecosystems

Output Options
--------------

Custom Output File
~~~~~~~~~~~~~~~~~~

::

    package-scan --output my_report.json

Disable JSON Report
~~~~~~~~~~~~~~~~~~~

::

    package-scan --no-save


Listing Compromised Packages
-----------------------------

Display Compromised Packages
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    package-scan --list-affected-packages

This displays all compromised packages in the threat database(s) in a formatted view.

CSV Output of Database
~~~~~~~~~~~~~~~~~~~~~~

::

    package-scan --list-affected-packages-csv

Outputs the raw CSV data from the threat database.

Filter by Threat
~~~~~~~~~~~~~~~~

::

    package-scan --list-affected-packages --threat sha1-Hulud

Docker Usage
------------

Basic Docker Scan
~~~~~~~~~~~~~~~~~

::

    docker run --rm -v "$(pwd):/workspace" kitchencoder/package-scan:latest

Scan for Specific Threat
~~~~~~~~~~~~~~~~~~~~~~~~~

::

    docker run --rm -v "$(pwd):/workspace" kitchencoder/package-scan:latest --threat sha1-Hulud

Custom Threat Database
~~~~~~~~~~~~~~~~~~~~~~

::

    docker run --rm \
      -v "$(pwd):/workspace" \
      -v "$(pwd)/custom.csv:/app/custom.csv" \
      kitchencoder/package-scan:latest --csv /app/custom.csv

Save Report to Host
~~~~~~~~~~~~~~~~~~~

::

    docker run --rm -v "$(pwd):/workspace" kitchencoder/package-scan:latest --output scan_results.json

The report will be saved to ``./scan_results.json`` on your host machine.

Exit Codes
~~~~~~~~~~

* **0**: No threats found
* **1**: Threats found
* **2**: Error occurred

Legacy Commands
---------------

npm-scan Command
~~~~~~~~~~~~~~~~

For backward compatibility, the ``npm-scan`` command is still available::

    npm-scan --dir /path/to/project

This is equivalent to::

    package-scan --ecosystem npm --dir /path/to/project

hulud-scan Alias
~~~~~~~~~~~~~~~~

The ``hulud-scan`` command is an alias for ``package-scan``::

    hulud-scan --dir /path/to/project

Common Use Cases
----------------

CI/CD Integration
~~~~~~~~~~~~~~~~~

GitHub Actions example::

    - name: Scan for compromised packages
      run: |
        pip install package-scan
        package-scan --no-save || exit 1

The ``--no-save`` flag skips writing the JSON report, and the command exits with code 1 if threats are found.

Scan Monorepo
~~~~~~~~~~~~~

::

    package-scan --dir /path/to/monorepo

The scanner will automatically detect and scan all sub-projects.

Audit Specific Dependency File
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    package-scan --dir /path/to/directory --ecosystem npm

Generate Audit Report
~~~~~~~~~~~~~~~~~~~~~

::

    package-scan --output audit-$(date +%Y%m%d).json

Troubleshooting
---------------

No Findings When Expected
~~~~~~~~~~~~~~~~~~~~~~~~~

1. Check that threat database includes the package::

    package-scan --list-affected-packages | grep package-name

2. Verify ecosystem is being scanned::

    package-scan --list-ecosystems

3. Check version matching is correct

False Positives
~~~~~~~~~~~~~~~

If you believe a finding is incorrect:

1. Check the package version in your manifest/lockfile
2. Verify the threat database has the correct version
3. Review version range matching behavior

Performance Issues
~~~~~~~~~~~~~~~~~~

For large monorepos:

1. Scan specific ecosystems: ``--ecosystem npm``
2. Scan specific directories
3. Use Docker for isolated environment

Output Format
-------------

Console Output
~~~~~~~~~~~~~~

The console output groups findings by ecosystem and type:

* **MANIFEST FILES**: Dependencies with vulnerable version ranges
* **LOCK FILES**: Exact resolved versions from lockfiles
* **INSTALLED PACKAGES**: Actually installed packages (npm only)

Each finding includes:
* File path
* Package name and version
* Version specification (for manifests)
* Match type (exact or range)

JSON Output
~~~~~~~~~~~

The JSON report includes::

    {
      "total_findings": 10,
      "threats": ["sha1-Hulud"],
      "ecosystems": ["npm", "maven", "pip"],
      "summary": {
        "npm": {
          "total": 5,
          "manifest": 2,
          "lockfile": 3,
          "unique_packages": 4
        },
        ...
      },
      "findings": [...]
    }

Each finding contains:
* ``ecosystem``: Package ecosystem
* ``finding_type``: manifest, lockfile, or installed
* ``file_path``: Path to file where found
* ``package_name``: Name of package
* ``version``: Compromised version
* ``match_type``: exact or range
* ``declared_spec``: Version specification (for ranges)
