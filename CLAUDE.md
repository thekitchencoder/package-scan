# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

package-scan is a Python CLI tool for detecting compromised packages across multiple ecosystems. It scans JavaScript (npm), Java (Maven/Gradle), and Python (pip/poetry/pipenv/conda) projects against a CSV database of known compromised packages.

**Supported Ecosystems:**
- **npm**: JavaScript/Node.js packages (package.json, lockfiles, node_modules)
- **maven**: Java packages via Maven (pom.xml) and Gradle (build.gradle)
- **pip**: Python packages via pip, Poetry, Pipenv, and conda

## Development Setup

1. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install in editable mode with all optional dependencies:
   ```bash
   pip install -e ".[all]"
   # Or just core dependencies:
   pip install -e .
   ```

3. Verify installation:
   ```bash
   package-scan --help
   package-scan --list-ecosystems
   ```

## Running the Tool

### Multi-Ecosystem Scanning

**Basic scanning:**
```bash
package-scan                                    # Scan current directory (all threats)
package-scan --dir /path/to/project             # Scan specific directory
package-scan --output custom_report.json        # Custom output file
package-scan --no-save                          # Don't save JSON report
```

**Threat selection:**
```bash
package-scan --threat sha1-Hulud                # Scan for specific threat
package-scan --threat sha1-Hulud --threat other # Scan for multiple threats
package-scan --csv /path/to/custom.csv          # Use custom threat CSV file
```

**Scan specific ecosystem:**
```bash
package-scan --ecosystem npm                    # npm only
package-scan --ecosystem maven                  # Maven/Gradle only
package-scan --ecosystem pip                    # Python only
package-scan --ecosystem npm,maven,pip          # Multiple ecosystems
```

**List supported ecosystems:**
```bash
package-scan --list-ecosystems
```

**List compromised packages in database:**
```bash
package-scan --list-affected-packages           # Formatted display
package-scan --list-affected-packages-csv       # Raw CSV output
```

### Legacy npm-only Command

For backward compatibility, the original `npm-scan` command is still available:
```bash
npm-scan --dir /path/to/project
```

### Docker Usage

**Build image:**
```bash
docker build -t package-scan .
```

**Scan a project:**
```bash
# Scan current directory (all threats)
docker run --rm -v "$(pwd):/workspace" package-scan

# Scan for specific threat
docker run --rm -v "$(pwd):/workspace" package-scan --threat sha1-Hulud

# Scan specific ecosystem
docker run --rm -v "$(pwd):/workspace" package-scan --ecosystem maven

# Use custom threat CSV
docker run --rm \
  -v "$(pwd):/workspace" \
  -v "$(pwd)/custom-threat.csv:/app/custom.csv" \
  package-scan --csv /app/custom.csv

# Get help
docker run --rm package-scan --help
```

**Output:**
- Reports saved as `./package_scan_report.json` in the mounted workspace
- Use `--output` to change report filename
- Use `--no-save` to skip saving (console output only)

## Architecture

### Modular Design

The scanner uses a modular architecture with ecosystem-specific adapters:

```
src/package_scan/
├── cli.py                         # Multi-ecosystem CLI
├── core/                          # Shared components
│   ├── models.py                  # Finding, Remediation dataclasses
│   ├── threat_database.py         # Multi-ecosystem CSV loading
│   └── report_engine.py           # Unified reporting
├── adapters/                      # Ecosystem-specific scanners
│   ├── base.py                    # EcosystemAdapter interface
│   ├── npm_adapter.py             # JavaScript/Node.js
│   ├── java_adapter.py            # Maven/Gradle
│   └── python_adapter.py          # pip/poetry/pipenv/conda
└── scan_npm_threats.py            # Legacy npm-only scanner (deprecated)
```

### Core Components

**ThreatDatabase** (`core/threat_database.py`):
- Loads threats from `threats/` directory or custom CSV files
- Supports loading specific threats by name (e.g., `sha1-Hulud`)
- CSV format: `ecosystem,name,version`
- Supports legacy format: `Package Name,Version` (defaults to npm)
- Tracks which threats were loaded for reporting
- Methods: `load_threats()`, `load()` (legacy), `get_compromised_versions()`, `get_all_packages()`, `get_ecosystems()`, `get_loaded_threats()`

**ReportEngine** (`core/report_engine.py`):
- Aggregates findings from all adapters
- Generates formatted console reports grouped by ecosystem
- Exports JSON reports with ecosystem sections
- Methods: `add_findings()`, `print_report()`, `save_report()`

**Finding Model** (`core/models.py`):
- Standardized finding structure across all ecosystems
- Fields: ecosystem, finding_type (manifest/lockfile/installed), file_path, package_name, version, match_type (exact/range), declared_spec, remediation
- Converts to dictionary for JSON export

### Ecosystem Adapters

Each adapter implements the `EcosystemAdapter` interface:

#### NpmAdapter (`adapters/npm_adapter.py`)

**Supported Formats:**
- `package.json`: Manifest with dependencies, devDependencies, peerDependencies, optionalDependencies
- `package-lock.json`: npm lockfile (v1/v2/v3 formats)
- `yarn.lock`: Yarn lockfile
- `pnpm-lock.yaml`: pnpm lockfile (requires PyYAML)
- `node_modules/`: Installed packages

**Version Matching:**
- Uses `semantic_version.NpmSpec` for npm semver ranges (^, ~, >=, etc.)
- Handles scoped packages (@org/package)
- Supports exact versions and version ranges

**Key Methods:**
- `detect_projects()`: Finds directories with package.json
- `scan_project()`: Scans manifests, lockfiles, and node_modules
- `_scan_package_json()`: Parses JSON and checks dependencies
- `_scan_package_lock_json()`: Handles v1/v2/v3 lockfile formats
- `_scan_yarn_lock()`: Regex-based yarn.lock parsing
- `_scan_pnpm_lock_yaml()`: YAML parsing for pnpm
- `_scan_node_modules()`: Recursively scans installed packages

#### JavaAdapter (`adapters/java_adapter.py`)

**Supported Formats:**
- `pom.xml`: Maven manifest
- `build.gradle`: Gradle Groovy DSL
- `build.gradle.kts`: Gradle Kotlin DSL
- `gradle.lockfile`: Gradle 7+ lockfile

**Version Matching:**
- Maven version ranges: `[1.0,2.0)`, `[1.0,)`, `(,2.0)` with inclusive/exclusive bounds
- Gradle dynamic versions: `1.2.+` converted to regex patterns
- Exact versions: `1.2.3`

**Key Methods:**
- `detect_projects()`: Finds directories with pom.xml or build.gradle
- `scan_project()`: Scans Maven and Gradle files
- `_scan_pom_xml()`: XML parsing with namespace handling
- `_scan_gradle_build()`: Regex-based Groovy/Kotlin DSL parsing
- `_scan_gradle_lockfile()`: Parses Gradle lockfile format
- `_is_maven_range()`: Detects Maven version ranges
- `_get_matching_maven_versions()`: Range matching logic

#### PythonAdapter (`adapters/python_adapter.py`)

**Supported Formats:**
- `requirements.txt`, `requirements-*.txt`: pip requirements files
- `pyproject.toml`: Poetry manifest (tool.poetry.dependencies)
- `poetry.lock`: Poetry lockfile (TOML format)
- `Pipfile`: pipenv manifest (TOML format)
- `Pipfile.lock`: pipenv lockfile (JSON format)
- `environment.yml`: conda environment file (YAML format)

**Version Matching:**
- PEP 440 specifiers: `==`, `>=`, `<=`, `>`, `<`, `!=`, `~=`
- Compound specifiers: `>=1.0,<2.0`
- Poetry caret: `^1.2.3` → `>=1.2.3,<2.0.0`
- Poetry tilde: `~1.2.3` → `>=1.2.3,<1.3.0`

**Key Methods:**
- `detect_projects()`: Finds directories with Python manifests
- `scan_project()`: Scans all Python package manager files
- `_scan_requirements_txt()`: Line-by-line requirements parsing
- `_scan_pyproject_toml()`: TOML parsing for Poetry (requires toml/tomli)
- `_scan_poetry_lock()`: TOML parsing for poetry.lock
- `_scan_pipfile()`: TOML parsing for Pipfile
- `_scan_pipfile_lock()`: JSON parsing for Pipfile.lock
- `_scan_conda_environment()`: YAML parsing for conda (requires PyYAML)
- `_get_matching_pep440_versions()`: PEP 440 compliance checking

## Threat Database System

### Multi-Threat Architecture

The scanner supports partitioned threat databases, allowing you to:
- **Scan for specific threats**: Use `--threat` to target specific supply chain attacks
- **Scan for multiple threats**: Repeat `--threat` flag for multiple threats
- **Scan all threats**: Default behavior loads all CSVs from `threats/` directory
- **Use custom CSV**: Provide your own threat database with `--csv`

### Threat Directory Structure

```
threats/
├── sha1-Hulud.csv         # sha1-Hulud supply chain worm (npm + maven)
├── sample-threats.csv     # Test threats for all ecosystems
└── custom-threat.csv      # Your custom threats
```

### CSV Format

**Current format (multi-ecosystem):**
```csv
ecosystem,name,version
npm,left-pad,1.3.0
npm,@accordproject/concerto-linter,3.24.1
maven,org.apache.logging.log4j:log4j-core,2.14.1
maven,org.mvnpm:posthog-node,4.18.1
pip,requests,2.8.1
```

**Legacy format (npm-only, still supported):**
```csv
Package Name,Version
left-pad,1.3.0
@accordproject/concerto-linter,3.24.1
```

### Package Naming Conventions

- **npm**: Package name as-is (supports scoped packages with @)
- **maven**: `groupId:artifactId` format (e.g., `org.springframework:spring-core`)
- **pip**: Package name in lowercase (PyPI convention)

### Current Threats

**sha1-Hulud.csv** (sha1-Hulud supply chain worm):
- **Total**: 790 packages, 1,056 versions
- **npm**: 789 packages, 1,055 versions (compromised npm packages)
- **maven**: 1 package, 1 version (org.mvnpm:posthog-node:4.18.1)

**sample-threats.csv** (test/sample threats):
- **Total**: 13 packages, 71 versions
- **npm**: ~800 versions (subset of sha1-Hulud for testing)
- **maven**: 4 packages, 35 versions (Log4j, Spring, Jackson, Commons Collections)
- **pip**: 9 packages, 36 versions (requests, Django, Flask, PyYAML, etc.)

## Dependencies

### Core Dependencies (required)
- `click>=8.1`: CLI framework
- `semantic_version>=2.10`: npm semver range parsing

### Optional Dependencies

Install extras for specific ecosystems:
```bash
pip install -e ".[pnpm]"      # PyYAML for pnpm-lock.yaml
pip install -e ".[java]"       # lxml for Maven pom.xml
pip install -e ".[python]"     # toml, packaging for Python
pip install -e ".[all]"        # All optional dependencies
```

**pnpm**: `pyyaml>=6.0` (for pnpm-lock.yaml and conda environment.yml)
**java**: `lxml>=4.9` (for advanced Maven pom.xml features, optional)
**python**: `toml>=0.10`, `packaging>=21.0` (for Poetry and Pipenv)

The adapters gracefully handle missing optional dependencies with warnings.

## Output Format

### Console Output

Findings are grouped by ecosystem and type:
1. **MANIFEST FILES**: Declared dependencies with vulnerable versions/ranges
2. **LOCK FILES**: Exact resolved versions from lockfiles
3. **INSTALLED PACKAGES**: Actually installed packages (npm only)

Each finding includes:
- File path
- Package name and version
- Version specification (for manifests)
- Match type (exact or range)
- Remediation suggestions (upgrade strategy, suggested version)

### JSON Output

Structured report with ecosystem sections and threat tracking:
```json
{
  "total_findings": 31,
  "threats": ["sha1-Hulud"],
  "ecosystems": ["maven", "npm", "pip"],
  "summary": {
    "maven": {"total": 10, "manifest": 10, "lockfile": 0, "unique_packages": 4},
    "npm": {"total": 6, "manifest": 2, "lockfile": 4, "unique_packages": 4},
    "pip": {"total": 15, "manifest": 15, "lockfile": 0, "unique_packages": 9}
  },
  "findings": [...]
}
```

## Docker Deployment

**Image Details:**
- Base: `python:3.11-slim` (~150MB final size)
- User: Non-root `scanner:scanner`
- Entrypoint: `package-scan` CLI
- Working directory: `/workspace`
- Threat databases: Baked into `/app/threats/` directory

**Dependencies Included:**
- Core: click, semantic_version
- Optional: pyyaml, toml (for full ecosystem support)

**Auto-detection:**
- Automatically detects ecosystems in mounted workspace
- Scans npm, Maven/Gradle, and Python projects
- Generates unified report

**Volume Mounts:**
- `/workspace`: Mount your project here
- Reports saved to `/workspace/package_scan_report.json`

**Example Workflows:**

Scan a polyglot monorepo:
```bash
docker run --rm -v "$(pwd):/workspace" package-scan
# Auto-detects all ecosystems, reports combined findings
```

CI/CD integration:
```bash
docker run --rm -v "$(pwd):/workspace" package-scan --no-save > /dev/null
# Exit code: 0 = clean, 1 = threats found
```

Scan for specific threat:
```bash
docker run --rm -v "$(pwd):/workspace" package-scan --threat sha1-Hulud
# Only scans for sha1-Hulud worm packages
```

Custom threat database:
```bash
docker run --rm \
  -v "$(pwd):/workspace" \
  -v "$(pwd)/custom-threats.csv:/app/custom.csv" \
  package-scan --csv /app/custom.csv
```

## Test Fixtures

The repository includes test fixtures for all supported ecosystems:

- `examples/test-package/`: npm project with vulnerable packages
- `examples/test-maven/`: Maven pom.xml with vulnerable Java dependencies
- `examples/test-gradle/`: Gradle build.gradle with vulnerable Java dependencies
- `examples/test-python/`: Python project with requirements.txt, pyproject.toml, and Pipfile

Run tests:
```bash
package-scan --dir examples --no-save
# Should detect 31 total findings across all ecosystems
```

## Adding New Ecosystems

To add support for a new ecosystem (e.g., Ruby/gem, Rust/cargo):

1. Create adapter: `src/package_scan/adapters/new_adapter.py`
2. Inherit from `EcosystemAdapter`
3. Implement required methods:
   - `_get_ecosystem_name()`: Return ecosystem identifier
   - `get_manifest_files()`: List of manifest filenames
   - `get_lockfile_names()`: List of lockfile filenames
   - `detect_projects()`: Find project directories
   - `scan_project()`: Scan manifests, lockfiles, installed packages
4. Register in `adapters/__init__.py`: `ADAPTER_REGISTRY['ecosystem'] = NewAdapter`
5. Add ecosystem to auto-detection in `cli.py`
6. Add test fixtures in `examples/test-ecosystem/`
7. Add sample threats to `threats/` directory (create new CSV or add to existing threats)

The architecture requires no changes to core components.

## Adding New Threats

To add a new threat database:

1. Create a new CSV file in `threats/` directory (e.g., `threats/my-threat.csv`)
2. Use the multi-ecosystem format: `ecosystem,name,version`
3. Test with: `package-scan --threat my-threat --dir /path/to/project`
4. The threat will automatically be included in default scans (no --threat flag)

## Performance Considerations

- **Lazy Loading**: Only loads adapters for detected ecosystems
- **Skip Directories**: Automatically skips node_modules, .git, venv, build, etc.
- **Streaming**: Parses large files line-by-line where possible
- **No Execution**: Parses configuration files only, never executes package managers
- **Caching**: Single CSV load shared across all adapters

## Security Considerations

- **Sandboxed**: Only reads files, never executes commands
- **Non-root**: Docker runs as unprivileged user
- **Path Validation**: Stays within scan directory
- **No Network**: No external API calls or downloads
- **Static Analysis**: Threat detection is purely static file parsing
