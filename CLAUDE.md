# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Mission

**package-scan is a rapid-response tool for detecting compromised packages during active supply chain attacks.**

This is NOT a comprehensive vulnerability scanner like Snyk or npm audit. It's a focused tool for incident response that prioritizes:
- **Speed**: Deploy in minutes during active attacks
- **Simplicity**: CSV-based threat lists, minimal dependencies
- **Flexibility**: Multi-ecosystem support, easy to extend

**Use package-scan for:**
- Scanning against lists of compromised packages from emerging attacks
- Rapid deployment across infrastructure during incidents
- Sharing threat intelligence via simple CSV files

**Use other tools for:**
- Ongoing vulnerability monitoring (Snyk, Dependabot)
- CVE database scanning (npm audit, pip-audit)
- SBOM generation (Syft, CycloneDX)
- Static code analysis (Semgrep, CodeQL)

See [ROADMAP.md](ROADMAP.md) for detailed scope and priorities.

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

## Version Management

The project uses a **single source of truth** approach for version management:

**Source of Truth:** `pyproject.toml` (project.version)

**Auto-synced files** (read from package metadata at runtime):
- `src/package_scan/__init__.py` - Uses `importlib.metadata.version()`
- `docs/source/conf.py` - Uses `importlib.metadata.version()`

**Manually synced files** (updated by script):
- `Dockerfile` - LABEL version
- `scripts/tag-and-push.sh` - VERSION variable

### Releasing a New Version (Automated via GitHub)

**Recommended: Create a GitHub Release** (fully automated):

1. **Create a new release on GitHub:**
   - Go to: https://github.com/thekitchencoder/package-scan/releases/new
   - Create a new tag: `v0.4.0` (use semantic versioning with `v` prefix)
   - Fill in release title and description
   - Click "Publish release"

2. **GitHub Actions automatically:**
   - Extracts version from tag (v0.4.0 → 0.4.0)
   - Updates `pyproject.toml` with the new version
   - Runs `sync-version.sh` to update Dockerfile and tag-and-push.sh
   - Commits version updates back to the repository
   - Builds and pushes Docker image to Docker Hub with proper tags

**Manual Release Process** (local development):

If you need to release manually without GitHub:

1. **Update version in pyproject.toml:**
   ```bash
   vim pyproject.toml  # Change version = "0.3.1" to "0.4.0"
   ```

2. **Sync version to Docker files:**
   ```bash
   ./scripts/sync-version.sh
   ```

3. **Review and commit:**
   ```bash
   git diff
   git add -A
   git commit -m "chore: bump version to 0.4.0"
   git tag v0.4.0
   git push && git push --tags
   ```

4. **Build and push Docker image:**
   ```bash
   ./scripts/tag-and-push.sh
   ```

**How It Works:**

The `sync-version.sh` script automatically updates:
- `Dockerfile` LABEL version
- `scripts/tag-and-push.sh` VERSION variable

Auto-synced files (read from package metadata at runtime):
- `src/package_scan/__init__.py` - Uses `importlib.metadata.version()`
- `docs/source/conf.py` - Uses `importlib.metadata.version()`

**GitHub Actions Workflow:**
- Workflow: `.github/workflows/DockerImageReleaseWorkflow.yml`
- Triggers: When a new release is published on GitHub
- Permissions: Requires `contents: write` to commit version updates

## Running the Tool

### Multi-Ecosystem Scanning

**Basic scanning:**
```bash
package-scan                                    # Scan current directory (all threats)
package-scan --dir /path/to/project             # Scan specific directory
package-scan --output custom_report.json        # Custom output file
package-scan --no-save                          # Don't save JSON report
```

**Path formatting (via environment variable):**
```bash
# Default: absolute paths
package-scan --dir /path/to/project             # Shows: /path/to/project/package.json

# Relative paths
export SCAN_PATH_PREFIX="."
package-scan --dir /path/to/project             # Shows: ./package.json

# Custom prefix (useful for reporting)
export SCAN_PATH_PREFIX="/home/user/projects"
package-scan --dir /path/to/project             # Shows: /home/user/projects/package.json
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

**Validate threat CSV files:**
```bash
threat-db validate --file /path/to/threats.csv  # Validate threat database format
threat-db validate --file threats.csv --strict  # Strict mode: fail on unknown ecosystems
threat-db validate --file threats.csv --verbose # Show all warnings and details
```

### Docker Usage

**Build image:**
```bash
docker build -t package-scan .
```

**Scan a project:**
```bash
# Scan current directory (all threats) - uses relative paths by default
docker run --rm -v "$(pwd):/workspace" package-scan

# Scan for specific threat
docker run --rm -v "$(pwd):/workspace" package-scan --threat sha1-Hulud

# Scan specific ecosystem
docker run --rm -v "$(pwd):/workspace" package-scan --ecosystem maven

# Use full host paths in output (instead of ./package.json)
docker run --rm -v "$(pwd):/workspace" -e SCAN_PATH_PREFIX="$(pwd)" package-scan --threat sha1-Hulud
# Output will show: /home/user/project/package.json

# Show Docker paths instead of relative
docker run --rm -v "$(pwd):/workspace" -e SCAN_PATH_PREFIX="/workspace" package-scan
# Output will show: /workspace/package.json

# Disable path conversion (show absolute paths as-is)
docker run --rm -v "$(pwd):/workspace" -e SCAN_PATH_PREFIX="" package-scan

# Use custom threat CSV
docker run --rm \
  -v "$(pwd):/workspace" \
  -v "$(pwd)/custom-threat.csv:/app/custom.csv" \
  package-scan --csv /app/custom.csv

# Get help
docker run --rm package-scan --help
```

**Path formatting in Docker:**
The Docker image sets `SCAN_PATH_PREFIX="."` by default to show clean relative paths (`./package.json`) instead of Docker paths (`/workspace/package.json`). You can override this with `-e SCAN_PATH_PREFIX=` to customize path output:
- `"."` = relative paths (default)
- `"$(pwd)"` = full host system paths
- `"/workspace"` = Docker container paths
- `""` = no conversion (absolute paths as scanned)

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
│   ├── models.py                  # Finding dataclass
│   ├── threat_database.py         # Multi-ecosystem CSV loading
│   └── report_engine.py           # Unified reporting
└── adapters/                      # Ecosystem-specific scanners
    ├── base.py                    # EcosystemAdapter interface
    ├── npm_adapter.py             # JavaScript/Node.js
    ├── java_adapter.py            # Maven/Gradle
    └── python_adapter.py          # pip/poetry/pipenv/conda
```

### Core Components

**ThreatDatabase** (`core/threat_database.py`):
- Loads threats from `threats/` directory or custom CSV files
- Supports loading specific threats by name (e.g., `sha1-Hulud`)
- CSV format: `ecosystem,name,version`
- Tracks which threats were loaded for reporting
- Methods: `load_threats()`, `get_compromised_versions()`, `get_all_packages()`, `get_ecosystems()`, `get_loaded_threats()`

**ThreatValidator** (`core/threat_validator.py`):
- Validates threat CSV files before use
- Checks headers, field values, ecosystems, package names, versions
- Detects duplicates and formatting issues
- Provides detailed error reporting with line numbers
- Supports strict mode (fail on unknown ecosystems) and verbose mode
- CLI command: `threat-db validate --file threats.csv [--strict] [--verbose]`
- Methods: `validate_file()`, `print_result()`, convenience function `validate_threat_file()`

**ReportEngine** (`core/report_engine.py`):
- Aggregates findings from all adapters
- Generates formatted console reports grouped by ecosystem
- Exports JSON reports with ecosystem sections
- Methods: `add_findings()`, `print_report()`, `save_report()`

**Finding Model** (`core/models.py`):
- Standardized finding structure across all ecosystems
- Fields: ecosystem, finding_type (manifest/lockfile/installed), file_path, package_name, version, match_type (exact/range), declared_spec
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

## Testing

### Running Tests

```bash
# All tests
pytest

# Specific test file
pytest tests/test_npm_adapter.py

# With coverage
pytest --cov=package_scan --cov-report=html
```

### Test Structure

Comprehensive test suite covering all components:

- **Core Components**:
  - `tests/test_threat_database.py`: CSV loading, threat filtering, queries
  - `tests/test_report_engine.py`: Report generation, JSON export, summaries
  - `tests/test_models.py`: Finding data model

- **Ecosystem Adapters**:
  - `tests/test_npm_adapter.py`: npm/yarn/pnpm scanning and version matching
  - `tests/test_java_adapter.py`: Maven/Gradle scanning and version ranges
  - `tests/test_python_adapter.py`: pip/Poetry/Pipenv scanning and PEP 440

- **CLI**:
  - `tests/test_scanner.py`: Command-line interface tests

### Test Fixtures

Real-world project examples in `examples/`:
- `examples/test-package/`: npm project with vulnerable packages
- `examples/test-maven/`: Maven project with Java vulnerabilities
- `examples/test-gradle/`: Gradle project with Java vulnerabilities
- `examples/test-python/`: Python project with multiple package managers

## Documentation

### Sphinx Documentation

Build HTML documentation:
```bash
cd docs
make html
open build/html/index.html
```

Documentation structure:
- **introduction.rst**: Project mission and overview
- **installation.rst**: Multiple installation methods
- **usage.rst**: Complete CLI examples and Docker usage
- **architecture.rst**: Detailed technical architecture
- **contributing.rst**: Development guidelines and PR process
- **api/**: Complete API reference for core and adapters

### Documentation Files

- **README.md**: Quick start, installation, usage examples
- **ROADMAP.md**: Project vision, priorities, and future features
- **CONTRIBUTING.md**: How to contribute, scope, and guidelines
- **CLAUDE.md**: This file - guidance for AI coding assistants
- **ARCHITECTURE.md**: Detailed technical architecture documentation

## Project Structure

```
package-scan/
├── src/package_scan/          # Source code
│   ├── cli.py                 # Command-line interface
│   ├── core/                  # Core components
│   │   ├── models.py          # Data models
│   │   ├── threat_database.py # CSV threat loading
│   │   └── report_engine.py   # Report generation
│   └── adapters/              # Ecosystem adapters
│       ├── base.py            # Base adapter interface
│       ├── npm_adapter.py     # npm/yarn/pnpm
│       ├── java_adapter.py    # Maven/Gradle
│       └── python_adapter.py  # pip/Poetry/Pipenv
├── tests/                     # Unit tests
│   ├── test_*.py              # Test files
│   └── __init__.py
├── docs/                      # Sphinx documentation
│   ├── source/                # Documentation source files
│   └── Makefile               # Build documentation
├── examples/                  # Test fixtures
│   ├── test-package/          # npm examples
│   ├── test-maven/            # Maven examples
│   ├── test-gradle/           # Gradle examples
│   └── test-python/           # Python examples
├── threats/                   # Threat databases
│   ├── sha1-Hulud.csv         # sha1-Hulud worm packages
│   └── sample-threats.csv     # Test threats
├── scripts/                   # Utility scripts
│   └── tag-and-push.sh        # Docker release script
├── pyproject.toml             # Package configuration
├── Dockerfile                 # Docker image build
├── README.md                  # Project overview
├── ROADMAP.md                 # Project roadmap
├── CONTRIBUTING.md            # Contributing guidelines
└── CLAUDE.md                  # This file
```

## Recent Project Improvements

### Project Cleanup (December 2025)

- ✅ Moved utility scripts to `scripts/` directory
- ✅ Removed all backward compatibility features:
  - Removed legacy CSV format support (Package Name,Version)
  - Removed npm-scan and hulud-scan CLI commands
  - Removed legacy load() method from ThreatDatabase
- ✅ Simplified `setup.py` (main config in `pyproject.toml`)
- ✅ Updated all documentation to reflect rapid-response mission

### Comprehensive Test Suite

- ✅ Unit tests for all core components
- ✅ Integration tests for all ecosystem adapters
- ✅ Test fixtures for npm, Maven, Gradle, and Python
- ✅ 80+ tests covering version matching, CSV parsing, and reporting

### Documentation Overhaul

- ✅ Sphinx documentation with API reference
- ✅ Complete README rewrite with usage examples
- ✅ ROADMAP clarifying scope and priorities
- ✅ CONTRIBUTING guide with detailed instructions
- ✅ All docs emphasize rapid-response mission vs comprehensive scanning

## Usage Examples for Common Scenarios

### Incident Response: New Attack Discovered

```bash
# 1. Security vendor publishes compromised package list
# 2. Create CSV file (my-attack.csv):
echo "ecosystem,name,version" > my-attack.csv
echo "npm,malicious-package,1.0.0" >> my-attack.csv
echo "maven,com.evil:library,2.0.0" >> my-attack.csv

# 3. Scan your infrastructure
package-scan --csv my-attack.csv --dir /path/to/repos

# 4. Generate report for security team
package-scan --csv my-attack.csv --output incident-report.json
```

### CI/CD: Continuous Scanning During Attack

```yaml
# .github/workflows/security-scan.yml
name: Supply Chain Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Scan for compromised packages
        run: |
          docker run --rm \
            -v "$PWD:/workspace" \
            kitchencoder/package-scan:latest \
            --threat sha1-Hulud \
            --no-save || exit 1
```

### Monorepo: Scan Multiple Projects

```bash
# Scan entire monorepo
package-scan --dir /path/to/monorepo

# Scan specific service
package-scan --dir /path/to/monorepo/services/api --ecosystem npm

# Generate per-service reports
for service in services/*/; do
  package-scan --dir "$service" --output "${service//\//-}report.json"
done
```

### Security Team: Share Threat Intelligence

```bash
# Export threat database for sharing
package-scan --list-affected-packages-csv > team-threat-db.csv

# Team members use shared database
package-scan --csv team-threat-db.csv --dir ~/projects

# Combine multiple threat sources
cat vendor-threat.csv internal-threat.csv > combined-threats.csv
package-scan --csv combined-threats.csv
```

## Integration with Other Tools

### Transform JSON to SARIF (GitHub Code Scanning)

```python
# Example script: json-to-sarif.py
import json, sys

with open(sys.argv[1]) as f:
    scan_results = json.load(f)

sarif = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{
        "tool": {"driver": {"name": "package-scan"}},
        "results": [
            {
                "ruleId": f"compromised-{finding['ecosystem']}",
                "message": {"text": f"Compromised package: {finding['package_name']}@{finding['version']}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding['file_path']},
                        "region": {"startLine": 1}
                    }
                }]
            }
            for finding in scan_results['findings']
        ]
    }]
}

print(json.dumps(sarif, indent=2))
```

Usage:
```bash
package-scan --output scan.json
python json-to-sarif.py scan.json > results.sarif
```

### Slack/Teams Notification

```bash
# Generate notification message
FINDINGS=$(package-scan --no-save | grep "Total findings:")
THREAT_COUNT=$(echo "$FINDINGS" | awk '{print $3}')

if [ "$THREAT_COUNT" -gt 0 ]; then
  curl -X POST "$SLACK_WEBHOOK" \
    -H 'Content-Type: application/json' \
    -d "{\"text\":\"⚠️ Found $THREAT_COUNT compromised packages!\"}"
fi
```

## Best Practices

### Creating Threat Databases

1. **Use official sources**: Security vendor advisories, GitHub Security Lab
2. **Verify package names**: Match exact names for each ecosystem
3. **Include all versions**: List all known compromised versions
4. **Document sources**: Add comments or metadata about where threats came from
5. **Test thoroughly**: Scan known-vulnerable projects to verify detection

### Scanning Workflows

1. **Scan immediately**: When attack is announced, scan infrastructure first
2. **Scan continuously**: Add to CI/CD during active incident
3. **Scan comprehensively**: Don't limit to specific ecosystems unless necessary
4. **Share results**: JSON reports enable team collaboration
5. **Update regularly**: Refresh threat databases as new information emerges

### Avoiding False Positives

1. **Verify versions**: Ensure CSV has exact versions, not ranges
2. **Check ecosystem**: npm vs maven vs pip have different naming conventions
3. **Review findings**: Manual verification of critical findings
4. **Test with fixtures**: Use `examples/` to verify scanning logic

### Performance Optimization

1. **Use Docker**: Faster than pip install for one-time scans
2. **Scan selectively**: Use `--ecosystem` to limit scope if needed
3. **Skip output**: Use `--no-save` in CI/CD to reduce I/O
4. **Parallel scanning**: Scan multiple repos concurrently

## Troubleshooting

### Tests Failing

```bash
# Ensure all dependencies installed
pip install -e ".[all]"
pip install pytest

# Run specific failing test with verbose output
pytest tests/test_npm_adapter.py::test_specific_function -v

# Check for import errors
python -c "from package_scan.core import ThreatDatabase"
```

### Docker Build Issues

```bash
# Clean build
docker build --no-cache -t package-scan .

# Check build logs
docker build -t package-scan . 2>&1 | tee build.log

# Verify dependencies in image
docker run --rm package-scan pip list
```

### Documentation Build Errors

```bash
# Install documentation dependencies
pip install -e ".[dev]"

# Clean build
cd docs
make clean
make html

# Check for Sphinx warnings
make html 2>&1 | grep WARNING
```
