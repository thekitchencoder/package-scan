# package-scan

[![Tests](https://github.com/thekitchencoder/package-scan/actions/workflows/RunTests.yml/badge.svg)](https://github.com/thekitchencoder/package-scan/actions/workflows/RunTests.yml)
[![Documentation Status](https://github.com/thekitchencoder/package-scan/actions/workflows/BuildAndDeployDocs.yml/badge.svg)](https://github.com/thekitchencoder/package-scan/actions/workflows/BuildAndDeployDocs.yml)
[![Docker Build](https://github.com/thekitchencoder/package-scan/actions/workflows/DockerImageReleaseWorkflow.yml/badge.svg)](https://github.com/thekitchencoder/package-scan/actions/workflows/DockerImageReleaseWorkflow.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Docker Pulls](https://img.shields.io/docker/pulls/kitchencoder/package-scan)](https://hub.docker.com/r/kitchencoder/package-scan)

**Rapid-response supply chain attack scanner** for detecting compromised packages during active security incidents.

📚 **[Full Documentation](https://thekitchencoder.github.io/package-scan/)** | 🐙 **[GitHub](https://github.com/thekitchencoder/package-scan)**

When a new supply chain attack emerges (like the sha1-Hulud worm or event-stream incident), security teams need to **quickly scan their infrastructure** against lists of known compromised packages. `package-scan` fills this critical gap—it's not a replacement for comprehensive vulnerability scanners like Snyk or npm audit, but a **focused tool for rapid incident response**.

## Why package-scan?

**✅ Use package-scan when:**
- A new supply chain attack is discovered
- You have a list of compromised packages to check against
- You need results in minutes, not hours
- You're scanning multiple ecosystems (npm, Maven, Python)
- You need to share threat intelligence via simple CSV files

**❌ Use other tools for:**
- Ongoing vulnerability monitoring → Snyk, Dependabot
- CVE database scanning → npm audit, pip-audit
- SBOM generation → Syft, CycloneDX
- Static code analysis → Semgrep, CodeQL

## Key Features

- **Multi-ecosystem**: Scans npm, Maven/Gradle, Python (pip/Poetry/Pipenv/conda)
- **Rapid deployment**: Docker container or pip install
- **Simple threat lists**: CSV-based, easy to create and share
- **Version intelligence**: Handles semver ranges, Maven ranges, PEP 440 specifiers
- **CI/CD ready**: JSON output, exit codes, Docker support

## Quick Start

### Using Docker (Recommended for rapid deployment)

```bash
# Pull the latest image
docker pull kitchencoder/package-scan:latest

# Scan your current directory (all ecosystems, all threats)
docker run --rm -v "$(pwd):/workspace" kitchencoder/package-scan:latest

# Scan for specific threat (e.g., sha1-Hulud worm)
docker run --rm -v "$(pwd):/workspace" kitchencoder/package-scan:latest --threat sha1-Hulud

# Scan specific ecosystem only
docker run --rm -v "$(pwd):/workspace" kitchencoder/package-scan:latest --ecosystem npm
```

### Using pip

```bash
# Install
pip install -e .

# Scan current directory
package-scan

# Scan for specific threat
package-scan --threat sha1-Hulud

# Scan specific ecosystem
package-scan --ecosystem maven

# Use custom threat CSV
package-scan --csv /path/to/threat-list.csv
```

## Installation

### Docker (Recommended)

Pre-built images are available on Docker Hub:

```bash
docker pull kitchencoder/package-scan:latest
```

Or build locally:

```bash
docker build -t package-scan .
```

### Python Package

1. Create virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   ```

2. Install with all ecosystem support:
   ```bash
   pip install -e ".[all]"
   ```

   Or install for specific ecosystems:
   ```bash
   pip install -e ".[pnpm]"    # pnpm/conda support
   pip install -e ".[java]"     # Maven/Gradle support
   pip install -e ".[python]"   # Python ecosystem support
   ```

3. Verify installation:
   ```bash
   package-scan --help
   package-scan --list-ecosystems
   ```

## Usage

### Basic Scanning

```bash
# Scan current directory (all ecosystems, all threats)
package-scan

# Scan specific directory
package-scan --dir /path/to/project

# Scan for specific threat
package-scan --threat sha1-Hulud

# Scan specific ecosystem
package-scan --ecosystem npm
package-scan --ecosystem maven,pip  # Multiple ecosystems
```

### Threat Management

```bash
# List available ecosystems
package-scan --list-ecosystems

# List all compromised packages in database
package-scan --list-affected-packages

# Export threat database as CSV
package-scan --list-affected-packages-csv > my-threats.csv

# Use custom threat CSV
package-scan --csv /path/to/custom-threats.csv

# Validate threat CSV before use
threat-db validate --file /path/to/custom-threats.csv

# Validate with strict ecosystem checking
threat-db validate --file threats.csv --strict

# Validate with verbose output (shows all warnings)
threat-db validate --file threats.csv --verbose
```

### Output Options

```bash
# Custom output file
package-scan --output scan-results.json

# No JSON file (console only)
package-scan --no-save
```

### Docker Examples

```bash
# Scan with custom threat CSV
docker run --rm \
  -v "$(pwd):/workspace" \
  -v "/path/to/custom.csv:/app/custom.csv" \
  kitchencoder/package-scan:latest --csv /app/custom.csv
  
# Host file paths in the report
docker run --rm \
  -v "$(pwd):/workspace" \
  -e  SCAN_PATH_PREFIX="$(pwd)" \
  kitchencoder/package-scan:latest --csv /app/custom.csv

# CI/CD: Exit with error if threats found
docker run --rm -v "$(pwd):/workspace" kitchencoder/package-scan:latest --no-save || exit 1

# Scan monorepo subdirectory
docker run --rm -v "$(pwd):/workspace" kitchencoder/package-scan:latest --dir /workspace/services/api
```

## CLI Options

- `--dir PATH`: Directory to scan (default: current directory)
- `--threat NAME`: Scan for specific threat (can be repeated)
- `--csv FILE`: Use custom threat CSV file
- `--ecosystem LIST`: Comma-separated list of ecosystems to scan
- `--output FILE`: JSON report filename (default: `package_scan_report.json`)
- `--no-save`: Don't write JSON report
- `--list-ecosystems`: List supported ecosystems and exit
- `--list-affected-packages`: Display compromised packages and exit
- `--list-affected-packages-csv`: Output threat database as CSV

## Threat CSV Format

Threat databases use a simple CSV format with three columns:

```csv
ecosystem,name,version
npm,left-pad,1.3.0
npm,@scope/package,2.0.0
maven,org.springframework:spring-core,5.3.0
maven,org.apache.logging.log4j:log4j-core,2.14.1
pip,requests,2.8.1
pip,django,3.0.0
```

**Package naming conventions:**
- **npm**: Package name as-is (supports `@scope/package`)
- **maven**: `groupId:artifactId` format
- **pip**: Lowercase package name (PyPI convention)

### Validating Threat Files

Before using a custom threat CSV file, you can validate it to ensure proper formatting:

```bash
threat-db validate --file my-threats.csv
```

The validator checks for:
- ✓ Correct headers (`ecosystem,name,version`)
- ✓ Non-empty required fields
- ✓ Valid ecosystem names (npm, maven, pip, gem)
- ✓ Proper package name format (e.g., Maven's `groupId:artifactId`)
- ✓ Valid version strings
- ✓ Duplicate entries

**Validation modes:**
- **Normal mode** (default): Warns about unknown ecosystems but passes validation
- **Strict mode** (`--strict`): Fails validation for unknown ecosystems
- **Verbose mode** (`--verbose`): Shows all warnings and detailed statistics

Example validation output:
```
🔍 THREAT DATABASE VALIDATION
File: my-threats.csv
Format: modern

Statistics:
  Total rows: 150
  Valid rows: 148
  Invalid rows: 2
  Unique entries: 148
  Unique packages: 95
  Ecosystems: maven, npm, pip

⚠️  WARNINGS (3):
  • Line 45 [name]: Maven package should be in 'groupId:artifactId' format: 'log4j-core'
  • Line 89: Duplicate entry: ecosystem=npm, name=left-pad, version=1.3.0

❌ ERRORS (2):
  • Line 23 [version]: Version contains whitespace characters: '1.0 .0'
  • Line 67 [name]: Empty package name

✗ VALIDATION FAILED
```

## What Gets Scanned

The scanner detects and analyzes multiple ecosystems:

### npm Ecosystem
- **Manifests**: package.json (dependencies, devDependencies, etc.)
- **Lockfiles**: package-lock.json (v1/v2/v3), yarn.lock, pnpm-lock.yaml
- **Installed**: node_modules/ directories
- **Version matching**: npm semver (^1.0.0, ~1.2.0, >=2.0.0, etc.)

### Maven/Gradle Ecosystem
- **Manifests**: pom.xml, build.gradle, build.gradle.kts
- **Lockfiles**: gradle.lockfile
- **Version matching**: Maven ranges ([1.0,2.0)), Gradle dynamic (1.2.+)

### Python Ecosystem
- **Manifests**: requirements.txt, pyproject.toml, Pipfile, environment.yml
- **Lockfiles**: poetry.lock, Pipfile.lock
- **Version matching**: PEP 440 specifiers (==, >=, ~=, etc.)

The scanner automatically detects which ecosystems are present in your project and scans accordingly.

## Output

### Console Output

Findings are grouped by ecosystem and type:

```
═══════════════════════════════════════════════════════════
📦 npm Findings
═══════════════════════════════════════════════════════════

MANIFEST FILES (package.json):
  /project/package.json
    left-pad@1.3.0 (declared: ^1.3.0)

LOCK FILES:
  /project/package-lock.json
    some-package@2.0.1 (exact match)

═══════════════════════════════════════════════════════════
☕ maven Findings
═══════════════════════════════════════════════════════════

MANIFEST FILES (pom.xml):
  /project/pom.xml
    org.springframework:spring-core@5.3.0 (declared: [5.0,6.0))
```

### JSON Output

Default filename: `package_scan_report.json`

```json
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
    }
  },
  "findings": [
    {
      "ecosystem": "npm",
      "finding_type": "manifest",
      "file_path": "/project/package.json",
      "package_name": "left-pad",
      "version": "1.3.0",
      "match_type": "range",
      "declared_spec": "^1.3.0"
    }
  ]
}
```

## Use Cases

### Incident Response

When a new supply chain attack is announced:

1. **Gather threat intelligence**: Collect list of compromised packages from security advisories
2. **Create threat CSV**: Format as `ecosystem,name,version`
3. **Deploy scanner**: Use Docker for rapid deployment across infrastructure
4. **Scan all repos**: Identify which projects are affected
5. **Share findings**: JSON reports for security team analysis

### CI/CD Integration

Add scanning to your CI pipeline:

```yaml
# GitHub Actions example
- name: Scan for supply chain threats
  run: |
    docker run --rm -v "$PWD:/workspace" \
      kitchencoder/package-scan:latest \
      --threat sha1-Hulud \
      --no-save || exit 1
```

### Security Team Workflows

- **Threat database sharing**: Distribute CSV files to development teams
- **Monorepo scanning**: Scan large codebases across multiple ecosystems
- **Audit reports**: Generate JSON reports for compliance
- **Custom integrations**: Transform JSON output for SIEM/ticketing systems

## Creating Threat Databases

When a new attack is discovered:

1. **Gather compromised packages** from security vendor advisories
2. **Create CSV file** with format:
   ```csv
   ecosystem,name,version
   npm,malicious-package,1.0.0
   maven,com.evil:library,2.0.0
   ```
3. **Test scanning**:
   ```bash
   package-scan --csv my-threat.csv --list-affected-packages
   ```
4. **Share with team** via git, shared drive, or internal repository

See [ROADMAP.md](ROADMAP.md) for future plans around centralized threat databases.

## Architecture

package-scan uses a modular architecture:

```
src/package_scan/
├── cli.py                  # Command-line interface
├── core/                   # Shared components
│   ├── models.py           # Data models
│   ├── threat_database.py  # CSV loading
│   └── report_engine.py    # Report generation
└── adapters/               # Ecosystem scanners
    ├── npm_adapter.py      # npm/yarn/pnpm
    ├── java_adapter.py     # Maven/Gradle
    └── python_adapter.py   # pip/Poetry/Pipenv
```

**Adding new ecosystems** is straightforward—see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Development

### Running from Source

```bash
# Clone repository
git clone https://github.com/thekitchencoder/package-scan.git
cd package-scan

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install with dev dependencies
pip install -e ".[dev]"

# Run scanner
python -m package_scan.cli --help

# Run tests
pytest

# Build documentation
cd docs && make html
```

### Project Structure

- **pyproject.toml**: Package configuration
- **src/package_scan/**: Source code
- **tests/**: Unit tests
- **docs/**: Sphinx documentation
- **threats/**: Built-in threat databases
- **examples/**: Test fixtures for all ecosystems

## Troubleshooting

**Command not found:**
- Ensure virtual environment is activated
- Try: `python -m package_scan.cli --help`

**Missing optional dependencies:**
- For pnpm: `pip install pyyaml`
- For Maven: `pip install lxml`
- For Python ecosystem: `pip install toml packaging`
- Or install all: `pip install -e ".[all]"`

**No findings when expected:**
- Check threat CSV format
- Verify package names match ecosystem conventions
- Use `--list-affected-packages` to inspect database

## Contributing

We welcome contributions! Priorities:

- **New ecosystem adapters** (Ruby, Rust, Go, .NET)
- **Threat databases** from real-world attacks
- **CI/CD examples** for additional platforms
- **Output format scripts** (SARIF, HTML, etc.)

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and [ROADMAP.md](ROADMAP.md) for planned features.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built in response to the sha1-Hulud supply chain attack
- Inspired by the need for rapid incident response tools
- Thanks to the security community for threat intelligence sharing

## Links

- **Documentation**: [https://thekitchencoder.github.io/package-scan/](https://thekitchencoder.github.io/package-scan/)
- **GitHub Repository**: [https://github.com/thekitchencoder/package-scan](https://github.com/thekitchencoder/package-scan)
- **Issues**: [GitHub Issues](https://github.com/thekitchencoder/package-scan/issues)
- **Docker Hub**: [kitchencoder/package-scan](https://hub.docker.com/r/kitchencoder/package-scan)
- **Roadmap**: [ROADMAP.md](ROADMAP.md)