# Modular Scanner Architecture

## Overview

This document describes the modular architecture for hulud-scan, extending it from an npm-only scanner to a multi-ecosystem threat detection tool supporting npm, Maven/Gradle, Python, and Ruby.

## Design Principles

1. **Separation of Concerns**: Threat database management, ecosystem-specific scanning, and reporting are separate responsibilities
2. **Consistent Interface**: All ecosystem adapters expose the same interface for scanning
3. **Extensibility**: Adding new ecosystems requires only implementing the adapter interface
4. **Backward Compatibility**: Existing npm-only usage patterns remain supported
5. **Docker-Friendly**: Multi-ecosystem scanning works seamlessly in containers

## Architecture Components

### 1. Core Components (Shared)

#### ThreatDatabase
- **Responsibility**: Load and manage threat data from CSV
- **Format**: CSV with columns: `ecosystem,name,version`
- **Interface**:
  ```python
  class ThreatDatabase:
      def load(csv_file: str) -> None
      def get_compromised_versions(ecosystem: str, package_name: str) -> Set[str]
      def get_all_packages(ecosystem: str = None) -> Dict[str, Set[str]]
      def get_ecosystems() -> Set[str]
  ```

#### ReportEngine
- **Responsibility**: Aggregate findings from all adapters and generate reports
- **Output Formats**: Console (formatted), JSON
- **Interface**:
  ```python
  class ReportEngine:
      def add_findings(findings: List[Finding]) -> None
      def print_report() -> None
      def save_report(output_file: str, relative_paths: bool = False) -> None
  ```

#### Finding (Data Model)
- **Responsibility**: Standardized finding structure across all ecosystems
- **Fields**:
  ```python
  @dataclass
  class Finding:
      ecosystem: str              # npm, maven, pip, gem
      finding_type: str           # manifest, lockfile, installed
      file_path: str              # Path to manifest/lock file
      package_name: str           # Package identifier
      version: str                # Compromised version found
      declared_spec: Optional[str]  # Version spec from manifest
      match_type: str             # exact, range
      dependency_type: Optional[str]  # dependencies, devDependencies, etc.
      metadata: Dict              # Ecosystem-specific extra data
  ```

### 2. Ecosystem Adapters

#### Base Interface: EcosystemAdapter

```python
from abc import ABC, abstractmethod
from typing import List, Set
from pathlib import Path

class EcosystemAdapter(ABC):
    """Base class for ecosystem-specific scanners"""

    def __init__(self, threat_db: ThreatDatabase, root_dir: Path):
        self.threat_db = threat_db
        self.root_dir = root_dir
        self.ecosystem_name = self._get_ecosystem_name()

    @abstractmethod
    def _get_ecosystem_name(self) -> str:
        """Return ecosystem identifier (npm, maven, pip, gem)"""
        pass

    @abstractmethod
    def detect_projects(self) -> List[Path]:
        """Detect project directories containing this ecosystem's files"""
        pass

    @abstractmethod
    def scan_project(self, project_dir: Path) -> List[Finding]:
        """Scan a single project directory for compromised packages"""
        pass

    @abstractmethod
    def get_manifest_files(self) -> List[str]:
        """Return list of manifest file names (package.json, pom.xml, etc.)"""
        pass

    @abstractmethod
    def get_lockfile_names(self) -> List[str]:
        """Return list of lockfile names (package-lock.json, Gemfile.lock, etc.)"""
        pass

    # Common helpers
    def scan_all_projects(self) -> List[Finding]:
        """Scan all detected projects"""
        all_findings = []
        projects = self.detect_projects()
        for project_dir in projects:
            findings = self.scan_project(project_dir)
            all_findings.extend(findings)
        return all_findings
```

### 3. Ecosystem-Specific Implementations

#### NpmAdapter
- **Manifests**: package.json
- **Lockfiles**: package-lock.json, yarn.lock, pnpm-lock.yaml
- **Installed**: node_modules/
- **Version Matching**: semantic_version for npm semver ranges
- **Special Handling**: Scoped packages (@org/package)

#### JavaAdapter (Maven/Gradle)
- **Manifests**:
  - pom.xml (Maven)
  - build.gradle, build.gradle.kts (Gradle)
- **Lockfiles**:
  - gradle.lockfile (Gradle 7+)
  - Maven: parse `mvn dependency:tree` output or use resolved-dependencies.json
- **Installed**:
  - ~/.m2/repository (Maven local cache)
  - build/libs, target/ (built artifacts - lower priority)
- **Version Matching**: Maven version ranges, Gradle dynamic versions
- **Dependencies**:
  - lxml or xml.etree for XML parsing
  - Regex for Gradle Kotlin DSL parsing

#### PythonAdapter
- **Manifests**:
  - pyproject.toml (PEP 621, Poetry)
  - setup.py, setup.cfg (legacy)
  - requirements.txt, requirements-*.txt
  - environment.yml (Conda)
  - Pipfile (pipenv)
- **Lockfiles**:
  - poetry.lock (Poetry)
  - Pipfile.lock (pipenv)
  - conda-lock.yml
- **Installed**:
  - Use importlib.metadata.distributions() to get installed packages
  - Parse pip freeze output
- **Version Matching**:
  - PEP 440 specifiers (packaging.specifiers)
  - Simple string matching for requirements.txt
- **Dependencies**:
  - toml or tomli for TOML parsing
  - packaging for PEP 440 version matching

#### RubyAdapter
- **Manifests**: Gemfile
- **Lockfiles**: Gemfile.lock
- **Installed**:
  - vendor/bundle/
  - System gems: parse `gem list --local` output
- **Version Matching**:
  - Gem version operators (~>, >=, =)
  - Parse Bundler lockfile format
- **Dependencies**: None (pure Python regex parsing)

## Data Flow

```
1. CLI Entry Point
   ├─> Load ThreatDatabase (CSV with ecosystem column)
   ├─> Determine ecosystems to scan (--ecosystem flag or auto-detect)
   └─> For each ecosystem:
       ├─> Instantiate adapter (NpmAdapter, JavaAdapter, etc.)
       ├─> adapter.scan_all_projects()
       │   ├─> detect_projects() - find manifest files
       │   └─> For each project:
       │       ├─> scan_manifests() - check declared dependencies
       │       ├─> scan_lockfiles() - check resolved versions
       │       └─> scan_installed() - check installed packages
       └─> Return List[Finding]

2. Report Generation
   ├─> ReportEngine.add_findings() from all adapters
   ├─> Group findings by ecosystem and type
   └─> Output console report + JSON file
```

## CSV Format

### New Format (with ecosystem)
```csv
ecosystem,name,version
npm,left-pad,1.3.0
npm,@accordproject/concerto-linter,3.24.1
maven,org.apache.logging.log4j:log4j-core,2.14.1
pip,requests,2.25.1
gem,strong_migrations,0.7.9
```

### Backward Compatibility
- Default ecosystem to `npm` if column is missing
- Support reading old format (Package Name,Version)
- Auto-convert on load with warning

## CLI Interface

### New Options
```bash
# Auto-detect all ecosystems
hulud-scan

# Scan specific ecosystem(s)
hulud-scan --ecosystem npm
hulud-scan --ecosystem npm,maven,pip

# Legacy npm-scan command (symlink)
npm-scan --dir /path/to/project

# List supported ecosystems
hulud-scan --list-ecosystems

# List threats for specific ecosystem
hulud-scan --list-affected-packages --ecosystem maven
```

### Auto-Detection Logic
1. Walk directory tree
2. Identify manifest files (package.json, pom.xml, pyproject.toml, Gemfile)
3. Load only adapters for detected ecosystems
4. Report which ecosystems were found and scanned

## Docker Considerations

### Multi-Stage Build
```dockerfile
FROM python:3.11-slim AS base

# Install system dependencies for all ecosystems
RUN apt-get update && apt-get install -y \
    # Java tools
    openjdk-17-jdk-headless \
    maven \
    # Ruby tools
    ruby ruby-dev \
    # Build tools
    gcc g++ make \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    click semantic_version \
    pyyaml toml packaging lxml

# Copy application
COPY src/ /app/src/
COPY sha1-Hulud.csv /app/

# Set path prefix for cleaner output in Docker
# "." = relative paths (./package.json)
# Override with -e SCAN_PATH_PREFIX="$(pwd)" to get full host paths
ENV SCAN_PATH_PREFIX="."

# Set entrypoint to the multi-ecosystem scanner CLI
ENTRYPOINT ["package-scan"]

CMD []
```

### Volume Mounts
- `/workspace` - Project to scan (single mount point)
- Auto-detect ecosystems present in workspace
- Reports saved to `/workspace/hulud_scan_report.json`

### Image Size Considerations
- Base image: ~500MB (includes JDK, Ruby)
- Optional: Create ecosystem-specific images (hulud-scan:npm, hulud-scan:java)
- Use multi-stage builds to minimize layer size

## Testing Strategy

### Unit Tests
- Test each adapter's parsing logic independently
- Mock ThreatDatabase for isolated testing
- Test version matching for each ecosystem's version scheme

### Integration Tests
- Fixture projects for each ecosystem
  - npm: examples/test-npm/
  - Maven: examples/test-maven/
  - Gradle: examples/test-gradle/
  - Python: examples/test-python/
  - Ruby: examples/test-ruby/
  - Polyglot: examples/test-polyglot/ (multiple ecosystems)
- Each fixture contains:
  - Manifests with known compromised packages
  - Lockfiles with resolved compromised versions
  - Mixed scenarios (transitive dependencies)

### Edge Cases to Test
- Malformed manifests (invalid JSON/XML/YAML)
- Multiple lockfile versions (old vs new format)
- Scoped/namespaced packages (@org/pkg, org.company:artifact)
- Missing lockfiles
- Empty node_modules / site-packages
- Permission errors
- Large monorepos with multiple ecosystems

## Migration Path

### Phase 1: Core Refactoring (Current Phase)
1. Create adapter interface
2. Extract ThreatDatabase class
3. Refactor npm code into NpmAdapter
4. Update CSV format (backward compatible)
5. Update CLI to use adapter pattern
6. Maintain backward compatibility with npm-scan command

### Phase 2: Add Java Support
1. Implement JavaAdapter
2. Add Maven pom.xml parsing
3. Add Gradle build.gradle parsing
4. Add test fixtures
5. Update Docker image

### Phase 3: Add Python Support
1. Implement PythonAdapter
2. Support pyproject.toml, requirements.txt, poetry.lock
3. Add test fixtures
4. Update documentation

### Phase 4: Add Ruby Support
1. Implement RubyAdapter
2. Support Gemfile, Gemfile.lock
3. Add test fixtures
4. Complete multi-ecosystem testing

### Phase 5: Optimization
1. Parallel scanning of multiple ecosystems
2. Caching for large repositories
3. Performance benchmarks
4. Docker image optimization

## File Structure

```
hulud-scan/
├── src/
│   └── hulud_scan/
│       ├── __init__.py
│       ├── cli.py                    # CLI entry point
│       ├── core/
│       │   ├── __init__.py
│       │   ├── threat_database.py    # ThreatDatabase class
│       │   ├── report_engine.py      # ReportEngine class
│       │   └── models.py             # Finding dataclass
│       └── adapters/
│           ├── __init__.py
│           ├── base.py               # EcosystemAdapter ABC
│           ├── npm_adapter.py        # NpmAdapter
│           ├── java_adapter.py       # JavaAdapter
│           └── python_adapter.py     # PythonAdapter
├── tests/
│   ├── test_threat_database.py
│   ├── test_report_engine.py
│   ├── test_npm_adapter.py
│   ├── test_java_adapter.py
│   └── test_python_adapter.py
├── examples/
│   ├── test-npm/              # npm test fixtures
│   ├── test-maven/            # Maven test fixtures
│   ├── test-gradle/           # Gradle test fixtures
│   ├── test-python/           # Python test fixtures
│   ├── test-ruby/             # Ruby test fixtures
│   └── test-polyglot/         # Multi-ecosystem test fixture
├── sha1-Hulud.csv             # Threat database (with ecosystem column)
├── pyproject.toml
├── Dockerfile
├── ARCHITECTURE.md            # This file
└── CLAUDE.md                  # Updated with new architecture info
```

## Benefits of This Architecture

1. **Modularity**: Each adapter is self-contained and testable
2. **Extensibility**: New ecosystems can be added without modifying core
3. **Consistency**: Standardized Finding model across all ecosystems
4. **Maintainability**: Clear separation between scanning logic and reporting
5. **Docker-Friendly**: Single container can scan polyglot repositories
6. **Backward Compatible**: Existing npm-scan usage still works
7. **Testability**: Each component can be tested in isolation

## Performance Considerations

1. **Lazy Loading**: Only instantiate adapters for detected ecosystems
2. **Parallel Scanning**: Use ThreadPoolExecutor for multiple projects
3. **Caching**: Cache threat database lookups
4. **Skip Directories**: Don't recurse into node_modules, .git, venv, etc.
5. **Streaming**: Parse large lockfiles line-by-line where possible

## Security Considerations

1. **Sandboxing**: Adapters should not execute package manager commands without explicit user opt-in
2. **Path Traversal**: Validate all file paths stay within scan directory
3. **Resource Limits**: Set timeouts for parsing large files
4. **Privilege Dropping**: Docker container runs as non-root user
5. **Input Validation**: Sanitize all file contents before parsing

## Future Enhancements

1. **SBOM Support**: Export findings in CycloneDX/SPDX format
2. **CI/CD Integration**: GitHub Actions, GitLab CI templates
3. **Severity Scoring**: Add CVSS scores to threat database
4. **Web UI**: Interactive dashboard for scan results
5. **Plugin System**: Allow custom adapters without modifying core
6. **Differential Scanning**: Only scan changed files in CI

**Note**: Automatic remediation suggestions (version upgrades) are intentionally excluded. During active supply chain attacks, we cannot guarantee that newer versions are safe. The tool focuses on threat detection only.
