# Contributing to package-scan

Thank you for considering contributing to `package-scan`! This tool serves a critical need in the security community: **rapid response to emerging supply chain attacks**.

## Project Mission

`package-scan` is a **focused tool** for incident response, not a comprehensive vulnerability scanner. Before contributing, please understand the scope:

**✅ In Scope:**
- Multi-ecosystem support (npm, Maven, Python, Ruby, Rust, Go, .NET)
- CSV-based threat databases for rapid deployment
- CI/CD integration for continuous scanning during attacks
- Simple, fast scanning with minimal dependencies
- Output format flexibility (JSON, SARIF, HTML)

**❌ Out of Scope:**
- General CVE/vulnerability scanning (use Snyk, npm audit)
- SBOM generation (use Syft, CycloneDX)
- Static/dynamic code analysis (use Semgrep, CodeQL)
- Typosquatting detection (use package registry scanners)

See [ROADMAP.md](ROADMAP.md) for detailed scope and priorities.

## Ways to Contribute

### 1. Add New Ecosystem Support

**Priority:** High (see ROADMAP Priority 1)

Add support for Ruby, Rust, Go, or .NET by creating a new adapter:

1. Create `src/package_scan/adapters/new_adapter.py`
2. Inherit from `EcosystemAdapter`
3. Implement required methods (see `docs/source/architecture.rst`)
4. Add comprehensive tests
5. Create test fixtures in `examples/`
6. Update documentation

See existing adapters (`npm_adapter.py`, `java_adapter.py`, `python_adapter.py`) as examples.

### 2. Share Threat Databases

**Priority:** High

If you've identified compromised packages from a real attack:

1. Create CSV with format: `ecosystem,name,version`
2. Test with: `package-scan --csv your-threat.csv --list-affected-packages`
3. Submit PR adding file to `threats/` directory
4. Include description of the attack/threat

Real-world threat databases are invaluable for the security community!

### 3. CI/CD Integration Examples

**Priority:** Medium (see ROADMAP Priority 2)

Create examples for:
- GitHub Actions workflows
- GitLab CI templates
- Jenkins pipelines
- CircleCI configs
- Azure DevOps pipelines

### 4. Output Format Scripts

**Priority:** Medium (see ROADMAP Priority 4)

Create example scripts that transform JSON output to:
- SARIF (for GitHub Code Scanning)
- HTML reports
- Slack/Teams notifications
- CSV summaries
- SIEM integration formats

### 5. Documentation

Always welcome:
- Improve existing docs
- Add real-world use case examples
- Create tutorials
- Fix typos/clarity issues

### 6. Bug Fixes

Found a bug? Please:
1. Open an issue with reproduction steps
2. Submit PR with fix and test
3. Reference the issue in PR description

## Development Setup

### Quick Start

```bash
# Clone repository
git clone https://github.com/thekitchencoder/package-scan.git
cd package-scan

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install with dev dependencies
pip install -e ".[dev]"

# Verify installation
package-scan --help
package-scan --list-ecosystems

# Run tests
pytest

# Build documentation
cd docs && make html
```

### Install Optional Dependencies

```bash
# All ecosystems
pip install -e ".[all]"

# Specific ecosystems
pip install -e ".[pnpm]"    # pnpm/conda support
pip install -e ".[java]"     # Maven/Gradle
pip install -e ".[python]"   # Python ecosystem
```

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

### Writing Tests

All new features must include tests:

- **Unit tests** for core components (`test_*.py`)
- **Integration tests** with real file fixtures
- **Adapter tests** scanning example projects

Use pytest fixtures for reusable test data:

```python
def test_scan_package_json(temp_project_dir, threat_db):
    """Test scanning package.json."""
    adapter = NpmAdapter(threat_db)
    # ... test code
```

## Code Style

- Follow PEP 8
- Use type hints where appropriate
- Write docstrings for public APIs
- Keep functions focused and testable
- Use descriptive variable names

## Pull Request Process

1. **Fork the repository**

2. **Create feature branch**:
   ```bash
   git checkout -b feature/add-ruby-support
   ```

3. **Make changes**:
   - Write code
   - Add tests
   - Update documentation
   - Run tests locally

4. **Commit with clear messages**:
   ```bash
   git commit -m "feat: Add Ruby/Gem ecosystem adapter"
   ```

5. **Push and create PR**:
   ```bash
   git push origin feature/add-ruby-support
   ```

6. **PR checklist**:
   - [ ] Tests pass (`pytest`)
   - [ ] Documentation updated
   - [ ] Clear PR description
   - [ ] References related issues
   - [ ] Follows code style

## Commit Message Format

Use conventional commits:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation only
- `test:` Adding or updating tests
- `refactor:` Code refactoring
- `chore:` Maintenance tasks

Examples:
```
feat: Add Rust/Cargo ecosystem adapter
fix: Handle empty package.json files
docs: Update installation instructions
test: Add tests for Maven version ranges
```

## Adding a New Ecosystem Adapter

Detailed guide for adding ecosystem support:

### 1. Create Adapter File

`src/package_scan/adapters/ruby_adapter.py`:

```python
from typing import List
from pathlib import Path
from .base import EcosystemAdapter
from package_scan.core import Finding, ThreatDatabase

class RubyAdapter(EcosystemAdapter):
    def _get_ecosystem_name(self) -> str:
        return 'gem'

    def get_manifest_files(self) -> List[str]:
        return ['Gemfile']

    def get_lockfile_names(self) -> List[str]:
        return ['Gemfile.lock']

    def detect_projects(self, root_dir: str) -> List[Path]:
        # Implementation
        pass

    def scan_project(self, project_dir: str) -> List[Finding]:
        # Implementation
        pass
```

### 2. Register Adapter

In `src/package_scan/adapters/__init__.py`:

```python
from .ruby_adapter import RubyAdapter

ADAPTER_REGISTRY = {
    'npm': NpmAdapter,
    'maven': JavaAdapter,
    'pip': PythonAdapter,
    'gem': RubyAdapter,  # Add here
}
```

### 3. Create Test Fixtures

`examples/test-ruby/`:
```
examples/test-ruby/
├── Gemfile
├── Gemfile.lock
└── README.md
```

### 4. Write Tests

`tests/test_ruby_adapter.py`:
```python
def test_scan_gemfile(temp_project_dir, threat_db):
    adapter = RubyAdapter(threat_db)
    # ... test implementation
```

### 5. Update Documentation

- Add to `docs/source/architecture.rst`
- Update README.md ecosystems list
- Add usage examples

## Community Guidelines

- Be respectful and inclusive
- Help newcomers get started
- Review PRs constructively
- Share knowledge and expertise
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md)

## Questions?

- **Bugs/Features**: Open a GitHub issue
- **Discussions**: Use GitHub Discussions
- **Security**: See SECURITY.md for reporting vulnerabilities

## Recognition

Contributors are recognized in:
- GitHub contributors page
- Project documentation
- Release notes

Thank you for helping make package-scan a valuable tool for the security community! 🛡️
