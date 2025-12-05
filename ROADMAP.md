# ROADMAP for package-scan

This document outlines the strategic direction for `package-scan`, a rapid-response tool designed for defenders during active software supply chain attacks.

## Vision and Purpose

`package-scan` is **NOT** a replacement for comprehensive vulnerability scanners like Snyk, npm audit, or Dependabot. Those tools excel at ongoing security monitoring and CVE detection.

Instead, `package-scan` serves a specific, critical need: **rapid deployment during emerging supply chain attacks**. When a new attack is discovered (like the sha1-Hulud worm or the event-stream incident), defenders need to:

1. **Quickly scan** their infrastructure against lists of known compromised packages
2. **Deploy easily** across multiple projects and ecosystems
3. **Respond immediately** without waiting for official CVE databases or scanner updates
4. **Share intelligence** with their security team using simple CSV threat lists

This tool prioritizes **speed, simplicity, and flexibility** over comprehensive analysis.

## Completed Features ✅

### Multi-Ecosystem Support
- ✅ **npm ecosystem**: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml, node_modules
- ✅ **Maven/Gradle**: pom.xml, build.gradle, build.gradle.kts, gradle.lockfile
- ✅ **Python/pip**: requirements.txt, pyproject.toml, poetry.lock, Pipfile, Pipfile.lock, environment.yml
- ✅ **Version range matching**: Intelligent matching for npm semver (^, ~), Maven ranges ([,)), PEP 440 (>=, ~=)

### Threat Database System
- ✅ **CSV-based threats**: Simple format for rapid threat list creation
- ✅ **Multi-threat support**: Scan for specific threats or all threats
- ✅ **Custom databases**: Load any CSV file with compromised packages

### Deployment & Integration
- ✅ **Docker support**: Pre-built images for rapid deployment
- ✅ **CLI tool**: Simple command-line interface
- ✅ **JSON reporting**: Machine-readable output for automation
- ✅ **Modular architecture**: Easy to extend with new ecosystems

### Documentation
- ✅ **Comprehensive docs**: Sphinx documentation with API reference
- ✅ **Test coverage**: Unit tests for core components and adapters
- ✅ **Usage examples**: Docker, CI/CD, and command-line examples

## Priority 1: Core Ecosystem Expansion

**Goal**: Support the most common package ecosystems to maximize usefulness during supply chain attacks.

### Ruby/Gem Support
- [ ] Parse `Gemfile` and `Gemfile.lock`
- [ ] Support Bundler version specifications
- [ ] Create RubyAdapter with version matching
- [ ] Add test fixtures and documentation

### Rust/Cargo Support
- [ ] Parse `Cargo.toml` and `Cargo.lock`
- [ ] Support Cargo version requirements
- [ ] Create CargoAdapter with version matching
- [ ] Add test fixtures and documentation

### Go Modules Support
- [ ] Parse `go.mod` and `go.sum`
- [ ] Support Go module versioning
- [ ] Create GoAdapter with version matching
- [ ] Add test fixtures and documentation

### .NET/NuGet Support
- [ ] Parse `.csproj`, `packages.config`, `packages.lock.json`
- [ ] Support NuGet version ranges
- [ ] Create NuGetAdapter with version matching
- [ ] Add test fixtures and documentation

## Priority 2: CI/CD Integration

**Goal**: Enable teams to scan continuously during active attacks to ensure they remain uncompromised.

### GitHub Actions Integration
- [ ] Create official GitHub Action for package-scan
- [ ] Support matrix builds for monorepos
- [ ] Add examples for PR checks and scheduled scans
- [ ] Document exit codes and failure modes

### GitLab CI Integration
- [ ] Create GitLab CI template
- [ ] Add examples for pipeline integration
- [ ] Document artifacts and reports

### Jenkins Integration
- [ ] Create Jenkins pipeline examples
- [ ] Document integration patterns
- [ ] Add examples for multi-branch scanning

### General CI/CD Features
- [ ] Add `--fail-on-findings` flag to exit with error code
- [ ] Add `--quiet` mode for minimal output
- [ ] Improve JSON output for CI/CD consumption
- [ ] Add badge/status generation

## Priority 3: Enhanced Threat Database Features

**Goal**: Make it easier for security teams to create, share, and use threat databases.

### Threat Database Enhancements
- [ ] Add severity/risk levels to CSV format (critical, high, medium, low)
- [ ] Support metadata fields (CVE IDs, advisory URLs, notes)
- [ ] Add threat database validation tool
- [ ] Create threat database templates for common attack patterns

### Documentation & Examples
- [ ] Create guide for building threat CSVs from security advisories
- [ ] Add examples of scraping vendor security pages
- [ ] Document best practices for threat database organization
- [ ] Provide templates for incident response teams

## Priority 4: Output Format Flexibility

**Goal**: Make it easy to integrate package-scan output into various tools and workflows.

### JSON Transformation Scripts
- [ ] Provide example script: JSON → SARIF (for GitHub Code Scanning)
- [ ] Provide example script: JSON → HTML report
- [ ] Provide example script: JSON → CSV summary
- [ ] Provide example script: JSON → Slack/Teams notification
- [ ] Document JSON schema for custom transformations

### Enhanced Reporting
- [ ] Add `--format` flag (json, sarif, html, csv)
- [ ] Support severity-based filtering in output
- [ ] Add summary statistics to console output

## Future/Community-Driven Features

**Goal**: Features that would benefit the community but require collaboration or sustained effort.

### Centralized Threat Database (Community)
- [ ] Design API for centralized threat database
- [ ] Create community-maintained threat repository
- [ ] Add `--update-threats` command to pull latest threats
- [ ] Implement caching and offline mode
- [ ] **Requires**: Community hosting, moderation, and maintenance

### Automated Threat Detection (AI/Research)
- [ ] Explore AI/ML for identifying compromised packages from vendor feeds
- [ ] Create scrapers for major security vendor advisories
- [ ] Automate CSV generation from identified attacks
- [ ] Build confidence scoring system
- [ ] **Requires**: Research, compute resources, and community validation

### Package Registry Integration (Optional)
- [ ] Add support for private registries (npm, Maven, PyPI, etc.)
- [ ] Support authentication for private packages
- [ ] Add registry-specific metadata checking
- [ ] **Requires**: Careful design to avoid scope creep

## Explicitly Out of Scope

These features are better handled by existing comprehensive security tools:

❌ **General CVE/vulnerability database integration** (Use: npm audit, Snyk, Dependabot)
❌ **SBOM generation and analysis** (Use: Syft, CycloneDX tools)
❌ **Static/dynamic code analysis** (Use: Semgrep, CodeQL)
❌ **Typosquatting detection** (Use: Package registry scanners)
❌ **Package metadata risk analysis** (Use: Socket.dev, Phylum)
❌ **License compliance checking** (Use: FOSSA, Licensee)

`package-scan` is a focused tool for a specific purpose. For comprehensive supply chain security, use it alongside other specialized tools.

## Contributing

We welcome contributions, especially:
- **New ecosystem adapters**: Add support for additional package managers
- **Threat databases**: Share threat CSVs from real-world attacks
- **CI/CD templates**: Examples for additional platforms
- **Output format scripts**: JSON transformation examples

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Questions or Suggestions?

Open an issue on GitHub to discuss roadmap priorities or suggest new features that align with the rapid-response mission.
