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

---

## Implementation Roadmap

This roadmap is organized by implementation phases, balancing complexity with value. Each task includes specific deliverables suitable for AI coding agents.

### **Phase 1: Quick Wins (Low Complexity, High Value)**
*Timeline: 1-2 weeks per task*

#### **1.1 Threat Database Validation**
**Value**: Prevents distribution of malformed threat CSVs  
**Complexity**: Low  
**Tasks**:
- [ ] Create `src/package_scan/core/threat_validator.py`
- [ ] Implement CSV format validation (headers, data types)
- [ ] Add `package-scan threat-db validate --file threats.csv` command
- [ ] Add unit tests for validation logic
- [ ] Update documentation with validation examples

#### **1.2 Parallel Scanning Implementation**
**Value**: 2-3x faster scanning for multi-ecosystem projects  
**Complexity**: Low-Medium  
**Tasks**:
- [ ] Add `concurrent.futures.ThreadPoolExecutor` to `cli.py`
- [ ] Modify `scan_all_projects()` to run adapters in parallel
- [ ] Add `--parallel` flag with default enabled
- [ ] Add thread-safe progress reporting
- [ ] Add tests for parallel execution

#### **1.3 Enhanced Error Handling**
**Value**: Better user experience during scanning failures  
**Complexity**: Low  
**Tasks**:
- [ ] Wrap all adapter file operations in try-catch blocks
- [ ] Add specific error messages for common issues (permissions, malformed files)
- [ ] Implement graceful degradation when individual files fail
- [ ] Add `--verbose` flag for detailed error output
- [ ] Update tests with error scenarios

#### **1.4 Quick Scan Mode**
**Value**: 5x faster scanning for large repositories during incidents  
**Complexity**: Low  
**Tasks**:
- [ ] Add `--quick` flag that skips lockfiles and installed packages
- [ ] Modify adapters to support manifest-only scanning
- [ ] Add warning about reduced accuracy in quick mode
- [ ] Add performance benchmarks to documentation
- [ ] Create tests for quick mode functionality

---

### **Phase 2: Strategic Enhancements (Medium Complexity, High Value)**
*Timeline: 2-4 weeks per task*

#### **2.1 Threat Database Management Tools**
**Value**: Streamlines threat intelligence workflow  
**Complexity**: Medium  
**Tasks**:
- [ ] Create `src/package_scan/core/threat_manager.py`
- [ ] Implement `threat-db merge --file1.csv --file2.csv --output merged.csv`
- [ ] Implement `threat-db diff --old.csv --new.csv --output changes.csv`
- [ ] Add threat source tracking in merged databases
- [ ] Create comprehensive test suite
- [ ] Update CLI help and documentation

#### **2.2 SARIF Output Format**
**Value**: Native GitHub Code Scanning integration  
**Complexity**: Medium  
**Tasks**:
- [ ] Create `src/package_scan/output/sarif_formatter.py`
- [ ] Implement SARIF 2.1.0 schema compliance
- [ ] Add `--format sarif` flag to CLI
- [ ] Map findings to SARIF results with proper severity levels
- [ ] Add GitHub Actions workflow example
- [ ] Create SARIF validation tests

#### **2.3 Configuration File Support**
**Value**: Reduces repetitive command-line arguments  
**Complexity**: Medium  
**Tasks**:
- [ ] Add `pyyaml` dependency for YAML config files
- [ ] Create `src/package_scan/core/config.py`
- [ ] Implement `.package-scan.yaml` configuration loading
- [ ] Support all CLI options in config file
- [ ] Add `--config` flag to specify custom config path
- [ ] Create config file validation and examples
- [ ] Update documentation with configuration guide

#### **2.4 Baseline and Ignore Features**
**Value**: Reduces noise in CI/CD by ignoring known findings  
**Complexity**: Medium  
**Tasks**:
- [ ] Add `--baseline` flag to load previous scan results
- [ ] Implement finding comparison logic in `ReportEngine`
- [ ] Add `--ignore` flag for specific package/version combinations
- [ ] Create baseline file format (JSON with findings)
- [ ] Add baseline update workflow
- [ ] Create tests for baseline functionality

---

### **Phase 3: Ecosystem Expansion (High Complexity, Medium Value)**
*Timeline: 3-5 weeks per task*

#### **3.1 Ruby/Gem Adapter**
**Value**: Covers Ruby ecosystem, frequently targeted in attacks  
**Complexity**: High  
**Tasks**:
- [ ] Create `src/package_scan/adapters/ruby_adapter.py`
- [ ] Implement Gemfile parsing with regex
- [ ] Implement Gemfile.lock parsing
- [ ] Add Bundler version specification support
- [ ] Create test fixtures in `examples/test-ruby/`
- [ ] Add Ruby ecosystem detection logic
- [ ] Implement version matching for Gem requirements
- [ ] Add comprehensive unit tests
- [ ] Update Docker image with Ruby runtime
- [ ] Update documentation with Ruby examples

#### **3.2 Enhanced Threat Metadata**
**Value**: Richer threat intelligence for better decision making  
**Complexity**: Medium-High  
**Tasks**:
- [ ] Extend CSV format to include: severity, cve_id, advisory_url, notes
- [ ] Update `ThreatDatabase` to handle new columns
- [ ] Modify `Finding` model to include metadata
- [ ] Add severity filtering in CLI (`--severity critical,high`)
- [ ] Update JSON output to include metadata
- [ ] Create threat database migration tool
- [ ] Add metadata validation
- [ ] Update all test fixtures with new format
- [ ] Create backward compatibility layer for old CSV format

#### **3.3 Progress Indicators with ETA**
**Value**: Better user experience for large repository scans  
**Complexity**: Medium  
**Tasks**:
- [ ] Enhance `ProgressSpinner` class with time tracking
- [ ] Implement file counting before scanning starts
- [ ] Add ETA calculation based on scan speed
- [ ] Show current file being scanned
- [ ] Add ecosystem-specific progress bars
- [ ] Create progress bar tests
- [ ] Add `--no-progress` flag for CI/CD environments

---

### **Phase 4: Advanced Features (High Complexity, High Value)**
*Timeline: 4-6 weeks per task*

#### **4.1 GitHub Action with Matrix Scanning**
**Value**: Seamless CI/CD integration for DevOps teams  
**Complexity**: High  
**Tasks**:
- [ ] Create `.github/workflows/package-scan.yml`
- [ ] Implement matrix strategy for multiple ecosystems
- [ ] Add SARIF upload to GitHub Code Scanning
- [ ] Create action configuration schema
- [ ] Add PR comment generation for findings
- [ ] Implement caching for threat databases
- [ ] Create comprehensive action documentation
- [ ] Add action tests with sample repositories
- [ ] Publish action to GitHub Marketplace

#### **4.2 Interactive Mode**
**Value**: Guided scanning for non-technical users  
**Complexity**: High  
**Tasks**:
- [ ] Add `--interactive` flag to CLI
- [ ] Create `src/package_scan/interactive/interactive_mode.py`
- [ ] Implement menu-driven ecosystem selection
- [ ] Add guided threat database selection
- [ ] Create real-time progress display
- [ ] Add scan result exploration interface
- [ ] Implement help system with examples
- [ ] Create interactive mode tests
- [ ] Update documentation with interactive guide

#### **4.3 Advanced Reporting Dashboard**
**Value**: Visual threat overview for management reporting  
**Complexity**: High  
**Tasks**:
- [ ] Create `src/package_scan/output/html_dashboard.py`
- [ ] Implement responsive HTML template with charts
- [ ] Add threat breakdown by ecosystem and severity
- [ ] Include trend analysis for multiple scans
- [ ] Add export to PDF functionality
- [ ] Create dashboard CSS/JS assets
- [ ] Implement dark/light theme support
- [ ] Add dashboard tests
- [ ] Update Docker image with web server

---

## Implementation Dependencies

```
Phase 1 (can be parallel):
├── 1.1 Threat Validation (independent)
├── 1.2 Parallel Scanning (independent)
├── 1.3 Error Handling (independent)
└── 1.4 Quick Scan Mode (independent)

Phase 2 (sequential):
├── 2.1 Threat Management Tools (prerequisite for 2.4)
├── 2.2 SARIF Output (independent)
├── 2.3 Configuration File (prerequisite for 2.4)
└── 2.4 Baseline Features (depends on 2.1, 2.3)

Phase 3 (sequential):
├── 3.1 Ruby Adapter (independent)
├── 3.2 Enhanced Metadata (prerequisite for 4.1)
└── 3.3 Progress Indicators (independent)

Phase 4 (sequential):
├── 4.1 GitHub Action (depends on 2.2, 3.2)
├── 4.2 Interactive Mode (depends on 2.3, 3.3)
└── 4.3 HTML Dashboard (depends on 3.2, 3.3)
```

## Value vs Complexity Matrix

| Feature | Complexity | Value | Priority |
|---------|------------|-------|----------|
| Error Handling | Low | High | 1 |
| Quick Scan Mode | Low | High | 2 |
| Threat Validation | Low | High | 3 |
| Parallel Scanning | Low-Med | High | 4 |
| SARIF Output | Medium | High | 5 |
| Configuration File | Medium | High | 6 |
| Progress Indicators | Medium | High | 7 |
| Threat Management | Medium | High | 8 |
| Enhanced Metadata | Med-High | High | 9 |
| Baseline Features | Medium | Med | 10 |
| Ruby Adapter | High | Medium | 11 |
| GitHub Action | High | High | 12 |
| Interactive Mode | High | Medium | 13 |
| HTML Dashboard | High | Medium | 14 |

---

## Explicitly Out of Scope

These features are better handled by existing comprehensive security tools:

❌ **General CVE/vulnerability database integration** (Use: npm audit, Snyk, Dependabot)  
❌ **SBOM generation and analysis** (Use: Syft, CycloneDX tools)  
❌ **Static/dynamic code analysis** (Use: Semgrep, CodeQL)  
❌ **Typosquatting detection** (Use: Package registry scanners)  
❌ **Package metadata risk analysis** (Use: Socket.dev, Phylum)  
❌ **License compliance checking** (Use: FOSSA, Licensee)  

`package-scan` is a focused tool for a specific purpose. For comprehensive supply chain security, use it alongside other specialized tools.

---

## Contributing

We welcome contributions, especially:
- **New ecosystem adapters**: Add support for additional package managers
- **Threat databases**: Share threat CSVs from real-world attacks
- **CI/CD templates**: Examples for additional platforms
- **Output format scripts**: JSON transformation examples

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Questions or Suggestions?

Open an issue on GitHub to discuss roadmap priorities or suggest new features that align with the rapid-response mission.