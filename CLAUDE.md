# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

hulud-scan is a Python CLI tool for detecting npm packages compromised by the HULUD worm. It scans `package.json` files and `node_modules` directories against a CSV list of known compromised packages (sha1-Hulud.csv).

## Development Setup

1. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install in editable mode:
   ```bash
   pip install -e .
   ```

3. Verify installation:
   ```bash
   npm-scan --help
   ```

## Running the Tool

**Basic usage:**
```bash
npm-scan                                    # Scan current directory with ./sha1-Hulud.csv
npm-scan --dir /path/to/project            # Scan specific directory
npm-scan --csv /path/to/custom.csv         # Use custom CSV file
npm-scan --output custom_report.json       # Custom output file
npm-scan --no-save                         # Don't save JSON report
```

**Run directly from source:**
```bash
python scan_npm_threats.py --help
python -m scan_npm_threats --help
```

**Run with Docker:**
```bash
docker build -t hulud-scan .
docker run --rm -v "$(pwd):/workspace" hulud-scan
# Report saved as ./hulud_scan_report.json
```

## Architecture

### Core Components

**HuludScanner class** (scan_npm_threats.py):
- `load_compromised_packages()`: Loads CSV into `compromised_packages` dict mapping package names to sets of compromised versions
- `scan_directory()`: Walks directory tree, calling check methods for package.json files, lock files, and node_modules directories
- `check_package_json()`: Scans dependency declarations (dependencies, devDependencies, peerDependencies, optionalDependencies) using semantic_version to check if version specs match compromised versions
- `check_package_lock_json()`: Parses package-lock.json (npm v1-v3 formats) to extract exact resolved versions
- `check_yarn_lock()`: Parses yarn.lock files using regex patterns to extract package versions
- `check_pnpm_lock_yaml()`: Parses pnpm-lock.yaml files (requires optional PyYAML dependency)
- `check_node_modules()`: Scans installed packages, handling scoped packages (@org/package)
- `_check_installed_package()`: Checks individual installed package versions
- `print_report()`: Generates console output with findings grouped by type (package.json, lockfile, installed)
- `save_report()`: Writes JSON report to disk

### Key Behavior

**Three-phase detection:**
1. **package.json scanning**: Checks declared dependency ranges using semantic version matching
2. **Lock file parsing**: Extracts exact resolved versions from package-lock.json, yarn.lock, or pnpm-lock.yaml
3. **node_modules scanning**: Checks actually installed packages by reading their package.json files

This comprehensive approach catches:
- Vulnerable ranges that haven't been installed yet
- Transitive dependencies only visible in lock files
- Actually installed packages including nested dependencies

**Version matching:**
- Uses `semantic_version.NpmSpec` to parse npm semver ranges (^, ~, >=, etc.)
- For each compromised version, checks if it's included in the declared range
- Falls back to exact string matching for non-standard version specs (git URLs, file paths)
- Lock files provide exact version matches (no range checking needed)
- Match types: `exact` (specific version) or `range` (semver range includes compromised versions)

**Remediation suggestions:**
- Exact matches: Suggests upgrading to next patch version (e.g., 1.2.3 → >=1.2.4)
- Range matches: Suggests raising minimum version above highest compromised version
- Provides package manager-specific override instructions (npm/yarn/pnpm)

**Lock file parsing:**
- **package-lock.json**: Supports both old format (lockfileVersion 1/2 with nested dependencies) and new format (lockfileVersion 3 with flat packages object)
- **yarn.lock**: Uses regex parsing to extract package names and versions from the custom yarn format
- **pnpm-lock.yaml**: Parses YAML format with package keys like `/package-name/1.2.3` (requires PyYAML: `pip install pyyaml`)
- Lock files reveal the complete dependency graph including transitive dependencies not visible in package.json

**Scoped packages:**
- Handles @org/package format in package.json, lock files, and by recursing into @ directories in node_modules

**CSV format:**
The tool expects a CSV with headers `Package Name` and `Version`:
```csv
Package Name,Version
left-pad,1.3.0
some-package,2.0.1
```

## Project Structure

- `scan_npm_threats.py`: Single-file implementation containing scanner logic and CLI
- `pyproject.toml` / `setup.py`: Package configuration (setuptools)
- `Dockerfile`: Multi-stage build on python:3.11-slim base
- `.dockerignore`: Excludes unnecessary files from Docker build context
- `sha1-Hulud.csv`: Default compromised package list (included in Docker image)
- `examples/test-package/`: Test fixture with example package.json containing compromised dependencies
- Console script entry point: `npm-scan` → `scan_npm_threats:cli`

## Dependencies

- `click>=8.1`: CLI framework
- `semantic_version>=2.10`: npm semver range parsing and matching
- `pyyaml` (optional): Required only for pnpm-lock.yaml parsing. Install with `pip install pyyaml`

## Output Format

The tool reports findings in three categories:
1. **PACKAGE.JSON FILES**: Declared dependencies with vulnerable version ranges
2. **LOCK FILES**: Exact resolved versions from package-lock.json / yarn.lock / pnpm-lock.yaml
3. **INSTALLED PACKAGES**: Packages found in node_modules directories

Lock file findings are particularly valuable because they:
- Show exact versions that will be installed (not just ranges)
- Reveal transitive dependencies not declared in package.json
- Provide the most accurate view of what `npm install` / `yarn install` / `pnpm install` would produce

## Docker Deployment

The tool can be containerized for easy distribution and consistent execution environments.

**Dockerfile design:**
- Base image: `python:3.11-slim` (Debian-based, security updates, small footprint ~235MB)
- Security: Runs as non-root user `scanner:scanner`
- Dependencies: Pre-installs click, semantic_version, and PyYAML for full lock file support
- Default CSV: `sha1-Hulud.csv` baked into image at `/app/sha1-Hulud.csv`
- Working directory: `/workspace` - single volume mount keeps it simple
- Smart defaults: Automatically scans `.` and finds CSV in `/app/`
- Output: Reports saved to `/workspace/hulud_scan_report.json` by default

**Volume mounts:**
- `/workspace`: Single mount point for your project (scans and reports here)
- CSV auto-detected from `/app/sha1-Hulud.csv` (no mount needed)
- Custom CSV: Just place in workspace and use `--csv custom.csv`

**Build optimization:**
- `.dockerignore` excludes venv, examples, IDE files to reduce build context
- pip `--no-cache-dir` reduces image size
- Multi-layer caching: dependencies layer separate from code layer