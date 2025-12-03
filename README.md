# hulud-scan

NPM Package Threat Scanner for identifying projects impacted by the HULUD worm. This tool scans `package.json` files, lock files (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`), and installed packages in `node_modules` to flag known compromised packages from a provided CSV list.

## Installation

1. Create and activate a virtual environment (recommended):

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # Windows: .venv\Scripts\activate
   ```

2. Install the package in editable mode (installs dependencies like `click` automatically):

   ```bash
   pip install -e .
   ```

3. Verify the CLI is available:

   ```bash
   npm-scan --help
   ```

## Docker Installation (Alternative)

Run the scanner as a Docker container without installing Python locally.

1. Build the Docker image:

   ```bash
   docker build -t hulud-scan .
   ```

2. Run the scanner (simple - just mount your project):

   ```bash
   # Scan current directory - super simple!
   docker run --rm -v "$(pwd):/workspace" hulud-scan

   # That's it! The report is saved as ./hulud_scan_report.json
   ```

3. Advanced usage:

   ```bash
   # Custom output filename
   docker run --rm -v "$(pwd):/workspace" hulud-scan --output my-report.json

   # Scan subdirectory
   docker run --rm -v "$(pwd):/workspace" hulud-scan --dir ./src

   # Use custom CSV
   docker run --rm -v "$(pwd):/workspace" hulud-scan --csv /workspace/custom.csv

   # No report file (stdout only)
   docker run --rm -v "$(pwd):/workspace" hulud-scan --no-save
   ```

**How it works:**
- Mount your project to `/workspace` (single volume, simple!)
- Scanner automatically finds CSV in container
- Report saved directly in your mounted directory
- No need to specify paths like `/workspace/` - just use filenames

**Docker features:**
- Based on `python:3.11-slim` (secure, minimal base)
- Runs as non-root user for security
- Includes default `sha1-Hulud.csv`
- All dependencies pre-installed (including PyYAML for pnpm support)
- ~235MB image size

## Usage

Basic scan of the current directory using `./sha1-Hulud.csv` and writing `hulud_scan_report.json`:

```bash
npm-scan
```

Scan a specific project directory and write a custom output file:

```bash
npm-scan --dir /path/to/project --csv /path/to/sha1-Hulud.csv --output /tmp/report.json
```

Scan without saving a JSON report (prints findings to stdout only):

```bash
npm-scan --dir . --no-save
```

List all compromised packages in the threat database:

```bash
npm-scan --list-affected-packages

# Or with Docker
docker run --rm hulud-scan --list-affected-packages
```

Export the threat database as CSV (useful for piping to files or other tools):

```bash
# Save to file
npm-scan --list-affected-packages-csv > threats.csv

# With Docker
docker run --rm hulud-scan --list-affected-packages-csv > threats.csv

# Pipe to other tools
docker run --rm hulud-scan --list-affected-packages-csv | grep "package-name"
```

### CLI Options

- `--dir PATH`: Root directory to scan recursively. Defaults to the current working directory.
- `--csv FILE`: Path to CSV containing compromised packages (HULUD list). Defaults to `./sha1-Hulud.csv`.
  - If the specified CSV path does not exist, the CLI will also try `${--dir}/sha1-Hulud.csv` automatically.
- `--output FILE`: Path to write the JSON report. Defaults to `hulud_scan_report.json`.
- `--no-save`: Do not write a JSON report to disk; only print results.
- `--output-relative-paths`: Use relative paths in JSON output instead of absolute paths (auto-enabled in Docker).
- `--list-affected-packages`: Display the full list of compromised packages from the threat database and exit (useful for inspecting the embedded CSV).
- `--list-affected-packages-csv`: Output the threat database as raw CSV to stdout and exit (useful for piping to files or other tools).

## CSV Format

The scanner expects a CSV with headers including at least:

- `Package Name`
- `Version`

Example rows:

```csv
Package Name,Version
left-pad,1.3.0
some-package,2.0.1
```

## What Gets Scanned

The tool performs comprehensive scanning in three phases:

1. **package.json files**: Checks declared dependency ranges to identify if they could install compromised versions
2. **Lock files**: Parses exact resolved versions from:
   - `package-lock.json` (npm) - supports all lockfile versions
   - `yarn.lock` (Yarn)
   - `pnpm-lock.yaml` (pnpm) - requires `pip install pyyaml`
3. **node_modules directories**: Scans actually installed packages

Lock file scanning is particularly valuable because it:
- Shows exact versions that will be installed (not just ranges)
- Reveals transitive dependencies not visible in package.json
- Detects compromised packages even if they're not directly declared

## Output

- A human-readable report is printed to the console showing findings grouped by source (package.json, lock files, installed packages).
- If not using `--no-save`, a JSON report is written (default `hulud_scan_report.json`) with the following structure:

```json
{
  "total_findings": 3,
  "findings": [
    {
      "type": "package.json",
      "file": "/path/to/project/package.json",
      "package": "left-pad",
      "version": "1.3.0",
      "version_spec": "^1.3.0",
      "dependency_type": "dependencies"
    },
    {
      "type": "lockfile",
      "lockfile_type": "package-lock.json",
      "file": "/path/to/project/package-lock.json",
      "package": "some-package",
      "version": "2.0.1",
      "match_type": "exact"
    },
    {
      "type": "installed",
      "location": "/path/to/project/node_modules",
      "package": "left-pad",
      "version": "1.3.0",
      "package_path": "/path/to/project/node_modules/left-pad"
    }
  ]
}
```

## Troubleshooting

- `ModuleNotFoundError: No module named 'click'`
  - Ensure you installed the project into your active virtual environment: `pip install -e .`
  - Verify you activated the venv: `source .venv/bin/activate` (or Windows equivalent).

- `npm-scan: command not found`
  - Confirm the venv is active and `pip install -e .` completed successfully.
  - On some shells, you may need to re-activate the venv after installation.
  - You can also run via Python directly: `python -m scan_npm_threats --help` or `python scan_npm_threats.py`.

- CSV not found
  - The tool looks at the path you pass to `--csv`. If not found, it will try `${--dir}/sha1-Hulud.csv`.
  - Place the CSV in your scan directory or pass an absolute path.

## Development

Run from source without installing globally (still recommended to use a venv):

```bash
python scan_npm_threats.py --help
python scan_npm_threats.py --dir /path/to/project --csv /path/to/sha1-Hulud.csv
```

Run linting/formatting or tests (if you add them) as desired. The project is packaged via `pyproject.toml` using `setuptools` and exposes the console script `npm-scan` mapped to `scan_npm_threats:cli`.

## License

MIT

## Contributing

Contributions are welcome! Please read the [contributing guidelines](CONTRIBUTING.md) to get started.

This project and everyone participating in it is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.
