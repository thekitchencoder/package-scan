# Project: hulud-scan

## Project Overview

`hulud-scan` is a Python-based command-line interface (CLI) tool designed to scan for threats in NPM packages. It specifically identifies projects impacted by the "HULUD worm" by checking `package.json` files and installed packages in `node_modules` against a provided CSV list of known compromised packages.

The main technologies used are:
- **Python:** The core language for the application.
- **Click:** A Python package for creating command-line interfaces.
- **semantic_version:** A library for parsing and comparing NPM semantic versioning (semver) strings.

The project is structured as a single-file Python script (`scan_npm_threats.py`) that contains all the logic for scanning and reporting. It is packaged using `setuptools`, with project metadata and dependencies defined in `pyproject.toml` and `setup.py`.

## Building and Running

### Installation

1.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

2.  **Install the package in editable mode:**
    This will install the necessary dependencies and make the `npm-scan` command available in your shell.
    ```bash
    pip install -e .
    ```

### Running the Scanner

The primary way to run the scanner is through the `npm-scan` command:

-   **Scan the current directory:**
    ```bash
    npm-scan
    ```

-   **Scan a specific directory:**
    ```bash
    npm-scan --dir /path/to/your/project
    ```

-   **Specify a different CSV file and output file:**
    ```bash
    npm-scan --dir /path/to/your/project --csv /path/to/your/sha1-Hulud.csv --output /tmp/report.json
    ```

You can also run the script directly using Python:

```bash
python scan_npm_threats.py --dir /path/to/your/project
```

## Development Conventions

-   **Packaging:** The project uses `setuptools` for packaging, with configuration in `pyproject.toml`.
-   **CLI:** The command-line interface is built using the `click` library. The entry point is the `cli` function in `scan_npm_threats.py`.
-   **Dependencies:** Project dependencies are listed in `pyproject.toml` and `setup.py`.
-   **Code Style:** The code is well-structured and includes comments explaining the functionality.
-   **Testing:** There are no tests in the project. If you add any, you should also add instructions on how to run them.
