# Repository Guidelines

## Project Structure & Key Paths
- Application code lives in `src/package_scan/` (CLI entry in `cli.py`, adapters per ecosystem in `adapters/`, shared models/core utilities in `core/`).
- Threat intelligence CSVs are in `threats/`; example fixtures per ecosystem are under `examples/`.
- Tests sit in `tests/` using pytest; docs are in `docs/` (Sphinx).
- Utility scripts reside in `scripts/`; Docker entrypoint is defined via `Dockerfile`.

## Build, Test, and Development Commands
- Create a virtual env and install dev deps: `python3 -m venv venv && source venv/bin/activate && pip install -e ".[dev]"`.
- Run the scanner locally: `python -m package_scan.cli --help` or `package-scan --list-ecosystems`.
- Execute tests: `pytest` (add `--cov=package_scan --cov-report=html` for coverage).
- Build docs: `cd docs && make html`.
- Docker build/run: `docker build -t package-scan .` then `docker run --rm -v "$PWD:/workspace" package-scan`.

## Coding Style & Naming Conventions
- Follow PEP 8 with type hints on public interfaces; prefer small, focused functions.
- Tests use `test_*.py` filenames and descriptive `test_can_*`/`test_handles_*` names.
- Keep adapter classes ending with `Adapter` (e.g., `PythonAdapter`), and new ecosystems go in `src/package_scan/adapters/`.
- Threat CSVs use `ecosystem,name,version` headers; keep filenames descriptive to the incident (e.g., `sha1-hulud.csv`).

## Testing Guidelines
- Add unit tests for new logic and adapter-specific cases; place fixtures in `examples/` when integration-style.
- Use pytest fixtures for temp projects; prefer realistic package manifests/lockfiles to catch parsing edge cases.
- Aim to keep coverage steady; include negative-path tests for malformed or missing files.

## Commit & Pull Request Guidelines
- Use conventional-style messages when possible (`feat: add ruby adapter`, `fix: handle missing lockfile`); keep subject lines imperative and concise.
- Before opening a PR, ensure `pytest` and (if touched) `make html` pass locally.
- PRs should link related issues, summarize changes, note threat CSV additions, and include screenshots only if output/report formatting changed.
- Keep diffs tight: avoid unrelated formatting churn and update relevant docs when behavior or flags change.

## Security & Configuration Tips
- Treat threat CSVs as sensitive intel; avoid committing proprietary feeds unless cleared.
- When adding new ecosystem support, validate version range parsing against upstream specs and document any constraints in `docs/`.
- Default scan output file is `package_scan_report.json`; override with `--output` and consider `--no-save` for CI secrets hygiene.
