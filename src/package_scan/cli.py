#!/usr/bin/env python3
"""
Multi-Ecosystem Package Threat Scanner
Scans for compromised packages across npm, Maven/Gradle, pip, and gem ecosystems

CLI usage:
    hulud-scan --dir /path/to/project --csv /path/to/threats.csv
    hulud-scan --ecosystem npm,maven
    npm-scan --dir /path/to/project  # Legacy npm-only mode
"""

import os
import sys
from pathlib import Path
from typing import List, Optional
import click

from package_scan.core import ThreatDatabase, ReportEngine
from package_scan.adapters import get_adapter_class, get_available_ecosystems, ADAPTER_REGISTRY
from package_scan.adapters.base import ProgressSpinner


def resolve_threats_dir() -> Path:
    """
    Resolve threats directory with smart defaults

    Returns:
        Resolved threats directory path
    """
    # Try multiple default locations for threats directory
    candidates = [
        Path.cwd() / 'threats',      # Current directory
        Path('/app/threats'),         # Docker app directory
    ]

    for candidate in candidates:
        if candidate.exists() and candidate.is_dir():
            return candidate

    # Default to first candidate (for better error message)
    return candidates[0]


def auto_detect_ecosystems(root_dir: Path) -> List[str]:
    """
    Auto-detect which ecosystems are present in the directory

    Args:
        root_dir: Root directory to scan

    Returns:
        List of detected ecosystem names
    """
    detected = set()

    # Mapping of file patterns to ecosystems
    # Note: Both Maven and Gradle use 'maven' ecosystem (Maven Central artifact format)
    indicators = {
        'npm': ['package.json'],
        'maven': ['pom.xml', 'build.gradle', 'build.gradle.kts'],
        'pip': ['requirements.txt', 'pyproject.toml', 'setup.py', 'Pipfile'],
        'gem': ['Gemfile'],
    }

    # Walk directory tree looking for indicator files
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Skip common excluded directories
        dirnames[:] = [d for d in dirnames if d not in {
            'node_modules', '.git', 'venv', 'env', '.venv',
            'build', 'dist', 'target', 'vendor', '__pycache__'
        }]

        for ecosystem, patterns in indicators.items():
            if any(pattern in filenames for pattern in patterns):
                detected.add(ecosystem)

        # Early exit if we've found all possible ecosystems
        if len(detected) == len(indicators):
            break

    return sorted(detected)


def filter_available_ecosystems(requested: List[str]) -> List[str]:
    """
    Filter requested ecosystems to only those with implemented adapters

    Args:
        requested: List of requested ecosystem names

    Returns:
        List of available ecosystem names, with warnings for unavailable ones
    """
    available = get_available_ecosystems()
    filtered = []

    for ecosystem in requested:
        if ecosystem in available:
            filtered.append(ecosystem)
        else:
            click.echo(click.style(
                f"⚠️  Warning: {ecosystem} ecosystem requested but adapter not yet implemented. Skipping.",
                fg='yellow'), err=True)
            click.echo(click.style(
                f"   Available: {', '.join(available)}",
                fg='yellow', dim=True), err=True)

    return filtered


@click.command(name="hulud-scan", help="Multi-ecosystem package threat scanner")
@click.option(
    "--dir",
    "scan_dir",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=str),
    default=lambda: os.getcwd(),
    show_default="current working directory",
    help="Root directory to scan recursively",
)
@click.option(
    "--threat",
    "threat_names",
    type=str,
    multiple=True,
    help="Threat name to scan for (repeatable). Example: --threat sha1-Hulud --threat other-threat",
)
@click.option(
    "--csv",
    "csv_file",
    type=click.Path(exists=False, file_okay=True, dir_okay=False, path_type=str),
    default=None,
    help="Path to custom CSV file (overrides --threat). For backward compatibility.",
)
@click.option(
    "--ecosystem",
    "ecosystems",
    type=str,
    default=None,
    help="Comma-separated list of ecosystems to scan (e.g., 'npm,maven'). Default: auto-detect",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(writable=True, dir_okay=False, path_type=str),
    default="package_scan_report.json",
    show_default=True,
    help="File to write JSON report",
)
@click.option(
    "--no-save",
    is_flag=True,
    help="Do not write JSON report to disk"
)
@click.option(
    "--output-relative-paths",
    is_flag=True,
    help="Use relative paths in JSON output (useful for Docker)"
)
@click.option(
    "--list-ecosystems",
    is_flag=True,
    help="List supported ecosystems and exit"
)
@click.option(
    "--list-affected-packages",
    is_flag=True,
    help="Display compromised packages from threat database and exit"
)
@click.option(
    "--list-affected-packages-csv",
    is_flag=True,
    help="Output threat database as raw CSV to stdout and exit"
)
def cli(
    scan_dir: str,
    threat_names: tuple,
    csv_file: Optional[str],
    ecosystems: Optional[str],
    output_file: str,
    no_save: bool,
    output_relative_paths: bool,
    list_ecosystems: bool,
    list_affected_packages: bool,
    list_affected_packages_csv: bool
):
    """Multi-ecosystem package threat scanner CLI"""

    # Handle --list-ecosystems
    if list_ecosystems:
        available = get_available_ecosystems()
        click.echo(click.style("=" * 80, fg='cyan', bold=True))
        click.echo(click.style("🌍 SUPPORTED ECOSYSTEMS", fg='cyan', bold=True))
        click.echo(click.style("=" * 80, fg='cyan', bold=True))
        click.echo(f"\n{len(available)} ecosystem(s) currently supported:\n")

        for ecosystem in available:
            adapter_class = get_adapter_class(ecosystem)
            click.echo(f"  • {click.style(ecosystem, fg='green', bold=True)}")

            # Create a dummy instance to get file info
            dummy_db = ThreatDatabase()
            dummy_adapter = adapter_class(dummy_db, Path.cwd(), ProgressSpinner(enabled=False))

            manifests = ', '.join(dummy_adapter.get_manifest_files())
            lockfiles = ', '.join(dummy_adapter.get_lockfile_names())

            click.echo(f"    Manifests: {manifests}")
            click.echo(f"    Lockfiles: {lockfiles}")
            click.echo()

        sys.exit(0)

    # Resolve threats directory
    threats_dir = resolve_threats_dir()

    # Load threat database early if --list-affected-packages* flags are used
    # This ensures --threat arguments are respected
    if list_affected_packages or list_affected_packages_csv:
        # Load threat database with respect to --threat arguments
        threat_db = ThreatDatabase(threats_dir=str(threats_dir))
        threat_list = list(threat_names) if threat_names else None

        if not threat_db.load_threats(threat_names=threat_list, csv_file=csv_file):
            sys.exit(1)

        # Handle --list-affected-packages-csv (raw CSV dump)
        if list_affected_packages_csv:
            # Output in CSV format
            click.echo("ecosystem,name,version")
            for ecosystem in sorted(threat_db.get_ecosystems()):
                packages = threat_db.get_all_packages(ecosystem)
                for pkg_name in sorted(packages.keys()):
                    for version in sorted(packages[pkg_name]):
                        click.echo(f"{ecosystem},{pkg_name},{version}")
            sys.exit(0)

        # Handle --list-affected-packages (formatted display)
        if list_affected_packages:
            from collections import defaultdict

            click.echo("\n" + click.style("=" * 80, fg='yellow', bold=True))
            click.echo(click.style("⚠️  COMPROMISED PACKAGES IN THREAT DATABASE", fg='yellow', bold=True))
            click.echo(click.style("=" * 80, fg='yellow', bold=True))

            # Show which threats are included
            if threat_db.get_loaded_threats():
                threat_list_str = ', '.join(threat_db.get_loaded_threats())
                click.echo(click.style(f"\n🔎 Threats: {threat_list_str}", fg='cyan', bold=True))

            all_ecosystems = threat_db.get_ecosystems()

            for ecosystem in sorted(all_ecosystems):
                packages = threat_db.get_all_packages(ecosystem)

                click.echo(f"\n{click.style(f'📦 {ecosystem.upper()}:', fg='magenta', bold=True)}")
                click.echo(f"   {len(packages)} unique packages, "
                          f"{threat_db.get_version_count(ecosystem)} versions\n")

                for pkg_name in sorted(packages.keys()):
                    versions = sorted(packages[pkg_name])
                    click.echo(f"  {click.style(pkg_name, fg='red', bold=True)}")
                    for ver in versions:
                        click.echo(f"    └─ {ver}")

            click.echo(f"\n" + click.style("=" * 80, fg='yellow', bold=True))
            sys.exit(0)

    # Print banner
    click.echo(click.style("=" * 80, fg='cyan', bold=True))
    click.echo(click.style("🛡️  Multi-Ecosystem Package Threat Scanner", fg='cyan', bold=True))
    click.echo(click.style("=" * 80, fg='cyan', bold=True))

    # Validate and resolve scan directory
    scan_dir = os.path.abspath(scan_dir)
    if not os.path.isdir(scan_dir):
        click.echo(click.style(f"✗ Error: Directory not found: {scan_dir}", fg='red', bold=True))
        sys.exit(1)

    click.echo(f"\n{click.style('Scan Directory:', bold=True)} {scan_dir}")
    if csv_file:
        click.echo(f"{click.style('Custom CSV:', bold=True)} {csv_file}")
    elif threat_names:
        click.echo(f"{click.style('Threats:', bold=True)} {', '.join(threat_names)}")
    else:
        click.echo(f"{click.style('Threats Directory:', bold=True)} {threats_dir} (all)")
    click.echo()

    # Load threat database
    threat_db = ThreatDatabase(threats_dir=str(threats_dir))

    # Convert threat_names tuple to list
    threat_list = list(threat_names) if threat_names else None

    if not threat_db.load_threats(threat_names=threat_list, csv_file=csv_file):
        sys.exit(1)

    threat_db.print_summary()

    # Determine which ecosystems to scan
    if ecosystems:
        # User specified ecosystems
        requested_ecosystems = [e.strip().lower() for e in ecosystems.split(',')]
        ecosystems_to_scan = filter_available_ecosystems(requested_ecosystems)

        if not ecosystems_to_scan:
            click.echo(click.style(
                "✗ Error: No valid ecosystems specified",
                fg='red', bold=True))
            click.echo(f"   Available: {', '.join(get_available_ecosystems())}")
            sys.exit(1)

        click.echo(click.style(
            f"🎯 Scanning ecosystems: {', '.join(ecosystems_to_scan)}",
            fg='cyan', bold=True))

    else:
        # Auto-detect ecosystems
        click.echo(click.style("🔍 Auto-detecting ecosystems...", fg='cyan'))
        detected = auto_detect_ecosystems(Path(scan_dir))

        if not detected:
            click.echo(click.style(
                "⚠️  Warning: No recognizable project files found. "
                "Try specifying --ecosystem explicitly.",
                fg='yellow', bold=True))
            sys.exit(0)

        # Filter to only implemented adapters
        ecosystems_to_scan = filter_available_ecosystems(detected)

        if not ecosystems_to_scan:
            click.echo(click.style(
                f"⚠️  Warning: Detected ecosystems {', '.join(detected)} "
                f"but no adapters implemented yet.",
                fg='yellow', bold=True))
            sys.exit(0)

        click.echo(click.style(
            f"✓ Detected: {', '.join(detected)}",
            fg='green'))

        if set(detected) != set(ecosystems_to_scan):
            not_available = set(detected) - set(ecosystems_to_scan)
            click.echo(click.style(
                f"   Note: {', '.join(not_available)} detected but not yet supported",
                fg='yellow', dim=True))

        click.echo(click.style(
            f"   Scanning: {', '.join(ecosystems_to_scan)}",
            fg='cyan', bold=True))

    # Initialize report engine
    report_engine = ReportEngine(scan_dir=scan_dir)

    # Set threats in report engine
    report_engine.set_threats(threat_db.get_loaded_threats())

    # Scan each ecosystem
    spinner = ProgressSpinner()

    for ecosystem in ecosystems_to_scan:
        # Check if ecosystem has threats in database
        if ecosystem not in threat_db.get_ecosystems():
            click.echo(click.style(
                f"\n⚠️  Note: No threats for {ecosystem} in database. Skipping.",
                fg='yellow', dim=True))
            continue

        # Get adapter class and instantiate
        adapter_class = get_adapter_class(ecosystem)
        if not adapter_class:
            click.echo(click.style(
                f"⚠️  Warning: Adapter for {ecosystem} not found. Skipping.",
                fg='yellow'), err=True)
            continue

        adapter = adapter_class(threat_db, Path(scan_dir), spinner)

        # Scan all projects for this ecosystem
        findings = adapter.scan_all_projects()
        report_engine.add_findings(findings)

    spinner.clear()

    # Print report
    report_engine.print_report()

    # Save report if requested
    if not no_save:
        absolute_output = os.path.abspath(output_file)
        if report_engine.save_report(absolute_output, relative_paths=output_relative_paths):
            click.echo(click.style(
                f"✓ Report saved to: {absolute_output}",
                fg='green', bold=True))

    # Exit with non-zero if threats found
    if report_engine.get_findings_count() > 0:
        sys.exit(1)
    else:
        sys.exit(0)


# Legacy npm-scan command for backward compatibility
@click.command(name="npm-scan", help="NPM Package Threat Scanner (legacy compatibility)")
@click.option(
    "--dir",
    "scan_dir",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=str),
    default=lambda: os.getcwd(),
    show_default="current working directory",
    help="Root directory to scan recursively",
)
@click.option(
    "--csv",
    "csv_file",
    type=click.Path(exists=False, file_okay=True, dir_okay=False, path_type=str),
    default=None,
    help="Path to CSV containing compromised packages",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(writable=True, dir_okay=False, path_type=str),
    default="package_scan_report.json",
    show_default=True,
    help="File to write JSON report",
)
@click.option("--no-save", is_flag=True, help="Do not write JSON report to disk")
@click.option("--output-relative-paths", is_flag=True, help="Use relative paths in JSON output")
@click.option("--list-affected-packages", is_flag=True, help="Display compromised packages and exit")
@click.option("--list-affected-packages-csv", is_flag=True, help="Output threat database as CSV and exit")
def npm_scan_cli(
    scan_dir: str,
    csv_file: Optional[str],
    output_file: str,
    no_save: bool,
    output_relative_paths: bool,
    list_affected_packages: bool,
    list_affected_packages_csv: bool
):
    """
    Legacy npm-scan command - redirects to main CLI with npm ecosystem

    Maintained for backward compatibility with existing scripts and documentation
    """
    # Redirect to main CLI with npm ecosystem forced
    ctx = click.get_current_context()
    ctx.invoke(
        cli,
        scan_dir=scan_dir,
        threat_names=(),  # Empty tuple for default behavior
        csv_file=csv_file,
        ecosystems='npm',  # Force npm ecosystem only
        output_file=output_file,
        no_save=no_save,
        output_relative_paths=output_relative_paths,
        list_ecosystems=False,
        list_affected_packages=list_affected_packages,
        list_affected_packages_csv=list_affected_packages_csv
    )


if __name__ == "__main__":
    cli()
