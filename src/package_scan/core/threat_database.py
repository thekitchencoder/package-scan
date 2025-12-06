"""Threat database management for multi-ecosystem scanning"""

import csv
from collections import defaultdict
from pathlib import Path
from typing import Dict, Set, Optional, List

import click


class ThreatDatabase:
    """
    Manages threat data from CSV files with multi-ecosystem support

    Supports:
    - Loading specific threats by name (e.g., 'sha1-Hulud', 'other-threat')
    - Loading all threats from threats/ directory
    - Loading custom CSV files

    CSV Format:
        ecosystem,name,version
        npm,left-pad,1.3.0
        maven,org.apache.logging.log4j:log4j-core,2.14.1
        pip,requests,2.25.1
        gem,strong_migrations,0.7.9
    """

    def __init__(self, threats_dir: str = "threats"):
        self.threats_dir = Path(threats_dir)
        self.loaded_threats: List[str] = []  # Track loaded threat names
        # Structure: {ecosystem: {package_name: set(versions)}}
        self.threats: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
        self._is_loaded = False

    def load_threats(self, threat_names: Optional[List[str]] = None,
                    csv_file: Optional[str] = None) -> bool:
        """
        Load threats by name or from custom CSV

        Args:
            threat_names: List of threat names to load (e.g., ['sha1-Hulud']).
                If None, loads all threats from threats/ directory.

            csv_file: Path to custom CSV file (overrides threat_names).

        Returns:
            True if at least one threat loaded successfully, False otherwise
        """
        success = False

        if csv_file:
            # Load custom CSV file
            if self._load_csv(Path(csv_file), threat_name='custom'):
                success = True
        elif threat_names:
            # Load specific threats by name
            for threat_name in threat_names:
                csv_path = self.threats_dir / f"{threat_name}.csv"
                if self._load_csv(csv_path, threat_name=threat_name):
                    success = True
        else:
            # Load all threats from directory
            if not self.threats_dir.exists():
                click.echo(click.style(
                    f"✗ Error: Threats directory not found: {self.threats_dir}",
                    fg='red', bold=True), err=True)
                return False

            csv_files = sorted(self.threats_dir.glob("*.csv"))
            if not csv_files:
                click.echo(click.style(
                    f"✗ Error: No threat CSV files found in {self.threats_dir}",
                    fg='red', bold=True), err=True)
                return False

            for csv_path in csv_files:
                threat_name = csv_path.stem
                if self._load_csv(csv_path, threat_name=threat_name):
                    success = True

        if success:
            self._is_loaded = True

        return success

    def _load_csv(self, csv_path: Path, threat_name: str) -> bool:
        """
        Load a single CSV file

        Args:
            csv_path: Path to CSV file
            threat_name: Name of the threat (for tracking)

        Returns:
            True if loaded successfully, False otherwise
        """
        if not csv_path.exists():
            click.echo(click.style(f"✗ Error: Threat CSV file not found: {csv_path}", fg='red', bold=True), err=True)
            return False

        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                headers = reader.fieldnames

                if not headers:
                    click.echo(click.style(f"✗ Error: CSV file has no headers: {csv_path}", fg='red', bold=True), err=True)
                    return False

                # Check for required headers
                if not ('ecosystem' in headers and 'name' in headers and 'version' in headers):
                    click.echo(click.style(
                        f"✗ Error: Invalid CSV format in {csv_path}. "
                        f"Expected headers: 'ecosystem,name,version'. "
                        f"Got: {','.join(headers)}",
                        fg='red', bold=True), err=True)
                    return False

                self._load_multi_ecosystem_format(reader)

            self.loaded_threats.append(threat_name)
            return True

        except UnicodeDecodeError as e:
            click.echo(click.style(f"✗ Error: CSV file encoding issue in {csv_path}: {e}", fg='red', bold=True), err=True)
            return False
        except Exception as e:
            click.echo(click.style(f"✗ Error loading {csv_path}: {e}", fg='red', bold=True), err=True)
            return False

    def _load_multi_ecosystem_format(self, reader):
        """Load CSV in multi-ecosystem format"""
        for row_num, row in enumerate(reader, start=2):  # Start at 2 (header is line 1)
            try:
                ecosystem = row['ecosystem'].strip().lower()
                name = row['name'].strip()
                version = row['version'].strip()

                if not ecosystem or not name or not version:
                    click.echo(click.style(
                        f"⚠️  Warning: Skipping row {row_num} with empty fields: {row}",
                        fg='yellow'), err=True)
                    continue

                self.threats[ecosystem][name].add(version)

            except KeyError as e:
                click.echo(click.style(
                    f"⚠️  Warning: Skipping row {row_num} with missing field {e}: {row}",
                    fg='yellow'), err=True)
                continue

    def get_compromised_versions(self, ecosystem: str, package_name: str) -> Set[str]:
        """
        Get all compromised versions for a specific package in an ecosystem

        Args:
            ecosystem: Ecosystem name (npm, maven, pip, gem, etc.)
            package_name: Package identifier

        Returns:
            Set of compromised version strings
        """
        if not self._is_loaded:
            return set()

        ecosystem = ecosystem.lower()
        return self.threats.get(ecosystem, {}).get(package_name, set())

    def is_compromised(self, ecosystem: str, package_name: str, version: str) -> bool:
        """
        Check if a specific package version is compromised

        Args:
            ecosystem: Ecosystem name
            package_name: Package identifier
            version: Version string

        Returns:
            True if compromised, False otherwise
        """
        compromised_versions = self.get_compromised_versions(ecosystem, package_name)
        return version in compromised_versions

    def get_all_packages(self, ecosystem: Optional[str] = None) -> Dict[str, Set[str]]:
        """
        Get all compromised packages, optionally filtered by ecosystem

        Args:
            ecosystem: Optional ecosystem filter

        Returns:
            Dictionary mapping package names to sets of compromised versions
        """
        if not self._is_loaded:
            return {}

        if ecosystem:
            ecosystem = ecosystem.lower()
            return dict(self.threats.get(ecosystem, {}))
        else:
            # Return all ecosystems merged (not recommended, use with caution)
            all_packages = defaultdict(set)
            for eco_threats in self.threats.values():
                for pkg_name, versions in eco_threats.items():
                    all_packages[pkg_name].update(versions)
            return dict(all_packages)

    def get_ecosystems(self) -> Set[str]:
        """
        Get all ecosystems present in the threat database

        Returns:
            Set of ecosystem names
        """
        if not self._is_loaded:
            return set()

        return set(self.threats.keys())

    def get_loaded_threats(self) -> List[str]:
        """
        Get list of loaded threat names

        Returns:
            List of threat names that were loaded
        """
        return self.loaded_threats.copy()

    def get_package_count(self, ecosystem: Optional[str] = None) -> int:
        """
        Get count of unique packages in threat database

        Args:
            ecosystem: Optional ecosystem filter

        Returns:
            Number of unique packages
        """
        if ecosystem:
            ecosystem = ecosystem.lower()
            return len(self.threats.get(ecosystem, {}))
        else:
            # Total across all ecosystems
            return sum(len(packages) for packages in self.threats.values())

    def get_version_count(self, ecosystem: Optional[str] = None) -> int:
        """
        Get count of compromised package versions

        Args:
            ecosystem: Optional ecosystem filter

        Returns:
            Total number of compromised versions
        """
        if ecosystem:
            ecosystem = ecosystem.lower()
            eco_threats = self.threats.get(ecosystem, {})
            return sum(len(versions) for versions in eco_threats.values())
        else:
            # Total across all ecosystems
            total = 0
            for eco_threats in self.threats.values():
                total += sum(len(versions) for versions in eco_threats.values())
            return total

    def print_summary(self):
        """Print a summary of loaded threats"""
        if not self._is_loaded:
            click.echo(click.style("✗ Threat database not loaded", fg='red', bold=True))
            return

        ecosystems = self.get_ecosystems()

        if not ecosystems:
            click.echo(click.style("⚠️  Warning: Threat database is empty", fg='yellow', bold=True))
            return

        total_packages = self.get_package_count()
        total_versions = self.get_version_count()

        # Show loaded threats
        if self.loaded_threats:
            threat_list = ', '.join(self.loaded_threats)
            click.echo(click.style(f"✓ Loaded threats: {threat_list}", fg='green', bold=True))

        click.echo(click.style(f"✓ Threat database: {total_packages} packages, {total_versions} versions", fg='green', bold=True))

        if len(ecosystems) > 1:
            click.echo(click.style(f"  Ecosystems: {', '.join(sorted(ecosystems))}", fg='cyan'))
            for ecosystem in sorted(ecosystems):
                pkg_count = self.get_package_count(ecosystem)
                ver_count = self.get_version_count(ecosystem)
                click.echo(click.style(f"    • {ecosystem}: {pkg_count} packages, {ver_count} versions", fg='cyan', dim=True))
        else:
            # Single ecosystem (likely legacy format)
            ecosystem = list(ecosystems)[0]
            click.echo(click.style(f"  Ecosystem: {ecosystem}", fg='cyan'))
