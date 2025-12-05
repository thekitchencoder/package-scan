"""Base adapter interface for ecosystem-specific scanners"""

import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

import click

from package_scan.core import Finding, ThreatDatabase


class ProgressSpinner:
    """Simple spinner for showing scan progress that updates in place"""

    def __init__(self, enabled: bool = True):
        self.frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.current_frame = 0
        self.is_tty = sys.stdout.isatty()
        self.enabled = enabled
        self.last_line_length = 0

    def update(self, message: str):
        """Update the spinner with a new message"""
        if not self.enabled:
            return

        # In non-TTY mode (piped, CI/CD), print each line separately
        if not self.is_tty:
            click.echo(f"  {message}")
            return

        # In TTY mode, show animated spinner with overwriting
        spinner = self.frames[self.current_frame % len(self.frames)]
        self.current_frame += 1

        # Truncate message if too long
        max_length = 100
        if len(message) > max_length:
            message = message[:max_length-3] + "..."

        # Build the full line
        line = f"\r{click.style(spinner, fg='cyan')} {click.style(message, dim=True)}"

        # Pad with spaces to clear any leftover characters
        visible_length = len(spinner) + 1 + len(message)
        if visible_length < self.last_line_length:
            line += " " * (self.last_line_length - visible_length)

        self.last_line_length = visible_length

        # Write spinner and message
        sys.stdout.write(line)
        sys.stdout.flush()

    def clear(self):
        """Clear the spinner line"""
        if not self.is_tty or self.last_line_length == 0:
            return

        sys.stdout.write("\r" + " " * self.last_line_length + "\r")
        sys.stdout.flush()
        self.last_line_length = 0


class EcosystemAdapter(ABC):
    """
    Base class for ecosystem-specific scanners

    Each adapter is responsible for:
    1. Detecting projects for its ecosystem
    2. Parsing manifest files (declared dependencies)
    3. Parsing lock files (resolved dependencies)
    4. Checking installed packages
    5. Version matching according to ecosystem conventions
    """

    def __init__(self, threat_db: ThreatDatabase, root_dir: Path, spinner: ProgressSpinner = None):
        """
        Initialize adapter

        Args:
            threat_db: Loaded threat database
            root_dir: Root directory to scan
            spinner: Optional progress spinner
        """
        self.threat_db = threat_db
        self.root_dir = Path(root_dir)
        self.ecosystem_name = self._get_ecosystem_name()
        self.spinner = spinner or ProgressSpinner(enabled=False)

        # Get compromised packages for this ecosystem
        self.compromised_packages = threat_db.get_all_packages(self.ecosystem_name)

    @abstractmethod
    def _get_ecosystem_name(self) -> str:
        """
        Return ecosystem identifier

        Returns:
            Ecosystem name (npm, maven, pip, gem, etc.)
        """
        pass

    @abstractmethod
    def detect_projects(self) -> List[Path]:
        """
        Detect project directories containing this ecosystem's files

        Walks the directory tree and identifies projects by looking for
        manifest files (package.json, pom.xml, pyproject.toml, Gemfile, etc.)

        Returns:
            List of project directory paths
        """
        pass

    @abstractmethod
    def scan_project(self, project_dir: Path) -> List[Finding]:
        """
        Scan a single project directory for compromised packages

        This should:
        1. Check manifest files for declared dependencies
        2. Check lock files for resolved dependencies
        3. Check installed packages (if applicable)

        Args:
            project_dir: Project directory to scan

        Returns:
            List of findings
        """
        pass

    @abstractmethod
    def get_manifest_files(self) -> List[str]:
        """
        Return list of manifest file names for this ecosystem

        Returns:
            List of file names (e.g., ['package.json'], ['pom.xml', 'build.gradle'])
        """
        pass

    @abstractmethod
    def get_lockfile_names(self) -> List[str]:
        """
        Return list of lockfile names for this ecosystem

        Returns:
            List of file names (e.g., ['package-lock.json', 'yarn.lock'])
        """
        pass

    def scan_all_projects(self) -> List[Finding]:
        """
        Scan all detected projects in the root directory

        Returns:
            List of all findings across all projects
        """
        all_findings = []

        # Detect projects
        projects = self.detect_projects()

        if not projects:
            return all_findings

        click.echo(click.style(
            f"\n🔍 Scanning {self.ecosystem_name} ecosystem: found {len(projects)} project(s)",
            fg='cyan', bold=True))

        # Scan each project
        for idx, project_dir in enumerate(projects, 1):
            self.spinner.update(f"[{idx}/{len(projects)}] Scanning {project_dir}")

            try:
                findings = self.scan_project(project_dir)
                all_findings.extend(findings)
            except Exception as e:
                click.echo(click.style(
                    f"\n⚠️  Warning: Error scanning {project_dir}: {e}",
                    fg='yellow'), err=True)

        self.spinner.clear()

        click.echo(click.style(
            f"✓ {self.ecosystem_name}: scanned {len(projects)} project(s), found {len(all_findings)} issue(s)",
            fg='green'))

        return all_findings

    def _should_skip_directory(self, dir_path: Path) -> bool:
        """
        Check if directory should be skipped during scanning

        Skips common directories that don't contain source code:
        - node_modules, vendor, .git, etc.

        Args:
            dir_path: Directory to check

        Returns:
            True if should skip, False otherwise
        """
        skip_dirs = {
            'node_modules',
            '.git',
            '.svn',
            '.hg',
            '__pycache__',
            '.pytest_cache',
            '.tox',
            'venv',
            'env',
            '.venv',
            '.env',
            'build',
            'dist',
            'target',  # Maven/Gradle
            '.gradle',
            '.m2',
            'vendor',  # Ruby
            '.bundle',
            'site-packages',
            '.eggs',
            '*.egg-info',
        }

        # Check if the directory name matches any skip patterns
        dir_name = dir_path.name
        if dir_name in skip_dirs or dir_name.startswith('.'):
            return True

        return False

    def _next_patch_version(self, version_str: str) -> str:
        """
        Calculate next patch version (common utility)

        Args:
            version_str: Version string (e.g., "1.2.3")

        Returns:
            Next patch version (e.g., "1.2.4") or original if parsing fails
        """
        try:
            parts = version_str.split('.')
            if len(parts) >= 3:
                major, minor, patch = parts[0], parts[1], parts[2]
                # Handle versions like "1.2.3-alpha"
                patch_num = int(patch.split('-')[0])
                return f"{major}.{minor}.{patch_num + 1}"
            return version_str
        except (ValueError, IndexError):
            return version_str
