"""NPM ecosystem adapter for scanning JavaScript/Node.js projects"""

import json
import os
import re
from pathlib import Path
from typing import List

import click
from semantic_version import Version, NpmSpec

from package_scan.core import Finding
from .base import EcosystemAdapter


class NpmAdapter(EcosystemAdapter):
    """
    Adapter for scanning npm/JavaScript/Node.js projects

    Supports:
    - Manifest files: package.json
    - Lock files: package-lock.json, yarn.lock, pnpm-lock.yaml
    - Installed packages: node_modules/
    - Version matching: npm semver ranges (^, ~, >=, etc.)
    """

    def _get_ecosystem_name(self) -> str:
        """Return ecosystem identifier"""
        return 'npm'

    def get_manifest_files(self) -> List[str]:
        """Return list of manifest file names"""
        return ['package.json']

    def get_lockfile_names(self) -> List[str]:
        """Return list of lockfile names"""
        return ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']

    def detect_projects(self) -> List[Path]:
        """
        Detect npm projects by looking for package.json files

        Returns:
            List of project directories containing package.json
        """
        projects = []

        for dirpath, dirnames, filenames in os.walk(self.root_dir):
            # Skip common excluded directories
            dirnames[:] = [d for d in dirnames if not self._should_skip_directory(Path(dirpath) / d)]

            if 'package.json' in filenames:
                projects.append(Path(dirpath))

        return projects

    def scan_project(self, project_dir: Path) -> List[Finding]:
        """
        if isinstance(project_dir, str):
            project_dir = Path(project_dir)

        Scan a single npm project for compromised packages

        Args:
            project_dir: Project directory containing package.json

        Returns:
            List of findings
        """
        findings = []

        # 1. Check package.json manifest
        package_json = project_dir / 'package.json'
        if package_json.exists():
            findings.extend(self._scan_package_json(package_json))

        # 2. Check lock files
        for lockfile_name in ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']:
            lockfile_path = project_dir / lockfile_name
            if lockfile_path.exists():
                if lockfile_name == 'package-lock.json':
                    findings.extend(self._scan_package_lock_json(lockfile_path))
                elif lockfile_name == 'yarn.lock':
                    findings.extend(self._scan_yarn_lock(lockfile_path))
                elif lockfile_name == 'pnpm-lock.yaml':
                    findings.extend(self._scan_pnpm_lock_yaml(lockfile_path))

        # 3. Check installed packages in node_modules
        node_modules = project_dir / 'node_modules'
        if node_modules.exists() and node_modules.is_dir():
            findings.extend(self._scan_node_modules(node_modules))

        return findings

    def _scan_package_json(self, file_path: Path) -> List[Finding]:
        """
        Scan package.json for compromised dependencies

        Args:
            file_path: Path to package.json

        Returns:
            List of findings
        """
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                package_data = json.load(f)

            # Check all dependency types
            dep_types = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']

            for dep_type in dep_types:
                if dep_type not in package_data:
                    continue

                for package_name, version_spec in package_data[dep_type].items():
                    if package_name not in self.compromised_packages:
                        continue

                    # Try to parse as npm semver range
                    try:
                        spec = NpmSpec(str(version_spec))
                        included_versions = self._get_matching_versions(spec, package_name)

                        if included_versions:
                            findings.append(Finding(
                                ecosystem='npm',
                                finding_type='manifest',
                                file_path=str(file_path),
                                package_name=package_name,
                                version=", ".join(sorted(included_versions)),
                                match_type='range',
                                declared_spec=version_spec,
                                dependency_type=dep_type,
                                metadata={'included_versions': sorted(included_versions)}
                            ))

                    except Exception:
                        # Not a standard semver spec; try exact match
                        clean_version = str(version_spec).lstrip('^~>=<')
                        if clean_version in self.compromised_packages[package_name]:
                            findings.append(Finding(
                                ecosystem='npm',
                                finding_type='manifest',
                                file_path=str(file_path),
                                package_name=package_name,
                                version=clean_version,
                                match_type='exact',
                                declared_spec=version_spec,
                                dependency_type=dep_type
                            ))

        except json.JSONDecodeError:
            click.echo(click.style(f"⚠️  Warning: Invalid JSON in {file_path}", fg='yellow'), err=True)
        except Exception as e:
            click.echo(click.style(f"⚠️  Warning: Error reading {file_path}: {e}", fg='yellow'), err=True)

        return findings

    def _get_matching_versions(self, spec: NpmSpec, package_name: str) -> List[str]:
        """
        Get compromised versions that match the npm semver spec

        Args:
            spec: NpmSpec range
            package_name: Package name

        Returns:
            List of matching compromised versions
        """
        included_versions = []

        for compromised_version in self.compromised_packages[package_name]:
            try:
                v = Version.coerce(compromised_version)
                if v in spec:
                    included_versions.append(compromised_version)
            except Exception:
                continue

        return included_versions

    def _scan_package_lock_json(self, file_path: Path) -> List[Finding]:
        """
        Scan package-lock.json for compromised packages

        Supports both lockfileVersion 1/2 (nested dependencies) and
        lockfileVersion 3 (flat packages object)

        Args:
            file_path: Path to package-lock.json

        Returns:
            List of findings
        """
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lock_data = json.load(f)

            packages_to_check = {}

            # Handle lockfileVersion 3+ (npm v7+)
            if 'packages' in lock_data:
                for package_path, package_info in lock_data['packages'].items():
                    if not package_path:  # Root package
                        continue
                    # Remove "node_modules/" prefix
                    package_name = package_path.replace('node_modules/', '')
                    version = package_info.get('version')
                    if version:
                        packages_to_check[package_name] = version

            # Handle lockfileVersion 1/2 (older npm)
            elif 'dependencies' in lock_data:
                self._extract_lock_v1_dependencies(lock_data['dependencies'], packages_to_check)

            # Check for compromised packages
            for package_name, version in packages_to_check.items():
                if package_name in self.compromised_packages:
                    if version in self.compromised_packages[package_name]:
                        findings.append(Finding(
                            ecosystem='npm',
                            finding_type='lockfile',
                            file_path=str(file_path),
                            package_name=package_name,
                            version=version,
                            match_type='exact',
                            metadata={'lockfile_type': 'package-lock.json'}
                        ))

        except json.JSONDecodeError:
            click.echo(click.style(f"⚠️  Warning: Invalid JSON in {file_path}", fg='yellow'), err=True)
        except Exception as e:
            click.echo(click.style(f"⚠️  Warning: Error reading {file_path}: {e}", fg='yellow'), err=True)

        return findings

    def _extract_lock_v1_dependencies(self, deps: dict, output: dict, prefix: str = ""):
        """
        Recursively extract dependencies from npm lock v1/v2 format

        Args:
            deps: Dependencies object from lock file
            output: Output dictionary to populate
            prefix: Package name prefix for nested dependencies
        """
        for name, info in deps.items():
            full_name = f"{prefix}{name}" if prefix else name
            version = info.get('version')
            if version:
                output[full_name] = version
            # Recurse into nested dependencies
            if 'dependencies' in info:
                self._extract_lock_v1_dependencies(
                    info['dependencies'], output, f"{full_name}/node_modules/")

    def _scan_yarn_lock(self, file_path: Path) -> List[Finding]:
        """
        Scan yarn.lock for compromised packages

        Args:
            file_path: Path to yarn.lock

        Returns:
            List of findings
        """
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Yarn lock format:
            # package-name@^1.0.0, package-name@^1.2.0:
            #   version "1.2.3"
            #   resolved "..."

            version_pattern = re.compile(r'^\s+version\s+"([^"]+)"', re.MULTILINE)
            lines = content.split('\n')

            i = 0
            while i < len(lines):
                line = lines[i]

                # Check if this line starts a package entry
                if '@' in line and ':' in line and not line.strip().startswith('#'):
                    # Extract package name (handle scoped packages)
                    pkg_match = re.search(r'["\']?(@?[^@"\s]+)@', line)
                    if pkg_match:
                        package_name = pkg_match.group(1)

                        # Look ahead for version line
                        j = i + 1
                        while j < len(lines) and j < i + 10:  # Look up to 10 lines ahead
                            version_match = version_pattern.match(lines[j])
                            if version_match:
                                version = version_match.group(1)

                                if package_name in self.compromised_packages:
                                    if version in self.compromised_packages[package_name]:
                                        findings.append(Finding(
                                            ecosystem='npm',
                                            finding_type='lockfile',
                                            file_path=str(file_path),
                                            package_name=package_name,
                                            version=version,
                                            match_type='exact',
                                            metadata={'lockfile_type': 'yarn.lock'}
                                        ))
                                break

                            # Stop if we hit a blank line or next package entry
                            if not lines[j].strip() or ('@' in lines[j] and ':' in lines[j]):
                                break
                            j += 1

                i += 1

        except Exception as e:
            click.echo(click.style(f"⚠️  Warning: Error reading {file_path}: {e}", fg='yellow'), err=True)

        return findings

    def _scan_pnpm_lock_yaml(self, file_path: Path) -> List[Finding]:
        """
        Scan pnpm-lock.yaml for compromised packages

        Args:
            file_path: Path to pnpm-lock.yaml

        Returns:
            List of findings
        """
        findings = []

        try:
            # Try to import yaml
            try:
                import yaml
            except ImportError:
                click.echo(click.style(
                    f"⚠️  Warning: PyYAML not installed, skipping {file_path}",
                    fg='yellow'), err=True)
                click.echo(click.style(
                    "   Install with: pip install pyyaml",
                    fg='yellow', dim=True), err=True)
                return findings

            with open(file_path, 'r', encoding='utf-8') as f:
                lock_data = yaml.safe_load(f)

            if not lock_data:
                return findings

            # pnpm v6+ uses 'packages' key
            packages = lock_data.get('packages', {})

            for package_key, package_info in packages.items():
                # Package key format: /package-name/1.2.3 or /@scope/package-name/1.2.3
                # Extract name and version
                match = re.match(r'^/(@?[^/]+(?:/[^/]+)?)/(.+?)(?:_|$)', package_key)
                if match:
                    package_name = match.group(1)
                    version = match.group(2)

                    if package_name in self.compromised_packages:
                        if version in self.compromised_packages[package_name]:
                            findings.append(Finding(
                                ecosystem='npm',
                                finding_type='lockfile',
                                file_path=str(file_path),
                                package_name=package_name,
                                version=version,
                                match_type='exact',
                                metadata={'lockfile_type': 'pnpm-lock.yaml'}
                            ))

        except Exception as e:
            click.echo(click.style(f"⚠️  Warning: Error reading {file_path}: {e}", fg='yellow'), err=True)

        return findings

    def _scan_node_modules(self, node_modules_path: Path) -> List[Finding]:
        """
        Scan installed packages in node_modules directory

        Args:
            node_modules_path: Path to node_modules directory

        Returns:
            List of findings
        """
        findings = []

        try:
            items = list(node_modules_path.iterdir())

            for idx, item_path in enumerate(items):
                # Update spinner with progress
                progress = f"[{idx+1}/{len(items)}]"
                self.spinner.update(f"{progress} Scanning {node_modules_path}/{item_path.name}")

                # Handle scoped packages (@org/package)
                if item_path.name.startswith('@') and item_path.is_dir():
                    for scoped_package in item_path.iterdir():
                        if scoped_package.is_dir():
                            package_name = f"{item_path.name}/{scoped_package.name}"
                            finding = self._check_installed_package(
                                scoped_package, package_name, node_modules_path)
                            if finding:
                                findings.append(finding)

                elif item_path.is_dir():
                    finding = self._check_installed_package(
                        item_path, item_path.name, node_modules_path)
                    if finding:
                        findings.append(finding)

        except PermissionError:
            click.echo(click.style(
                f"⚠️  Warning: Permission denied accessing {node_modules_path}",
                fg='yellow'), err=True)
        except Exception as e:
            click.echo(click.style(
                f"⚠️  Warning: Error scanning {node_modules_path}: {e}",
                fg='yellow'), err=True)

        return findings

    def _check_installed_package(
        self, package_path: Path, package_name: str, node_modules_path: Path
    ) -> Finding:
        """
        Check if an installed package is compromised

        Args:
            package_path: Path to the package directory
            package_name: Package name
            node_modules_path: Path to parent node_modules

        Returns:
            Finding if compromised, None otherwise
        """
        if package_name not in self.compromised_packages:
            return None

        package_json_path = package_path / 'package.json'
        if not package_json_path.exists():
            return None

        try:
            with open(package_json_path, 'r', encoding='utf-8') as f:
                package_data = json.load(f)

            installed_version = package_data.get('version', 'unknown')

            if installed_version in self.compromised_packages[package_name]:
                return Finding(
                    ecosystem='npm',
                    finding_type='installed',
                    file_path=str(node_modules_path),
                    package_name=package_name,
                    version=installed_version,
                    match_type='exact',
                    metadata={
                        'location': str(node_modules_path),
                        'package_path': str(package_path)
                    }
                )

        except Exception as e:
            click.echo(click.style(
                f"⚠️  Warning: Error checking {package_json_path}: {e}",
                fg='yellow'), err=True)

        return None
