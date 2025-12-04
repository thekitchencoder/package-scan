"""Python ecosystem adapter for scanning pip, poetry, pipenv, and conda projects"""

import os
import re
import json
from typing import List, Dict, Set, Optional, Tuple
from pathlib import Path

import click

from hulud_scan.core import Finding, Remediation, ThreatDatabase
from .base import EcosystemAdapter, ProgressSpinner


class PythonAdapter(EcosystemAdapter):
    """
    Adapter for scanning Python projects

    Supports:
    - pip: requirements.txt, requirements-*.txt
    - Poetry: pyproject.toml, poetry.lock
    - Pipenv: Pipfile, Pipfile.lock
    - conda: environment.yml
    - Version matching: PEP 440 specifiers (==, >=, ~=, !=, etc.)

    Ecosystem identifier: 'pip' (matches PyPI package format)
    """

    def _get_ecosystem_name(self) -> str:
        """Return ecosystem identifier"""
        return 'pip'

    def get_manifest_files(self) -> List[str]:
        """Return list of manifest file names"""
        return ['requirements.txt', 'pyproject.toml', 'Pipfile', 'environment.yml', 'setup.py']

    def get_lockfile_names(self) -> List[str]:
        """Return list of lockfile names"""
        return ['poetry.lock', 'Pipfile.lock', 'conda-lock.yml']

    def detect_projects(self) -> List[Path]:
        """
        Detect Python projects by looking for Python manifest files

        Returns:
            List of project directories
        """
        projects = []

        for dirpath, dirnames, filenames in os.walk(self.root_dir):
            # Skip common excluded directories
            dirnames[:] = [d for d in dirnames if not self._should_skip_directory(Path(dirpath) / d)]

            # Check for Python manifest files
            manifest_files = {
                'requirements.txt', 'pyproject.toml', 'Pipfile',
                'environment.yml', 'setup.py', 'setup.cfg'
            }

            # Also check for requirements-*.txt files
            has_requirements_variant = any(
                f.startswith('requirements') and f.endswith('.txt')
                for f in filenames
            )

            if manifest_files & set(filenames) or has_requirements_variant:
                projects.append(Path(dirpath))

        return projects

    def scan_project(self, project_dir: Path) -> List[Finding]:
        """
        Scan a single Python project for compromised packages

        Args:
            project_dir: Project directory

        Returns:
            List of findings
        """
        findings = []

        # 1. Check requirements.txt files (including requirements-*.txt)
        for req_file in project_dir.glob('requirements*.txt'):
            if req_file.is_file():
                findings.extend(self._scan_requirements_txt(req_file))

        # 2. Check pyproject.toml (Poetry)
        pyproject_toml = project_dir / 'pyproject.toml'
        if pyproject_toml.exists():
            findings.extend(self._scan_pyproject_toml(pyproject_toml))

        # 3. Check poetry.lock
        poetry_lock = project_dir / 'poetry.lock'
        if poetry_lock.exists():
            findings.extend(self._scan_poetry_lock(poetry_lock))

        # 4. Check Pipfile (pipenv)
        pipfile = project_dir / 'Pipfile'
        if pipfile.exists():
            findings.extend(self._scan_pipfile(pipfile))

        # 5. Check Pipfile.lock
        pipfile_lock = project_dir / 'Pipfile.lock'
        if pipfile_lock.exists():
            findings.extend(self._scan_pipfile_lock(pipfile_lock))

        # 6. Check environment.yml (conda)
        env_yml = project_dir / 'environment.yml'
        if env_yml.exists():
            findings.extend(self._scan_conda_environment(env_yml))

        return findings

    def _scan_requirements_txt(self, file_path: Path) -> List[Finding]:
        """
        Scan requirements.txt for compromised packages

        Format:
            package==1.2.3
            package>=1.0.0
            package~=1.2.0
            package>=1.0,<2.0
            package[extra]==1.2.3
            git+https://...

        Args:
            file_path: Path to requirements.txt

        Returns:
            List of findings
        """
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            for line_num, line in enumerate(lines, 1):
                # Remove comments and whitespace
                line = line.split('#')[0].strip()
                if not line or line.startswith('-'):
                    continue

                # Skip URLs and local paths
                if line.startswith(('http://', 'https://', 'git+', 'file://', './', '../')):
                    continue

                # Parse package specification
                # Pattern: package[extras]==version or package>=version,<version
                match = re.match(r'^([a-zA-Z0-9_\-\.]+)(\[.*?\])?\s*(.*)$', line)
                if not match:
                    continue

                package_name = match.group(1).lower()
                # extras = match.group(2)  # Not used for threat matching
                version_spec = match.group(3).strip()

                if package_name not in self.compromised_packages:
                    continue

                # Parse version specifier
                if not version_spec:
                    # No version specified - warn but don't report as threat
                    continue

                # Handle exact version (==)
                if version_spec.startswith('=='):
                    version = version_spec[2:].strip()
                    if version in self.compromised_packages[package_name]:
                        remediation = self._suggest_remediation_exact_python(version)

                        findings.append(Finding(
                            ecosystem='pip',
                            finding_type='manifest',
                            file_path=str(file_path),
                            package_name=package_name,
                            version=version,
                            match_type='exact',
                            declared_spec=version_spec,
                            dependency_type='requirement',
                            remediation=remediation
                        ))

                # Handle version ranges and operators
                else:
                    matching_versions = self._get_matching_pep440_versions(
                        version_spec, package_name)

                    if matching_versions:
                        remediation = self._suggest_remediation_range_python(
                            version_spec, matching_versions)

                        findings.append(Finding(
                            ecosystem='pip',
                            finding_type='manifest',
                            file_path=str(file_path),
                            package_name=package_name,
                            version=", ".join(sorted(matching_versions)),
                            match_type='range',
                            declared_spec=version_spec,
                            dependency_type='requirement',
                            remediation=remediation,
                            metadata={'included_versions': sorted(matching_versions)}
                        ))

        except Exception as e:
            click.echo(click.style(
                f"⚠️  Warning: Error reading {file_path}: {e}",
                fg='yellow'), err=True)

        return findings

    def _scan_pyproject_toml(self, file_path: Path) -> List[Finding]:
        """
        Scan pyproject.toml for compromised packages (Poetry format)

        Args:
            file_path: Path to pyproject.toml

        Returns:
            List of findings
        """
        findings = []

        try:
            # Try to import toml parser
            try:
                import toml
            except ImportError:
                try:
                    import tomli as toml
                except ImportError:
                    click.echo(click.style(
                        f"⚠️  Warning: toml/tomli not installed, skipping {file_path}",
                        fg='yellow'), err=True)
                    click.echo(click.style(
                        "   Install with: pip install toml",
                        fg='yellow', dim=True), err=True)
                    return findings

            with open(file_path, 'r', encoding='utf-8') as f:
                data = toml.load(f)

            # Poetry dependencies are in [tool.poetry.dependencies] and [tool.poetry.dev-dependencies]
            dep_sections = []
            if 'tool' in data and 'poetry' in data['tool']:
                poetry = data['tool']['poetry']
                if 'dependencies' in poetry:
                    dep_sections.append(('dependencies', poetry['dependencies']))
                if 'dev-dependencies' in poetry:
                    dep_sections.append(('dev-dependencies', poetry['dev-dependencies']))

            for dep_type, dependencies in dep_sections:
                for package_name, version_spec in dependencies.items():
                    # Skip python itself
                    if package_name.lower() == 'python':
                        continue

                    package_name = package_name.lower()
                    if package_name not in self.compromised_packages:
                        continue

                    # Poetry version specs can be strings or dicts
                    if isinstance(version_spec, dict):
                        version_spec = version_spec.get('version', '')

                    if not version_spec or version_spec == '*':
                        continue

                    # Convert Poetry caret (^) and tilde (~) to PEP 440
                    # ^1.2.3 means >=1.2.3,<2.0.0
                    # ~1.2.3 means >=1.2.3,<1.3.0
                    pep440_spec = self._convert_poetry_to_pep440(version_spec)

                    # Check for matches
                    matching_versions = self._get_matching_pep440_versions(
                        pep440_spec, package_name)

                    if matching_versions:
                        remediation = self._suggest_remediation_range_python(
                            version_spec, matching_versions)

                        findings.append(Finding(
                            ecosystem='pip',
                            finding_type='manifest',
                            file_path=str(file_path),
                            package_name=package_name,
                            version=", ".join(sorted(matching_versions)),
                            match_type='range' if len(matching_versions) > 1 else 'exact',
                            declared_spec=version_spec,
                            dependency_type=dep_type,
                            remediation=remediation,
                            metadata={'included_versions': sorted(matching_versions)}
                        ))

        except Exception as e:
            click.echo(click.style(
                f"⚠️  Warning: Error reading {file_path}: {e}",
                fg='yellow'), err=True)

        return findings

    def _scan_poetry_lock(self, file_path: Path) -> List[Finding]:
        """
        Scan poetry.lock for compromised packages

        Args:
            file_path: Path to poetry.lock

        Returns:
            List of findings
        """
        findings = []

        try:
            # Try to import toml parser
            try:
                import toml
            except ImportError:
                try:
                    import tomli as toml
                except ImportError:
                    return findings

            with open(file_path, 'r', encoding='utf-8') as f:
                data = toml.load(f)

            # Poetry lockfile has [[package]] sections
            packages = data.get('package', [])

            for pkg in packages:
                package_name = pkg.get('name', '').lower()
                version = pkg.get('version', '')

                if package_name in self.compromised_packages:
                    if version in self.compromised_packages[package_name]:
                        remediation = Remediation(
                            strategy='upgrade_and_update_lockfile',
                            suggested_spec=f">={self._next_patch_version(version)}",
                            note='Update pyproject.toml to exclude this version, delete poetry.lock, then run poetry install to regenerate.'
                        )

                        findings.append(Finding(
                            ecosystem='pip',
                            finding_type='lockfile',
                            file_path=str(file_path),
                            package_name=package_name,
                            version=version,
                            match_type='exact',
                            remediation=remediation,
                            metadata={'lockfile_type': 'poetry.lock'}
                        ))

        except Exception as e:
            click.echo(click.style(
                f"⚠️  Warning: Error reading {file_path}: {e}",
                fg='yellow'), err=True)

        return findings

    def _scan_pipfile(self, file_path: Path) -> List[Finding]:
        """
        Scan Pipfile for compromised packages

        Args:
            file_path: Path to Pipfile

        Returns:
            List of findings
        """
        findings = []

        try:
            # Try to import toml parser
            try:
                import toml
            except ImportError:
                try:
                    import tomli as toml
                except ImportError:
                    return findings

            with open(file_path, 'r', encoding='utf-8') as f:
                data = toml.load(f)

            # Pipfile has [packages] and [dev-packages]
            dep_sections = []
            if 'packages' in data:
                dep_sections.append(('packages', data['packages']))
            if 'dev-packages' in data:
                dep_sections.append(('dev-packages', data['dev-packages']))

            for dep_type, dependencies in dep_sections:
                for package_name, version_spec in dependencies.items():
                    package_name = package_name.lower()
                    if package_name not in self.compromised_packages:
                        continue

                    # Pipfile version specs can be strings or dicts
                    if isinstance(version_spec, dict):
                        version_spec = version_spec.get('version', '*')

                    if version_spec == '*':
                        continue

                    # Check for matches
                    matching_versions = self._get_matching_pep440_versions(
                        version_spec, package_name)

                    if matching_versions:
                        remediation = self._suggest_remediation_range_python(
                            version_spec, matching_versions)

                        findings.append(Finding(
                            ecosystem='pip',
                            finding_type='manifest',
                            file_path=str(file_path),
                            package_name=package_name,
                            version=", ".join(sorted(matching_versions)),
                            match_type='range' if len(matching_versions) > 1 else 'exact',
                            declared_spec=version_spec,
                            dependency_type=dep_type,
                            remediation=remediation,
                            metadata={'included_versions': sorted(matching_versions)}
                        ))

        except Exception as e:
            click.echo(click.style(
                f"⚠️  Warning: Error reading {file_path}: {e}",
                fg='yellow'), err=True)

        return findings

    def _scan_pipfile_lock(self, file_path: Path) -> List[Finding]:
        """
        Scan Pipfile.lock for compromised packages

        Args:
            file_path: Path to Pipfile.lock

        Returns:
            List of findings
        """
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Pipfile.lock has "default" and "develop" sections
            for section_name in ['default', 'develop']:
                section = data.get(section_name, {})

                for package_name, pkg_info in section.items():
                    package_name = package_name.lower()
                    version = pkg_info.get('version', '').lstrip('=')  # Remove leading ==

                    if package_name in self.compromised_packages:
                        if version in self.compromised_packages[package_name]:
                            remediation = Remediation(
                                strategy='upgrade_and_update_lockfile',
                                suggested_spec=f"=={self._next_patch_version(version)}",
                                note='Update Pipfile to exclude this version, delete Pipfile.lock, then run pipenv install to regenerate.'
                            )

                            findings.append(Finding(
                                ecosystem='pip',
                                finding_type='lockfile',
                                file_path=str(file_path),
                                package_name=package_name,
                                version=version,
                                match_type='exact',
                                remediation=remediation,
                                metadata={'lockfile_type': 'Pipfile.lock', 'section': section_name}
                            ))

        except json.JSONDecodeError:
            click.echo(click.style(
                f"⚠️  Warning: Invalid JSON in {file_path}",
                fg='yellow'), err=True)
        except Exception as e:
            click.echo(click.style(
                f"⚠️  Warning: Error reading {file_path}: {e}",
                fg='yellow'), err=True)

        return findings

    def _scan_conda_environment(self, file_path: Path) -> List[Finding]:
        """
        Scan conda environment.yml for compromised packages

        Args:
            file_path: Path to environment.yml

        Returns:
            List of findings
        """
        findings = []

        try:
            # Try to import yaml parser
            try:
                import yaml
            except ImportError:
                click.echo(click.style(
                    f"⚠️  Warning: PyYAML not installed, skipping {file_path}",
                    fg='yellow'), err=True)
                return findings

            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not data or 'dependencies' not in data:
                return findings

            dependencies = data['dependencies']

            for dep in dependencies:
                # Skip conda channels and pip sections
                if isinstance(dep, dict):
                    # pip dependencies section
                    if 'pip' in dep:
                        for pip_dep in dep['pip']:
                            # Parse pip format
                            match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*(.*)$', pip_dep)
                            if match:
                                package_name = match.group(1).lower()
                                version_spec = match.group(2).strip()

                                if package_name in self.compromised_packages:
                                    if version_spec.startswith('=='):
                                        version = version_spec[2:].strip()
                                        if version in self.compromised_packages[package_name]:
                                            remediation = self._suggest_remediation_exact_python(version)

                                            findings.append(Finding(
                                                ecosystem='pip',
                                                finding_type='manifest',
                                                file_path=str(file_path),
                                                package_name=package_name,
                                                version=version,
                                                match_type='exact',
                                                declared_spec=version_spec,
                                                dependency_type='pip-dependency',
                                                remediation=remediation
                                            ))
                    continue

                # Conda package format: package=version or package
                if isinstance(dep, str):
                    parts = dep.split('=')
                    package_name = parts[0].lower()

                    if package_name in self.compromised_packages and len(parts) >= 2:
                        version = parts[1]
                        if version in self.compromised_packages[package_name]:
                            remediation = self._suggest_remediation_exact_python(version)

                            findings.append(Finding(
                                ecosystem='pip',
                                finding_type='manifest',
                                file_path=str(file_path),
                                package_name=package_name,
                                version=version,
                                match_type='exact',
                                declared_spec=f"={version}",
                                dependency_type='conda-dependency',
                                remediation=remediation
                            ))

        except Exception as e:
            click.echo(click.style(
                f"⚠️  Warning: Error reading {file_path}: {e}",
                fg='yellow'), err=True)

        return findings

    def _convert_poetry_to_pep440(self, poetry_spec: str) -> str:
        """
        Convert Poetry version specifier to PEP 440

        ^1.2.3 → >=1.2.3,<2.0.0
        ~1.2.3 → >=1.2.3,<1.3.0

        Args:
            poetry_spec: Poetry version specifier

        Returns:
            PEP 440 specifier
        """
        if poetry_spec.startswith('^'):
            version = poetry_spec[1:]
            parts = version.split('.')
            if len(parts) >= 1:
                major = int(parts[0])
                return f">={version},<{major+1}.0.0"

        elif poetry_spec.startswith('~'):
            version = poetry_spec[1:]
            parts = version.split('.')
            if len(parts) >= 2:
                major, minor = parts[0], int(parts[1])
                return f">={version},<{major}.{minor+1}.0"

        return poetry_spec

    def _get_matching_pep440_versions(
        self, version_spec: str, package_name: str
    ) -> List[str]:
        """
        Get compromised versions matching PEP 440 specifier

        Simplified implementation for common operators:
        ==, >=, <=, >, <, !=, ~=

        Args:
            version_spec: PEP 440 version specifier
            package_name: Package name

        Returns:
            List of matching versions
        """
        matching = []

        # Handle comma-separated specs: >=1.0,<2.0
        specs = [s.strip() for s in version_spec.split(',')]

        for version in self.compromised_packages[package_name]:
            if all(self._check_pep440_spec(version, spec) for spec in specs):
                matching.append(version)

        return matching

    def _check_pep440_spec(self, version: str, spec: str) -> bool:
        """
        Check if version satisfies PEP 440 specifier

        Args:
            version: Version to check
            spec: PEP 440 specifier

        Returns:
            True if version satisfies spec
        """
        spec = spec.strip()

        # Handle different operators
        if spec.startswith('=='):
            return version == spec[2:].strip()
        elif spec.startswith('>='):
            return self._version_compare_simple(version, spec[2:].strip()) >= 0
        elif spec.startswith('<='):
            return self._version_compare_simple(version, spec[2:].strip()) <= 0
        elif spec.startswith('>'):
            return self._version_compare_simple(version, spec[1:].strip()) > 0
        elif spec.startswith('<'):
            return self._version_compare_simple(version, spec[1:].strip()) < 0
        elif spec.startswith('!='):
            return version != spec[2:].strip()
        elif spec.startswith('~='):
            # Compatible release: ~=1.2.3 means >=1.2.3,<1.3.0
            base = spec[2:].strip()
            parts = base.split('.')
            if len(parts) >= 2:
                upper = f"{parts[0]}.{int(parts[1])+1}.0"
                return (self._version_compare_simple(version, base) >= 0 and
                        self._version_compare_simple(version, upper) < 0)

        return False

    def _version_compare_simple(self, v1: str, v2: str) -> int:
        """
        Simple version comparison

        Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2
        """
        try:
            parts1 = [int(x) for x in v1.split('.')]
            parts2 = [int(x) for x in v2.split('.')]

            # Pad with zeros
            max_len = max(len(parts1), len(parts2))
            parts1 += [0] * (max_len - len(parts1))
            parts2 += [0] * (max_len - len(parts2))

            if parts1 < parts2:
                return -1
            elif parts1 > parts2:
                return 1
            return 0
        except (ValueError, AttributeError):
            # Fallback to string comparison
            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
            return 0

    def _suggest_remediation_exact_python(self, compromised_version: str) -> Remediation:
        """
        Suggest remediation for exact version match in Python projects

        Args:
            compromised_version: The compromised version

        Returns:
            Remediation object
        """
        next_patch = self._next_patch_version(compromised_version)
        return Remediation(
            strategy='upgrade_version',
            suggested_spec=f"=={next_patch}",
            note='Update the package version in requirements.txt, pyproject.toml, Pipfile, or environment.yml to a patched version. Run pip install --upgrade or poetry update.'
        )

    def _suggest_remediation_range_python(
        self, original_spec: str, included_versions: List[str]
    ) -> Remediation:
        """
        Suggest remediation for version range in Python projects

        Args:
            original_spec: Original version specification
            included_versions: List of compromised versions

        Returns:
            Remediation object
        """
        # Find highest compromised version
        highest = max(included_versions, key=lambda v: [int(x) for x in v.split('.')])
        next_patch = self._next_patch_version(highest)

        note = (
            "The declared version range includes compromised versions. "
            "Update requirements.txt, pyproject.toml, Pipfile, or environment.yml "
            f"to require >={next_patch} or pin to a specific safe version. "
            "Then regenerate lockfiles and reinstall dependencies."
        )

        return Remediation(
            strategy='update_version_range',
            suggested_spec=f">={next_patch}",
            note=note,
            affected_versions=sorted(included_versions)
        )
