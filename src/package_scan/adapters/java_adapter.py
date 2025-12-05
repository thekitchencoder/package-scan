"""Java ecosystem adapter for scanning Maven and Gradle projects"""

import os
import re
from pathlib import Path
from typing import List
from xml.etree import ElementTree as ET

import click

from package_scan.core import Finding
from .base import EcosystemAdapter


class JavaAdapter(EcosystemAdapter):
    """
    Adapter for scanning Java/Maven/Gradle projects

    Supports:
    - Maven: pom.xml (manifest)
    - Gradle: build.gradle, build.gradle.kts (manifest)
    - Lock files: gradle.lockfile (Gradle 7+)
    - Version matching: Maven version ranges, Gradle dynamic versions

    Ecosystem identifier: 'maven' (matches Maven Central artifact format)
    """

    def _get_ecosystem_name(self) -> str:
        """Return ecosystem identifier"""
        return 'maven'

    def get_manifest_files(self) -> List[str]:
        """Return list of manifest file names"""
        return ['pom.xml', 'build.gradle', 'build.gradle.kts']

    def get_lockfile_names(self) -> List[str]:
        """Return list of lockfile names"""
        return ['gradle.lockfile']

    def detect_projects(self) -> List[Path]:
        """
        Detect Maven/Gradle projects by looking for pom.xml or build.gradle files

        Returns:
            List of project directories
        """
        projects = []

        for dirpath, dirnames, filenames in os.walk(self.root_dir):
            # Skip common excluded directories
            dirnames[:] = [d for d in dirnames if not self._should_skip_directory(Path(dirpath) / d)]

            # Check for Maven or Gradle files
            if 'pom.xml' in filenames or 'build.gradle' in filenames or 'build.gradle.kts' in filenames:
                projects.append(Path(dirpath))

        return projects

    def scan_project(self, project_dir: Path) -> List[Finding]:
        """
        if isinstance(project_dir, str):
            project_dir = Path(project_dir)

        Scan a single Java project for compromised packages

        Args:
            project_dir: Project directory

        Returns:
            List of findings
        """
        findings = []

        # 1. Check Maven pom.xml
        pom_xml = project_dir / 'pom.xml'
        if pom_xml.exists():
            findings.extend(self._scan_pom_xml(pom_xml))

        # 2. Check Gradle build files
        for gradle_file in ['build.gradle', 'build.gradle.kts']:
            gradle_path = project_dir / gradle_file
            if gradle_path.exists():
                findings.extend(self._scan_gradle_build(gradle_path))

        # 3. Check Gradle lockfile
        lockfile = project_dir / 'gradle.lockfile'
        if lockfile.exists():
            findings.extend(self._scan_gradle_lockfile(lockfile))

        return findings

    def _scan_pom_xml(self, file_path: Path) -> List[Finding]:
        """
        Scan Maven pom.xml for compromised dependencies

        Args:
            file_path: Path to pom.xml

        Returns:
            List of findings
        """
        findings = []

        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            # Maven uses namespaces
            ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
            # Try without namespace as fallback
            namespaces = [ns, {}]

            for namespace in namespaces:
                # Find all dependency elements
                dependencies = root.findall('.//m:dependency' if namespace else './/dependency', namespace)

                for dep in dependencies:
                    group_id_elem = dep.find('m:groupId' if namespace else 'groupId', namespace)
                    artifact_id_elem = dep.find('m:artifactId' if namespace else 'artifactId', namespace)
                    version_elem = dep.find('m:version' if namespace else 'version', namespace)

                    if group_id_elem is None or artifact_id_elem is None:
                        continue

                    group_id = group_id_elem.text
                    artifact_id = artifact_id_elem.text
                    # Maven artifact format: groupId:artifactId
                    package_name = f"{group_id}:{artifact_id}"

                    if package_name not in self.compromised_packages:
                        continue

                    # Handle version
                    if version_elem is not None and version_elem.text:
                        version_spec = version_elem.text.strip()

                        # Check if version is a property reference like ${some.version}
                        if version_spec.startswith('${') and version_spec.endswith('}'):
                            # Property reference - we can't resolve it without full Maven context
                            click.echo(click.style(
                                f"⚠️  Warning: {package_name} uses property {version_spec}, cannot check version",
                                fg='yellow', dim=True), err=True)
                            continue

                        # Check if it's a range or specific version
                        if self._is_maven_range(version_spec):
                            # Maven version range
                            matching_versions = self._get_matching_maven_versions(
                                version_spec, package_name)

                            if matching_versions:
                                findings.append(Finding(
                                    ecosystem='maven',
                                    finding_type='manifest',
                                    file_path=str(file_path),
                                    package_name=package_name,
                                    version=", ".join(sorted(matching_versions)),
                                    match_type='range',
                                    declared_spec=version_spec,
                                    dependency_type='dependency',
                                    metadata={'included_versions': sorted(matching_versions)}
                                ))
                        else:
                            # Specific version
                            if version_spec in self.compromised_packages[package_name]:
                                findings.append(Finding(
                                    ecosystem='maven',
                                    finding_type='manifest',
                                    file_path=str(file_path),
                                    package_name=package_name,
                                    version=version_spec,
                                    match_type='exact',
                                    declared_spec=version_spec,
                                    dependency_type='dependency'
                                ))

                if dependencies:
                    break  # Found dependencies, no need to try other namespace

        except ET.ParseError as e:
            click.echo(click.style(
                f"⚠️  Warning: Invalid XML in {file_path}: {e}",
                fg='yellow'), err=True)
        except Exception as e:
            click.echo(click.style(
                f"⚠️  Warning: Error reading {file_path}: {e}",
                fg='yellow'), err=True)

        return findings

    def _scan_gradle_build(self, file_path: Path) -> List[Finding]:
        """
        Scan Gradle build file for compromised dependencies

        Supports both Groovy DSL (build.gradle) and Kotlin DSL (build.gradle.kts)

        Args:
            file_path: Path to build.gradle or build.gradle.kts

        Returns:
            List of findings
        """
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Parse Gradle dependencies
            # Patterns for different dependency formats:
            # implementation 'group:artifact:version'
            # implementation "group:artifact:version"
            # implementation group: 'group', name: 'artifact', version: 'version'
            # implementation("group:artifact:version")  // Kotlin DSL

            # Pattern 1: String literal format (most common)
            # Matches: 'group:artifact:version' or "group:artifact:version"
            pattern1 = r'''(?:implementation|compile|api|runtimeOnly|compileOnly|testImplementation|testCompile)\s*[(\s]*['"]([\w\.\-]+):([\w\.\-]+):([\w\.\-\+]+)['"]'''

            # Pattern 2: Map format
            # Matches: group: 'group', name: 'artifact', version: 'version'
            pattern2 = r'''(?:implementation|compile|api|runtimeOnly|compileOnly|testImplementation|testCompile)\s+group:\s*['"]([^'"]+)['"],\s*name:\s*['"]([^'"]+)['"],\s*version:\s*['"]([^'"]+)['"]'''

            for pattern in [pattern1, pattern2]:
                matches = re.finditer(pattern, content)

                for match in matches:
                    group_id = match.group(1)
                    artifact_id = match.group(2)
                    version = match.group(3)

                    package_name = f"{group_id}:{artifact_id}"

                    if package_name not in self.compromised_packages:
                        continue

                    # Check for dynamic versions (+ notation)
                    if '+' in version:
                        # Dynamic version like 1.2.+
                        matching_versions = self._get_matching_gradle_dynamic_versions(
                            version, package_name)

                        if matching_versions:
                            findings.append(Finding(
                                ecosystem='maven',
                                finding_type='manifest',
                                file_path=str(file_path),
                                package_name=package_name,
                                version=", ".join(sorted(matching_versions)),
                                match_type='range',
                                declared_spec=version,
                                dependency_type='dependency',
                                metadata={'included_versions': sorted(matching_versions)}
                            ))
                    else:
                        # Specific version
                        if version in self.compromised_packages[package_name]:
                            findings.append(Finding(
                                ecosystem='maven',
                                finding_type='manifest',
                                file_path=str(file_path),
                                package_name=package_name,
                                version=version,
                                match_type='exact',
                                declared_spec=version,
                                dependency_type='dependency'
                            ))

        except Exception as e:
            click.echo(click.style(
                f"⚠️  Warning: Error reading {file_path}: {e}",
                fg='yellow'), err=True)

        return findings

    def _scan_gradle_lockfile(self, file_path: Path) -> List[Finding]:
        """
        Scan Gradle lockfile for compromised dependencies

        Gradle 7+ can generate lockfiles with exact resolved versions

        Args:
            file_path: Path to gradle.lockfile

        Returns:
            List of findings
        """
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Gradle lockfile format:
            # group:artifact:version=classpath,config1,config2
            pattern = r'^([\w\.\-]+):([\w\.\-]+):([\w\.\-]+)='

            for line in content.split('\n'):
                match = re.match(pattern, line.strip())
                if match:
                    group_id = match.group(1)
                    artifact_id = match.group(2)
                    version = match.group(3)

                    package_name = f"{group_id}:{artifact_id}"

                    if package_name in self.compromised_packages:
                        if version in self.compromised_packages[package_name]:
                            findings.append(Finding(
                                ecosystem='maven',
                                finding_type='lockfile',
                                file_path=str(file_path),
                                package_name=package_name,
                                version=version,
                                match_type='exact',
                                metadata={'lockfile_type': 'gradle.lockfile'}
                            ))

        except Exception as e:
            click.echo(click.style(
                f"⚠️  Warning: Error reading {file_path}: {e}",
                fg='yellow'), err=True)

        return findings

    def _is_maven_range(self, version_spec: str) -> bool:
        """
        Check if version specification is a Maven version range

        Maven ranges use:
        - [1.0,2.0] = 1.0 <= x <= 2.0
        - [1.0,2.0) = 1.0 <= x < 2.0
        - (1.0,2.0] = 1.0 < x <= 2.0
        - (1.0,2.0) = 1.0 < x < 2.0
        - [1.0,) = x >= 1.0
        - (,2.0) = x < 2.0

        Args:
            version_spec: Version specification

        Returns:
            True if it's a range, False otherwise
        """
        return bool(re.match(r'^[\[\(].*[\]\)]$', version_spec.strip()))

    def _get_matching_maven_versions(
        self, version_range: str, package_name: str
    ) -> List[str]:
        """
        Get compromised versions that match Maven version range

        This is a simplified implementation that handles basic ranges.
        For production use, consider using a proper Maven version comparison library.

        Args:
            version_range: Maven version range specification
            package_name: Package name

        Returns:
            List of matching compromised versions
        """
        matching = []

        # Parse the range
        # Example: [1.0,2.0) means 1.0 <= x < 2.0
        match = re.match(r'^([\[\(])(.*?),(.*?)([\]\)])$', version_range.strip())
        if not match:
            return matching

        lower_inclusive = match.group(1) == '['
        lower_bound = match.group(2).strip()
        upper_bound = match.group(3).strip()
        upper_inclusive = match.group(4) == ']'

        for version in self.compromised_packages[package_name]:
            # Simple string comparison (works for most version formats)
            # For production, use proper version comparison
            try:
                if lower_bound and not self._version_compare(version, lower_bound, lower_inclusive, 'lower'):
                    continue
                if upper_bound and not self._version_compare(version, upper_bound, upper_inclusive, 'upper'):
                    continue
                matching.append(version)
            except Exception:
                continue

        return matching

    def _version_compare(
        self, version: str, bound: str, inclusive: bool, bound_type: str
    ) -> bool:
        """
        Compare version against a bound

        Args:
            version: Version to check
            bound: Bound version
            inclusive: Whether bound is inclusive
            bound_type: 'lower' or 'upper'

        Returns:
            True if version satisfies bound, False otherwise
        """
        # Convert versions to tuples of integers for comparison
        try:
            v_parts = [int(x) for x in version.split('.')]
            b_parts = [int(x) for x in bound.split('.')]

            # Pad shorter version with zeros
            max_len = max(len(v_parts), len(b_parts))
            v_parts += [0] * (max_len - len(v_parts))
            b_parts += [0] * (max_len - len(b_parts))

            if bound_type == 'lower':
                if inclusive:
                    return v_parts >= b_parts
                else:
                    return v_parts > b_parts
            else:  # upper
                if inclusive:
                    return v_parts <= b_parts
                else:
                    return v_parts < b_parts

        except (ValueError, AttributeError):
            # Fallback to string comparison if version format is non-standard
            if bound_type == 'lower':
                return version >= bound if inclusive else version > bound
            else:
                return version <= bound if inclusive else version < bound

    def _get_matching_gradle_dynamic_versions(
        self, dynamic_spec: str, package_name: str
    ) -> List[str]:
        """
        Get compromised versions that match Gradle dynamic version

        Examples:
        - 1.+ matches any version starting with 1.
        - 1.2.+ matches any version starting with 1.2.

        Args:
            dynamic_spec: Gradle dynamic version (e.g., "1.2.+")
            package_name: Package name

        Returns:
            List of matching compromised versions
        """
        matching = []

        # Convert 1.2.+ to regex pattern 1\.2\.\d+
        pattern = dynamic_spec.replace('+', r'\d+').replace('.', r'\.')
        pattern = f'^{pattern}$'

        for version in self.compromised_packages[package_name]:
            if re.match(pattern, version):
                matching.append(version)

        return matching
