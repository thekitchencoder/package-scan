"""Data models for threat scanning findings"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class Remediation:
    """Remediation suggestion for a compromised package"""
    strategy: str  # raise_minimum, upgrade_or_override, upgrade_and_update_lockfile, manual_review
    suggested_version: Optional[str] = None
    notes: Optional[str] = None
    affected_versions: Optional[list] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = {'strategy': self.strategy}
        if self.suggested_version:
            result['suggested_version'] = self.suggested_version
        if self.notes:
            result['notes'] = self.notes
        if self.affected_versions:
            result['affected_versions'] = self.affected_versions
        return result


@dataclass
class Finding:
    """Standardized finding structure across all ecosystems"""

    # Core identification
    ecosystem: str              # npm, maven, pip, gem, nuget, etc.
    finding_type: str           # manifest, lockfile, installed
    file_path: str              # Path to manifest/lock file or installation directory
    package_name: str           # Package identifier
    version: str                # Compromised version found

    # Match details
    match_type: str             # exact, range
    declared_spec: Optional[str] = None  # Version spec from manifest (if applicable)
    dependency_type: Optional[str] = None  # dependencies, devDependencies, etc.

    # Remediation
    remediation: Optional[Remediation] = None

    # Ecosystem-specific metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_note: bool = True) -> Dict[str, Any]:
        """
        Convert to dictionary for JSON serialization

        Args:
            include_note: Whether to include remediation notes (omit for JSON reports)
        """
        result = {
            'ecosystem': self.ecosystem,
            'finding_type': self.finding_type,
            'file_path': self.file_path,
            'package_name': self.package_name,
            'version': self.version,
            'match_type': self.match_type,
        }

        if self.declared_spec:
            result['declared_spec'] = self.declared_spec

        if self.dependency_type:
            result['dependency_type'] = self.dependency_type

        if self.remediation:
            rem_dict = self.remediation.to_dict()
            if not include_note:
                rem_dict.pop('notes', None)
            result['remediation'] = rem_dict

        # Add any ecosystem-specific metadata
        if self.metadata:
            result['metadata'] = self.metadata

        return result

    @classmethod
    def from_legacy_npm_dict(cls, legacy: Dict[str, Any]) -> 'Finding':
        """
        Convert legacy npm-only finding dict to new Finding model

        Args:
            legacy: Old-style finding dict from scan_npm_threats.py

        Returns:
            Finding object
        """
        # Map old 'type' to new 'finding_type'
        type_mapping = {
            'package.json': 'manifest',
            'lockfile': 'lockfile',
            'installed': 'installed'
        }

        finding_type = type_mapping.get(legacy.get('type'), 'unknown')

        # Build remediation if present
        remediation = None
        if 'remediation' in legacy and isinstance(legacy['remediation'], dict):
            rem = legacy['remediation']
            remediation = Remediation(
                strategy=rem.get('strategy', 'manual_review'),
                suggested_version=rem.get('suggested_version'),
                notes=rem.get('notes'),
                affected_versions=rem.get('affected_versions')
            )

        # Build metadata
        metadata = {}
        if 'lockfile_type' in legacy:
            metadata['lockfile_type'] = legacy['lockfile_type']
        if 'location' in legacy:
            metadata['location'] = legacy['location']
        if 'package_path' in legacy:
            metadata['package_path'] = legacy['package_path']
        if 'included_versions' in legacy:
            metadata['included_versions'] = legacy['included_versions']

        return cls(
            ecosystem='npm',
            finding_type=finding_type,
            file_path=legacy.get('file', legacy.get('location', '')),
            package_name=legacy['package'],
            version=legacy['version'],
            match_type=legacy.get('match_type', 'exact'),
            declared_spec=legacy.get('version_spec'),
            dependency_type=legacy.get('dependency_type'),
            remediation=remediation,
            metadata=metadata
        )
