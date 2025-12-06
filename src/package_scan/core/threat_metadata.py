"""
Threat metadata parsing and validation

Parses metadata from CSV comment lines in threat database files.
"""

import csv
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

import click


# Metadata field pattern: # Field: Value
METADATA_PATTERN = re.compile(r'^#\s*([^:]+):\s*(.+)$')

# Recommended metadata fields
RECOMMENDED_FIELDS = {'description', 'source', 'last updated'}


@dataclass
class ThreatMetadata:
    """Metadata extracted from threat CSV file"""
    file_path: Path
    metadata: Dict[str, str] = field(default_factory=dict)
    comment_lines: List[str] = field(default_factory=list)
    stats: Dict = field(default_factory=dict)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get metadata value by key (case-insensitive)"""
        key_lower = key.lower()
        for k, v in self.metadata.items():
            if k.lower() == key_lower:
                return v
        return default

    def has_field(self, key: str) -> bool:
        """Check if metadata has a field (case-insensitive)"""
        return self.get(key) is not None

    def get_missing_recommended_fields(self) -> List[str]:
        """Get list of missing recommended metadata fields"""
        missing = []
        for field in RECOMMENDED_FIELDS:
            if not self.has_field(field):
                missing.append(field)
        return missing

    def is_complete(self) -> bool:
        """Check if all recommended fields are present"""
        return len(self.get_missing_recommended_fields()) == 0

    def compute_stats(self):
        """Compute statistics from the CSV file"""
        if not self.file_path.exists():
            return

        try:
            # Get filtered CSV content (without comments)
            csv_content = get_csv_reader_without_comments(self.file_path)
            reader = csv.DictReader(csv_content)

            # Track ecosystems and packages
            ecosystems: Dict[str, Set[str]] = defaultdict(set)
            total_versions = 0

            for row in reader:
                ecosystem = row.get('ecosystem', '').strip().lower()
                name = row.get('name', '').strip()

                if ecosystem and name:
                    ecosystems[ecosystem].add(name)
                    total_versions += 1

            # Compute summary statistics
            self.stats = {
                'total_versions': total_versions,
                'total_packages': sum(len(packages) for packages in ecosystems.values()),
                'ecosystems': sorted(ecosystems.keys()),
                'ecosystem_details': {
                    eco: {'packages': len(packages), 'package_names': sorted(packages)}
                    for eco, packages in ecosystems.items()
                }
            }

        except Exception:
            # If we can't compute stats, just leave them empty
            pass

    def print_metadata(self):
        """Print metadata in a formatted way"""
        click.echo(click.style("=" * 80, fg='cyan', bold=True))
        click.echo(click.style("📋 THREAT METADATA", fg='cyan', bold=True))
        click.echo(click.style("=" * 80, fg='cyan', bold=True))
        click.echo()
        click.echo(click.style(f"File: {self.file_path}", fg='white', bold=True))
        click.echo()

        if self.metadata:
            # Show metadata fields
            for key, value in self.metadata.items():
                # Highlight recommended fields
                if key.lower() in RECOMMENDED_FIELDS:
                    click.echo(f"{click.style(key + ':', fg='green', bold=True)} {value}")
                else:
                    click.echo(f"{click.style(key + ':', fg='cyan')} {value}")

            # Check for missing recommended fields
            missing = self.get_missing_recommended_fields()
            if missing:
                click.echo()
                click.echo(click.style(
                    f"⚠️  Missing recommended fields: {', '.join(missing)}",
                    fg='yellow'
                ))
        else:
            click.echo(click.style("No metadata found in threat file", fg='yellow'))

        # Show statistics if available
        if self.stats:
            click.echo()
            click.echo(click.style("📊 THREAT STATISTICS", fg='cyan', bold=True))
            click.echo()

            total_packages = self.stats.get('total_packages', 0)
            total_versions = self.stats.get('total_versions', 0)
            ecosystems = self.stats.get('ecosystems', [])

            click.echo(f"{click.style('Total Packages:', bold=True)} {total_packages}")
            click.echo(f"{click.style('Total Versions:', bold=True)} {total_versions}")
            click.echo(f"{click.style('Ecosystems:', bold=True)} {', '.join(ecosystems)}")

            # Show per-ecosystem breakdown
            ecosystem_details = self.stats.get('ecosystem_details', {})
            if ecosystem_details:
                click.echo()
                for ecosystem in sorted(ecosystem_details.keys()):
                    details = ecosystem_details[ecosystem]
                    pkg_count = details.get('packages', 0)
                    click.echo(f"  {click.style(f'• {ecosystem}:', fg='magenta', bold=True)} {pkg_count} packages")

        click.echo()
        click.echo(click.style("=" * 80, fg='cyan', bold=True))


def parse_threat_metadata(file_path: Path) -> ThreatMetadata:
    """
    Parse metadata from threat CSV file

    Extracts metadata from comment lines at the start of the file.
    Format: # Field: Value

    Args:
        file_path: Path to threat CSV file

    Returns:
        ThreatMetadata object with parsed metadata
    """
    metadata = ThreatMetadata(file_path=file_path)

    if not file_path.exists():
        return metadata

    try:
        with open(file_path, 'r', encoding='utf-8-sig') as f:
            for line in f:
                line = line.strip()

                # Stop at first non-comment line (headers or data)
                if line and not line.startswith('#'):
                    break

                # Skip empty comment lines
                if not line or line == '#':
                    continue

                # Store all comment lines
                metadata.comment_lines.append(line)

                # Try to parse as metadata field
                match = METADATA_PATTERN.match(line)
                if match:
                    field_name = match.group(1).strip()
                    field_value = match.group(2).strip()
                    metadata.metadata[field_name] = field_value

    except Exception as e:
        click.echo(click.style(
            f"Warning: Could not parse metadata from {file_path}: {e}",
            fg='yellow'
        ), err=True)

    return metadata


def filter_csv_comments(lines: List[str]) -> List[str]:
    """
    Filter out comment lines from CSV content

    Args:
        lines: List of lines from CSV file

    Returns:
        List of lines with comments removed
    """
    filtered = []
    for line in lines:
        stripped = line.strip()
        # Skip comment lines and empty lines
        if not stripped or stripped.startswith('#'):
            continue
        filtered.append(line)
    return filtered


def get_csv_reader_without_comments(file_path: Path):
    """
    Get CSV reader that automatically skips comment lines

    Args:
        file_path: Path to CSV file

    Returns:
        File object with comments filtered out, ready for csv.DictReader
    """
    import io

    with open(file_path, 'r', encoding='utf-8-sig') as f:
        lines = f.readlines()

    # Filter out comments
    filtered_lines = filter_csv_comments(lines)

    # Return as file-like object
    return io.StringIO(''.join(filtered_lines))
