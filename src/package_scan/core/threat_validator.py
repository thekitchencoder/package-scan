"""
Threat Database CSV Validation

Validates threat CSV files to ensure they conform to expected format and contain valid data.
This prevents distribution of malformed threat CSVs that could cause scanning failures.
"""

import csv
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Set, Tuple, Optional

import click


# Known ecosystems (expandable as new adapters are added)
KNOWN_ECOSYSTEMS = {'npm', 'maven', 'pip', 'gem'}

# Required CSV headers
REQUIRED_HEADERS = {'ecosystem', 'name', 'version'}

# Version string validation patterns
VERSION_PATTERN = re.compile(r'^[0-9a-zA-Z.\-_+]+$')

# Maven package name pattern (groupId:artifactId)
MAVEN_PACKAGE_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+$')


@dataclass
class ValidationError:
    """Represents a validation error with context"""
    line_number: int
    severity: str  # 'error', 'warning'
    message: str
    field: Optional[str] = None
    value: Optional[str] = None


@dataclass
class ValidationResult:
    """Results of threat CSV validation"""
    file_path: Path
    is_valid: bool
    format_type: str  # 'valid', 'invalid'
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[ValidationError] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def add_error(self, line_number: int, message: str, field: Optional[str] = None, value: Optional[str] = None):
        """Add validation error"""
        self.errors.append(ValidationError(
            line_number=line_number,
            severity='error',
            message=message,
            field=field,
            value=value
        ))
        self.is_valid = False

    def add_warning(self, line_number: int, message: str, field: Optional[str] = None, value: Optional[str] = None):
        """Add validation warning"""
        self.warnings.append(ValidationError(
            line_number=line_number,
            severity='warning',
            message=message,
            field=field,
            value=value
        ))

    def has_errors(self) -> bool:
        """Check if there are any errors"""
        return len(self.errors) > 0

    def has_warnings(self) -> bool:
        """Check if there are any warnings"""
        return len(self.warnings) > 0


class ThreatValidator:
    """
    Validates threat database CSV files

    Checks:
    - File encoding and readability
    - Header format (modern or legacy)
    - Required fields presence
    - Field value validation (ecosystem, name, version)
    - Duplicate detection
    - Ecosystem validity
    - Package name format (ecosystem-specific)
    - Version string format
    """

    def __init__(self, strict_ecosystems: bool = False):
        """
        Initialize validator

        Args:
            strict_ecosystems: If True, only allow known ecosystems. If False, warn about unknown ones.
        """
        self.strict_ecosystems = strict_ecosystems

    def validate_file(self, file_path: Path) -> ValidationResult:
        """
        Validate a threat CSV file

        Args:
            file_path: Path to CSV file

        Returns:
            ValidationResult with errors, warnings, and stats
        """
        result = ValidationResult(
            file_path=file_path,
            is_valid=True,
            format_type='invalid'
        )

        # Check file exists
        if not file_path.exists():
            result.add_error(0, f"File not found: {file_path}")
            return result

        # Check file is readable
        if not file_path.is_file():
            result.add_error(0, f"Not a file: {file_path}")
            return result

        # Try to read and validate CSV
        # Use utf-8-sig to automatically handle UTF-8 BOM if present
        try:
            with open(file_path, 'r', encoding='utf-8-sig', newline='') as f:
                # Check if file is empty
                content = f.read()
                if not content.strip():
                    result.add_error(0, "File is empty")
                    return result

                # Reset file pointer
                f.seek(0)

                # Read CSV
                reader = csv.DictReader(f)
                headers = reader.fieldnames

                if not headers:
                    result.add_error(1, "No headers found in CSV file")
                    return result

                # Detect format
                format_type = self._detect_format(set(headers))
                result.format_type = format_type

                if format_type == 'invalid':
                    result.add_error(
                        1,
                        f"Invalid CSV headers. Expected 'ecosystem,name,version'. "
                        f"Got: {','.join(headers)}"
                    )
                    return result

                # Validate rows
                self._validate_rows(reader, result)

        except UnicodeDecodeError as e:
            result.add_error(0, f"File encoding error: {e}")
        except csv.Error as e:
            result.add_error(0, f"CSV parsing error: {e}")
        except Exception as e:
            result.add_error(0, f"Unexpected error reading file: {e}")

        return result

    def _detect_format(self, headers: Set[str]) -> str:
        """
        Detect CSV format type

        Args:
            headers: Set of header names

        Returns:
            'valid' or 'invalid'
        """
        if REQUIRED_HEADERS.issubset(headers):
            return 'valid'
        else:
            return 'invalid'

    def _validate_rows(self, reader: csv.DictReader, result: ValidationResult):
        """
        Validate all rows in CSV

        Args:
            reader: CSV DictReader
            result: ValidationResult to populate
        """
        seen_entries: Set[Tuple[str, str, str]] = set()
        ecosystems: Set[str] = set()
        packages: Set[str] = set()
        total_rows = 0
        valid_rows = 0

        for row_num, row in enumerate(reader, start=2):  # Start at 2 (header is line 1)
            total_rows += 1
            row_valid = True

            # Extract fields
            ecosystem = row.get('ecosystem', '').strip().lower()
            name = row.get('name', '').strip()
            version = row.get('version', '').strip()

            # Validate ecosystem
            if not ecosystem:
                result.add_error(row_num, "Empty ecosystem field", field='ecosystem')
                row_valid = False
            elif self.strict_ecosystems and ecosystem not in KNOWN_ECOSYSTEMS:
                result.add_error(
                    row_num,
                    f"Unknown ecosystem: '{ecosystem}'. Known: {', '.join(sorted(KNOWN_ECOSYSTEMS))}",
                    field='ecosystem',
                    value=ecosystem
                )
                row_valid = False
            elif ecosystem not in KNOWN_ECOSYSTEMS:
                result.add_warning(
                    row_num,
                    f"Unknown ecosystem: '{ecosystem}'. Known: {', '.join(sorted(KNOWN_ECOSYSTEMS))}",
                    field='ecosystem',
                    value=ecosystem
                )

            # Validate package name
            if not name:
                result.add_error(row_num, "Empty package name", field='name')
                row_valid = False
            else:
                # Ecosystem-specific package name validation
                if ecosystem == 'maven' and ':' not in name:
                    result.add_warning(
                        row_num,
                        f"Maven package should be in 'groupId:artifactId' format: '{name}'",
                        field='name',
                        value=name
                    )

                # Check for suspicious characters
                if '\n' in name or '\r' in name or '\t' in name:
                    result.add_error(
                        row_num,
                        f"Package name contains whitespace characters: '{name}'",
                        field='name',
                        value=name
                    )
                    row_valid = False

            # Validate version
            if not version:
                result.add_error(row_num, "Empty version field", field='version')
                row_valid = False
            else:
                # Check version format
                if not VERSION_PATTERN.match(version):
                    result.add_warning(
                        row_num,
                        f"Version contains unusual characters: '{version}'",
                        field='version',
                        value=version
                    )

                # Check for whitespace
                if '\n' in version or '\r' in version or '\t' in version:
                    result.add_error(
                        row_num,
                        f"Version contains whitespace characters: '{version}'",
                        field='version',
                        value=version
                    )
                    row_valid = False

            # Check for duplicates
            entry = (ecosystem, name, version)
            if entry in seen_entries:
                result.add_warning(
                    row_num,
                    f"Duplicate entry: ecosystem={ecosystem}, name={name}, version={version}"
                )
            else:
                seen_entries.add(entry)

            # Track stats
            if row_valid:
                valid_rows += 1
                ecosystems.add(ecosystem)
                packages.add(f"{ecosystem}:{name}")

        # Store statistics
        result.stats = {
            'total_rows': total_rows,
            'valid_rows': valid_rows,
            'invalid_rows': total_rows - valid_rows,
            'unique_ecosystems': len(ecosystems),
            'unique_packages': len(packages),
            'unique_entries': len(seen_entries),
            'ecosystems': sorted(ecosystems)
        }

        # Additional validation
        if total_rows == 0:
            result.add_error(2, "CSV file has no data rows (only headers)")

    def print_result(self, result: ValidationResult, verbose: bool = False):
        """
        Print validation result to console

        Args:
            result: ValidationResult to print
            verbose: If True, show all warnings and details
        """
        click.echo(click.style("\n" + "=" * 80, fg='cyan', bold=True))
        click.echo(click.style("🔍 THREAT DATABASE VALIDATION", fg='cyan', bold=True))
        click.echo(click.style("=" * 80, fg='cyan', bold=True))

        click.echo(f"\n{click.style('File:', bold=True)} {result.file_path}")
        click.echo(f"{click.style('Format:', bold=True)} {result.format_type}")

        # Show statistics if available
        if result.stats:
            stats = result.stats
            click.echo(f"\n{click.style('Statistics:', bold=True)}")
            click.echo(f"  Total rows: {stats.get('total_rows', 0)}")
            click.echo(f"  Valid rows: {stats.get('valid_rows', 0)}")
            if stats.get('invalid_rows', 0) > 0:
                click.echo(click.style(f"  Invalid rows: {stats['invalid_rows']}", fg='red'))
            click.echo(f"  Unique entries: {stats.get('unique_entries', 0)}")
            click.echo(f"  Unique packages: {stats.get('unique_packages', 0)}")
            click.echo(f"  Ecosystems: {', '.join(stats.get('ecosystems', []))}")

        # Show errors
        if result.has_errors():
            click.echo(click.style(f"\n❌ ERRORS ({len(result.errors)}):", fg='red', bold=True))
            for error in result.errors:
                line_info = f"Line {error.line_number}" if error.line_number > 0 else "File"
                field_info = f" [{error.field}]" if error.field else ""
                value_info = f" = '{error.value}'" if error.value else ""
                click.echo(click.style(
                    f"  • {line_info}{field_info}{value_info}: {error.message}",
                    fg='red'
                ))

        # Show warnings (if verbose or if no errors)
        if result.has_warnings() and (verbose or not result.has_errors()):
            click.echo(click.style(f"\n⚠️  WARNINGS ({len(result.warnings)}):", fg='yellow', bold=True))
            for warning in result.warnings:
                line_info = f"Line {warning.line_number}" if warning.line_number > 0 else "File"
                field_info = f" [{warning.field}]" if warning.field else ""
                value_info = f" = '{warning.value}'" if warning.value else ""
                click.echo(click.style(
                    f"  • {line_info}{field_info}{value_info}: {warning.message}",
                    fg='yellow'
                ))

        # Final result
        click.echo()
        if result.is_valid:
            click.echo(click.style("✓ VALIDATION PASSED", fg='green', bold=True))
            if result.has_warnings() and not verbose:
                click.echo(click.style(
                    f"  Note: {len(result.warnings)} warning(s) found. Use --verbose to see details.",
                    fg='yellow', dim=True
                ))
        else:
            click.echo(click.style("✗ VALIDATION FAILED", fg='red', bold=True))

        click.echo(click.style("=" * 80, fg='cyan', bold=True))


def validate_threat_file(file_path: str, strict: bool = False, verbose: bool = False) -> bool:
    """
    Validate a threat CSV file (convenience function)

    Args:
        file_path: Path to CSV file
        strict: If True, only allow known ecosystems
        verbose: If True, show all warnings and details

    Returns:
        True if validation passed, False otherwise
    """
    validator = ThreatValidator(strict_ecosystems=strict)
    result = validator.validate_file(Path(file_path))
    validator.print_result(result, verbose=verbose)
    return result.is_valid
