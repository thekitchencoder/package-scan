"""Unit tests for ThreatValidator."""

import os
import tempfile
from pathlib import Path

import pytest

from package_scan.core.threat_validator import (
    ThreatValidator,
    ValidationResult,
    validate_threat_file,
    KNOWN_ECOSYSTEMS,
)


@pytest.fixture
def valid_modern_csv():
    """Create a valid modern format CSV file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
        f.write("ecosystem,name,version\n")
        f.write("npm,left-pad,1.3.0\n")
        f.write("npm,@scope/package,2.0.0\n")
        f.write("maven,org.springframework:spring-core,5.3.0\n")
        f.write("pip,requests,2.8.1\n")
        temp_path = f.name

    yield temp_path

    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def invalid_headers_csv():
    """Create CSV with invalid headers."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
        f.write("package,ver,eco\n")
        f.write("npm,left-pad,1.3.0\n")
        temp_path = f.name

    yield temp_path

    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def empty_fields_csv():
    """Create CSV with empty fields."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
        f.write("ecosystem,name,version\n")
        f.write("npm,left-pad,1.3.0\n")
        f.write(",,\n")  # Empty row
        f.write("npm,,2.0.0\n")  # Empty name
        f.write(",package,3.0.0\n")  # Empty ecosystem
        f.write("npm,package,\n")  # Empty version
        temp_path = f.name

    yield temp_path

    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def unknown_ecosystem_csv():
    """Create CSV with unknown ecosystem."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
        f.write("ecosystem,name,version\n")
        f.write("npm,left-pad,1.3.0\n")
        f.write("rust,tokio,1.0.0\n")  # Unknown ecosystem
        f.write("golang,gin,1.7.0\n")  # Unknown ecosystem
        temp_path = f.name

    yield temp_path

    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def duplicate_entries_csv():
    """Create CSV with duplicate entries."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
        f.write("ecosystem,name,version\n")
        f.write("npm,left-pad,1.3.0\n")
        f.write("npm,lodash,4.17.20\n")
        f.write("npm,left-pad,1.3.0\n")  # Duplicate
        f.write("maven,org.springframework:spring-core,5.3.0\n")
        f.write("maven,org.springframework:spring-core,5.3.0\n")  # Duplicate
        temp_path = f.name

    yield temp_path

    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def invalid_version_csv():
    """Create CSV with invalid version strings."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
        f.write("ecosystem,name,version\n")
        f.write("npm,left-pad,1.3.0\n")
        f.write("npm,package,1.0.0@beta\n")  # Unusual character
        f.write("npm,other,1.0\ttab\n")  # Tab in version
        temp_path = f.name

    yield temp_path

    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def maven_package_format_csv():
    """Create CSV with Maven packages in various formats."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
        f.write("ecosystem,name,version\n")
        f.write("maven,org.springframework:spring-core,5.3.0\n")  # Valid
        f.write("maven,spring-core,5.3.0\n")  # Missing groupId
        f.write("maven,org.apache.logging.log4j:log4j-core,2.14.1\n")  # Valid
        temp_path = f.name

    yield temp_path

    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def empty_csv():
    """Create empty CSV file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
        temp_path = f.name

    yield temp_path

    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def headers_only_csv():
    """Create CSV with headers but no data."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
        f.write("ecosystem,name,version\n")
        temp_path = f.name

    yield temp_path

    if os.path.exists(temp_path):
        os.unlink(temp_path)


class TestThreatValidator:
    """Test ThreatValidator class."""

    def test_validate_valid_format(self, valid_modern_csv):
        """Test validation of valid CSV format."""
        validator = ThreatValidator()
        result = validator.validate_file(Path(valid_modern_csv))

        assert result.is_valid
        assert result.format_type == 'valid'
        assert not result.has_errors()
        assert result.stats['total_rows'] == 4
        assert result.stats['valid_rows'] == 4
        assert result.stats['unique_ecosystems'] == 3
        assert set(result.stats['ecosystems']) == {'npm', 'maven', 'pip'}

    def test_validate_invalid_headers(self, invalid_headers_csv):
        """Test validation fails with invalid headers."""
        validator = ThreatValidator()
        result = validator.validate_file(Path(invalid_headers_csv))

        assert not result.is_valid
        assert result.format_type == 'invalid'
        assert result.has_errors()
        assert any('Invalid CSV headers' in error.message for error in result.errors)

    def test_validate_empty_fields(self, empty_fields_csv):
        """Test validation detects empty fields."""
        validator = ThreatValidator()
        result = validator.validate_file(Path(empty_fields_csv))

        assert not result.is_valid
        assert result.has_errors()

        # Check for specific error types
        error_messages = [error.message for error in result.errors]
        assert any('Empty ecosystem' in msg for msg in error_messages)
        assert any('Empty package name' in msg for msg in error_messages)
        assert any('Empty version' in msg for msg in error_messages)

    def test_validate_unknown_ecosystem_non_strict(self, unknown_ecosystem_csv):
        """Test validation warns about unknown ecosystems in non-strict mode."""
        validator = ThreatValidator(strict_ecosystems=False)
        result = validator.validate_file(Path(unknown_ecosystem_csv))

        assert result.is_valid  # Still valid, just warnings
        assert result.has_warnings()

        # Check for ecosystem warnings
        warning_messages = [warning.message for warning in result.warnings]
        assert any('rust' in msg.lower() for msg in warning_messages)
        assert any('golang' in msg.lower() for msg in warning_messages)

    def test_validate_unknown_ecosystem_strict(self, unknown_ecosystem_csv):
        """Test validation fails with unknown ecosystems in strict mode."""
        validator = ThreatValidator(strict_ecosystems=True)
        result = validator.validate_file(Path(unknown_ecosystem_csv))

        assert not result.is_valid
        assert result.has_errors()

        # Check for ecosystem errors
        error_messages = [error.message for error in result.errors]
        assert any('rust' in msg.lower() for msg in error_messages)
        assert any('golang' in msg.lower() for msg in error_messages)

    def test_validate_duplicate_entries(self, duplicate_entries_csv):
        """Test validation detects duplicate entries."""
        validator = ThreatValidator()
        result = validator.validate_file(Path(duplicate_entries_csv))

        assert result.is_valid  # Duplicates are warnings, not errors
        assert result.has_warnings()

        # Check for duplicate warnings
        warning_messages = [warning.message for warning in result.warnings]
        assert any('Duplicate entry' in msg for msg in warning_messages)
        assert sum('Duplicate entry' in msg for msg in warning_messages) == 2

    def test_validate_invalid_version(self, invalid_version_csv):
        """Test validation detects invalid version strings."""
        validator = ThreatValidator()
        result = validator.validate_file(Path(invalid_version_csv))

        assert not result.is_valid
        assert result.has_errors()

        # Check for version-related issues
        all_issues = [e.message for e in result.errors + result.warnings]
        assert any('whitespace' in msg.lower() or 'unusual' in msg.lower() for msg in all_issues)

    def test_validate_maven_package_format(self, maven_package_format_csv):
        """Test validation warns about Maven package format."""
        validator = ThreatValidator()
        result = validator.validate_file(Path(maven_package_format_csv))

        assert result.is_valid  # Format warning, not error
        assert result.has_warnings()

        # Check for Maven format warning
        warning_messages = [warning.message for warning in result.warnings]
        assert any('groupId:artifactId' in msg for msg in warning_messages)

    def test_validate_empty_file(self, empty_csv):
        """Test validation fails with empty file."""
        validator = ThreatValidator()
        result = validator.validate_file(Path(empty_csv))

        assert not result.is_valid
        assert result.has_errors()
        assert any('empty' in error.message.lower() for error in result.errors)

    def test_validate_headers_only(self, headers_only_csv):
        """Test validation fails with headers but no data."""
        validator = ThreatValidator()
        result = validator.validate_file(Path(headers_only_csv))

        assert not result.is_valid
        assert result.has_errors()
        assert any('no data rows' in error.message.lower() for error in result.errors)

    def test_validate_nonexistent_file(self):
        """Test validation fails for nonexistent file."""
        validator = ThreatValidator()
        result = validator.validate_file(Path('/nonexistent/file.csv'))

        assert not result.is_valid
        assert result.has_errors()
        assert any('not found' in error.message.lower() for error in result.errors)

    def test_validation_result_statistics(self, valid_modern_csv):
        """Test validation result includes statistics."""
        validator = ThreatValidator()
        result = validator.validate_file(Path(valid_modern_csv))

        assert result.stats is not None
        assert 'total_rows' in result.stats
        assert 'valid_rows' in result.stats
        assert 'invalid_rows' in result.stats
        assert 'unique_ecosystems' in result.stats
        assert 'unique_packages' in result.stats
        assert 'unique_entries' in result.stats
        assert 'ecosystems' in result.stats

    def test_validation_error_has_line_numbers(self, empty_fields_csv):
        """Test validation errors include line numbers."""
        validator = ThreatValidator()
        result = validator.validate_file(Path(empty_fields_csv))

        assert result.has_errors()
        for error in result.errors:
            assert error.line_number > 0
            assert isinstance(error.message, str)

    def test_validation_tracks_field_names(self, empty_fields_csv):
        """Test validation tracks which fields have errors."""
        validator = ThreatValidator()
        result = validator.validate_file(Path(empty_fields_csv))

        assert result.has_errors()

        # Check that field names are tracked
        fields_with_errors = {error.field for error in result.errors if error.field}
        assert 'ecosystem' in fields_with_errors
        assert 'name' in fields_with_errors
        assert 'version' in fields_with_errors


class TestValidateThreatFileFunction:
    """Test validate_threat_file convenience function."""

    def test_validate_threat_file_valid(self, valid_modern_csv, capsys):
        """Test validate_threat_file returns True for valid file."""
        result = validate_threat_file(valid_modern_csv, strict=False, verbose=False)
        assert result is True

        # Check console output
        captured = capsys.readouterr()
        assert 'VALIDATION PASSED' in captured.out

    def test_validate_threat_file_invalid(self, invalid_headers_csv, capsys):
        """Test validate_threat_file returns False for invalid file."""
        result = validate_threat_file(invalid_headers_csv, strict=False, verbose=False)
        assert result is False

        # Check console output
        captured = capsys.readouterr()
        assert 'VALIDATION FAILED' in captured.out

    def test_validate_threat_file_verbose(self, duplicate_entries_csv, capsys):
        """Test validate_threat_file shows warnings in verbose mode."""
        result = validate_threat_file(duplicate_entries_csv, strict=False, verbose=True)
        assert result is True

        # Check console output includes warnings
        captured = capsys.readouterr()
        assert 'WARNINGS' in captured.out
        assert 'Duplicate entry' in captured.out


class TestRealThreatFiles:
    """Test validation against real threat database files."""

    def test_validate_sample_threats(self):
        """Test validation of sample-threats.csv."""
        sample_threats = Path(__file__).parent.parent / 'threats' / 'sample-threats.csv'

        if not sample_threats.exists():
            pytest.skip("sample-threats.csv not found")

        validator = ThreatValidator(strict_ecosystems=False)
        result = validator.validate_file(sample_threats)

        # Sample threats should be valid
        assert result.is_valid
        assert result.format_type == 'valid'
        assert result.stats['total_rows'] > 0

    def test_validate_sha1_hulud(self):
        """Test validation of sha1-Hulud.csv."""
        sha1_hulud = Path(__file__).parent.parent / 'threats' / 'sha1-Hulud.csv'

        if not sha1_hulud.exists():
            pytest.skip("sha1-Hulud.csv not found")

        validator = ThreatValidator(strict_ecosystems=False)
        result = validator.validate_file(sha1_hulud)

        # sha1-Hulud should be valid
        assert result.is_valid
        assert result.format_type == 'valid'
        assert result.stats['total_rows'] > 0


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_csv_with_extra_columns(self):
        """Test CSV with extra columns is accepted."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
            f.write("ecosystem,name,version,extra_column\n")
            f.write("npm,left-pad,1.3.0,ignored\n")
            temp_path = f.name

        try:
            validator = ThreatValidator()
            result = validator.validate_file(Path(temp_path))

            # Should still be valid (extra columns are ignored)
            assert result.is_valid
            assert result.format_type == 'valid'
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_csv_with_bom(self):
        """Test CSV with UTF-8 BOM is handled correctly."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8-sig') as f:
            f.write("ecosystem,name,version\n")
            f.write("npm,left-pad,1.3.0\n")
            temp_path = f.name

        try:
            validator = ThreatValidator()
            result = validator.validate_file(Path(temp_path))

            # Should handle BOM correctly
            assert result.is_valid or result.format_type != 'invalid'
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_csv_with_different_line_endings(self):
        """Test CSV with different line endings."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8', newline='') as f:
            f.write("ecosystem,name,version\r\n")  # Windows line endings
            f.write("npm,left-pad,1.3.0\r\n")
            temp_path = f.name

        try:
            validator = ThreatValidator()
            result = validator.validate_file(Path(temp_path))

            assert result.is_valid
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
