"""Unit tests for ReportEngine."""

import json
import os
import tempfile

import pytest

from package_scan.core.models import Finding
from package_scan.core.report_engine import ReportEngine


@pytest.fixture
def sample_findings():
    """Create sample findings for testing."""
    return [
        Finding(
            ecosystem='npm',
            finding_type='manifest',
            file_path='/project/package.json',
            package_name='left-pad',
            version='1.3.0',
            match_type='exact',
            declared_spec='1.3.0'
        ),
        Finding(
            ecosystem='npm',
            finding_type='lockfile',
            file_path='/project/package-lock.json',
            package_name='lodash',
            version='4.17.20',
            match_type='exact'
        ),
        Finding(
            ecosystem='maven',
            finding_type='manifest',
            file_path='/project/pom.xml',
            package_name='org.springframework:spring-core',
            version='5.3.0',
            match_type='range',
            declared_spec='[5.0,6.0)'
        ),
        Finding(
            ecosystem='pip',
            finding_type='manifest',
            file_path='/project/requirements.txt',
            package_name='django',
            version='3.0.0',
            match_type='range',
            declared_spec='>=3.0.0,<4.0.0'
        ),
    ]


def test_add_findings(sample_findings):
    """Test adding findings to the report engine."""
    engine = ReportEngine()

    # Add findings
    engine.add_findings(sample_findings[:2])  # npm findings
    engine.add_findings([sample_findings[2]])  # maven finding
    engine.add_findings([sample_findings[3]])  # pip finding

    # Check that findings were added
    assert len(engine.findings) == 4


def test_generate_summary(sample_findings):
    """Test generating summary statistics."""
    engine = ReportEngine()
    engine.add_findings(sample_findings)

    summary = engine._generate_summary()

    # Check npm summary
    assert summary['npm']['total'] == 2
    assert summary['npm']['manifest'] == 1
    assert summary['npm']['lockfile'] == 1
    assert summary['npm']['installed'] == 0
    assert summary['npm']['unique_packages'] == 2

    # Check maven summary
    assert summary['maven']['total'] == 1
    assert summary['maven']['manifest'] == 1

    # Check pip summary
    assert summary['pip']['total'] == 1


def test_save_report(sample_findings):
    """Test saving JSON report to file."""
    engine = ReportEngine()
    engine.add_findings(sample_findings)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name

    try:
        engine.save_report(temp_path)

        # Verify file was created and is valid JSON
        assert os.path.exists(temp_path)

        with open(temp_path, 'r') as f:
            report = json.load(f)

        # Check report structure
        assert 'total_findings' in report
        assert report['total_findings'] == 4

        assert 'summary' in report
        assert 'npm' in report['summary']
        assert 'maven' in report['summary']
        assert 'pip' in report['summary']

        assert 'findings' in report
        assert len(report['findings']) == 4

        # Check finding structure
        finding = report['findings'][0]
        assert 'ecosystem' in finding
        assert 'finding_type' in finding
        assert 'file_path' in finding
        assert 'package_name' in finding
        assert 'version' in finding

    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def test_save_report_with_relative_paths(sample_findings):
    """Test saving report with relative paths via environment variable."""
    # Set environment variable to trigger relative path conversion
    old_env = os.environ.get('SCAN_PATH_PREFIX')
    os.environ['SCAN_PATH_PREFIX'] = '.'

    try:
        engine = ReportEngine(scan_dir='/project')
        engine.add_findings(sample_findings)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            engine.save_report(temp_path)

            with open(temp_path, 'r') as f:
                report = json.load(f)

            # Check that paths are relative
            for finding in report['findings']:
                # Should start with ./ for relative paths
                assert finding['file_path'].startswith('./')
                # Should be relative to /project
                assert finding['file_path'] in ['./package.json', './package-lock.json', './pom.xml', './requirements.txt']

        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    finally:
        # Restore original environment
        if old_env is None:
            os.environ.pop('SCAN_PATH_PREFIX', None)
        else:
            os.environ['SCAN_PATH_PREFIX'] = old_env


def test_save_report_with_threats():
    """Test saving report with threat tracking."""
    engine = ReportEngine()
    # Use set_threats() method instead of constructor parameter
    engine.set_threats(['sha1-Hulud', 'custom-threat'])
    engine.add_findings([
        Finding(
            ecosystem='npm',
            finding_type='manifest',
            file_path='/project/package.json',
            package_name='test-pkg',
            version='1.0.0',
            match_type='exact'
        )
    ])

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name

    try:
        engine.save_report(temp_path)

        with open(temp_path, 'r') as f:
            report = json.load(f)

        # Check threats are included
        assert 'threats' in report
        assert 'sha1-Hulud' in report['threats']
        assert 'custom-threat' in report['threats']

    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def test_empty_report():
    """Test generating report with no findings."""
    engine = ReportEngine()

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name

    try:
        engine.save_report(temp_path)

        with open(temp_path, 'r') as f:
            report = json.load(f)

        assert report['total_findings'] == 0
        assert report['summary'] == {}
        assert report['findings'] == []

    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def test_print_report_no_findings(capsys):
    """Test printing report with no findings."""
    engine = ReportEngine()
    engine.print_report()

    captured = capsys.readouterr()
    assert "No compromised packages found" in captured.out


def test_print_report_with_findings(sample_findings, capsys):
    """Test printing report with findings."""
    engine = ReportEngine()
    engine.add_findings(sample_findings)
    engine.print_report()

    captured = capsys.readouterr()

    # Check that output contains ecosystem sections
    assert "npm" in captured.out.lower()
    assert "maven" in captured.out.lower()
    assert "pip" in captured.out.lower()

    # Check that package names appear
    assert "left-pad" in captured.out
    assert "lodash" in captured.out
    assert "spring-core" in captured.out
    assert "django" in captured.out


def test_unique_package_counting():
    """Test that unique package counting works correctly."""
    engine = ReportEngine()

    # Add same package multiple times (different finding types)
    findings = [
        Finding(
            ecosystem='npm',
            finding_type='manifest',
            file_path='/project/package.json',
            package_name='test-pkg',
            version='1.0.0',
            match_type='exact'
        ),
        Finding(
            ecosystem='npm',
            finding_type='lockfile',
            file_path='/project/package-lock.json',
            package_name='test-pkg',
            version='1.0.0',
            match_type='exact'
        ),
        Finding(
            ecosystem='npm',
            finding_type='installed',
            file_path='/project/node_modules/test-pkg',
            package_name='test-pkg',
            version='1.0.0',
            match_type='exact'
        ),
    ]

    engine.add_findings(findings)
    summary = engine._generate_summary()

    # Should count as 1 unique package despite 3 findings
    assert summary['npm']['total'] == 3
    assert summary['npm']['unique_packages'] == 1


def test_ecosystems_list():
    """Test getting list of ecosystems with findings."""
    engine = ReportEngine()
    engine.add_findings([
        Finding(
            ecosystem='npm',
            finding_type='manifest',
            file_path='/project/package.json',
            package_name='npm-pkg',
            version='1.0.0',
            match_type='exact'
        ),
        Finding(
            ecosystem='maven',
            finding_type='manifest',
            file_path='/project/pom.xml',
            package_name='org.example:lib',
            version='2.0.0',
            match_type='exact'
        ),
    ])

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name

    try:
        engine.save_report(temp_path)

        with open(temp_path, 'r') as f:
            report = json.load(f)

        # Check ecosystems list
        assert 'ecosystems' in report
        assert 'npm' in report['ecosystems']
        assert 'maven' in report['ecosystems']
        assert 'pip' not in report['ecosystems']

    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
