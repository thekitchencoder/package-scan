"""Unit tests for ThreatDatabase."""

import pytest
import tempfile
import os
from pathlib import Path
from package_scan.core.threat_database import ThreatDatabase


@pytest.fixture
def temp_csv_file():
    """Create a temporary CSV file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("ecosystem,name,version\n")
        f.write("npm,left-pad,1.3.0\n")
        f.write("npm,@scope/package,2.0.0\n")
        f.write("maven,org.springframework:spring-core,5.3.0\n")
        f.write("pip,requests,2.8.1\n")
        temp_path = f.name

    yield temp_path

    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def legacy_csv_file():
    """Create a legacy format CSV file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("Package Name,Version\n")
        f.write("left-pad,1.3.0\n")
        f.write("lodash,4.17.20\n")
        temp_path = f.name

    yield temp_path

    # Cleanup
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def temp_threats_dir():
    """Create a temporary threats directory with multiple CSV files."""
    temp_dir = tempfile.mkdtemp()

    # Create first threat CSV
    with open(os.path.join(temp_dir, 'threat1.csv'), 'w') as f:
        f.write("ecosystem,name,version\n")
        f.write("npm,package1,1.0.0\n")
        f.write("maven,org.example:lib,2.0.0\n")

    # Create second threat CSV
    with open(os.path.join(temp_dir, 'threat2.csv'), 'w') as f:
        f.write("ecosystem,name,version\n")
        f.write("pip,django,3.0.0\n")

    yield temp_dir

    # Cleanup
    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_load_threats_from_csv(temp_csv_file):
    """Test loading threats from a single CSV file."""
    db = ThreatDatabase()
    db.load_threats(csv_file=temp_csv_file)

    # Check npm packages
    assert db.get_compromised_versions('npm', 'left-pad') == {'1.3.0'}
    assert db.get_compromised_versions('npm', '@scope/package') == {'2.0.0'}

    # Check maven packages
    assert db.get_compromised_versions('maven', 'org.springframework:spring-core') == {'5.3.0'}

    # Check pip packages
    assert db.get_compromised_versions('pip', 'requests') == {'2.8.1'}

    # Check non-existent package
    assert db.get_compromised_versions('npm', 'nonexistent') == set()


def test_load_legacy_format(legacy_csv_file):
    """Test loading legacy CSV format (defaults to npm ecosystem)."""
    db = ThreatDatabase()
    db.load(legacy_csv_file)

    # Should default to npm ecosystem
    assert db.get_compromised_versions('npm', 'left-pad') == {'1.3.0'}
    assert db.get_compromised_versions('npm', 'lodash') == {'4.17.20'}


def test_load_specific_threat(temp_threats_dir):
    """Test loading a specific threat by name."""
    db = ThreatDatabase(threats_dir=temp_threats_dir)
    db.load_threats(threat_names=['threat1'])

    # Should only load threat1
    assert db.get_compromised_versions('npm', 'package1') == {'1.0.0'}
    assert db.get_compromised_versions('maven', 'org.example:lib') == {'2.0.0'}

    # Should not load threat2
    assert db.get_compromised_versions('pip', 'django') == set()

    # Check loaded threats
    assert db.get_loaded_threats() == ['threat1']


def test_load_multiple_threats(temp_threats_dir):
    """Test loading multiple specific threats."""
    db = ThreatDatabase(threats_dir=temp_threats_dir)
    db.load_threats(threat_names=['threat1', 'threat2'])

    # Should load both threats
    assert db.get_compromised_versions('npm', 'package1') == {'1.0.0'}
    assert db.get_compromised_versions('pip', 'django') == {'3.0.0'}

    # Check loaded threats
    loaded = db.get_loaded_threats()
    assert 'threat1' in loaded
    assert 'threat2' in loaded


def test_load_all_threats_from_directory(temp_threats_dir):
    """Test loading all threats from a directory."""
    db = ThreatDatabase(threats_dir=temp_threats_dir)
    db.load_threats()

    # Should load all CSV files in directory
    assert db.get_compromised_versions('npm', 'package1') == {'1.0.0'}
    assert db.get_compromised_versions('maven', 'org.example:lib') == {'2.0.0'}
    assert db.get_compromised_versions('pip', 'django') == {'3.0.0'}


def test_get_all_packages(temp_csv_file):
    """Test getting all packages from database."""
    db = ThreatDatabase()
    db.load_threats(csv_file=temp_csv_file)

    npm_packages = db.get_all_packages(ecosystem='npm')
    maven_packages = db.get_all_packages(ecosystem='maven')
    pip_packages = db.get_all_packages(ecosystem='pip')

    # Check that all packages are present
    assert 'left-pad' in npm_packages
    assert '@scope/package' in npm_packages
    assert 'org.springframework:spring-core' in maven_packages
    assert 'requests' in pip_packages


def test_get_ecosystems(temp_csv_file):
    """Test getting list of ecosystems in database."""
    db = ThreatDatabase()
    db.load_threats(csv_file=temp_csv_file)

    ecosystems = db.get_ecosystems()

    assert 'npm' in ecosystems
    assert 'maven' in ecosystems
    assert 'pip' in ecosystems


def test_multiple_versions_same_package():
    """Test handling multiple versions of the same package."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("ecosystem,name,version\n")
        f.write("npm,vulnerable-pkg,1.0.0\n")
        f.write("npm,vulnerable-pkg,1.0.1\n")
        f.write("npm,vulnerable-pkg,2.0.0\n")
        temp_path = f.name

    try:
        db = ThreatDatabase()
        db.load_threats(csv_file=temp_path)

        versions = db.get_compromised_versions('npm', 'vulnerable-pkg')
        assert '1.0.0' in versions
        assert '1.0.1' in versions
        assert '2.0.0' in versions
        assert len(versions) == 3
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def test_empty_database():
    """Test behavior with empty database."""
    db = ThreatDatabase()

    assert db.get_compromised_versions('npm', 'any-package') == set()
    assert db.get_all_packages() == {}
    assert db.get_ecosystems() == set()
    assert db.get_loaded_threats() == []


def test_case_sensitivity():
    """Test that package names are case-sensitive."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("ecosystem,name,version\n")
        f.write("npm,Package-Name,1.0.0\n")
        temp_path = f.name

    try:
        db = ThreatDatabase()
        db.load_threats(csv_file=temp_path)

        # Exact match should work
        assert db.get_compromised_versions('npm', 'Package-Name') == {'1.0.0'}

        # Different case should not match
        assert db.get_compromised_versions('npm', 'package-name') == set()
        assert db.get_compromised_versions('npm', 'PACKAGE-NAME') == set()
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
