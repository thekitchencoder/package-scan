"""Unit tests for NpmAdapter."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from package_scan.adapters.npm_adapter import NpmAdapter
from package_scan.core.threat_database import ThreatDatabase


@pytest.fixture
def threat_db():
    """Create a threat database with sample npm packages."""
    db = ThreatDatabase()

    # Create a temporary CSV with test threats
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("ecosystem,name,version\n")
        f.write("npm,left-pad,1.3.0\n")
        f.write("npm,lodash,4.17.20\n")
        f.write("npm,@scope/package,2.0.0\n")
        f.write("npm,vulnerable-pkg,1.0.0\n")
        f.write("npm,vulnerable-pkg,1.0.1\n")
        temp_path = f.name

    db.load_threats(csv_file=temp_path)
    os.unlink(temp_path)

    return db


@pytest.fixture
def temp_project_dir():
    """Create a temporary project directory."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir

    # Cleanup
    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_adapter_ecosystem_name(threat_db):
    """Test that adapter returns correct ecosystem name."""
    adapter = NpmAdapter(threat_db, Path('.'))
    assert adapter._get_ecosystem_name() == 'npm'


def test_detect_projects_with_package_json(temp_project_dir, threat_db):
    """Test detecting projects with package.json."""
    adapter = NpmAdapter(threat_db, Path(temp_project_dir))

    # Create a package.json
    package_json = os.path.join(temp_project_dir, 'package.json')
    with open(package_json, 'w') as f:
        json.dump({'name': 'test-project', 'version': '1.0.0'}, f)

    projects = adapter.detect_projects()

    assert len(projects) == 1
    assert projects[0] == Path(temp_project_dir)


def test_detect_multiple_projects(temp_project_dir, threat_db):
    """Test detecting multiple npm projects in subdirectories."""
    adapter = NpmAdapter(threat_db, Path(temp_project_dir))

    # Create multiple package.json files
    for subdir in ['project1', 'project2', 'nested/project3']:
        proj_dir = os.path.join(temp_project_dir, subdir)
        os.makedirs(proj_dir, exist_ok=True)

        package_json = os.path.join(proj_dir, 'package.json')
        with open(package_json, 'w') as f:
            json.dump({'name': subdir.replace('/', '-'), 'version': '1.0.0'}, f)

    projects = adapter.detect_projects()

    assert len(projects) == 3


def test_scan_package_json_exact_match(temp_project_dir, threat_db):
    """Test scanning package.json with exact version match."""
    adapter = NpmAdapter(threat_db, Path(temp_project_dir))

    # Create package.json with vulnerable package
    package_json = os.path.join(temp_project_dir, 'package.json')
    with open(package_json, 'w') as f:
        json.dump({
            'name': 'test-project',
            'version': '1.0.0',
            'dependencies': {
                'left-pad': '1.3.0'
            }
        }, f)

    findings = adapter.scan_project(Path(temp_project_dir))

    assert len(findings) == 1
    assert findings[0].package_name == 'left-pad'
    assert findings[0].version == '1.3.0'
    assert findings[0].finding_type == 'manifest'
    # Bare versions are treated as range matches (valid semver spec)
    assert findings[0].match_type == 'range'


def test_scan_package_json_range_match(temp_project_dir, threat_db):
    """Test scanning package.json with version range."""
    adapter = NpmAdapter(threat_db, Path(temp_project_dir))

    # Create package.json with version range that includes vulnerable version
    package_json = os.path.join(temp_project_dir, 'package.json')
    with open(package_json, 'w') as f:
        json.dump({
            'name': 'test-project',
            'version': '1.0.0',
            'dependencies': {
                'lodash': '^4.17.0'  # Includes 4.17.20
            }
        }, f)

    findings = adapter.scan_project(Path(temp_project_dir))

    assert len(findings) == 1
    assert findings[0].package_name == 'lodash'
    assert findings[0].version == '4.17.20'
    assert findings[0].match_type == 'range'
    assert findings[0].declared_spec == '^4.17.0'


def test_scan_package_json_no_match(temp_project_dir, threat_db):
    """Test scanning package.json with safe packages."""
    adapter = NpmAdapter(threat_db, Path(temp_project_dir))

    package_json = os.path.join(temp_project_dir, 'package.json')
    with open(package_json, 'w') as f:
        json.dump({
            'name': 'test-project',
            'version': '1.0.0',
            'dependencies': {
                'safe-package': '1.0.0',
                'another-safe': '^2.0.0'
            }
        }, f)

    findings = adapter.scan_project(Path(temp_project_dir))

    assert len(findings) == 0


def test_scan_scoped_package(temp_project_dir, threat_db):
    """Test scanning scoped npm packages."""
    adapter = NpmAdapter(threat_db, Path(temp_project_dir))

    package_json = os.path.join(temp_project_dir, 'package.json')
    with open(package_json, 'w') as f:
        json.dump({
            'name': 'test-project',
            'dependencies': {
                '@scope/package': '2.0.0'
            }
        }, f)

    findings = adapter.scan_project(Path(temp_project_dir))

    assert len(findings) == 1
    assert findings[0].package_name == '@scope/package'


def test_scan_dev_dependencies(temp_project_dir, threat_db):
    """Test scanning devDependencies."""
    adapter = NpmAdapter(threat_db, Path(temp_project_dir))

    package_json = os.path.join(temp_project_dir, 'package.json')
    with open(package_json, 'w') as f:
        json.dump({
            'name': 'test-project',
            'devDependencies': {
                'left-pad': '1.3.0'
            }
        }, f)

    findings = adapter.scan_project(Path(temp_project_dir))

    assert len(findings) == 1
    assert findings[0].package_name == 'left-pad'


def test_scan_all_dependency_types(temp_project_dir, threat_db):
    """Test scanning all dependency types (dependencies, devDependencies, etc.)."""
    adapter = NpmAdapter(threat_db, Path(temp_project_dir))

    package_json = os.path.join(temp_project_dir, 'package.json')
    with open(package_json, 'w') as f:
        json.dump({
            'name': 'test-project',
            'dependencies': {'left-pad': '1.3.0'},
            'devDependencies': {'lodash': '4.17.20'},
            'peerDependencies': {'@scope/package': '2.0.0'},
            'optionalDependencies': {'vulnerable-pkg': '1.0.0'}
        }, f)

    findings = adapter.scan_project(Path(temp_project_dir))

    # Should find all 4 vulnerable packages
    assert len(findings) == 4
    package_names = {f.package_name for f in findings}
    assert package_names == {'left-pad', 'lodash', '@scope/package', 'vulnerable-pkg'}


def test_scan_package_lock_json(temp_project_dir, threat_db):
    """Test scanning package-lock.json."""
    adapter = NpmAdapter(threat_db, Path(temp_project_dir))

    # Create package-lock.json (v2/v3 format)
    lock_file = os.path.join(temp_project_dir, 'package-lock.json')
    with open(lock_file, 'w') as f:
        json.dump({
            'name': 'test-project',
            'lockfileVersion': 2,
            'packages': {
                '': {'name': 'test-project'},
                'node_modules/left-pad': {
                    'version': '1.3.0',
                    'resolved': 'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz'
                },
                'node_modules/safe-pkg': {
                    'version': '2.0.0'
                }
            }
        }, f)

    findings = adapter.scan_project(Path(temp_project_dir))

    assert len(findings) == 1
    assert findings[0].package_name == 'left-pad'
    assert findings[0].finding_type == 'lockfile'


def test_scan_package_lock_v1_format(temp_project_dir, threat_db):
    """Test scanning package-lock.json v1 format."""
    adapter = NpmAdapter(threat_db, Path(temp_project_dir))

    lock_file = os.path.join(temp_project_dir, 'package-lock.json')
    with open(lock_file, 'w') as f:
        json.dump({
            'name': 'test-project',
            'lockfileVersion': 1,
            'dependencies': {
                'left-pad': {
                    'version': '1.3.0'
                }
            }
        }, f)

    findings = adapter.scan_project(Path(temp_project_dir))

    assert len(findings) == 1
    assert findings[0].package_name == 'left-pad'


def test_no_duplicate_findings(temp_project_dir, threat_db):
    """Test that same package in manifest and lockfile doesn't create duplicates."""
    adapter = NpmAdapter(threat_db, Path(temp_project_dir))

    # Create both package.json and package-lock.json with same package
    package_json = os.path.join(temp_project_dir, 'package.json')
    with open(package_json, 'w') as f:
        json.dump({
            'name': 'test-project',
            'dependencies': {'left-pad': '1.3.0'}
        }, f)

    lock_file = os.path.join(temp_project_dir, 'package-lock.json')
    with open(lock_file, 'w') as f:
        json.dump({
            'lockfileVersion': 2,
            'packages': {
                'node_modules/left-pad': {'version': '1.3.0'}
            }
        }, f)

    findings = adapter.scan_project(Path(temp_project_dir))

    # Should have 2 findings (one from manifest, one from lockfile)
    assert len(findings) == 2
    finding_types = {f.finding_type for f in findings}
    assert finding_types == {'manifest', 'lockfile'}


def test_invalid_json_handling(temp_project_dir, threat_db, capsys):
    """Test handling of invalid JSON files."""
    adapter = NpmAdapter(threat_db, Path(temp_project_dir))

    # Create invalid package.json
    package_json = os.path.join(temp_project_dir, 'package.json')
    with open(package_json, 'w') as f:
        f.write('{invalid json')

    # Should not crash, just skip the file
    findings = adapter.scan_project(Path(temp_project_dir))
    assert len(findings) == 0


def test_missing_package_json(temp_project_dir, threat_db):
    """Test scanning directory without package.json."""
    adapter = NpmAdapter(threat_db, Path(temp_project_dir))

    findings = adapter.scan_project(Path(temp_project_dir))

    assert len(findings) == 0


def test_version_range_not_matching(temp_project_dir, threat_db):
    """Test that version ranges that don't include vulnerable version are not flagged."""
    adapter = NpmAdapter(threat_db, Path(temp_project_dir))

    package_json = os.path.join(temp_project_dir, 'package.json')
    with open(package_json, 'w') as f:
        json.dump({
            'name': 'test-project',
            'dependencies': {
                'lodash': '^4.18.0'  # Does not include 4.17.20
            }
        }, f)

    findings = adapter.scan_project(Path(temp_project_dir))

    assert len(findings) == 0


def test_multiple_vulnerable_versions(temp_project_dir, threat_db):
    """Test package with multiple vulnerable versions."""
    adapter = NpmAdapter(threat_db, Path(temp_project_dir))

    package_json = os.path.join(temp_project_dir, 'package.json')
    with open(package_json, 'w') as f:
        json.dump({
            'name': 'test-project',
            'dependencies': {
                'vulnerable-pkg': '>=1.0.0 <2.0.0'  # Includes 1.0.0 and 1.0.1
            }
        }, f)

    findings = adapter.scan_project(Path(temp_project_dir))

    # Should report one finding with both versions combined
    assert len(findings) == 1
    finding = findings[0]
    assert finding.package_name == 'vulnerable-pkg'
    # Versions are comma-separated in the version field
    assert finding.version == '1.0.0, 1.0.1'
    # Individual versions are in metadata
    assert finding.metadata['included_versions'] == ['1.0.0', '1.0.1']


def test_get_manifest_files():
    """Test getting list of manifest file names."""
    adapter = NpmAdapter(ThreatDatabase(), Path('.'))
    manifests = adapter.get_manifest_files()

    assert 'package.json' in manifests


def test_get_lockfile_names():
    """Test getting list of lockfile names."""
    adapter = NpmAdapter(ThreatDatabase(), Path('.'))
    lockfiles = adapter.get_lockfile_names()

    assert 'package-lock.json' in lockfiles
    assert 'yarn.lock' in lockfiles
    assert 'pnpm-lock.yaml' in lockfiles
