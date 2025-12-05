"""Unit tests for Finding model."""

from package_scan.core.models import Finding


def test_finding_creation_minimal():
    """Test creating a Finding with minimal required fields."""
    finding = Finding(
        ecosystem='npm',
        finding_type='manifest',
        file_path='/project/package.json',
        package_name='test-package',
        version='1.0.0',
        match_type='exact'
    )

    assert finding.ecosystem == 'npm'
    assert finding.finding_type == 'manifest'
    assert finding.file_path == '/project/package.json'
    assert finding.package_name == 'test-package'
    assert finding.version == '1.0.0'
    assert finding.match_type == 'exact'
    assert finding.declared_spec is None


def test_finding_creation_full():
    """Test creating a Finding with all fields."""
    finding = Finding(
        ecosystem='npm',
        finding_type='manifest',
        file_path='/project/package.json',
        package_name='test-package',
        version='1.0.0',
        match_type='range',
        declared_spec='^1.0.0'
    )

    assert finding.match_type == 'range'
    assert finding.declared_spec == '^1.0.0'


def test_finding_to_dict_minimal():
    """Test converting Finding to dict without optional fields."""
    finding = Finding(
        ecosystem='npm',
        finding_type='lockfile',
        file_path='/project/package-lock.json',
        package_name='lodash',
        version='4.17.20',
        match_type='exact'
    )

    result = finding.to_dict()

    assert result['ecosystem'] == 'npm'
    assert result['finding_type'] == 'lockfile'
    assert result['file_path'] == '/project/package-lock.json'
    assert result['package_name'] == 'lodash'
    assert result['version'] == '4.17.20'
    assert result['match_type'] == 'exact'
    assert 'declared_spec' not in result  # Not included when None


def test_finding_from_legacy_npm_dict():
    """Test converting legacy npm-only dict to Finding."""
    legacy = {
        'type': 'package.json',  # Changed to match actual type mapping
        'file': '/project/package.json',
        'package': 'old-package',
        'version': '0.9.0',
        'version_spec': '^0.9.0'  # Changed from 'declared_version' to match actual implementation
    }

    finding = Finding.from_legacy_npm_dict(legacy)

    assert finding.ecosystem == 'npm'
    assert finding.finding_type == 'manifest'
    assert finding.file_path == '/project/package.json'
    assert finding.package_name == 'old-package'
    assert finding.version == '0.9.0'
    assert finding.declared_spec == '^0.9.0'


def test_finding_from_legacy_lockfile():
    """Test converting legacy lockfile dict to Finding."""
    legacy = {
        'type': 'lockfile',
        'file': '/project/package-lock.json',
        'package': 'locked-pkg',
        'version': '1.2.3'
    }

    finding = Finding.from_legacy_npm_dict(legacy)

    assert finding.ecosystem == 'npm'
    assert finding.finding_type == 'lockfile'
    assert finding.file_path == '/project/package-lock.json'
    assert finding.package_name == 'locked-pkg'
    assert finding.version == '1.2.3'
    assert finding.declared_spec is None


def test_finding_from_legacy_installed():
    """Test converting legacy installed dict to Finding."""
    legacy = {
        'type': 'installed',
        'file': '/project/node_modules/installed-pkg',
        'package': 'installed-pkg',
        'version': '2.0.0'
    }

    finding = Finding.from_legacy_npm_dict(legacy)

    assert finding.finding_type == 'installed'
    assert finding.file_path == '/project/node_modules/installed-pkg'


def test_finding_ecosystems():
    """Test creating findings for different ecosystems."""
    ecosystems = ['npm', 'maven', 'pip', 'gem', 'cargo']

    for ecosystem in ecosystems:
        finding = Finding(
            ecosystem=ecosystem,
            finding_type='manifest',
            file_path=f'/project/{ecosystem}-manifest',
            package_name=f'{ecosystem}-package',
            version='1.0.0',
            match_type='exact'
        )

        assert finding.ecosystem == ecosystem
        assert finding.to_dict()['ecosystem'] == ecosystem


def test_finding_types():
    """Test different finding types."""
    finding_types = ['manifest', 'lockfile', 'installed']

    for ftype in finding_types:
        finding = Finding(
            ecosystem='npm',
            finding_type=ftype,
            file_path=f'/project/{ftype}',
            package_name='test-pkg',
            version='1.0.0',
            match_type='exact'
        )

        assert finding.finding_type == ftype
        assert finding.to_dict()['finding_type'] == ftype


def test_match_types():
    """Test different match types."""
    # Exact match
    finding_exact = Finding(
        ecosystem='npm',
        finding_type='manifest',
        file_path='/project/package.json',
        package_name='exact-pkg',
        version='1.0.0',
        match_type='exact',
        declared_spec='1.0.0'
    )

    assert finding_exact.match_type == 'exact'

    # Range match
    finding_range = Finding(
        ecosystem='npm',
        finding_type='manifest',
        file_path='/project/package.json',
        package_name='range-pkg',
        version='1.5.0',
        match_type='range',
        declared_spec='^1.0.0'
    )

    assert finding_range.match_type == 'range'


def test_scoped_package_names():
    """Test handling scoped package names."""
    # npm scoped package
    finding = Finding(
        ecosystem='npm',
        finding_type='manifest',
        file_path='/project/package.json',
        package_name='@scope/package',
        version='1.0.0',
        match_type='exact'
    )

    assert finding.package_name == '@scope/package'
    assert finding.to_dict()['package_name'] == '@scope/package'

    # Maven package with groupId:artifactId
    finding_maven = Finding(
        ecosystem='maven',
        finding_type='manifest',
        file_path='/project/pom.xml',
        package_name='org.springframework:spring-core',
        version='5.3.0',
        match_type='exact'
    )

    assert finding_maven.package_name == 'org.springframework:spring-core'


def test_relative_paths():
    """Test handling of relative vs absolute paths."""
    # Absolute path
    finding_abs = Finding(
        ecosystem='npm',
        finding_type='manifest',
        file_path='/project/subdir/package.json',
        package_name='pkg',
        version='1.0.0',
        match_type='exact'
    )

    assert finding_abs.file_path == '/project/subdir/package.json'

    # Relative path
    finding_rel = Finding(
        ecosystem='npm',
        finding_type='manifest',
        file_path='subdir/package.json',
        package_name='pkg',
        version='1.0.0',
        match_type='exact'
    )

    assert finding_rel.file_path == 'subdir/package.json'


def test_finding_equality():
    """Test Finding equality comparison."""
    finding1 = Finding(
        ecosystem='npm',
        finding_type='manifest',
        file_path='/project/package.json',
        package_name='pkg',
        version='1.0.0',
        match_type='exact'
    )

    finding2 = Finding(
        ecosystem='npm',
        finding_type='manifest',
        file_path='/project/package.json',
        package_name='pkg',
        version='1.0.0',
        match_type='exact'
    )

    # Dataclasses should be equal if all fields match
    assert finding1 == finding2
