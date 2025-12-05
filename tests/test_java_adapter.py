"""Unit tests for JavaAdapter."""

import os
import tempfile
from pathlib import Path

import pytest

from package_scan.adapters.java_adapter import JavaAdapter
from package_scan.core.threat_database import ThreatDatabase


@pytest.fixture
def threat_db():
    """Create a threat database with sample Maven packages."""
    db = ThreatDatabase()

    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("ecosystem,name,version\n")
        f.write("maven,org.springframework:spring-core,5.3.0\n")
        f.write("maven,org.apache.logging.log4j:log4j-core,2.14.1\n")
        f.write("maven,com.fasterxml.jackson.core:jackson-databind,2.9.8\n")
        f.write("maven,commons-collections:commons-collections,3.2.1\n")
        temp_path = f.name

    db.load_threats(csv_file=temp_path)
    os.unlink(temp_path)

    return db


@pytest.fixture
def temp_project_dir():
    """Create a temporary project directory."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir

    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_adapter_ecosystem_name(threat_db):
    """Test that adapter returns correct ecosystem name."""
    adapter = JavaAdapter(threat_db, Path('.'))
    assert adapter._get_ecosystem_name() == 'maven'


def test_detect_maven_project(temp_project_dir, threat_db):
    """Test detecting Maven project with pom.xml."""
    adapter = JavaAdapter(threat_db, Path(temp_project_dir))

    pom_xml = os.path.join(temp_project_dir, 'pom.xml')
    with open(pom_xml, 'w') as f:
        f.write('<?xml version="1.0"?><project></project>')

    projects = adapter.detect_projects()

    assert len(projects) == 1
    assert projects[0] == Path(temp_project_dir)


def test_detect_gradle_project(temp_project_dir, threat_db):
    """Test detecting Gradle project with build.gradle."""
    adapter = JavaAdapter(threat_db, Path(temp_project_dir))

    build_gradle = os.path.join(temp_project_dir, 'build.gradle')
    with open(build_gradle, 'w') as f:
        f.write('// Gradle build file')

    projects = adapter.detect_projects()

    assert len(projects) == 1


def test_scan_pom_xml_exact_match(temp_project_dir, threat_db):
    """Test scanning pom.xml with exact version."""
    adapter = JavaAdapter(threat_db, Path(temp_project_dir))

    pom_xml = os.path.join(temp_project_dir, 'pom.xml')
    with open(pom_xml, 'w') as f:
        f.write('''<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-project</artifactId>
    <version>1.0.0</version>

    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.0</version>
        </dependency>
    </dependencies>
</project>''')

    findings = adapter.scan_project(Path(temp_project_dir))

    assert len(findings) == 1
    assert findings[0].package_name == 'org.springframework:spring-core'
    assert findings[0].version == '5.3.0'
    assert findings[0].finding_type == 'manifest'
    assert findings[0].match_type == 'exact'


def test_scan_pom_xml_version_range(temp_project_dir, threat_db):
    """Test scanning pom.xml with Maven version range."""
    adapter = JavaAdapter(threat_db, Path(temp_project_dir))

    pom_xml = os.path.join(temp_project_dir, 'pom.xml')
    with open(pom_xml, 'w') as f:
        f.write('''<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>[5.0,6.0)</version>
        </dependency>
    </dependencies>
</project>''')

    findings = adapter.scan_project(Path(temp_project_dir))

    assert len(findings) == 1
    assert findings[0].version == '5.3.0'
    assert findings[0].match_type == 'range'
    assert findings[0].declared_spec == '[5.0,6.0)'


def test_scan_pom_xml_multiple_dependencies(temp_project_dir, threat_db):
    """Test scanning pom.xml with multiple dependencies."""
    adapter = JavaAdapter(threat_db, Path(temp_project_dir))

    pom_xml = os.path.join(temp_project_dir, 'pom.xml')
    with open(pom_xml, 'w') as f:
        f.write('''<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.0</version>
        </dependency>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>
        </dependency>
        <dependency>
            <groupId>safe.group</groupId>
            <artifactId>safe-artifact</artifactId>
            <version>1.0.0</version>
        </dependency>
    </dependencies>
</project>''')

    findings = adapter.scan_project(Path(temp_project_dir))

    assert len(findings) == 2
    package_names = {f.package_name for f in findings}
    assert 'org.springframework:spring-core' in package_names
    assert 'org.apache.logging.log4j:log4j-core' in package_names


def test_scan_build_gradle_groovy(temp_project_dir, threat_db):
    """Test scanning build.gradle (Groovy DSL)."""
    adapter = JavaAdapter(threat_db, Path(temp_project_dir))

    build_gradle = os.path.join(temp_project_dir, 'build.gradle')
    with open(build_gradle, 'w') as f:
        f.write('''
plugins {
    id 'java'
}

dependencies {
    implementation 'org.springframework:spring-core:5.3.0'
    testImplementation 'org.apache.logging.log4j:log4j-core:2.14.1'
    compile 'safe.group:safe-artifact:1.0.0'
}
''')

    findings = adapter.scan_project(Path(temp_project_dir))

    assert len(findings) == 2
    package_names = {f.package_name for f in findings}
    assert 'org.springframework:spring-core' in package_names
    assert 'org.apache.logging.log4j:log4j-core' in package_names


def test_scan_build_gradle_kotlin(temp_project_dir, threat_db):
    """Test scanning build.gradle.kts (Kotlin DSL)."""
    adapter = JavaAdapter(threat_db, Path(temp_project_dir))

    build_gradle_kts = os.path.join(temp_project_dir, 'build.gradle.kts')
    with open(build_gradle_kts, 'w') as f:
        f.write('''
plugins {
    java
}

dependencies {
    implementation("org.springframework:spring-core:5.3.0")
    testImplementation("commons-collections:commons-collections:3.2.1")
}
''')

    findings = adapter.scan_project(Path(temp_project_dir))

    assert len(findings) == 2


def test_scan_gradle_dynamic_version(temp_project_dir, threat_db):
    """Test scanning Gradle files with dynamic versions."""
    adapter = JavaAdapter(threat_db, Path(temp_project_dir))

    build_gradle = os.path.join(temp_project_dir, 'build.gradle')
    with open(build_gradle, 'w') as f:
        f.write('''
dependencies {
    implementation 'org.springframework:spring-core:5.3.+'
}
''')

    findings = adapter.scan_project(Path(temp_project_dir))

    # Should match 5.3.0 with dynamic version 5.3.+
    assert len(findings) == 1
    assert findings[0].match_type == 'range'


def test_maven_version_range_formats(temp_project_dir, threat_db):
    """Test different Maven version range formats."""
    adapter = JavaAdapter(threat_db, Path(temp_project_dir))

    test_cases = [
        ('[5.3.0]', False),        # Exactly 5.3.0 - not supported (no comma in range)
        ('[5.0,6.0)', True),       # 5.0 <= x < 6.0
        ('[5.3.0,)', True),        # x >= 5.3.0
        ('(,6.0)', True),          # x < 6.0
        ('[6.0,7.0)', False),      # 6.0 <= x < 7.0 (doesn't include 5.3.0)
    ]

    for version_spec, should_match in test_cases:
        pom_xml = os.path.join(temp_project_dir, 'pom.xml')
        with open(pom_xml, 'w') as f:
            f.write(f'''<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>{version_spec}</version>
        </dependency>
    </dependencies>
</project>''')

        findings = adapter.scan_project(Path(temp_project_dir))

        if should_match:
            assert len(findings) == 1, f"Version spec {version_spec} should match"
        else:
            assert len(findings) == 0, f"Version spec {version_spec} should not match"


def test_pom_xml_without_namespace(temp_project_dir, threat_db):
    """Test scanning pom.xml without namespace."""
    adapter = JavaAdapter(threat_db, Path(temp_project_dir))

    pom_xml = os.path.join(temp_project_dir, 'pom.xml')
    with open(pom_xml, 'w') as f:
        f.write('''<?xml version="1.0"?>
<project>
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.0</version>
        </dependency>
    </dependencies>
</project>''')

    findings = adapter.scan_project(Path(temp_project_dir))

    assert len(findings) == 1


def test_invalid_xml_handling(temp_project_dir, threat_db):
    """Test handling of invalid XML."""
    adapter = JavaAdapter(threat_db, Path(temp_project_dir))

    pom_xml = os.path.join(temp_project_dir, 'pom.xml')
    with open(pom_xml, 'w') as f:
        f.write('<invalid><xml')

    # Should not crash
    findings = adapter.scan_project(Path(temp_project_dir))
    assert len(findings) == 0


def test_missing_version_element(temp_project_dir, threat_db):
    """Test handling dependency without version element."""
    adapter = JavaAdapter(threat_db, Path(temp_project_dir))

    pom_xml = os.path.join(temp_project_dir, 'pom.xml')
    with open(pom_xml, 'w') as f:
        f.write('''<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <!-- No version element -->
        </dependency>
    </dependencies>
</project>''')

    # Should skip dependency without version
    findings = adapter.scan_project(Path(temp_project_dir))
    assert len(findings) == 0


def test_get_manifest_files():
    """Test getting list of manifest file names."""
    adapter = JavaAdapter(ThreatDatabase(), Path('.'))
    manifests = adapter.get_manifest_files()

    assert 'pom.xml' in manifests
    assert 'build.gradle' in manifests
    assert 'build.gradle.kts' in manifests


def test_get_lockfile_names():
    """Test getting list of lockfile names."""
    adapter = JavaAdapter(ThreatDatabase(), Path('.'))
    lockfiles = adapter.get_lockfile_names()

    assert 'gradle.lockfile' in lockfiles


def test_gradle_with_quotes_variations(temp_project_dir, threat_db):
    """Test Gradle dependencies with different quote styles."""
    adapter = JavaAdapter(threat_db, Path(temp_project_dir))

    build_gradle = os.path.join(temp_project_dir, 'build.gradle')
    with open(build_gradle, 'w') as f:
        f.write('''
dependencies {
    implementation "org.springframework:spring-core:5.3.0"
    implementation 'org.apache.logging.log4j:log4j-core:2.14.1'
    implementation('com.fasterxml.jackson.core:jackson-databind:2.9.8')
}
''')

    findings = adapter.scan_project(Path(temp_project_dir))

    assert len(findings) == 3


def test_no_dependencies_section(temp_project_dir, threat_db):
    """Test handling pom.xml without dependencies section."""
    adapter = JavaAdapter(threat_db, Path(temp_project_dir))

    pom_xml = os.path.join(temp_project_dir, 'pom.xml')
    with open(pom_xml, 'w') as f:
        f.write('''<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test</artifactId>
</project>''')

    findings = adapter.scan_project(Path(temp_project_dir))
    assert len(findings) == 0
