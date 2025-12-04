#!/usr/bin/env python3
"""
NPM Package Threat Scanner
Scans for compromised npm packages known to contain the HULUD worm

CLI usage (after installing the package):

    npm-scan --dir /path/to/project --csv /path/to/sha1-Hulud.csv --output report.json

The command name is "npm-scan" (provided by the console_scripts entry point).
"""

import os
import json
import csv
import sys
import time
from pathlib import Path
from typing import Dict, Set, List, Optional
from collections import defaultdict
import click
from semantic_version import Version, NpmSpec
import re


class ProgressSpinner:
    """Simple spinner for showing scan progress that updates in place"""

    def __init__(self, enabled: bool = True):
        self.frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.current_frame = 0
        self.is_tty = sys.stdout.isatty()
        self.enabled = enabled
        self.last_line_length = 0

    def update(self, message: str):
        """Update the spinner with a new message"""
        if not self.enabled:
            return

        # In non-TTY mode (piped, CI/CD), print each line separately
        if not self.is_tty:
            print(f"  {message}")
            return

        # In TTY mode, show animated spinner with overwriting
        # Clear the line and show spinner with message
        spinner = self.frames[self.current_frame % len(self.frames)]
        self.current_frame += 1

        # Truncate message if too long
        max_length = 100
        if len(message) > max_length:
            message = message[:max_length-3] + "..."

        # Build the full line
        line = f"\r{click.style(spinner, fg='cyan')} {click.style(message, dim=True)}"

        # Pad with spaces to clear any leftover characters from longer previous lines
        # Calculate visible length (without ANSI codes)
        visible_length = len(spinner) + 1 + len(message)  # spinner + space + message
        if visible_length < self.last_line_length:
            line += " " * (self.last_line_length - visible_length)

        self.last_line_length = visible_length

        # Write spinner and message, overwriting previous line
        sys.stdout.write(line)
        sys.stdout.flush()

    def clear(self):
        """Clear the spinner line"""
        if not self.is_tty or self.last_line_length == 0:
            return

        # Clear the entire line
        sys.stdout.write("\r" + " " * self.last_line_length + "\r")
        sys.stdout.flush()
        self.last_line_length = 0


class HuludScanner:
    def __init__(self, csv_file: str, scan_dir: str = None):
        """Initialize scanner with the compromised packages CSV file"""
        self.csv_file = csv_file
        self.scan_dir = scan_dir
        self.compromised_packages: Dict[str, Set[str]] = defaultdict(set)
        self.findings: List[Dict] = []
        self.spinner = ProgressSpinner()

    def load_compromised_packages(self):
        """Load compromised packages from CSV file"""
        try:
            with open(self.csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    package_name = row['Package Name'].strip()
                    version = row['Version'].strip()
                    self.compromised_packages[package_name].add(version)

            count = len(self.compromised_packages)
            print(click.style(f"✓ Loaded {count} compromised packages from threat database", fg='green', bold=True))
            return True
        except FileNotFoundError:
            print(click.style(f"✗ Error: CSV file not found: {self.csv_file}", fg='red', bold=True))
            return False
        except Exception as e:
            print(click.style(f"✗ Error loading CSV: {e}", fg='red', bold=True))
            return False

    def check_package_json(self, file_path: str):
        """Check a package.json file for compromised packages"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                package_data = json.load(f)

            # Check all dependency types
            dep_types = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']

            for dep_type in dep_types:
                if dep_type in package_data:
                    for package_name, version_spec in package_data[dep_type].items():
                        if package_name in self.compromised_packages:
                            # Attempt to parse npm semver range; skip if not a valid semver range (e.g., git/file deps)
                            try:
                                spec = NpmSpec(str(version_spec))
                            except Exception:
                                # Not a standard semver spec; fall back to exact match check by stripping operators
                                clean_version = str(version_spec).lstrip('^~>=<')
                                if clean_version in self.compromised_packages[package_name]:
                                    remediation = self._suggest_remediation_exact(clean_version)
                                    self.findings.append({
                                        'type': 'package.json',
                                        'file': file_path,
                                        'package': package_name,
                                        'version': clean_version,
                                        'version_spec': version_spec,
                                        'dependency_type': dep_type,
                                        'match_type': 'exact',
                                        'remediation': remediation
                                    })
                                continue

                            included_versions: List[str] = []
                            for compromised_version in self.compromised_packages[package_name]:
                                try:
                                    v = Version.coerce(compromised_version)
                                except Exception:
                                    continue
                                if v in spec:
                                    included_versions.append(compromised_version)

                            if included_versions:
                                remediation = self._suggest_remediation_range(version_spec, included_versions)
                                self.findings.append({
                                    'type': 'package.json',
                                    'file': file_path,
                                    'package': package_name,
                                    'version': ", ".join(sorted(included_versions)),
                                    'version_spec': version_spec,
                                    'dependency_type': dep_type,
                                    'included_versions': sorted(included_versions),
                                    'match_type': 'range',
                                    'remediation': remediation
                                })
        except json.JSONDecodeError:
            print(f"[!] Warning: Invalid JSON in {file_path}")
        except Exception as e:
            print(f"[!] Error reading {file_path}: {e}")

    def check_node_modules(self, node_modules_path: str):
        """Check installed packages in node_modules directory"""
        try:
            items = os.listdir(node_modules_path)
            for idx, item in enumerate(items):
                item_path = os.path.join(node_modules_path, item)

                # Update spinner with progress
                progress = f"[{idx+1}/{len(items)}]"
                self.spinner.update(f"{progress} Scanning {node_modules_path}/{item}")

                # Handle scoped packages (@org/package)
                if item.startswith('@') and os.path.isdir(item_path):
                    for scoped_package in os.listdir(item_path):
                        scoped_path = os.path.join(item_path, scoped_package)
                        if os.path.isdir(scoped_path):
                            package_name = f"{item}/{scoped_package}"
                            self._check_installed_package(scoped_path, package_name, node_modules_path)
                elif os.path.isdir(item_path):
                    self._check_installed_package(item_path, item, node_modules_path)
        except PermissionError:
            print(f"[!] Warning: Permission denied accessing {node_modules_path}")
        except Exception as e:
            print(f"[!] Error scanning {node_modules_path}: {e}")

    def _check_installed_package(self, package_path: str, package_name: str, node_modules_path: str):
        """Check if an installed package is compromised"""
        if package_name not in self.compromised_packages:
            return

        package_json_path = os.path.join(package_path, 'package.json')
        if not os.path.exists(package_json_path):
            return

        try:
            with open(package_json_path, 'r', encoding='utf-8') as f:
                package_data = json.load(f)

            installed_version = package_data.get('version', 'unknown')

            if installed_version in self.compromised_packages[package_name]:
                self.findings.append({
                    'type': 'installed',
                    'location': node_modules_path,
                    'package': package_name,
                    'version': installed_version,
                    'package_path': package_path,
                    'match_type': 'exact',
                    'remediation': {
                        'strategy': 'upgrade_or_override',
                        'suggested_spec': f">={self._next_patch(installed_version)}" if self._next_patch(installed_version) else None,
                        'note': 'Update to a patched version above the compromised one and/or use npm/yarn/pnpm overrides/resolutions to force a safe version. Run a full test cycle.'
                    }
                })
        except Exception as e:
            print(f"[!] Error checking {package_json_path}: {e}")

    def check_package_lock_json(self, lock_file_path: str):
        """Check package-lock.json (npm) for compromised packages"""
        try:
            with open(lock_file_path, 'r', encoding='utf-8') as f:
                lock_data = json.load(f)

            # npm v1/v2 uses "dependencies" at root, npm v3+ uses "packages"
            packages_to_check = {}

            # Handle lockfileVersion 3+ (npm v7+)
            if 'packages' in lock_data:
                for package_path, package_info in lock_data['packages'].items():
                    if not package_path:  # Root package
                        continue
                    # Remove "node_modules/" prefix
                    package_name = package_path.replace('node_modules/', '')
                    version = package_info.get('version')
                    if version:
                        packages_to_check[package_name] = version

            # Handle lockfileVersion 1/2 (older npm)
            elif 'dependencies' in lock_data:
                self._extract_lock_v1_dependencies(lock_data['dependencies'], packages_to_check)

            # Check for compromised packages
            for package_name, version in packages_to_check.items():
                if package_name in self.compromised_packages:
                    if version in self.compromised_packages[package_name]:
                        self.findings.append({
                            'type': 'lockfile',
                            'lockfile_type': 'package-lock.json',
                            'file': lock_file_path,
                            'package': package_name,
                            'version': version,
                            'match_type': 'exact',
                            'remediation': {
                                'strategy': 'upgrade_and_update_lockfile',
                                'suggested_spec': f">={self._next_patch(version)}" if self._next_patch(version) else None,
                                'note': 'Update the parent package.json to exclude this version, delete lock file and node_modules, then run npm install to regenerate.'
                            }
                        })
        except json.JSONDecodeError:
            print(f"[!] Warning: Invalid JSON in {lock_file_path}")
        except Exception as e:
            print(f"[!] Error reading {lock_file_path}: {e}")

    def _extract_lock_v1_dependencies(self, deps: dict, output: dict, prefix: str = ""):
        """Recursively extract dependencies from npm lock v1/v2 format"""
        for name, info in deps.items():
            full_name = f"{prefix}{name}" if prefix else name
            version = info.get('version')
            if version:
                output[full_name] = version
            # Recurse into nested dependencies
            if 'dependencies' in info:
                self._extract_lock_v1_dependencies(info['dependencies'], output, f"{full_name}/node_modules/")

    def check_yarn_lock(self, lock_file_path: str):
        """Check yarn.lock for compromised packages"""
        try:
            with open(lock_file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Yarn lock format:
            # package-name@^1.0.0, package-name@^1.2.0:
            #   version "1.2.3"
            #   resolved "..."

            # Pattern to match package entries
            # Matches: "package-name@version-range:" or package-name@version-range:
            package_pattern = re.compile(r'^["\']?([^@\s]+)@[^:]+:?\s*$', re.MULTILINE)
            version_pattern = re.compile(r'^\s+version\s+"([^"]+)"', re.MULTILINE)

            lines = content.split('\n')
            i = 0
            while i < len(lines):
                line = lines[i]
                # Check if this line starts a package entry
                # Yarn lock entries can be: "package@range:", package@range:, or "@scope/package@range:"
                if '@' in line and ':' in line and not line.strip().startswith('#'):
                    # Extract package name (handle multiple names on same line, scoped packages)
                    # Format: "package@1.0.0", "package@^1.0.0", "@scope/package@1.0.0":
                    pkg_match = re.search(r'["\']?(@?[^@"\s]+)@', line)
                    if pkg_match:
                        package_name = pkg_match.group(1)

                        # Look ahead for version line
                        j = i + 1
                        while j < len(lines) and j < i + 10:  # Look up to 10 lines ahead
                            version_match = version_pattern.match(lines[j])
                            if version_match:
                                version = version_match.group(1)

                                if package_name in self.compromised_packages:
                                    if version in self.compromised_packages[package_name]:
                                        self.findings.append({
                                            'type': 'lockfile',
                                            'lockfile_type': 'yarn.lock',
                                            'file': lock_file_path,
                                            'package': package_name,
                                            'version': version,
                                            'match_type': 'exact',
                                            'remediation': {
                                                'strategy': 'upgrade_and_update_lockfile',
                                                'suggested_spec': f">={self._next_patch(version)}" if self._next_patch(version) else None,
                                                'note': 'Update the parent package.json to exclude this version, delete yarn.lock and node_modules, then run yarn install to regenerate.'
                                            }
                                        })
                                break
                            # Stop if we hit a blank line or next package entry
                            if not lines[j].strip() or ('@' in lines[j] and ':' in lines[j]):
                                break
                            j += 1
                i += 1

        except Exception as e:
            print(f"[!] Error reading {lock_file_path}: {e}")

    def check_pnpm_lock_yaml(self, lock_file_path: str):
        """Check pnpm-lock.yaml for compromised packages"""
        try:
            # Try to import yaml, but make it optional
            try:
                import yaml
            except ImportError:
                print(f"[!] Warning: PyYAML not installed, skipping {lock_file_path}")
                print(f"[!] Install with: pip install pyyaml")
                return

            with open(lock_file_path, 'r', encoding='utf-8') as f:
                lock_data = yaml.safe_load(f)

            if not lock_data:
                return

            # pnpm v6+ uses 'packages' key
            packages = lock_data.get('packages', {})

            for package_key, package_info in packages.items():
                # Package key format: /package-name/1.2.3 or /@scope/package-name/1.2.3
                # Extract name and version
                match = re.match(r'^/(@?[^/]+(?:/[^/]+)?)/(.+?)(?:_|$)', package_key)
                if match:
                    package_name = match.group(1)
                    version = match.group(2)

                    if package_name in self.compromised_packages:
                        if version in self.compromised_packages[package_name]:
                            self.findings.append({
                                'type': 'lockfile',
                                'lockfile_type': 'pnpm-lock.yaml',
                                'file': lock_file_path,
                                'package': package_name,
                                'version': version,
                                'match_type': 'exact',
                                'remediation': {
                                    'strategy': 'upgrade_and_update_lockfile',
                                    'suggested_spec': f">={self._next_patch(version)}" if self._next_patch(version) else None,
                                    'note': 'Update the parent package.json to exclude this version, delete pnpm-lock.yaml and node_modules, then run pnpm install to regenerate.'
                                }
                            })
        except Exception as e:
            print(f"[!] Error reading {lock_file_path}: {e}")

    def scan_directory(self, root_dir: str):
        """Recursively scan directory tree for package.json, lock files, and node_modules"""
        print(click.style(f"\n🔍 Scanning for compromised packages...", fg='cyan', bold=True))
        print()  # Extra line for spinner to use

        files_scanned = 0
        directories_scanned = 0

        for dirpath, dirnames, filenames in os.walk(root_dir):
            # Check for package.json files
            if 'package.json' in filenames:
                package_json_path = os.path.join(dirpath, 'package.json')
                self.spinner.update(f"  Checking {package_json_path}")
                self.check_package_json(package_json_path)
                files_scanned += 1

            # Check for lock files
            if 'package-lock.json' in filenames:
                lock_path = os.path.join(dirpath, 'package-lock.json')
                self.spinner.update(f"  Checking {lock_path}")
                self.check_package_lock_json(lock_path)
                files_scanned += 1

            if 'yarn.lock' in filenames:
                lock_path = os.path.join(dirpath, 'yarn.lock')
                self.spinner.update(f"  Checking {lock_path}")
                self.check_yarn_lock(lock_path)
                files_scanned += 1

            if 'pnpm-lock.yaml' in filenames:
                lock_path = os.path.join(dirpath, 'pnpm-lock.yaml')
                self.spinner.update(f"  Checking {lock_path}")
                self.check_pnpm_lock_yaml(lock_path)
                files_scanned += 1

            # Check for node_modules directories
            if 'node_modules' in dirnames:
                node_modules_path = os.path.join(dirpath, 'node_modules')
                self.spinner.update(f"Scanning {node_modules_path}")
                self.check_node_modules(node_modules_path)
                directories_scanned += 1
                # Don't recurse into node_modules to avoid nested scanning
                dirnames.remove('node_modules')

        # Clear spinner and show completion
        self.spinner.clear()

        # Build summary message
        summary_parts = []
        if files_scanned > 0:
            summary_parts.append(f"{files_scanned} file(s)")
        if directories_scanned > 0:
            summary_parts.append(f"{directories_scanned} directory(s)")

        summary = ", ".join(summary_parts) if summary_parts else "0 files"
        print(click.style(f"✓ Scan complete: checked {summary}", fg='green'))

    def print_report(self):
        """Print scan results"""
        print("\n" + click.style("=" * 80, fg='white', bold=True))
        print(click.style("SCAN REPORT", fg='white', bold=True))
        print(click.style("=" * 80, fg='white', bold=True))

        if not self.findings:
            print(click.style("\n✓ No compromised packages found!", fg='green', bold=True))
            print(click.style("   Your project appears clean.\n", fg='green'))
            return

        # Show findings count with high impact
        count = len(self.findings)
        print(click.style(f"\n⚠️  THREAT DETECTED: ", fg='red', bold=True) +
              click.style(f"Found {count} compromised package reference(s)\n", fg='yellow', bold=True))

        # Group findings by type
        package_json_findings = [f for f in self.findings if f['type'] == 'package.json']
        lockfile_findings = [f for f in self.findings if f['type'] == 'lockfile']
        installed_findings = [f for f in self.findings if f['type'] == 'installed']

        if package_json_findings:
            print(click.style("─" * 80, fg='yellow'))
            print(click.style("📄 PACKAGE.JSON FILES WITH COMPROMISED DEPENDENCIES:", fg='yellow', bold=True))
            print(click.style("─" * 80, fg='yellow'))
            for finding in package_json_findings:
                print(f"\n  File: {finding['file']}")
                print(f"  Package: " + click.style(f"{finding['package']}@{finding['version']}", fg='red', bold=True))
                print(f"  Version Spec: {finding['version_spec']}")
                print(f"  Dependency Type: {finding['dependency_type']}")
                if 'match_type' in finding:
                    print(f"  Match Type: {finding['match_type']}")
                if 'remediation' in finding and finding['remediation']:
                    rem = finding['remediation']
                    print(click.style("  Remediation:", fg='cyan'))
                    print(f"    - strategy: {rem.get('strategy')}")
                    if rem.get('suggested_spec'):
                        print(f"    - suggested_spec: " + click.style(rem.get('suggested_spec'), fg='green', bold=True))

        if lockfile_findings:
            print("\n" + click.style("─" * 80, fg='red'))
            print(click.style("🔒 LOCK FILES WITH COMPROMISED PACKAGES:", fg='red', bold=True))
            print(click.style("─" * 80, fg='red'))
            for finding in lockfile_findings:
                print(f"\n  File: {finding['file']}")
                print(f"  Lock File Type: {finding['lockfile_type']}")
                print(f"  Package: " + click.style(f"{finding['package']}@{finding['version']}", fg='red', bold=True))
                if 'match_type' in finding:
                    print(f"  Match Type: {finding['match_type']}")
                if 'remediation' in finding and finding['remediation']:
                    rem = finding['remediation']
                    print(click.style("  Remediation:", fg='cyan'))
                    print(f"    - strategy: {rem.get('strategy')}")
                    if rem.get('suggested_spec'):
                        print(f"    - suggested_spec: " + click.style(rem.get('suggested_spec'), fg='green', bold=True))

        if installed_findings:
            print("\n" + click.style("─" * 80, fg='red'))
            print(click.style("📦 INSTALLED COMPROMISED PACKAGES (in node_modules):", fg='red', bold=True))
            print(click.style("─" * 80, fg='red'))
            for finding in installed_findings:
                print(f"\n  Location: {finding['location']}")
                print(f"  Package: " + click.style(f"{finding['package']}@{finding['version']}", fg='red', bold=True))
                print(f"  Path: {finding['package_path']}")
                if 'remediation' in finding and finding['remediation']:
                    rem = finding['remediation']
                    print(click.style("  Remediation:", fg='cyan'))
                    print(f"    - strategy: {rem.get('strategy')}")
                    if rem.get('suggested_spec'):
                        print(f"    - suggested_spec: " + click.style(rem.get('suggested_spec'), fg='green', bold=True))

        print("\n" + click.style("=" * 80, fg='white', bold=True))
        print(click.style(f"Total findings: ", fg='white', bold=True) +
              click.style(f"{len(self.findings)}", fg='red', bold=True))
        print(click.style("=" * 80, fg='white', bold=True))
        # Print a single remediation summary note at the end
        if self.findings:
            exact_count = sum(1 for f in self.findings if f.get('match_type') == 'exact')
            range_count = sum(1 for f in self.findings if f.get('match_type') == 'range')
            unique_pkgs = sorted({f.get('package') for f in self.findings})

            print("\n" + click.style("📊 Remediation Summary:", fg='cyan', bold=True))
            print("   The scan detected the following compromised dependency references:")
            print(f"   • Exact version matches: " + click.style(str(exact_count), fg='red', bold=True))
            print(f"   • Semver range matches: " + click.style(str(range_count), fg='yellow', bold=True))
            print(f"   • Unique affected packages: " + click.style(str(len(unique_pkgs)), fg='magenta', bold=True))
            # Provide general guidance
            print("\n" + click.style("💡 Suggested Actions:", fg='cyan', bold=True))
            if range_count:
                print(click.style("   • For range matches:", fg='yellow') + " raise the minimum allowed version to a patched release that excludes all compromised versions (e.g., '>=X.Y.Z').")
            if exact_count:
                print(click.style("   • For exact matches:", fg='red') + " upgrade to at least the next patched version.")
            print(click.style("   • Package manager overrides:", fg='cyan') + " If you cannot change your declared ranges, use package manager overrides to force a safe version:")
            print("       - npm:   package.json → " + click.style('"overrides"', fg='green'))
            print("       - yarn:  package.json → " + click.style('"resolutions"', fg='green'))
            print("       - pnpm:  package.json → " + click.style('"pnpm.overrides"', fg='green'))
            print(click.style("   • After changes:", fg='cyan') + " run a full install and test cycle.\n")

    def save_report(self, output_file: str = "package_scan_report.json", relative_paths: bool = False):
        """Save findings to JSON file"""
        try:
            # Prepare findings for JSON without verbose per-finding remediation notes
            sanitized: List[Dict] = []
            for fnd in self.findings:
                f_copy = dict(fnd)

                # Convert absolute paths to relative if requested
                if relative_paths and self.scan_dir:
                    scan_dir_abs = os.path.abspath(self.scan_dir)
                    for path_field in ['file', 'location', 'package_path']:
                        if path_field in f_copy:
                            abs_path = f_copy[path_field]
                            # Convert to relative path
                            try:
                                rel_path = os.path.relpath(abs_path, scan_dir_abs)
                                # Use ./ prefix for clarity
                                if not rel_path.startswith('..'):
                                    f_copy[path_field] = './' + rel_path if not rel_path.startswith('.') else rel_path
                            except (ValueError, TypeError):
                                # If conversion fails, keep absolute path
                                pass

                # If remediation exists, drop only the 'note' field as requested
                if 'remediation' in f_copy and isinstance(f_copy['remediation'], dict):
                    rem = dict(f_copy['remediation'])
                    rem.pop('note', None)
                    f_copy['remediation'] = rem
                sanitized.append(f_copy)

            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'total_findings': len(self.findings),
                    'findings': sanitized
                }, f, indent=2)
        except Exception as e:
            print(click.style(f"✗ Error saving report: {e}", fg='red', bold=True))

    # --- Remediation helpers ---
    def _next_patch(self, version_str: str):
        try:
            v = Version.coerce(version_str)
            # bump patch, drop pre-release/build
            bumped = Version(f"{v.major}.{v.minor}.{(v.patch or 0) + 1}")
            return str(bumped)
        except Exception:
            return None

    def _suggest_remediation_exact(self, compromised_version: str) -> Dict:
        next_patch = self._next_patch(compromised_version)
        return {
            'strategy': 'raise_minimum',
            'suggested_spec': f">={next_patch}" if next_patch else None,
            'note': 'Change the dependency version to a patched release above the compromised one. If using ranges with caret/tilde, bump accordingly. Consider using overrides/resolutions to force a safe version.'
        }

    def _suggest_remediation_range(self, original_spec: str, included_versions: List[str]) -> Dict:
        # pick highest compromised version and propose next patch as new lower bound
        try:
            highest = max((Version.coerce(v) for v in included_versions))
            next_patch = Version(f"{highest.major}.{highest.minor}.{(highest.patch or 0) + 1}")
            suggested = f">={next_patch}"
            note = (
                "The declared range includes compromised versions. Consider raising the minimum "
                "requirement to a patched version that excludes them, or explicitly pin to a "
                "known-safe version. If you cannot change the app range, use package manager overrides "
                "(npm overrides / yarn resolutions / pnpm overrides) to force a safe version."
            )
            return {
                'strategy': 'raise_minimum',
                'suggested_spec': suggested,
                'note': note,
                'affected_versions': sorted(included_versions)
            }
        except Exception:
            return {
                'strategy': 'manual_review',
                'suggested_spec': None,
                'note': 'Unable to compute an automatic safe range. Manually exclude the listed versions by upgrading to a patched release or using overrides.'
            }


@click.command(name="npm-scan", help="Scan a directory for compromised npm packages (HULUD worm list)")
@click.option(
    "--dir",
    "scan_dir",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=str),
    default=lambda: os.getcwd(),
    show_default="current working directory",
    help="Root directory to scan recursively",
)
@click.option(
    "--csv",
    "csv_file",
    type=click.Path(exists=False, file_okay=True, dir_okay=False, path_type=str),
    default=None,
    help="Path to CSV containing compromised packages (default: ./sha1-Hulud.csv or /app/sha1-Hulud.csv)",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(writable=True, dir_okay=False, path_type=str),
    default="package_scan_report.json",
    show_default=True,
    help="File to write JSON report",
)
@click.option("--no-save", is_flag=True, help="Do not write JSON report to disk")
@click.option("--output-relative-paths", is_flag=True, help="Use relative paths in JSON output (auto-enabled in Docker)")
@click.option("--list-affected-packages", is_flag=True, help="Display the list of compromised packages from the threat database and exit")
@click.option("--list-affected-packages-csv", is_flag=True, help="Output the threat database as raw CSV to stdout and exit")
def cli(scan_dir: str, csv_file: str, output_file: str, no_save: bool, output_relative_paths: bool, list_affected_packages: bool, list_affected_packages_csv: bool):
    """Entry point for the npm-scan CLI."""
    import sys

    # Resolve CSV path early for CSV dump mode
    if list_affected_packages_csv:
        # Resolve CSV path with smart defaults
        if csv_file is None:
            csv_candidates = [
                os.path.join(os.getcwd(), 'sha1-Hulud.csv'),
                '/app/sha1-Hulud.csv',
                os.path.join(os.path.abspath(scan_dir), 'sha1-Hulud.csv'),
            ]
            csv_file = next((path for path in csv_candidates if os.path.exists(path)), csv_candidates[0])

        resolved_csv = csv_file if os.path.isabs(csv_file) else os.path.abspath(csv_file)

        # Output raw CSV to stdout and exit (no formatting, no banner)
        try:
            with open(resolved_csv, 'r', encoding='utf-8') as f:
                sys.stdout.write(f.read())
            sys.exit(0)
        except FileNotFoundError:
            print(click.style(f"✗ Error: Threat database not found: {resolved_csv}", fg='red', bold=True), file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(click.style(f"✗ Error reading threat database: {e}", fg='red', bold=True), file=sys.stderr)
            sys.exit(1)

    # Normal mode: print banner
    print(click.style("=" * 80, fg='cyan', bold=True))
    print(click.style("🛡️  NPM Package Threat Scanner - HULUD Worm Detection", fg='cyan', bold=True))
    print(click.style("=" * 80, fg='cyan', bold=True))

    # Resolve paths
    scan_dir = os.path.abspath(scan_dir)
    if not os.path.isdir(scan_dir):
        click.echo(click.style(f"✗ Error: Directory not found: {scan_dir}", fg='red', bold=True))
        sys.exit(1)

    # Resolve CSV path with smart defaults
    if csv_file is None:
        # Try multiple default locations
        csv_candidates = [
            os.path.join(os.getcwd(), 'sha1-Hulud.csv'),  # Current directory
            '/app/sha1-Hulud.csv',  # Docker app directory
            os.path.join(scan_dir, 'sha1-Hulud.csv'),  # Scan directory
        ]
        csv_file = next((path for path in csv_candidates if os.path.exists(path)), csv_candidates[0])

    resolved_csv = csv_file
    if not os.path.isabs(resolved_csv):
        resolved_csv = os.path.abspath(resolved_csv)
    if not os.path.exists(resolved_csv):
        alt = os.path.join(scan_dir, os.path.basename(csv_file))
        if os.path.exists(alt):
            resolved_csv = alt

    # Handle --list-affected-packages flag (formatted display)
    if list_affected_packages:
        print(f"\n" + click.style("Threat Database: ", bold=True) + f"{resolved_csv}\n")

        try:
            with open(resolved_csv, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                packages = []
                for row in reader:
                    package_name = row.get('Package Name', '').strip()
                    version = row.get('Version', '').strip()
                    if package_name and version:
                        packages.append((package_name, version))

            if not packages:
                print(click.style("✗ No packages found in threat database", fg='red', bold=True))
                sys.exit(1)

            # Group by package name for cleaner display
            by_package = defaultdict(list)
            for pkg, ver in packages:
                by_package[pkg].append(ver)

            print(click.style("=" * 80, fg='yellow', bold=True))
            print(click.style("⚠️  COMPROMISED PACKAGES IN THREAT DATABASE", fg='yellow', bold=True))
            print(click.style("=" * 80, fg='yellow', bold=True))
            print(f"\nTotal: {click.style(str(len(packages)), fg='red', bold=True)} compromised package versions")
            print(f"Unique packages: {click.style(str(len(by_package)), fg='red', bold=True)}\n")

            # Display grouped by package
            for pkg_name in sorted(by_package.keys()):
                versions = sorted(by_package[pkg_name])
                print(f"  {click.style(pkg_name, fg='red', bold=True)}")
                for ver in versions:
                    print(f"    └─ {ver}")

            print(f"\n" + click.style("=" * 80, fg='yellow', bold=True))
            sys.exit(0)

        except FileNotFoundError:
            print(click.style(f"✗ Error: Threat database not found: {resolved_csv}", fg='red', bold=True))
            sys.exit(1)
        except Exception as e:
            print(click.style(f"✗ Error reading threat database: {e}", fg='red', bold=True))
            sys.exit(1)

    print(f"\n" + click.style("Scan Directory: ", bold=True) + f"{scan_dir}")
    print(click.style("Threat Database: ", bold=True) + f"{resolved_csv}\n")

    # Initialize and run scanner
    scanner = HuludScanner(resolved_csv, scan_dir)

    if not scanner.load_compromised_packages():
        sys.exit(1)

    scanner.scan_directory(scan_dir)
    scanner.print_report()
    if not no_save:
        # Convert to absolute path for clarity
        absolute_output = os.path.abspath(output_file)
        scanner.save_report(absolute_output, relative_paths=output_relative_paths)
        print(click.style(f"✓ Report saved to: {absolute_output}", fg='green', bold=True))


if __name__ == "__main__":
    # Allow running as a module or script
    cli()
