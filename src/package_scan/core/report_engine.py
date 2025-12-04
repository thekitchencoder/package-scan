"""Report generation engine for multi-ecosystem threat scanning"""

import json
import os
from typing import List, Dict, Optional
from pathlib import Path
from collections import defaultdict
import click

from .models import Finding


class ReportEngine:
    """
    Aggregates findings from all adapters and generates reports

    Supports:
    - Console output with colored formatting
    - JSON export with optional relative paths
    - Multi-ecosystem grouping
    """

    def __init__(self, scan_dir: Optional[str] = None):
        """
        Initialize report engine

        Args:
            scan_dir: Root directory that was scanned (for relative path conversion)
        """
        self.scan_dir = Path(scan_dir) if scan_dir else None
        self.findings: List[Finding] = []
        self.threats: List[str] = []  # Track which threats were scanned

    def add_finding(self, finding: Finding):
        """Add a single finding"""
        self.findings.append(finding)

    def add_findings(self, findings: List[Finding]):
        """Add multiple findings"""
        self.findings.extend(findings)

    def set_threats(self, threats: List[str]):
        """Set the list of threats that were scanned"""
        self.threats = threats.copy()

    def clear(self):
        """Clear all findings and threats"""
        self.findings.clear()
        self.threats.clear()

    def get_findings_count(self) -> int:
        """Get total number of findings"""
        return len(self.findings)

    def get_ecosystems(self) -> List[str]:
        """Get list of ecosystems with findings"""
        return sorted(set(f.ecosystem for f in self.findings))

    def _generate_summary(self) -> dict:
        """
        Generate summary statistics for all ecosystems

        Returns:
            Dictionary mapping ecosystem names to summary stats
        """
        ecosystem_summary = {}
        for ecosystem in self.get_ecosystems():
            ecosystem_findings = [f for f in self.findings if f.ecosystem == ecosystem]
            ecosystem_summary[ecosystem] = {
                'total': len(ecosystem_findings),
                'manifest': sum(1 for f in ecosystem_findings if f.finding_type == 'manifest'),
                'lockfile': sum(1 for f in ecosystem_findings if f.finding_type == 'lockfile'),
                'installed': sum(1 for f in ecosystem_findings if f.finding_type == 'installed'),
                'unique_packages': len(set(f.package_name for f in ecosystem_findings))
            }
        return ecosystem_summary

    def print_report(self):
        """Print formatted console report"""
        click.echo("\n" + click.style("=" * 80, fg='white', bold=True))
        click.echo(click.style("SCAN REPORT", fg='white', bold=True))
        click.echo(click.style("=" * 80, fg='white', bold=True))

        # Show which threats were scanned
        if self.threats:
            threat_list = ', '.join(self.threats)
            click.echo(click.style(f"🔎 Scanned for threats: {threat_list}", fg='cyan', bold=True))

        if not self.findings:
            click.echo(click.style("\n✓ No compromised packages found!", fg='green', bold=True))
            click.echo(click.style("   Your project appears clean.\n", fg='green'))
            return

        # Show findings count with high impact
        count = len(self.findings)
        click.echo(click.style(f"\n⚠️  THREAT DETECTED: ", fg='red', bold=True) +
                  click.style(f"Found {count} compromised package reference(s)\n", fg='yellow', bold=True))

        # Group findings by ecosystem
        ecosystems = self.get_ecosystems()

        if len(ecosystems) > 1:
            click.echo(click.style(f"📦 Multiple ecosystems affected: {', '.join(ecosystems)}\n", fg='magenta', bold=True))

        for ecosystem in ecosystems:
            ecosystem_findings = [f for f in self.findings if f.ecosystem == ecosystem]
            self._print_ecosystem_report(ecosystem, ecosystem_findings)

        # Print overall summary
        self._print_summary()

    def _print_ecosystem_report(self, ecosystem: str, findings: List[Finding]):
        """Print findings for a specific ecosystem"""
        click.echo(click.style("─" * 80, fg='cyan'))
        click.echo(click.style(f"🔍 ECOSYSTEM: {ecosystem.upper()}", fg='cyan', bold=True))
        click.echo(click.style("─" * 80, fg='cyan'))
        click.echo(click.style(f"   {len(findings)} finding(s)\n", fg='cyan', dim=True))

        # Group by finding type
        manifest_findings = [f for f in findings if f.finding_type == 'manifest']
        lockfile_findings = [f for f in findings if f.finding_type == 'lockfile']
        installed_findings = [f for f in findings if f.finding_type == 'installed']

        if manifest_findings:
            click.echo(click.style("─" * 80, fg='yellow'))
            click.echo(click.style(f"📄 MANIFEST FILES ({len(manifest_findings)}):", fg='yellow', bold=True))
            click.echo(click.style("─" * 80, fg='yellow'))
            for finding in manifest_findings:
                self._print_finding(finding)

        if lockfile_findings:
            click.echo("\n" + click.style("─" * 80, fg='red'))
            click.echo(click.style(f"🔒 LOCK FILES ({len(lockfile_findings)}):", fg='red', bold=True))
            click.echo(click.style("─" * 80, fg='red'))
            for finding in lockfile_findings:
                self._print_finding(finding)

        if installed_findings:
            click.echo("\n" + click.style("─" * 80, fg='red'))
            click.echo(click.style(f"📦 INSTALLED PACKAGES ({len(installed_findings)}):", fg='red', bold=True))
            click.echo(click.style("─" * 80, fg='red'))
            for finding in installed_findings:
                self._print_finding(finding)

        click.echo()  # Extra newline

    def _print_finding(self, finding: Finding):
        """Print a single finding"""
        click.echo(f"\n  File: {finding.file_path}")
        click.echo(f"  Package: " + click.style(f"{finding.package_name}@{finding.version}", fg='red', bold=True))

        if finding.declared_spec:
            click.echo(f"  Version Spec: {finding.declared_spec}")

        if finding.dependency_type:
            click.echo(f"  Dependency Type: {finding.dependency_type}")

        click.echo(f"  Match Type: {finding.match_type}")

        # Print ecosystem-specific metadata
        if finding.metadata:
            if 'lockfile_type' in finding.metadata:
                click.echo(f"  Lock File Type: {finding.metadata['lockfile_type']}")
            if 'location' in finding.metadata:
                click.echo(f"  Location: {finding.metadata['location']}")
            if 'package_path' in finding.metadata:
                click.echo(f"  Path: {finding.metadata['package_path']}")

        # Print remediation
        if finding.remediation:
            rem = finding.remediation
            click.echo(click.style("  Remediation:", fg='cyan'))
            click.echo(f"    - strategy: {rem.strategy}")
            if rem.suggested_spec:
                click.echo(f"    - suggested_spec: " + click.style(rem.suggested_spec, fg='green', bold=True))

    def _print_summary(self):
        """Print overall summary"""
        click.echo(click.style("=" * 80, fg='white', bold=True))
        click.echo(click.style(f"Total findings: ", fg='white', bold=True) +
                  click.style(f"{len(self.findings)}", fg='red', bold=True))
        click.echo(click.style("=" * 80, fg='white', bold=True))

        # Calculate statistics
        exact_count = sum(1 for f in self.findings if f.match_type == 'exact')
        range_count = sum(1 for f in self.findings if f.match_type == 'range')

        # Group by ecosystem
        ecosystem_stats = defaultdict(lambda: {'packages': set(), 'findings': 0})
        for finding in self.findings:
            ecosystem_stats[finding.ecosystem]['packages'].add(finding.package_name)
            ecosystem_stats[finding.ecosystem]['findings'] += 1

        click.echo("\n" + click.style("📊 Summary:", fg='cyan', bold=True))
        click.echo(f"   • Exact version matches: " + click.style(str(exact_count), fg='red', bold=True))
        click.echo(f"   • Semver range matches: " + click.style(str(range_count), fg='yellow', bold=True))

        if len(ecosystem_stats) > 1:
            click.echo(f"\n   " + click.style("By Ecosystem:", fg='cyan', bold=True))
            for ecosystem in sorted(ecosystem_stats.keys()):
                stats = ecosystem_stats[ecosystem]
                click.echo(f"   • {ecosystem}: " +
                          click.style(f"{len(stats['packages'])} packages, {stats['findings']} findings",
                                    fg='magenta', bold=True))

        # Print remediation guidance
        click.echo("\n" + click.style("💡 Next Steps:", fg='cyan', bold=True))
        click.echo(click.style("   1.", fg='cyan') + " Review all findings above")
        click.echo(click.style("   2.", fg='cyan') + " Update manifests to exclude compromised versions")
        click.echo(click.style("   3.", fg='cyan') + " Regenerate lockfiles (delete locks and reinstall)")
        click.echo(click.style("   4.", fg='cyan') + " Run full test suite")
        click.echo(click.style("   5.", fg='cyan') + " Consider using package manager overrides if needed")

        if any(f.ecosystem == 'npm' for f in self.findings):
            click.echo(click.style("\n   NPM Overrides:", fg='cyan'))
            click.echo("   • npm:   package.json → " + click.style('"overrides"', fg='green'))
            click.echo("   • yarn:  package.json → " + click.style('"resolutions"', fg='green'))
            click.echo("   • pnpm:  package.json → " + click.style('"pnpm.overrides"', fg='green'))

        click.echo()  # Final newline

    def save_report(self, output_file: str, relative_paths: bool = False) -> bool:
        """
        Save findings to JSON file

        Args:
            output_file: Path to output file
            relative_paths: Convert absolute paths to relative paths

        Returns:
            True if saved successfully, False otherwise
        """
        try:
            # Convert findings to dictionaries
            findings_data = []
            for finding in self.findings:
                finding_dict = finding.to_dict(include_note=False)

                # Convert paths to relative if requested
                if relative_paths and self.scan_dir:
                    scan_dir_abs = self.scan_dir.absolute()
                    for path_field in ['file', 'location', 'package_path']:
                        if path_field in finding_dict:
                            abs_path = Path(finding_dict[path_field])
                            try:
                                rel_path = abs_path.relative_to(scan_dir_abs)
                                # Add ./ prefix for clarity
                                finding_dict[path_field] = f"./{rel_path}"
                            except ValueError:
                                # Path is outside scan directory, keep absolute
                                pass

                        # Also check metadata
                        if path_field in finding_dict.get('metadata', {}):
                            abs_path = Path(finding_dict['metadata'][path_field])
                            try:
                                rel_path = abs_path.relative_to(scan_dir_abs)
                                finding_dict['metadata'][path_field] = f"./{rel_path}"
                            except ValueError:
                                pass

                findings_data.append(finding_dict)

            # Build report structure
            report = {
                'total_findings': len(self.findings),
                'threats': self.threats,
                'ecosystems': self.get_ecosystems(),
                'findings': findings_data
            }

            # Add ecosystem summary
            report['summary'] = self._generate_summary()

            # Write to file
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)

            return True

        except Exception as e:
            click.echo(click.style(f"✗ Error saving report: {e}", fg='red', bold=True), err=True)
            return False
