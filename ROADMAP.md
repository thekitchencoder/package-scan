# ROADMAP for hulud-scan

This document outlines the strategic direction for `hulud-scan`, evolving it from a single-purpose tool into a comprehensive software supply chain security solution. The recommendations are based on an analysis of the current state of supply chain attacks and are prioritized to deliver the most value to developers.

## Current State and Vision

`hulud-scan` is currently a valuable tool for detecting a specific threat (the HULUD worm) in NPM projects. However, the software supply chain landscape is constantly evolving, with a dramatic increase in attacks targeting open-source ecosystems.

Our vision is to transform `hulud-scan` into a versatile, multi-ecosystem security tool that proactively identifies a wide range of threats, integrates seamlessly into developer workflows, and provides clear, actionable guidance.

## Actionable Task List

The following tasks are ordered by priority, with the goal of adding the most value to developers as quickly as possible.

### 1. Integrate with Public Vulnerability Databases

**Description:**
The current reliance on a static CSV file for threat intelligence is a significant limitation. Integrating with public vulnerability databases will provide a much broader and more up-to-date source of information.

**Tasks:**
- [ ] Integrate with the [OSV (Open Source Vulnerability) database](https://osv.dev/) API to fetch vulnerability data for a given package and version.
- [ ] Integrate with the [GitHub Advisory Database](https://github.com/advisories) to supplement the OSV data.
- [ ] Integrate with the [NVD (National Vulnerability Database)](https://nvd.nist.gov/) for CVE information.
- [ ] Modify the scanning logic to query these databases instead of relying on the CSV file.
- [ ] Update the reporting to include links to the relevant vulnerability advisories.

### 2. Multi-Ecosystem Support

**Description:**
To be a truly valuable tool, `hulud-scan` needs to support more than just NPM. Adding support for other popular package ecosystems will make it useful to a much wider audience.

**Tasks:**
- [ ] Add support for **PyPI (Python)** by parsing `requirements.txt` and `pyproject.toml` files.
- [ ] Add support for **Maven (Java)** by parsing `pom.xml` files.
- [ ] Add support for **RubyGems (Ruby)** by parsing `Gemfile` files.
- [ ] Abstract the scanning logic to be language-agnostic, with specific implementations for each package manager.

### 3. Improved Reporting and Remediation Guidance

**Description:**
The current report is a good start, but it could be more actionable. Providing clear, concise remediation guidance will help developers fix vulnerabilities more quickly.

**Tasks:**
- [ ] Enhance the console report with color-coding to highlight the severity of vulnerabilities.
- [ ] Provide clear, step-by-step remediation instructions for each vulnerability, including the exact version to upgrade to.
- [ ] Include links to relevant documentation and blog posts that explain the vulnerability in more detail.
- [ ] Offer a "quiet" mode that only outputs machine-readable JSON for easier integration with other tools.

### 4. CI/CD Integration

**Description:**
To be truly effective, security scanning needs to be an automated part of the development process. Making `hulud-scan` easy to integrate into CI/CD pipelines is crucial.

**Tasks:**
- [ ] Provide clear documentation and examples for integrating `hulud-scan` with popular CI/CD platforms like GitHub Actions, GitLab CI, and Jenkins.
- [ ] Add a configuration option to fail the build if vulnerabilities of a certain severity are found.
- [ ] Create a GitHub Action for `hulud-scan` to make it easy to add to any GitHub repository.

### 5. Typosquatting and Dependency Confusion Detection

**Description:**
Proactively detecting potential threats is a key part of a modern security tool. Adding detection for typosquatting and dependency confusion attacks will help protect developers from these common attack vectors.

**Tasks:**
- [ ] Implement a Levenshtein distance algorithm to identify package names that are similar to popular packages.
- [ ] Create a list of common typosquatting variations for popular packages.
- [ ] For private packages, check if the same package name is available on public repositories.
- [ ] Add a new section to the report for potential typosquatting and dependency confusion vulnerabilities.

### 6. SBOM (Software Bill of Materials) Generation and Analysis

**Description:**
An SBOM is a critical component of modern software supply chain security. Adding the ability to generate and analyze SBOMs will make `hulud-scan` a more comprehensive tool.

**Tasks:**
- [ ] Add a new command to generate an SBOM for a project in the CycloneDX or SPDX format.
- [ ] Add the ability to scan an existing SBOM for vulnerabilities.
- [ ] Integrate the SBOM analysis into the main scanning logic.

### 7. Package Metadata Analysis

**Description:**
Analyzing package metadata can reveal suspicious signs that may indicate a malicious package.

**Tasks:**
- [ ] Add checks for suspicious metadata, such as:
    - New packages with no history or few downloads.
    - Packages with suspiciously high version numbers.
    - Packages with maintainers who have no history or are associated with other malicious packages.
    - Packages with install scripts that execute arbitrary code.
- [ ] Add a new section to the report for suspicious packages.

### 8. Static and Dynamic Code Analysis

**Description:**
This is the most advanced feature on the roadmap, but it provides the deepest level of protection. Incorporating static and dynamic code analysis will allow `hulud-scan` to identify malicious code within dependencies, even if the package is not yet known to be malicious.

**Tasks:**
- [ ] Integrate with a static analysis engine like `bandit` (for Python) or `eslint` (for JavaScript) to identify potentially malicious code patterns.
- [ ] Explore the use of dynamic analysis (sandboxing) to execute package install scripts and tests in a safe environment to observe their behavior.
- [ ] Add a new section to the report for vulnerabilities found through code analysis.
