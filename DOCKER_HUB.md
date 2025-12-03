# Publishing to Docker Hub

This guide explains how to publish the hulud-scan Docker image to Docker Hub under the `kitchencoder` account.

## Prerequisites

- Docker installed and running
- Docker Hub account (username: `kitchencoder`)
- Image built locally (`docker build -t hulud-scan .`)

## Step 1: Log in to Docker Hub

```bash
docker login
```

Enter your Docker Hub credentials when prompted:
- Username: `kitchencoder`
- Password: (your Docker Hub password or access token)

## Step 2: Tag Your Image

Tag the image with your Docker Hub username and desired repository name:

```bash
# Tag with 'latest'
docker tag hulud-scan kitchencoder/hulud-scan:latest

# Also tag with a version number (recommended)
docker tag hulud-scan kitchencoder/hulud-scan:0.1.0

# Optional: tag with additional labels
docker tag hulud-scan kitchencoder/hulud-scan:0.1.0-lockfile-support
```

## Step 3: Push to Docker Hub

```bash
# Push the latest tag
docker push kitchencoder/hulud-scan:latest

# Push the versioned tag
docker push kitchencoder/hulud-scan:0.1.0

# Or push all tags at once
docker push kitchencoder/hulud-scan --all-tags
```

## Step 4: Verify

Visit `https://hub.docker.com/r/kitchencoder/hulud-scan` to see your published image.

## How Others Can Use It

Once pushed, anyone can pull and run your scanner:

```bash
# Pull and run in one command - super simple!
docker run --rm -v "$(pwd):/workspace" kitchencoder/hulud-scan:latest

# That's it! Report saved as ./hulud_scan_report.json
```

**Advanced usage:**

```bash
# Custom output filename
docker run --rm -v "$(pwd):/workspace" kitchencoder/hulud-scan:latest --output my-report.json

# Scan subdirectory
docker run --rm -v "$(pwd):/workspace" kitchencoder/hulud-scan:latest --dir ./src

# Use custom CSV
docker run --rm -v "$(pwd):/workspace" kitchencoder/hulud-scan:latest --csv /workspace/custom.csv

# List all compromised packages in the embedded database
docker run --rm kitchencoder/hulud-scan:latest --list-affected-packages

# Export threat database as raw CSV
docker run --rm kitchencoder/hulud-scan:latest --list-affected-packages-csv > threats.csv
```

## Automated Build & Push Script

Create a script for consistent releases:

```bash
#!/bin/bash
# tag-and-push.sh

VERSION="0.1.0"
IMAGE_NAME="kitchencoder/hulud-scan"

echo "Building image..."
docker build -t hulud-scan .

echo "Tagging with version ${VERSION} and latest..."
docker tag hulud-scan ${IMAGE_NAME}:${VERSION}
docker tag hulud-scan ${IMAGE_NAME}:latest

echo "Pushing to Docker Hub..."
docker push ${IMAGE_NAME}:${VERSION}
docker push ${IMAGE_NAME}:latest

echo "✓ Pushed ${IMAGE_NAME}:${VERSION} and ${IMAGE_NAME}:latest"
echo "✓ View at: https://hub.docker.com/r/kitchencoder/hulud-scan"
```

Make it executable:
```bash
chmod +x tag-and-push.sh
./tag-and-push.sh
```

## Version Tagging Best Practices

Use semantic versioning (MAJOR.MINOR.PATCH):

- **MAJOR**: Breaking changes (e.g., 1.0.0 → 2.0.0)
- **MINOR**: New features, backward compatible (e.g., 0.1.0 → 0.2.0)
- **PATCH**: Bug fixes (e.g., 0.1.0 → 0.1.1)

```bash
# Patch release (bug fixes)
docker tag hulud-scan kitchencoder/hulud-scan:0.1.1

# Minor release (new features, like lock file support)
docker tag hulud-scan kitchencoder/hulud-scan:0.2.0

# Major release (breaking changes)
docker tag hulud-scan kitchencoder/hulud-scan:1.0.0
```

Always maintain a `latest` tag pointing to the most recent stable release.

## Full Workflow Example

```bash
# 1. Build the image
docker build -t hulud-scan .

# 2. Test locally
docker run --rm -v "$(pwd)/examples:/scan" hulud-scan --dir /scan --no-save

# 3. Tag for Docker Hub
docker tag hulud-scan kitchencoder/hulud-scan:0.1.0
docker tag hulud-scan kitchencoder/hulud-scan:latest

# 4. Push to Docker Hub
docker push kitchencoder/hulud-scan:0.1.0
docker push kitchencoder/hulud-scan:latest

# 5. Test the public image
docker run --rm -v "$(pwd)/examples:/scan" \
  kitchencoder/hulud-scan:latest --dir /scan --no-save
```

## Docker Hub Repository Settings

### Recommended Description

On Docker Hub (`https://hub.docker.com/r/kitchencoder/hulud-scan`), add this description:

```
NPM Package Threat Scanner for HULUD worm detection

Scans package.json files, lock files (npm/yarn/pnpm), and node_modules
to identify compromised packages from the HULUD worm incident.

Features:
• Three-phase detection (package.json, lock files, installed packages)
• Semantic version range matching
• Lock file parsing for all major package managers
• Actionable remediation guidance with color-coded output
• Runs as non-root user for security
• Based on python:3.11-slim (~235MB)

Quick Start:
docker run --rm -v "$(pwd):/scan" kitchencoder/hulud-scan:latest --dir /scan

Documentation: https://github.com/kitchencoder/hulud-scan
```

### Recommended README for Docker Hub

Add a comprehensive README on Docker Hub:

```markdown
# hulud-scan

NPM Package Threat Scanner for identifying projects impacted by the HULUD worm.

## Usage

### Basic Scan

```bash
docker run --rm -v "$(pwd):/scan" kitchencoder/hulud-scan:latest --dir /scan
```

### List Compromised Packages

View all packages in the embedded threat database:

```bash
# Formatted display
docker run --rm kitchencoder/hulud-scan:latest --list-affected-packages

# Raw CSV output (for piping/saving)
docker run --rm kitchencoder/hulud-scan:latest --list-affected-packages-csv > threats.csv
```

This displays all 1055+ compromised package versions without needing to mount any volumes. Use the CSV option to export the database for use in other tools.

### Custom Threat Database

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  -v "$(pwd)/custom-threats.csv:/data/threats.csv" \
  kitchencoder/hulud-scan:latest --dir /scan --csv /data/threats.csv
```

### Save Report to Host

```bash
# IMPORTANT: Output path must be in mounted volume (/scan)
docker run --rm \
  -v "$(pwd):/scan" \
  kitchencoder/hulud-scan:latest --dir /scan --output /scan/report.json

# Report will be saved at: ./report.json on your host
```

**Note:** The default output path (`hulud_scan_report.json`) saves to `/app/` inside the container, which is not accessible from the host. Always specify `--output /scan/report.json` to save the report to your mounted directory.

## What Gets Scanned

1. **package.json files** - Checks declared dependency ranges
2. **Lock files** - Parses exact versions from package-lock.json, yarn.lock, pnpm-lock.yaml
3. **node_modules** - Scans actually installed packages

## Features

- ✓ Comprehensive three-phase detection
- ✓ Semantic version range matching
- ✓ Support for npm, Yarn, and pnpm lock files
- ✓ Color-coded terminal output with emoji
- ✓ Actionable remediation guidance
- ✓ JSON report output
- ✓ Runs as non-root user
- ✓ Secure python:3.11-slim base image

## Source Code

https://github.com/kitchencoder/hulud-scan
```

## Verify Image Details

Check your image before pushing:

```bash
# Check image size
docker images kitchencoder/hulud-scan

# Inspect image metadata
docker inspect kitchencoder/hulud-scan:latest

# Test the image
docker run --rm kitchencoder/hulud-scan:latest --help
```

## Troubleshooting

### Authentication Failed

```bash
# Use access token instead of password
docker logout
docker login -u kitchencoder
```

Generate an access token at: https://hub.docker.com/settings/security

### Image Too Large

The image should be ~235MB. If it's significantly larger:

```bash
# Check what's taking space
docker history kitchencoder/hulud-scan:latest

# Rebuild with --no-cache
docker build --no-cache -t hulud-scan .
```

### Push Denied

Ensure you're logged in with the correct account:

```bash
docker logout
docker login -u kitchencoder
```

## Updating the Image

When you make changes:

1. Update version in `pyproject.toml`
2. Rebuild: `docker build -t hulud-scan .`
3. Test locally
4. Tag with new version
5. Push both version tag and latest tag

```bash
# Example: releasing v0.2.0
docker build -t hulud-scan .
docker tag hulud-scan kitchencoder/hulud-scan:0.2.0
docker tag hulud-scan kitchencoder/hulud-scan:latest
docker push kitchencoder/hulud-scan:0.2.0
docker push kitchencoder/hulud-scan:latest
```

## CI/CD Integration (Optional)

For automated builds on GitHub Actions, create `.github/workflows/docker-publish.yml`:

```yaml
name: Docker Publish

on:
  push:
    tags:
      - 'v*'

jobs:
  docker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2

      - name: Login to Docker Hub
        uses: docker/login-action@v2
        with:
          username: kitchencoder
          password: ${{ secrets.DOCKERHUB_TOKEN }}

      - name: Extract version
        id: meta
        run: echo "VERSION=${GITHUB_REF#refs/tags/v}" >> $GITHUB_OUTPUT

      - name: Build and push
        uses: docker/build-push-action@v4
        with:
          push: true
          tags: |
            kitchencoder/hulud-scan:${{ steps.meta.outputs.VERSION }}
            kitchencoder/hulud-scan:latest
```

Add `DOCKERHUB_TOKEN` to your GitHub repository secrets.
