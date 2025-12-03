# Use Python slim image for security and minimal size
FROM python:3.11-slim AS base

# Metadata
LABEL maintainer="Hulud Security"
LABEL description="NPM Package Threat Scanner for HULUD worm detection"
LABEL version="0.1.0"

# Create non-root user for security
RUN groupadd -r scanner && useradd -r -g scanner scanner

# Set up application directory
WORKDIR /app

# Install dependencies in a separate layer for caching
COPY pyproject.toml setup.py ./
RUN pip install --no-cache-dir -e . && \
    pip install --no-cache-dir pyyaml && \
    pip cache purge

# Copy application code and default CSV file
COPY scan_npm_threats.py ./
COPY sha1-Hulud.csv ./

# Create workspace directory for user files
RUN mkdir -p /workspace && chown -R scanner:scanner /workspace /app

# Switch to non-root user
USER scanner

# Set workspace as working directory (where commands run)
WORKDIR /workspace

# Set entrypoint to the scanner CLI
ENTRYPOINT ["python", "/app/scan_npm_threats.py"]

# Default: scan current directory (workspace), CSV auto-detected, use relative paths
CMD ["--dir", ".", "--output-relative-paths"]
