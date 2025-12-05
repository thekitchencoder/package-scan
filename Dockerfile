# Use Python slim image for security and minimal size
FROM python:3.11-slim AS base

# Metadata
LABEL maintainer="Hulud Security"
LABEL description="Multi-Ecosystem Package Threat Scanner (npm, Maven/Gradle, pip)"
LABEL version="0.4.0"

# Create non-root user for security
RUN groupadd -r scanner && useradd -r -g scanner scanner

# Set up application directory
WORKDIR /app

# Copy application code first (needed for editable install)
COPY pyproject.toml setup.py ./
COPY src/ ./src/

# Install dependencies
RUN pip install --no-cache-dir -e . && \
    pip install --no-cache-dir pyyaml toml && \
    pip cache purge

# Copy threat databases
COPY threats/ ./threats/

# Create workspace directory for user files
RUN mkdir -p /workspace && chown -R scanner:scanner /workspace /app

# Switch to non-root user
USER scanner

# Set workspace as working directory (where commands run)
WORKDIR /workspace

# Set path prefix for cleaner output in Docker
# "." = relative paths (./package.json)
# Override with -e SCAN_PATH_PREFIX="$(pwd)" to get full host paths
ENV SCAN_PATH_PREFIX="."

# Set entrypoint to the multi-ecosystem scanner CLI
ENTRYPOINT ["package-scan"]

CMD []
