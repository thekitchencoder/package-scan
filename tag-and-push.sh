#!/bin/bash
# tag-and-push.sh
# Script to build, tag, and push hulud-scan to Docker Hub

VERSION="0.1.0"
IMAGE_NAME="kitchencoder/hulud-scan"

set -e  # Exit on error

echo "🔨 Building image..."
docker build -t hulud-scan .

echo ""
echo "🏷️  Tagging with version ${VERSION} and latest..."
docker tag hulud-scan ${IMAGE_NAME}:${VERSION}
docker tag hulud-scan ${IMAGE_NAME}:latest

echo ""
echo "📤 Pushing to Docker Hub..."
docker push ${IMAGE_NAME}:${VERSION}
docker push ${IMAGE_NAME}:latest

echo ""
echo "✅ Successfully pushed ${IMAGE_NAME}:${VERSION} and ${IMAGE_NAME}:latest"
echo "🔗 View at: https://hub.docker.com/r/kitchencoder/hulud-scan"
echo ""
echo "📝 Users can now run:"
echo "   docker run --rm -v \"\$(pwd):/scan\" ${IMAGE_NAME}:latest --dir /scan"
