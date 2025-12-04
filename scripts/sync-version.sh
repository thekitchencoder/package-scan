#!/bin/bash
# sync-version.sh
# Synchronize version from pyproject.toml to Dockerfile and tag-and-push.sh
#
# Usage: ./scripts/sync-version.sh

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔍 Reading version from pyproject.toml...${NC}"

# Extract version from pyproject.toml
VERSION=$(grep '^version = ' pyproject.toml | sed 's/version = "\(.*\)"/\1/')

if [ -z "$VERSION" ]; then
    echo -e "${YELLOW}❌ Could not find version in pyproject.toml${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Found version: ${VERSION}${NC}"
echo ""

# Update Dockerfile
echo -e "${BLUE}📝 Updating Dockerfile...${NC}"
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS sed requires backup extension
    sed -i '' "s/^LABEL version=.*/LABEL version=\"${VERSION}\"/" Dockerfile
else
    # Linux sed
    sed -i "s/^LABEL version=.*/LABEL version=\"${VERSION}\"/" Dockerfile
fi
echo -e "${GREEN}✓ Dockerfile updated${NC}"

# Update tag-and-push.sh
echo -e "${BLUE}📝 Updating scripts/tag-and-push.sh...${NC}"
if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "s/^VERSION=.*/VERSION=\"${VERSION}\"/" scripts/tag-and-push.sh
else
    sed -i "s/^VERSION=.*/VERSION=\"${VERSION}\"/" scripts/tag-and-push.sh
fi
echo -e "${GREEN}✓ scripts/tag-and-push.sh updated${NC}"

echo ""
echo -e "${GREEN}✅ Version ${VERSION} synchronized across all files!${NC}"
echo ""
echo -e "${BLUE}Files updated:${NC}"
echo "  • Dockerfile (LABEL version)"
echo "  • scripts/tag-and-push.sh (VERSION variable)"
echo ""
echo -e "${BLUE}Files that auto-sync (no action needed):${NC}"
echo "  • src/package_scan/__init__.py (reads from package metadata)"
echo "  • docs/source/conf.py (reads from package metadata)"
echo ""
echo -e "${YELLOW}📋 Next steps:${NC}"
echo "  1. Review changes: git diff"
echo "  2. Test build: docker build -t package-scan ."
echo "  3. Commit changes: git add -A && git commit -m 'chore: bump version to ${VERSION}'"
echo "  4. Create tag: git tag v${VERSION}"
echo "  5. Push: git push && git push --tags"
echo "  6. Build and push Docker: ./scripts/tag-and-push.sh"
echo ""
