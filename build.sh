#!/usr/bin/env bash
# Build (and optionally push) the Ransomware.live PRO enrichment connector image.
#
# Usage:
#   ./build.sh [TAG] [REGISTRY]
#
# Examples:
#   ./build.sh                         -> opencti-ransomwarelive-enrichment:1.0
#   ./build.sh 1.1                     -> opencti-ransomwarelive-enrichment:1.1
#   ./build.sh 1.1 myreg.example.com   -> build + push myreg.example.com/opencti-ransomwarelive-enrichment:1.1
#
# After it prints the image name, set that value as the `image:` line in your
# docker-compose.yml, then: docker compose up -d connector-ransomwarelive-enrichment
set -euo pipefail

IMAGE_NAME="opencti-ransomwarelive-enrichment"
TAG="${1:-1.0}"
REGISTRY="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -n "${REGISTRY}" ]; then
  FULL="${REGISTRY%/}/${IMAGE_NAME}:${TAG}"
else
  FULL="${IMAGE_NAME}:${TAG}"
fi

echo ">> Building ${FULL}"
docker build -t "${FULL}" "${SCRIPT_DIR}"

if [ -n "${REGISTRY}" ]; then
  echo ">> Pushing ${FULL}"
  docker push "${FULL}"
fi

echo ">> Done: ${FULL}"
echo ">> In docker-compose.yml set:  image: ${FULL}"
