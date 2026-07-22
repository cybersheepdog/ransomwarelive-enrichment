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
# Prefers `docker buildx` (BuildKit). The classic `docker build` is deprecated /
# removed in recent Docker; if buildx is missing this script falls back to the
# legacy builder with BuildKit enabled and tells you how to install buildx.
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

if docker buildx version >/dev/null 2>&1; then
  echo ">> Building ${FULL} (buildx / BuildKit)"
  if [ -n "${REGISTRY}" ]; then
    docker buildx build --push -t "${FULL}" "${SCRIPT_DIR}"
  else
    # --load puts the result in the local image store so compose can use it
    docker buildx build --load -t "${FULL}" "${SCRIPT_DIR}"
  fi
else
  echo ">> buildx not found -- falling back to legacy builder with BuildKit."
  echo ">> To install buildx, see the note printed at the end."
  DOCKER_BUILDKIT=1 docker build -t "${FULL}" "${SCRIPT_DIR}"
  if [ -n "${REGISTRY}" ]; then
    docker push "${FULL}"
  fi
fi

echo ">> Done: ${FULL}"
echo ">> In docker-compose.yml set:  image: ${FULL}"

if ! docker buildx version >/dev/null 2>&1; then
  cat <<'NOTE'

--------------------------------------------------------------------------
buildx was not detected. Install it to silence the deprecation and be
future-proof:

  * Docker Desktop (Windows/Mac): update Docker Desktop -- buildx is bundled.
  * Debian/Ubuntu (incl. WSL2) with Docker's apt repo:
        sudo apt-get update && sudo apt-get install docker-buildx-plugin
  * Manual (any Linux): download the buildx binary from
        https://github.com/docker/buildx/releases
    to  ~/.docker/cli-plugins/docker-buildx  and  chmod +x  it.

  Then (optional) make `docker build` use buildx by default:
        docker buildx install
--------------------------------------------------------------------------
NOTE
fi
