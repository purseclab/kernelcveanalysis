#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
image_tag="${CUTTLEFISH_DOCKER_IMAGE:-cuttlefish-host:latest}"
base_image="${CUTTLEFISH_BASE_IMAGE:-us-docker.pkg.dev/android-cuttlefish-artifacts/cuttlefish-orchestration/cuttlefish-orchestration:stable}"

docker build \
  --pull \
  --build-arg "CUTTLEFISH_BASE_IMAGE=${base_image}" \
  --file "${script_dir}/Dockerfile" \
  --tag "${image_tag}" \
  "${script_dir}"

printf 'Built Cuttlefish image: %s\n' "${image_tag}"
