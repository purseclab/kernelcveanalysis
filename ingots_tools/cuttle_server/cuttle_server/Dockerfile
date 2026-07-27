# syntax=docker/dockerfile:1

ARG CUTTLEFISH_BASE_IMAGE=us-docker.pkg.dev/android-cuttlefish-artifacts/cuttlefish-orchestration/cuttlefish-orchestration:stable
FROM ${CUTTLEFISH_BASE_IMAGE}

# The server supplies the launch command and mounts the Cuttlefish runtime at
# /opt/cuttlefish. Root avoids host/runtime ownership and device-access issues.
USER root

EXPOSE 6520/tcp

# Commands are supplied by DockerCuttlefishBackend, not the orchestration
# image's multi-service entrypoint.
ENTRYPOINT []
