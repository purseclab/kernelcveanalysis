# syntax=docker/dockerfile:1

ARG CUTTLEFISH_BASE_IMAGE=us-docker.pkg.dev/android-cuttlefish-artifacts/cuttlefish-orchestration/cuttlefish-orchestration:stable
FROM ${CUTTLEFISH_BASE_IMAGE}

# The server supplies the launch command and mounts the Cuttlefish runtime at
# /opt/cuttlefish. Root avoids host/runtime ownership and device-access issues.
USER root

COPY --chmod=0755 container-entrypoint.sh /usr/local/bin/cuttlefish-entrypoint

EXPOSE 6520/tcp

# Initialize the per-container Cuttlefish network resources before executing
# the launch command supplied by DockerCuttlefishBackend.
ENTRYPOINT ["/usr/local/bin/cuttlefish-entrypoint"]
