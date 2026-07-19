FROM rust:1.88-alpine3.22 AS rust-base

RUN apk add --no-cache musl-dev perl make

FROM rust-base AS daemon-builder
WORKDIR /build/daemon
COPY daemon/Cargo.toml daemon/Cargo.lock* ./
COPY daemon/src ./src
RUN cargo build --release --locked

FROM rust-base AS search-tools-builder
RUN cargo install --locked --version 14.1.1 ripgrep --root /tools
RUN cargo install --locked --version 10.2.0 fd-find --root /tools

FROM scratch
COPY --from=daemon-builder /build/daemon/target/release/ksandbox-daemon /opt/ksandbox/bin/ksandbox-daemon
COPY --from=search-tools-builder /tools/bin/rg /opt/ksandbox/bin/rg
COPY --from=search-tools-builder /tools/bin/fd /opt/ksandbox/bin/fd
