# Official multi-architecture Rust image; update digest and version together.
FROM rust:1.97.1-slim-trixie@sha256:8e8cf8f7fd54a2d23d5a743b3a03f56e26b6c774276c33fa0595111704ebb15c
RUN rustup component add clippy && apt-get update && apt-get install -y --no-install-recommends python3 git libclang-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash developer \
    && chmod -R a+rX /usr/local/cargo /usr/local/rustup
ENV CARGO_HOME=/home/developer/.cargo CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
USER developer
