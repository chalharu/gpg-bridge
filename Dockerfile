# Development environment for gpg-bridge
# Usage: docker build -t gpg-bridge-dev .
#        docker run --rm -v "$PWD:/workspace" \
#          -v gpg-bridge-cargo-registry:/usr/local/cargo/registry \
#          -v gpg-bridge-cargo-git:/usr/local/cargo/git \
#          -w /workspace gpg-bridge-dev <command>

FROM rust:1.93-bookworm

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    unzip \
    xz-utils \
    clang \
    cmake \
    ninja-build \
    pkg-config \
    libgtk-3-dev \
    libssl-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# Rust components (add rustfmt, clippy, and llvm-tools for coverage)
RUN rustup component add rustfmt clippy llvm-tools-preview

# Cargo tools
RUN cargo install cargo-llvm-cov@0.8.4 && \
    cargo install sqlx-cli@0.8.6 --no-default-features --features postgres,sqlite,rustls

# Flutter SDK
ENV FLUTTER_HOME=/opt/flutter
ENV PATH="${FLUTTER_HOME}/bin:${FLUTTER_HOME}/bin/cache/dart-sdk/bin:${PATH}"
RUN git clone --depth 1 --branch 3.41.2 https://github.com/flutter/flutter.git ${FLUTTER_HOME} && \
    flutter precache && \
    flutter config --no-analytics && \
    dart --disable-analytics

# Git safe directory (allow mounted workspace)
RUN git config --global --add safe.directory /workspace

# NOTE: Container runs as root intentionally for development simplicity
# (bind mounts on macOS are simpler without UID mapping).
# Reconsider adding a non-root USER directive for CI environments.

WORKDIR /workspace
