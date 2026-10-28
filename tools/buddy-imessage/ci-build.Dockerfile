# Modified 2026-10-28 for OrdinaryPlace Buddy. SSPL v1; see LICENSE.
# Build tools only: no source checkout, Apple runtime resources or account state.
FROM rust:1.90.0-slim-bookworm@sha256:64232e656c058f4468e8d024e990acff04f0fd5a5c0a88a574dc37773d7325c9

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential cmake ninja-build pkg-config libclang-dev \
       protobuf-compiler perl python3 git ca-certificates binutils file \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install 1.99.1 --profile minimal \
    && rustup default 1.99.1

ENV CARGO_BUILD_JOBS=2 \
    CARGO_PROFILE_DEV_DEBUG=0 \
    CARGO_TERM_COLOR=never \
    GIT_TERMINAL_PROMPT=0

WORKDIR /src
