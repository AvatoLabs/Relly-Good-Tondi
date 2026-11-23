FROM rust:1.95.0-slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates make python3 clang libclang-dev cmake pkg-config libssl-dev protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /src/RGT
COPY --from=tondi Cargo.toml /src/Tondi/Cargo.toml
COPY --from=tondi vm /src/Tondi/vm
COPY --from=tondi consensus/Cargo.toml /src/Tondi/consensus/Cargo.toml
COPY --from=tondi consensus/examples /src/Tondi/consensus/examples
COPY --from=tondi consensus/src /src/Tondi/consensus/src
COPY --from=tondi consensus/core /src/Tondi/consensus/core
COPY --from=tondi consensus/karmadag /src/Tondi/consensus/karmadag
COPY --from=tondi crypto/addresses /src/Tondi/crypto/addresses
COPY --from=tondi crypto/hashes /src/Tondi/crypto/hashes
COPY --from=tondi utils /src/Tondi/utils
COPY --from=tondi math /src/Tondi/math
COPY --from=tondi wallet/pstt /src/Tondi/wallet/pstt
COPY . .
ARG CARGO_BUILD_JOBS
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/var/cache/rgt-target \
    cargo build --locked --release --bin rgt --bin rgtx --bin rgt-proof --target-dir /var/cache/rgt-target && \
    install -D /var/cache/rgt-target/release/rgt-proof /out/rgt-proof && \
    install -D /var/cache/rgt-target/release/rgt /out/rgt && \
    install -D /var/cache/rgt-target/release/rgtx /out/rgtx

FROM debian:bookworm-slim
COPY --from=builder /out/rgt-proof /usr/local/bin/rgt-proof
COPY --from=builder /out/rgt /usr/local/bin/rgt
COPY --from=builder /out/rgtx /usr/local/bin/rgtx
USER 65534:65534
WORKDIR /tmp
ENTRYPOINT ["rgt"]
