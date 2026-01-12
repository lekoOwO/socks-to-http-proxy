# syntax=docker/dockerfile:1

FROM rust:1.83 AS builder
ARG TARGETARCH=amd64
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends musl-tools pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests

RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) export RUST_TARGET=x86_64-unknown-linux-musl ;; \
      arm64) export RUST_TARGET=aarch64-unknown-linux-musl ;; \
      *) echo "Unsupported architecture: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    rustup target add "${RUST_TARGET}"; \
    cargo build --release --locked --target "${RUST_TARGET}"; \
    install -Dm755 "target/${RUST_TARGET}/release/sthp" /out/sthp

RUN install -Dm644 /etc/ssl/certs/ca-certificates.crt /out/ca-certificates.crt

FROM scratch AS runtime
COPY --from=builder /out/sthp /sthp
COPY --from=builder /out/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
EXPOSE 8080
ENTRYPOINT ["/sthp"]
