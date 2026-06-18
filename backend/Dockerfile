ARG PROJECT_NAME=backend
ARG BINARY_NAME=backend

# ============================================
# Builder stage
# ============================================
FROM --platform=$BUILDPLATFORM rust:1.91.1-slim AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG PROJECT_NAME
ARG BINARY_NAME

WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config \
    musl-tools \
    gcc-aarch64-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl && \
    rustup target add aarch64-unknown-linux-musl

COPY Cargo.toml Cargo.lock ./

RUN mkdir src && echo "fn main() {}" > src/main.rs

RUN case "$TARGETPLATFORM" in \
      "linux/amd64") echo "x86_64-unknown-linux-musl" > /tmp/rust-target ;; \
      "linux/arm64") echo "aarch64-unknown-linux-musl" > /tmp/rust-target ;; \
      *) echo "Unsupported platform: $TARGETPLATFORM" && exit 1 ;; \
    esac

RUN export RUST_TARGET=$(cat /tmp/rust-target) && \
    cargo fetch && \
    cargo build --release --target $RUST_TARGET

RUN export RUST_TARGET=$(cat /tmp/rust-target) && \
    rm -rf src \
    target/$RUST_TARGET/release/deps/${PROJECT_NAME}* \
    target/$RUST_TARGET/release/${PROJECT_NAME}

COPY src ./src

RUN export RUST_TARGET=$(cat /tmp/rust-target) && \
    cargo build --release --target $RUST_TARGET && \
    strip target/$RUST_TARGET/release/${BINARY_NAME} && \
    mkdir -p /output && \
    cp target/$RUST_TARGET/release/${BINARY_NAME} /output/app

# ============================================
# Runtime stage
# ============================================
FROM alpine:latest

ARG PROJECT_NAME
ARG BINARY_NAME

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 appuser && \
    chown -R appuser:appuser /app

COPY --from=builder --chown=appuser:appuser /output/app /app/app

USER appuser

ENV RUST_LOG=info
ENV TZ=UTC

CMD ["./app"]
