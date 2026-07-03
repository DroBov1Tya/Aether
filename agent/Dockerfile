ARG PROJECT_NAME=agent
ARG BINARY_NAME=agent

# Builder stage
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

RUN export RUST_TARGET=$(cat /tmp/rust-target) && \
    cargo install rustscan --target $RUST_TARGET --root /output/tools && \
    cp /output/tools/bin/rustscan /output/rustscan

# Runtime stage
FROM debian:bookworm-slim

ARG PROJECT_NAME
ARG BINARY_NAME

WORKDIR /app

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates \
    tzdata \
    nmap \
    whatweb \
    chromium \
    chromium-driver \
    dnsutils \
    whois \
    openssl \
    bash \
    libgbm1 \
    libnss3 \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /output/app /app/agent
COPY --from=builder /output/rustscan /usr/local/bin/rustscan

ENV RUST_LOG=info
ENV HOME=/tmp
ENV XDG_RUNTIME_DIR=/tmp

ENV TZ=Europe/Moscow
RUN ln -snf /usr/share/zoneinfo/Europe/Moscow /etc/localtime && echo Europe/Moscow > /etc/timezone
RUN mkdir -p /app/screenshots && chmod 777 /app/screenshots

CMD ["./agent"]
