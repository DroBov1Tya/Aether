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

# httpx (ProjectDiscovery) — batch HTTP probe + screenshots. Pull the
# release binary for the target arch instead of building from source.
ARG HTTPX_VERSION=1.6.9
RUN case "$TARGETPLATFORM" in \
      "linux/amd64") HX_ARCH="amd64" ;; \
      "linux/arm64") HX_ARCH="arm64" ;; \
      *) echo "Unsupported platform: $TARGETPLATFORM" && exit 1 ;; \
    esac && \
    apt-get update && apt-get install -y curl unzip && \
    curl -sSL -o /tmp/httpx.zip \
      "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${HX_ARCH}.zip" && \
    unzip -o /tmp/httpx.zip -d /tmp/httpx && \
    cp /tmp/httpx/httpx /output/httpx && \
    chmod +x /output/httpx

# nuclei (ProjectDiscovery) — the "hunt" layer. Release binary per arch.
ARG NUCLEI_VERSION=3.3.7
RUN case "$TARGETPLATFORM" in \
      "linux/amd64") NX_ARCH="amd64" ;; \
      "linux/arm64") NX_ARCH="arm64" ;; \
      *) echo "Unsupported platform: $TARGETPLATFORM" && exit 1 ;; \
    esac && \
    curl -sSL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NX_ARCH}.zip" && \
    unzip -o /tmp/nuclei.zip -d /tmp/nuclei && \
    cp /tmp/nuclei/nuclei /output/nuclei && \
    chmod +x /output/nuclei

# tlsx + dnsx (ProjectDiscovery) — batch TLS grab (SAN/JARM) and resolver.
ARG TLSX_VERSION=1.1.9
ARG DNSX_VERSION=1.2.2
RUN case "$TARGETPLATFORM" in \
      "linux/amd64") PD_ARCH="amd64" ;; \
      "linux/arm64") PD_ARCH="arm64" ;; \
      *) echo "Unsupported platform: $TARGETPLATFORM" && exit 1 ;; \
    esac && \
    curl -sSL -o /tmp/tlsx.zip \
      "https://github.com/projectdiscovery/tlsx/releases/download/v${TLSX_VERSION}/tlsx_${TLSX_VERSION}_linux_${PD_ARCH}.zip" && \
    unzip -o /tmp/tlsx.zip -d /tmp/tlsx && \
    cp /tmp/tlsx/tlsx /output/tlsx && chmod +x /output/tlsx && \
    curl -sSL -o /tmp/dnsx.zip \
      "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_${PD_ARCH}.zip" && \
    unzip -o /tmp/dnsx.zip -d /tmp/dnsx && \
    cp /tmp/dnsx/dnsx /output/dnsx && chmod +x /output/dnsx

# Runtime stage
FROM debian:bookworm-slim

ARG PROJECT_NAME
ARG BINARY_NAME

WORKDIR /app

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates \
    tzdata \
    nmap \
    masscan \
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
COPY --from=builder /output/httpx /usr/local/bin/httpx
COPY --from=builder /output/nuclei /usr/local/bin/nuclei
COPY --from=builder /output/tlsx /usr/local/bin/tlsx
COPY --from=builder /output/dnsx /usr/local/bin/dnsx

ENV RUST_LOG=info
ENV HOME=/tmp
ENV XDG_RUNTIME_DIR=/tmp

ENV TZ=Europe/Moscow
RUN ln -snf /usr/share/zoneinfo/Europe/Moscow /etc/localtime && echo Europe/Moscow > /etc/timezone
RUN mkdir -p /app/screenshots && chmod 777 /app/screenshots

CMD ["./agent"]
