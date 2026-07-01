FROM rust:1.87-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --features v2board-daemon --bin v2board-wireguard

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iproute2 nftables \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/v2board-wireguard /usr/local/bin/v2board-wireguard
ENTRYPOINT ["/usr/local/bin/v2board-wireguard"]
