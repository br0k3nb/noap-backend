FROM rust:1.97-bookworm as builder
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/noap-server /usr/local/bin/noap-server
ENV PORT=3002
EXPOSE 3002
CMD ["noap-server"]
