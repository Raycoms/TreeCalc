# ----------- Stage 1: Build -----------
FROM rust:1.83.0 AS builder
WORKDIR /usr/src/tree
COPY . .
RUN cargo build --release


# ----------- Stage 2: Runtime -----------
FROM rust:1.83.0-slim
RUN apt-get update && apt-get install -y iproute2 && apt-get clean
COPY --from=builder /usr/src/tree/target/release/tree /usr/local/bin/tree
COPY run.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/run.sh
CMD ["/usr/local/bin/run.sh"]