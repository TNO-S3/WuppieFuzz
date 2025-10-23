FROM rust:latest AS builder

WORKDIR /app

# Cache downloaded+built dependencies
COPY Cargo.toml .
COPY ./build.rs .

RUN useradd -ms /bin/bash fuzzer
RUN chown fuzzer:fuzzer /app

RUN apt-get update \
    && apt-get install -qy cmake clang \
    && rm -rf /var/lib/apt/lists/*

USER fuzzer

COPY . .

RUN cargo build --release

FROM debian:bookworm-slim AS wuppiefuzz
WORKDIR /app
COPY --from=builder /app/target/release/wuppiefuzz /app/wuppiefuzz

ENTRYPOINT ["/app/wuppiefuzz"]
CMD ["--help"]