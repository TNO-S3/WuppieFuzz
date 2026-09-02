FROM rust:trixie AS builder

WORKDIR /app

# Cache downloaded+built dependencies
COPY Cargo.toml .
COPY ./build.rs .

RUN useradd -ms /bin/bash fuzzer
RUN chown fuzzer:fuzzer /app

RUN apt-get update \
    && apt-get install -qy cmake clang \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cargo build --release

FROM debian:trixie-slim AS wuppiefuzz
RUN apt-get update \
    && apt-get install -qy libstdc++6 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -ms /bin/bash fuzzer
USER fuzzer
WORKDIR /app
COPY --from=builder /app/target/release/wuppiefuzz /app/wuppiefuzz

ENTRYPOINT ["/app/wuppiefuzz"]
CMD ["--help"]