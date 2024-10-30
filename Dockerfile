FROM rust:latest AS wuppiefuzz

WORKDIR /app

# Cache downloaded+built dependencies
COPY Cargo.toml .
COPY ./build.rs .

RUN useradd -ms /bin/bash fuzzer
RUN chown fuzzer:fuzzer /app

USER fuzzer

RUN mkdir src && \
    echo 'fn main() {}' > src/main.rs && \
    cargo build --release && \
    rm -Rvf src

COPY . .

RUN cargo build --release

ENTRYPOINT ["cargo", "run", "--release", "--manifest-path", "/app/Cargo.toml", "--"]

CMD ["--help"] # Shows usage, must be overridden by user to target specific API

