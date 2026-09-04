# syntax=docker/dockerfile:1.7
FROM rust:1-slim AS builder

# curl + ca-certificates: fetching the cargo-leptos release tarball.
# The pre-built binary is used instead of `cargo install cargo-leptos`, which
# drags in git2 -> libgit2-sys -> openssl-sys and needs a full C/Perl toolchain.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly --component rust-src \
 && rustup default nightly \
 && rustup target add wasm32-unknown-unknown

# Pinned: an unpinned install silently changes the build on every cargo-leptos
# release.
ARG CARGO_LEPTOS_VERSION=0.3.7
RUN curl -L \
    "https://github.com/leptos-rs/cargo-leptos/releases/download/v${CARGO_LEPTOS_VERSION}/cargo-leptos-x86_64-unknown-linux-gnu.tar.gz" \
    | tar xz --strip-components=1 -C /usr/local/cargo/bin/ \
 && chmod +x /usr/local/cargo/bin/cargo-leptos \
 && cargo leptos --version

WORKDIR /build
COPY . .

RUN cargo leptos build --release

# Not the :nonroot variant — the app binds port 80, which needs privileges.
FROM gcr.io/distroless/cc-debian12 AS runtime
WORKDIR /app

COPY --from=builder /build/target/release/time-tracking-leptos /app/time-tracking-leptos
COPY --from=builder /build/target/site /app/site

ENV LEPTOS_OUTPUT_NAME=time-tracking-leptos \
    LEPTOS_SITE_ROOT=/app/site \
    LEPTOS_SITE_PKG_DIR=pkg \
    LEPTOS_SITE_ADDR=0.0.0.0:80

EXPOSE 80
CMD ["/app/time-tracking-leptos"]
