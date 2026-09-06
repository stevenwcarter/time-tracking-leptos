# syntax=docker/dockerfile:1.7
FROM rust:1-slim AS builder

# curl + ca-certificates: fetching the cargo-leptos release tarball.
# The pre-built binary is used instead of `cargo install cargo-leptos`, which
# drags in git2 -> libgit2-sys -> openssl-sys and needs a full C/Perl toolchain.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# `rust-toolchain.toml` drives the install, and it happens in one layer.
#
# Installing a hand-written subset here instead lets the manifest reconcile the
# difference later, during `cargo leptos build` — and reconciling syncs the
# channel, which replaces `rust-std` for wasm32 by renaming a directory created
# in an *earlier* image layer. overlayfs without `redirect_dir` refuses that
# with `Invalid cross-device link (os error 18)`. It builds on `overlay2` and
# fails on the `overlayfs` driver, which is a difference between machines
# rather than between Dockerfiles.
#
# Copying the manifest on its own also keeps this layer cached against the
# toolchain pin rather than against the source, so editing code does not
# re-download a toolchain.
WORKDIR /build
COPY rust-toolchain.toml ./
RUN rustup show

# Pinned: an unpinned install silently changes the build on every cargo-leptos
# release.
ARG CARGO_LEPTOS_VERSION=0.3.7
RUN curl -L \
    "https://github.com/leptos-rs/cargo-leptos/releases/download/v${CARGO_LEPTOS_VERSION}/cargo-leptos-x86_64-unknown-linux-gnu.tar.gz" \
    | tar xz --strip-components=1 -C /usr/local/cargo/bin/ \
 && chmod +x /usr/local/cargo/bin/cargo-leptos \
 && cargo leptos --version

COPY . .

# --precompress ships .gz/.br siblings next to the wasm/js/css bundle;
# leptos_axum's file_and_error_handler (main.rs's fallback) already serves
# them via .precompressed_gzip()/.precompressed_br() when present. This is a
# CLI flag, not a [package.metadata.leptos] key — cargo-leptos 0.3.7 ignores
# `precompress` there and warns "not recognized".
RUN cargo leptos build --release --precompress

# Not the :nonroot variant — the app binds port 80, which needs privileges.
FROM gcr.io/distroless/cc-debian12 AS runtime
WORKDIR /app

COPY --from=builder /build/target/release/time-tracking-leptos /app/time-tracking-leptos
COPY --from=builder /build/target/site /app/site

ENV LEPTOS_OUTPUT_NAME=time-tracking-leptos \
    LEPTOS_SITE_ROOT=/app/site \
    LEPTOS_SITE_PKG_DIR=pkg \
    LEPTOS_SITE_ADDR=0.0.0.0:80

# SQLite needs a writable, persistent location; /app is the read-only image
# layer's WORKDIR, not a place to keep data across recreates.
ENV DATABASE_URL=/data/time-tracking.db
VOLUME ["/data"]

EXPOSE 80
# SESSION_KEY has no default in a release build (see src/session.rs and
# main's startup check) — the container logs an error naming the variable
# and exits immediately if it is unset OR left empty at run time. Intended:
# refusing to boot beats silently signing every session with a guessable key.
CMD ["/app/time-tracking-leptos"]
