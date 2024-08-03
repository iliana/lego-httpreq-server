# syntax=docker/dockerfile:1.9
# check=error=true

FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /usr/src
COPY . .
RUN --mount=type=cache,target=/usr/src/target,sharing=private \
    --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install --path . --locked --target-dir=target
RUN objcopy --compress-debug-sections /usr/local/cargo/bin/lego-httpreq-server

FROM scratch
COPY --from=builder /usr/local/cargo/bin/lego-httpreq-server /
CMD ["/lego-httpreq-server"]
ENV RUST_BACKTRACE=1
EXPOSE 53/tcp
EXPOSE 53/udp
STOPSIGNAL SIGINT
