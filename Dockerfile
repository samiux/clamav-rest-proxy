FROM rust:1.65-alpine3.16 as builder
LABEL stage=builder

WORKDIR /clamav-rest-proxy

# Rust build flags
ENV RUSTFLAGS="-C target-feature=-crt-static"
COPY ./ ./
RUN apk add -q build-base openssl-dev

RUN set -eux; \
    	apkArch="$(apk --print-arch)"; \
      if [ "$apkArch" = "aarch64" ]; then \
      export JEMALLOC_SYS_WITH_LG_PAGE=16; \
      fi && \
      cargo build --release

FROM alpine:3.16 as runtime
RUN apk update --quiet \
    	&& apk add -q --no-cache libgcc curl

COPY --from=builder /clamav-rest-proxy/target/release/clamav-rest-proxy /bin/clamav-rest-proxy
CMD ["/bin/clamav-rest-proxy"]
