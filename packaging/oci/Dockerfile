FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

RUN apk add --no-cache ca-certificates git \
    && addgroup -g 65532 -S revoot \
    && adduser -u 65532 -S -D -H -G revoot revoot

COPY --chmod=0555 revoot /usr/local/bin/revoot

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/revoot"]
