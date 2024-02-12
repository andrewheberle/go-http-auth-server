FROM golang:1.22@sha256:ef61a20960397f4d44b0e729298bf02327ca94f1519239ddc6d91689615b1367 AS builder

COPY . /build

RUN cd /build && \
    go build ./cmd/http-auth-server

FROM gcr.io/distroless/base-debian12:nonroot@sha256:684dee415923cb150793530f7997c96b3cef006c868738a2728597773cf27359

COPY --from=builder /build/http-auth-server /app/http-auth-server

ENV AUTH_LISTEN=":9091"

ENTRYPOINT [ "/app/http-auth-server" ]
