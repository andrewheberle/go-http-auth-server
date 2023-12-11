FROM golang:1.21@sha256:ae34fbf671566a533f92e5469f3f3d34e9e6fb14c826db09956454da9a84c9a9 AS builder

COPY . /build

RUN cd /build && \
    go build ./cmd/http-auth-server

FROM gcr.io/distroless/base-debian12:nonroot@sha256:5a779e9c2635dbea68ae7988f398f95686ccde186cd2abf51207e41ed2ec51f4

COPY --from=builder /build/http-auth-server /app/http-auth-server

ENV AUTH_LISTEN=":9091"

ENTRYPOINT [ "/app/http-auth-server" ]
