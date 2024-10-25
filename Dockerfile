FROM golang:1.22@sha256:d5302d40dc5fbbf38ec472d1848a9d2391a13f93293a6a5b0b87c99dc0eaa6ae AS builder

COPY . /build

RUN cd /build && \
    go build ./cmd/http-auth-server

FROM gcr.io/distroless/base-debian12:nonroot@sha256:c3584d9160af7bbc6a0a6089dc954d0938bb7f755465bb4ef4265aad0221343e

COPY --from=builder /build/http-auth-server /app/http-auth-server

ENV AUTH_LISTEN=":9091"

ENTRYPOINT [ "/app/http-auth-server" ]
