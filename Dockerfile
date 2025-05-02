FROM golang:1.24@sha256:30baaea08c5d1e858329c50f29fe381e9b7d7bced11a0f5f1f69a1504cdfbf5e  AS builder

COPY . /build

RUN cd /build && \
    go build ./cmd/http-auth-server

FROM gcr.io/distroless/base-debian12:nonroot@sha256:fa5f94fa433728f8df3f63363ffc8dec4adcfb57e4d8c18b44bceccfea095ebc

COPY --from=builder /build/http-auth-server /app/http-auth-server

ENV AUTH_LISTEN=":9091"

ENTRYPOINT [ "/app/http-auth-server" ]
