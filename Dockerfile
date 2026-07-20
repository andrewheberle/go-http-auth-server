FROM golang:1.26@sha256:3aff6657219a4d9c14e27fb1d8976c49c29fddb70ba835014f477e1c70636647  AS builder

COPY . /build

RUN cd /build && \
    go build ./cmd/http-auth-server

FROM gcr.io/distroless/base-debian12:nonroot@sha256:4b5196599229a5cf312a676cfe1ee8587ecf2371dcc22620f8c7a66d77d125c8

COPY --from=builder /build/http-auth-server /app/http-auth-server

ENV AUTH_LISTEN=":9091"

ENTRYPOINT [ "/app/http-auth-server" ]
