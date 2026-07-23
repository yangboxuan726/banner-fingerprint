# syntax=docker/dockerfile:1.7

FROM golang:1.26.2-bookworm AS build

WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/

ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN mkdir -p /out && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/client ./cmd/client

FROM gcr.io/distroless/static-debian12:nonroot AS server

WORKDIR /app
COPY --from=build --chown=nonroot:nonroot /out/server /app/server
COPY --chown=nonroot:nonroot rules/ /app/rules/

ENV ADDR=:8080
ENV RULES_FILE=/app/rules/rules.json

EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK --interval=5s --timeout=2s --start-period=2s --retries=10 \
  CMD ["/app/server", "healthcheck", "-url", "http://127.0.0.1:8080/health", "-timeout", "2s"]
ENTRYPOINT ["/app/server"]

FROM gcr.io/distroless/static-debian12:nonroot AS client

WORKDIR /app
COPY --from=build --chown=nonroot:nonroot /out/client /app/client
COPY --chown=nonroot:nonroot testdata/sample.json /data/sample.json

USER nonroot:nonroot
ENTRYPOINT ["/app/client"]
CMD ["-input", "/data/sample.json", "-server", "http://server:8080", "-timeout", "10s"]
