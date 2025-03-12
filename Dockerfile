FROM --platform=${BUILDPLATFORM} mirror.gcr.io/library/golang:1.24.0 AS builder

WORKDIR /app/
ADD . .
RUN CGO_ENABLED=0 GOOS=linux \
  go build -ldflags '-extldflags "-static"' \
  -o aws-cvpn-pki-manager cmd/main.go

# FROM debian:bullseye-slim
# RUN apt update && apt -y install ca-certificates

FROM --platform=${BUILDPLATFORM} gcr.io/distroless/static:nonroot
WORKDIR /app/
COPY --from=builder /app/aws-cvpn-pki-manager /app/aws-cvpn-pki-manager .
USER 65532:65532

EXPOSE 8080
ENTRYPOINT [ "/app/aws-cvpn-pki-manager", "server" ]