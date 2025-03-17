FROM --platform=$BUILDPLATFORM mirror.gcr.io/library/golang:1.24.0 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app/
ADD . .
RUN CGO_ENABLED=0 GOOS=linux GO111MODULE=on GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -a -o aws-cvpn-pki-manager cmd/main.go

FROM gcr.io/distroless/static:nonroot
WORKDIR /app/
COPY --from=builder /app/aws-cvpn-pki-manager /app/aws-cvpn-pki-manager
USER 65532:65532

EXPOSE 8080
ENTRYPOINT [ "/app/aws-cvpn-pki-manager", "server" ]