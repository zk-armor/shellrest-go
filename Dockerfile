# syntax=docker/dockerfile:1

# Build stage
FROM golang:1.22-alpine AS build
WORKDIR /app
COPY go.mod ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GO111MODULE=on go build -ldflags='-s -w' -o /shellrest-go .

# Run stage
FROM alpine:3.19
RUN apk add --no-cache ca-certificates bash
COPY --from=build /shellrest-go /shellrest-go
COPY sshrest.conf /etc/shellrest/sshrest.conf
EXPOSE 8080
# run as non-root numeric user (65532)
USER 65532:65532
ENTRYPOINT ["/shellrest-go"]
