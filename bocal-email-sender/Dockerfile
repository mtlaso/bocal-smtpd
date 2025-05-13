FROM golang:1.24-alpine

WORKDIR /app

# Copy go.mod and go.sum first for better caching.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=bind,source=go.sum,target=go.sum \
    --mount=type=bind,source=go.mod,target=go.mod \
    go mod download

# Copy the rest of the code.
COPY ./bocal-email-sender .

# Generate self-signed certificates for TLS connections.
RUN apk add openssl
RUN mkdir -p /app/certs && \
    openssl req -x509 -newkey rsa:4096 -keyout /app/certs/client.key -out /app/certs/client.crt -days 365 -nodes -subj "/CN=mail-sender"

# Build the application
ENV GOCACHE=/root/.cache/go-build
RUN --mount=type=cache,target=/go/pkg/mod \
    go build -o bocal-email-sender .

# This command keeps the container running but does nothing until you 'docker exec' into it.
CMD ["tail", "-f", "/dev/null"]
# CMD ["./bocal-email-sender"]
