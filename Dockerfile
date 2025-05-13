FROM golang:1.24-alpine

WORKDIR /app

# Copy go.mod and go.sum first for better caching.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod/ \
    --mount=type=bind,source=go.sum,target=go.sum \
    --mount=type=bind,source=go.mod,target=go.mod \
    go mod download

# Copy the rest of the code.
COPY . .

# Generate self-signed certificates for development.
RUN apk add openssl
RUN mkdir -p /app/certs && \
    openssl req -x509 -newkey rsa:4096 -keyout /app/certs/server.key -out /app/certs/server.crt -days 365 -nodes -subj "/CN=localhost"

# Build the application
ENV GOCACHE=/root/.cache/go-build
RUN --mount=type=cache,target=/go/pkg/mod \
    go build -o bocal-smtpd .

# Expose the SMTP port
EXPOSE 1025

# Command to run the server
CMD ["./bocal-smtpd"]
