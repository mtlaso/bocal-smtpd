###########################
###### Builder Stage ######
###########################
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod/ \
    go mod download
COPY . .
ENV GOCACHE=/root/.cache/go-build
RUN --mount=type=cache,target=/go/pkg/mod \
    go build -o bocal-smtpd .

###############################
###### Development Stage ######
###############################
FROM golang:1.24-alpine AS dev
WORKDIR /app
# For future reference, `app/bocal-smtpd` is THE executable.
COPY --from=builder /app/bocal-smtpd /app/
RUN apk add openssl
RUN mkdir -p /app/certs && \
    openssl req -x509 -newkey rsa:4096 -keyout /app/certs/privatekey.pem -out /app/certs/fullchain.pem -days 365 -nodes -subj "/CN=localhost"
CMD ["./bocal-smtpd"]

##############################
###### Production Stage ######
##############################
FROM alpine:latest AS prod
WORKDIR /app
# For future reference, `app/bocal-smtpd` is THE executable.
COPY --from=builder /app/bocal-smtpd /app/
RUN apk add --no-cache ca-certificates
CMD ["./bocal-smtpd"]
