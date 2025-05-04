#!/bin/bash

mkdir -p dev_certs
cd dev_certs

# Generate a private key
openssl genrsa -out server.key 2048

# Generate a self-signed certificate
openssl req -new -x509 -key server.key -out server.crt -days 365 -subj "/CN=localhost"

echo "Development certificates generated in dev_certs/"
