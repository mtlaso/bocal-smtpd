# bocal-smtpd

## SSL/TLS Certificates

This application requires TLS certificates for secure SMTP communication.

For development:
1. Generate self-signed certificates using the provided script: `./scripts/generate-certs.sh`
2. Certificates will be created in the `dev_certs/` directory (which is gitignored)

For production:
1. Set the following environment variables:
   - `TLS_CERT_PATH`: Path to your TLS certificate
   - `TLS_KEY_PATH`: Path to your TLS private key
