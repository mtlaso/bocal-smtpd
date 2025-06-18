#!/bin/bash

clear

PREFIX="[script]"
SMTP_SERVER_SERVICE="bocal-smtpd"
HOST_KEY_DIR="./dns/keys"

# Exit immediately if a command exits with a non-zero status.
set -e

BUILD_BOCAL_SMTPD=false
for arg in "$@"; do
    if [ "$arg" == "--build-bocal-smtpd" ]; then
        BUILD_BOCAL_SMTPD=true
    fi
done

echo "$PREFIX === setting up testing environment ==="

# Create necessary directories (if they don't exist).
mkdir -p dns/zones
mkdir -p dns/keys
mkdir -p "$HOST_KEY_DIR"

echo "$PREFIX Generating DKIM keys on host..."
if [ ! -f "$HOST_KEY_DIR/dkim.private" ]; then
    openssl genpkey -algorithm RSA -out "$HOST_KEY_DIR/dkim.private.pkcs8" -pkeyopt rsa_keygen_bits:1024
    openssl pkcs8 -topk8 -nocrypt -in "$HOST_KEY_DIR/dkim.private.pkcs8" -outform PEM -out "$HOST_KEY_DIR/dkim.private"
    rm "$HOST_KEY_DIR/dkim.private.pkcs8"
    # Extract the public key in DER format and base64 encode it with no line breaks
    openssl rsa -in "$HOST_KEY_DIR/dkim.private" -pubout -outform der | base64 -w0 > "$HOST_KEY_DIR/dkim.public"
else
    echo "$PREFIX DKIM keys already exist in $HOST_KEY_DIR"
fi

PUBLIC_KEY=$(openssl rsa -in "$HOST_KEY_DIR/dkim.private" -pubout -outform der | base64 -w0)
echo "$PREFIX Public key: $PUBLIC_KEY"

echo "$PREFIX Generating self-signed certificate for internal/bocalmail..."
OUT=$(openssl req -x509 -newkey rsa:4096 -keyout internal/bocalmail/privatekey.pem -out internal/bocalmail/fullchain.pem -days 365 -nodes -subj "/CN=localhost")

if [ ! -f dns/Corefile ]; then
    echo "$PREFIX Creating CoreDNS configuration..."
    cat > dns/Corefile << EOF
example.com {
    file /etc/coredns/zones/example.com.zone
    log
}

test.com {
    file /etc/coredns/zones/test.com.zone
    log
}

. {
    # Forward to Docker's built-in DNS.
    forward . 127.0.0.11
    log
}

EOF
fi

# Create initial zone files with placeholder for DKIM public key (if they don't exist).
if [ ! -f dns/zones/example.com.zone ]; then
    echo "$PREFIX Creating example.com zone file..."
    cat > dns/zones/example.com.zone << EOF
\$ORIGIN example.com.
@       IN      SOA     ns.example.com. admin.example.com. (
                       2023042201      ; serial
                       7200            ; refresh
                       3600            ; retry
                       1209600         ; expire
                       3600            ; minimum
                       )
@       IN      NS      ns.example.com.
@       IN      TXT     "v=spf1 +all"  ; We use +all so SPF records are always valid because we don't know the IP address of the client (test) will use to send a request.
_dmarc  IN      TXT     "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
selector._domainkey IN TXT "v=DKIM1; k=rsa; p=$PUBLIC_KEY"
EOF
fi

if [ ! -f dns/zones/test.com.zone ]; then
     echo "$PREFIX Creating test.com zone file..."
     cat > dns/zones/test.com.zone << EOF
\$ORIGIN test.com.
@       IN      SOA     ns.test.com. admin.test.com. (
                        2023042201      ; serial
                        7200            ; refresh
                        3600            ; retry
                        1209600         ; expire
                        3600            ; minimum
                        )
@       IN      NS      ns.test.com.
@       IN      A       172.28.1.3
@       IN      TXT     "v=spf1 +all"   ; We use +all so SPF records are always valid because we don't know the IP address of the client (test) will use to send a request.
_dmarc  IN      TXT     "v=DMARC1; p=reject; rua=mailto:dmarc@test.com"
selector._domainkey IN TXT "v=DKIM1; k=rsa; p=$PUBLIC_KEY"
EOF
fi

echo "$PREFIX starting Docker containers..."
docker compose -f docker-compose.dev.yml down -v
if [ "$BUILD_BOCAL_SMTPD" = true ]; then
    echo "$PREFIX building container: $SMTP_SERVER_SERVICE"
    docker compose -f docker-compose.dev.yml build $SMTP_SERVER_SERVICE --parallel
fi
docker compose -f docker-compose.dev.yml up -d

echo "$PREFIX checking if services are running..."
if ! docker compose -f docker-compose.dev.yml ps | grep -q " Up "; then
    echo "$PREFIX error: services failed to start properly."
    docker compose -f docker-compose.dev.yml logs
    exit 1
fi
