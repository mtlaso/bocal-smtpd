#!/bin/bash

clear

PREFIX="[script]"
SMTP_SERVER_SERVICE="bocal-smtpd"
EMAIL_SENDER_SERVICE="bocal-email-sender"
EMAIL_SENDER_BINARY="bocal-email-sender"
# Dir to store DKIM keys.
HOST_KEY_DIR="./bocal-email-sender/keys"

# Exit immediately if a command exits with a non-zero status.
set -e
echo "$PREFIX === setting up testing environment ==="

# Create necessary directories (if they don't exist).
mkdir -p dns/zones
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

# PUBLIC_KEY=$(cat "$HOST_KEY_DIR/dkim.public")
# Make sure that the public key has no white space.
# PUBLIC_KEY=$(cat "$HOST_KEY_DIR/dkim.public" | tr -d '\n\r\t ')
PUBLIC_KEY=$(openssl rsa -in "$HOST_KEY_DIR/dkim.private" -pubout -outform der | base64 -w0)
echo "$PREFIX Public key: $PUBLIC_KEY"

# Create CoreDNS configuration (if it doesn't exist).
if [ ! -f dns/Corefile ]; then
    echo "$PREFIX Creating CoreDNS configuration..."
    cat > dns/Corefile << EOF
. {
    forward . 8.8.8.8
    log
}

example.com {
    file /etc/coredns/zones/example.com.zone
    log
}

test.com {
    file /etc/coredns/zones/test.com.zone
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
@       IN      A       172.28.1.3 ; This is the IP address of your email-sender container in the test network
@       IN      TXT     "v=spf1 ip4:172.28.1.3 -all"
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
@       IN      TXT     "v=spf1 -all"
_dmarc  IN      TXT     "v=DMARC1; p=reject; rua=mailto:dmarc@test.com"
selector._domainkey IN TXT "v=DKIM1; k=rsa; p=$PUBLIC_KEY"
EOF
fi

# echo "$PREFIX updating example.com zone file with DKIM public key..."
# sed "s|DKIM_PUBLIC_KEY_PLACEHOLDER|$PUBLIC_KEY|" dns/zones/example.com.zone > dns/zones/example.com.zone.tmp
# mv dns/zones/example.com.zone.tmp dns/zones/example.com.zone

# echo "$PREFIX updating test.com zone file with DKIM public key..."
# sed "s|DKIM_PUBLIC_KEY_PLACEHOLDER|$PUBLIC_KEY|" dns/zones/test.com.zone > dns/zones/test.com.zone.tmp
# mv dns/zones/test.com.zone.tmp dns/zones/test.com.zone

echo "$PREFIX starting Docker containers..."
docker compose down -v
# docker compose build --parallel
docker compose up -d

echo "$PREFIX checking if services are running..."
if ! docker compose ps | grep -q " Up "; then
    echo "$PREFIX error: services failed to start properly."
    docker compose logs
    exit 1
fi

echo "$PREFIX === Docker containers are running. ==="
echo "$PREFIX The email sender is running in a waiting state."
echo "$PREFIX To access logs:"
echo "$PREFIX   docker compose logs -f"
echo "$PREFIX "
echo "$PREFIX To run the test scenarios:"
echo "$PREFIX   docker compose exec $EMAIL_SENDER_SERVICE ./$EMAIL_SENDER_BINARY"
echo "$PREFIX "
echo "$PREFIX Shutdown with:"
echo "$PREFIX   docker compose down"
