#!/bin/sh

set -e

echo 'Cert-Fetcher Script: Starting...'
ERRPREFIX="Error (.sh): fetch-certs.sh"

# These environment variables are expected to be set when this script is run
# (i.e., passed from docker-compose to the bitwarden/bws container)
# - BWS_ACCESS_TOKEN
# - BWS_PROJECT_ID
# - BWS_PRIVATEKEY_ID
# - BWS_FULLCHAIN_ID
# - TLS_CERT_PATH (e.g. app/certs/fullchain.pem)
# - TLS_KEY_PATH (e.g. app/certs/privkey.pem)


########################################
#### Validate environment variables ####
########################################
if [ -z "$BWS_ACCESS_TOKEN" ]; then
  echo "$ERRPREFIX BWS_ACCESS_TOKEN environment variable is not set." >&2
  exit 1
fi
if [ -z "$BWS_PROJECT_ID" ]; then
  echo "$ERRPREFIX BWS_PROJECT_ID environment variable is not set." >&2
  exit 1
fi
if [ -z "$BWS_PRIVATEKEY_ID" ]; then
  echo "$ERRPREFIX BWS_PRIVATEKEY_ID environment variable is not set." >&2
  exit 1
fi
if [ -z "$BWS_FULLCHAIN_ID" ]; then
  echo "$ERRPREFIX BWS_FULLCHAIN_ID environment variable is not set." >&2
  exit 1
fi
if [ -z "$TLS_CERT_PATH" ] || [ -z "$TLS_KEY_PATH" ]; then
  echo "$ERRPREFIX TLS_CERT_PATH or TLS_KEY_PATH environment variables are not set." >&2
  exit 1
fi


########################
#### Retreive certs ####
########################
mkdir -p "$(dirname "$TLS_CERT_PATH")"
mkdir -p "$(dirname "$TLS_KEY_PATH")"

FULLCHAIN=$(bws secret get "$BWS_FULLCHAIN_ID" --access-token $BWS_ACCESS_TOKEN | jq -r '.value' | base64 --decode)
if [ -z "$FULLCHAIN" ]; then
  echo "$ERRPREFIX: Failed to fetch fullchain secret or it was empty." >&2
  exit 1
fi
echo "$FULLCHAIN" > "$TLS_CERT_PATH"
if [ $? -ne 0 ]; then
  echo "$ERRPREFIX: Failed to decode or write fullchain." >&2
  exit 1
fi

chmod 600 "$TLS_CERT_PATH"
echo "Fullchain certificate written to $TLS_CERT_PATH"

PRIVKEY=$(bws secret get "$BWS_PRIVATEKEY_ID" --access-token $BWS_ACCESS_TOKEN | jq -r '.value' | base64 --decode)
if [ -z "$PRIVKEY" ]; then
  echo "$ERRPREFIX: Failed to fetch private key secret or it was empty." >&2
  exit 1
fi
echo "$PRIVKEY" > "$TLS_KEY_PATH"
if [ $? -ne 0 ]; then
  echo "$ERRPREFIX: Failed to decode or write private key." >&2
  exit 1
fi

chmod 600 "$TLS_KEY_PATH"
echo "Private key written to $TLS_KEY_PATH"

echo "Cert-Fetcher Script: certificates fetched successfully."
exit 0 # Explicitly exit with success for service_completed_successfully condition
