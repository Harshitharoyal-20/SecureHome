#!/bin/sh
# DuckDNS Dynamic DNS Shell Updater for SecureHome
# Updates your free subdomain (e.g., https://yourdomain.duckdns.org) with your current public IP.

DOMAIN="${DUCKDNS_DOMAIN:-yoursubdomain}"
TOKEN="${DUCKDNS_TOKEN:-your-token-from-duckdns}"

if [ "$DOMAIN" = "yoursubdomain" ] || [ "$TOKEN" = "your-token-from-duckdns" ]; then
  echo "Error: Please set DUCKDNS_DOMAIN and DUCKDNS_TOKEN environment variables."
  echo "Example: DUCKDNS_DOMAIN=securehome DUCKDNS_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx ./duckdns-updater.sh"
  exit 1
fi

echo "Updating DuckDNS domain: ${DOMAIN}.duckdns.org..."
RESPONSE=$(curl -s "https://www.duckdns.org/update?domains=${DOMAIN}&token=${TOKEN}&ip=")

if [ "$RESPONSE" = "OK" ]; then
  echo "Success: ${DOMAIN}.duckdns.org updated successfully to current public IP."
else
  echo "Failed: DuckDNS returned response: $RESPONSE"
  exit 1
fi
