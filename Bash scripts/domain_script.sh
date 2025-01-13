#!/bin/bash
# This script checks if a domain is malicious using VirusTotal API and blocks it locally if it is malicious.
API_KEY="your_virustotal_api_key"

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

DOMAIN="$1"

response=$(curl -s -X GET \
  "https://www.virustotal.com/api/v3/domains/$DOMAIN" \
  -H "x-apikey: $API_KEY")

malicious=$(echo "$response" | jq '.data.attributes.last_analysis_stats.malicious')

if [ "$malicious" -gt 0 ]; then
    echo "Domain $DOMAIN is malicious! Blocking it..."
    echo "127.0.0.1 $DOMAIN" | sudo tee -a /etc/hosts > /dev/null
    sudo iptables -A OUTPUT -d "$DOMAIN" -j REJECT
    echo "Domain $DOMAIN has been blocked successfully."
else
    echo "Domain $DOMAIN is safe. No action needed."
fi
