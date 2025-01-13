#!/bin/bash
API_KEY="YOUR_VIRUSTOTAL_API_KEY"
URL="https://www.virustotal.com/api/v3/domains/"
check_domain() {
    local domain=$1
    response=$(curl -s -X GET "$URL$domain" -H "x-apikey: $API_KEY")
    malicious=$(echo $response | jq '.data.attributes.last_analysis_stats.malicious')
    if [ "$malicious" -gt 0 ]; then
        echo "Domain $domain is suspicious! Blocking local machine..."
        block_local_machine
    else
        echo "Domain $domain is safe."
    fi
}
block_local_machine() {
    local_ip=$(hostname -I | awk '{print $1}')
    echo "Blocking IP: $local_ip"
    sudo iptables -A INPUT -s $local_ip -j DROP
}
for domain in "$@"; do
    check_domain $domain
done
